using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>Keyed payload obtained solely through the project's clean-room readers.</summary>
public sealed record ProsperoDecodedPackage(
    ProsperoPackageInspection Inspection,
    byte[] InnerImage,
    byte[] Naps,
    byte[] Mount,
    IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> Blocks,
    bool OuterPfsIcvValid);

/// <summary>
/// Lazy, file-backed decode result for multi-GB packages: the outer PFS is opened once and the
/// inner mount is served on demand through <see cref="ProsperoInnerMountStream"/>. Neither the
/// inner image nor the mount is materialized as a single <c>byte[]</c>, and no temporary mount
/// file is written. <see cref="Entries"/> is enumerated from the inner-PFS metadata only, so it
/// never reads the file data. Callers own disposal, which releases the package stream.
/// </summary>
public sealed class ProsperoFileBackedPackage : IDisposable
{
    private readonly FileStream _stream;
    private readonly AesXts _xts;
    private readonly Func<long, int, byte[]> _readRegion;

    internal ProsperoFileBackedPackage(
        ProsperoPackageInspection inspection,
        byte[] naps,
        IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks,
        long innerImageLength,
        long mountLength,
        bool outerPfsIcvValid,
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries,
        FileStream stream,
        AesXts xts,
        Func<long, int, byte[]> readRegion)
    {
        Inspection = inspection;
        Naps = naps;
        Blocks = blocks;
        InnerImageLength = innerImageLength;
        MountLength = mountLength;
        OuterPfsIcvValid = outerPfsIcvValid;
        Entries = entries;
        _stream = stream;
        _xts = xts;
        _readRegion = readRegion;
    }

    public ProsperoPackageInspection Inspection { get; }
    public byte[] Naps { get; }
    public IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> Blocks { get; }
    public long InnerImageLength { get; }
    public long MountLength { get; }
    public bool OuterPfsIcvValid { get; }
    public IReadOnlyList<ProsperoInnerPfsReader.Entry> Entries { get; }

    /// <summary>Open a fresh lazy view of the reconstructed inner mount.</summary>
    public Stream OpenMount() => new ProsperoInnerMountStream(Blocks, InnerImageLength, _readRegion);

    /// <summary>Decrypt and return an arbitrary <c>pfs_image.dat</c> region on demand.</summary>
    public byte[] ReadInnerImageRegion(long offset, int length) => _readRegion(offset, length);

    /// <summary>Decode every block (discarding the bytes) to validate the whole image.</summary>
    public void DecodeAllBlocks() =>
        ProsperoPs5InnerImageReader.DecodeAllBlocks(Blocks, _readRegion, InnerImageLength);

    public void Dispose()
    {
        _xts.Dispose();
        _stream.Dispose();
    }
}

public static class ProsperoPackageContent
{
    /// <summary>
    /// Decode a finalized-debug package lazily: open the outer PFS once (using the FIH superblock
    /// hint so a multi-GB image is not scanned linearly) and serve the inner mount on demand. No
    /// temporary mount file is written, and enumerating the result touches only the inner-PFS
    /// metadata blocks, so listing or summarising a multi-GB package is fast. The caller must
    /// dispose the result to release the package stream.
    /// </summary>
    public static ProsperoFileBackedPackage ReadFileBacked(string packagePath, string? passcode = null,
        bool repairTruncatedOffsets = false)
    {
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(packagePath);
        if (inspection.Fih is not { } fih)
            throw new InvalidDataException("The package has no finalized FIH/PFS payload.");
        if (inspection.Kind != ProsperoPackageKind.FinalizedDebug)
            throw new InvalidDataException("The file-backed reader supports finalized debug packages only.");
        if (inspection.Cnt.ContentId.Length != 36)
            throw new InvalidDataException("The package CNT has no usable content ID for outer-PFS key derivation.");

        var stream = new FileStream(Path.GetFullPath(packagePath), FileMode.Open, FileAccess.Read, FileShare.Read);
        try
        {
            long pfsOffset = checked((long)fih.PfsOffset);
            long pfsSize = checked((long)fih.PfsSize);
            OuterPfsReader pfs = OuterPfsReader.Open(stream, pfsOffset, pfsSize,
                ReadOuterSuperblockIndexHint(stream, pfsSize));
            byte[] ekpfs = ProsperoKeys.ComputeEkpfs(inspection.Cnt.ContentId,
                passcode ?? Gp5.Gp5Constants.DefaultPasscode);
            (byte[] tweak, byte[] data) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
            var xts = new AesXts(data, tweak);
            try
            {
                byte[] naps = pfs.ReadNaps(xts);
                long innerLength = pfs.InnerImageLength;
                byte[] ReadRegion(long offset, int length) => pfs.ReadInnerImageRegion(xts, offset, length);
                IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks =
                    NapsDialectRegistry.Select(naps, innerLength, candidate =>
                        NapsDialectRegistry.ProbePfs(candidate, innerLength, ReadRegion, ReadInnerSuperblockHint(stream)));
                long mountLength = ProsperoPs5InnerImageReader.MountSize(blocks);

                IReadOnlyList<ProsperoInnerPfsReader.Entry> entries;
                using (var mount = new ProsperoInnerMountStream(blocks, innerLength, ReadRegion))
                    entries = ProsperoInnerPfsReader.Enumerate(mount, ReadInnerSuperblockHint(stream), repairTruncatedOffsets);

                return new ProsperoFileBackedPackage(
                    inspection, naps, blocks, innerLength, mountLength, pfs.VerifySuperblockIcv(), entries,
                    stream, xts, ReadRegion);
            }
            catch
            {
                xts.Dispose();
                throw;
            }
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    /// <summary>
    /// True when a finalized-debug package's decoded inner mount is too large to materialize as one
    /// <c>byte[]</c> (its uncompressed size exceeds <see cref="int.MaxValue"/>), so callers must use
    /// <see cref="ReadFileBacked"/>. The compressed PFS size is not a reliable proxy: a ~1.3 GiB
    /// package can decode to a ~3.5 GiB mount and would otherwise fail the in-memory size check.
    /// </summary>
    public static bool RequiresFileBacked(string packagePath, string? passcode = null)
    {
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(packagePath);
        if (inspection.Kind != ProsperoPackageKind.FinalizedDebug || inspection.Fih is not { } fih)
            return false;
        if (fih.PfsSize > (1L << 31))
            return true;
        if (inspection.Cnt.ContentId.Length != 36)
            return false;
        try
        {
            using var stream = new FileStream(Path.GetFullPath(packagePath), FileMode.Open, FileAccess.Read, FileShare.Read);
            OuterPfsReader pfs = OuterPfsReader.Open(stream, checked((long)fih.PfsOffset), checked((long)fih.PfsSize),
                ReadOuterSuperblockIndexHint(stream, (long)fih.PfsSize));
            byte[] ekpfs = ProsperoKeys.ComputeEkpfs(inspection.Cnt.ContentId,
                passcode ?? Gp5.Gp5Constants.DefaultPasscode);
            (byte[] tweak, byte[] data) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
            using var xts = new AesXts(data, tweak);
            byte[] naps = pfs.ReadNaps(xts);
            long mountLength = ProsperoPs5InnerImageReader.MountSize(
                NapsDialectRegistry.Select(naps, pfs.InnerImageLength, candidate =>
                    NapsDialectRegistry.ProbePfs(candidate, pfs.InnerImageLength,
                        (offset, length) => pfs.ReadInnerImageRegion(xts, offset, length), ReadInnerSuperblockHint(stream))));
            return mountLength > int.MaxValue;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or CryptographicException or NotSupportedException or ArgumentException)
        {
            return false; // let the normal path surface the real error
        }
    }

    /// <summary>
    /// Derive the outer-PFS superblock block index from the FIH header field at 0x20
    /// (<c>0x10000 + superblockOffset</c>), or -1 when it is absent/implausible. The hint only
    /// speeds up <see cref="OuterPfsReader.Open"/>; a wrong hint falls back to a full scan.
    /// </summary>
    private static int ReadOuterSuperblockIndexHint(Stream stream, long pfsSize)
    {
        Span<byte> header = stackalloc byte[0x60];
        stream.Position = 0;
        stream.ReadExactly(header);
        ulong field = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(0x20, 8));
        if (field < OuterPfsReader.BlockSize)
            return -1;
        long offset = (long)field - OuterPfsReader.BlockSize;
        if (offset % OuterPfsReader.BlockSize != 0)
            return -1;
        long index = offset / OuterPfsReader.BlockSize;
        int blockCount = (int)(pfsSize / OuterPfsReader.BlockSize);
        return index >= 0 && index < blockCount ? (int)index : -1;
    }

    /// <summary>
    /// Derive the inner-PFS superblock logical mount offset from the FIH metadata-base field at
    /// 0x50 (a 64 KiB block count), or -1 when absent. A wrong/absent hint falls back to a scan.
    /// </summary>
    private static long ReadInnerSuperblockHint(Stream stream)
    {
        Span<byte> header = stackalloc byte[0x58];
        stream.Position = 0;
        stream.ReadExactly(header);
        ulong blocks = BinaryPrimitives.ReadUInt64LittleEndian(header.Slice(0x50, 8));
        return blocks > 0 ? (long)blocks * ProsperoInnerPfsReader.BlockSize : -1;
    }

    public static ProsperoDecodedPackage Read(string packagePath, string? passcode = null, string? referencePackagePath = null)
    {
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(packagePath);
        if (inspection.Fih is not { } fih)
            throw new InvalidDataException("The package has no finalized FIH/PFS payload.");
        if (inspection.Kind == ProsperoPackageKind.FinalizedPatchDebug)
            return ReadPatch(packagePath, referencePackagePath, passcode, inspection);
        if (inspection.Kind == ProsperoPackageKind.FinalizedRetail)
            throw new InvalidDataException("Encrypted payload: key required (retail payload keys are not available to this clean-room reader).");
        if (inspection.Cnt.ContentId.Length != 36)
            throw new InvalidDataException("The package CNT has no usable content ID for outer-PFS key derivation.");

        using var stream = File.OpenRead(Path.GetFullPath(packagePath));
        OuterPfsReader pfs = OuterPfsReader.Open(stream, checked((long)fih.PfsOffset), checked((long)fih.PfsSize));
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(inspection.Cnt.ContentId,
            passcode ?? Gp5.Gp5Constants.DefaultPasscode);
        (byte[] tweak, byte[] data) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(data, tweak);
        byte[] naps = pfs.ReadNaps(xts);
        byte[] image = pfs.ReadInnerImage(xts);
        IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks = NapsDialectRegistry.Select(naps, image.Length,
            candidate => NapsDialectRegistry.ProbePfs(candidate, image.Length,
                (offset, length) => image.AsSpan(checked((int)offset), length).ToArray(), ReadInnerSuperblockHint(stream)));
        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(image, blocks);
        return new ProsperoDecodedPackage(inspection, image, naps, mount, blocks, pfs.VerifySuperblockIcv());
    }

    private static ProsperoDecodedPackage ReadPatch(string packagePath, string? referencePackagePath,
        string? passcode, ProsperoPackageInspection inspection)
    {
        if (string.IsNullOrWhiteSpace(referencePackagePath))
            throw new InvalidDataException("Patch payload reconstruction requires the base/reference package path.");
        ProsperoPackageInspection reference = ProsperoPackageReader.Read(referencePackagePath);
        if (reference.Kind != ProsperoPackageKind.FinalizedDebug)
            throw new InvalidDataException("Patch reference must be a finalized debug base package; patch-chain references are not yet verified.");
        if (!string.Equals(reference.Cnt.ContentId, inspection.Cnt.ContentId, StringComparison.Ordinal))
            throw new InvalidDataException("Patch and reference package content IDs do not match.");
        if (inspection.Fih is not { } fih || inspection.Lih is not { } lih)
            throw new InvalidDataException("Patch LIH/FIH geometry is unavailable.");

        using (var patchHeader = File.OpenRead(Path.GetFullPath(packagePath)))
        using (var referenceHeader = File.OpenRead(Path.GetFullPath(referencePackagePath)))
        {
            byte[] expectedReferenceDigest = new byte[32];
            byte[] actualReferenceDigest = new byte[32];
            patchHeader.Position = checked((long)lih.FihOffset + 0xD0);
            patchHeader.ReadExactly(expectedReferenceDigest);
            referenceHeader.Position = 0x30;
            referenceHeader.ReadExactly(actualReferenceDigest);
            if (!expectedReferenceDigest.AsSpan().SequenceEqual(actualReferenceDigest))
                throw new InvalidDataException("Patch FIH reference digest does not match the supplied base package.");
        }

        using var package = File.OpenRead(Path.GetFullPath(packagePath));
        OuterPfsReader pfs = OuterPfsReader.Open(package, checked((long)fih.PfsOffset), checked((long)fih.PfsSize));
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(inspection.Cnt.ContentId,
            passcode ?? Gp5.Gp5Constants.DefaultPasscode);
        (byte[] tweak, byte[] data) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(data, tweak);

        byte[] fihHeader = new byte[0x40];
        package.Position = checked((long)lih.FihOffset);
        package.ReadExactly(fihHeader);
        long metadataSectorBase = BinaryPrimitives.ReadInt64LittleEndian(fihHeader.AsSpan(0x20, 8)) / OuterPfsReader.BlockSize;
        if (metadataSectorBase < 2)
            throw new InvalidDataException("Patch FIH metadata-sector base is invalid.");
        int napsBlock = pfs.SuperblockIndex - 1;
        if (napsBlock < 0)
            throw new InvalidDataException("Patch outer PFS has no NAPS block before its superblock.");
        byte[] encryptedNaps = new byte[OuterPfsReader.BlockSize];
        package.Position = checked((long)fih.PfsOffset + napsBlock * OuterPfsReader.BlockSize);
        package.ReadExactly(encryptedNaps);
        byte[] naps = xts.Decrypt(encryptedNaps, 0x800000000000UL | checked((ulong)(metadataSectorBase - 2)));
        _ = ProsperoNapsLayout.DecodeHeader(naps);

        ProsperoPatchRelocation.Tables tables = ProsperoPatchRelocation.Read(packagePath, inspection);
        byte[] encryptedVirtualImage = ProsperoPatchRelocation.MaterializeEncryptedVirtualImage(
            packagePath, referencePackagePath, tables);
        byte[] mount = ProsperoPs5InnerImageReader.ReconstructRunEncryptedMount(encryptedVirtualImage, naps, xts);
        _ = ProsperoInnerPfsReader.Enumerate(mount);
        return new ProsperoDecodedPackage(inspection, encryptedVirtualImage, naps, mount, [], pfs.VerifySuperblockIcv());
    }

    public static byte[] ReadCntEntry(string packagePath, ProsperoPackageInspection inspection, ProsperoCntEntry entry, long? length = null)
    {
        long cntBase = inspection.Fih is null ? 0 : checked((long)inspection.Fih.CntOffset);
        long start = checked(cntBase + entry.DataOffset);
        long size = length ?? entry.DataSize;
        using var stream = File.OpenRead(Path.GetFullPath(packagePath));
        if (start < 0 || size < 0 || size > stream.Length - start)
            throw new InvalidDataException($"CNT entry 0x{entry.Id:X8} is outside the package.");
        byte[] result = new byte[size];
        stream.Position = start;
        stream.ReadExactly(result);
        return result;
    }

    /// <summary>
    /// The candidate stored lengths an entry's CNT body digest may cover. Non-encrypted entries use
    /// the exact data size. Encrypted/protected entries (<c>Flags1</c> high bit) are stored 16-byte
    /// aligned, so the digest may cover the rounded-up length including padding (reference writers)
    /// or the exact declared size (this writer, which does not apply block padding); both are
    /// accepted so neither convention is falsely reported, while corruption still fails both.
    /// </summary>
    public static IReadOnlyList<long> CntDigestLengths(ProsperoCntEntry entry)
    {
        long exact = entry.DataSize;
        if (!entry.IsEncrypted)
            return [exact];
        long padded = (exact + 15L) & ~15L;
        return padded == exact ? [exact] : [exact, padded];
    }

    public static bool TryOpenSi(string packagePath, ProsperoPackageInspection inspection, out string? error)
    {
        error = null;
        ProsperoPackageSegment? si = inspection.Segments.FirstOrDefault(s => s.Name == "SI");
        if (si is null || si.Size == 0) return false;
        try
        {
            using var stream = File.OpenRead(Path.GetFullPath(packagePath));
            using var slice = new SubReadStream(stream, si.Offset, si.Size);
            using var zip = new ZipArchive(slice, ZipArchiveMode.Read, leaveOpen: false);
            _ = zip.Entries.Count;
            return true;
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            error = ex.Message;
            return false;
        }
    }

    private sealed class SubReadStream(Stream baseStream, long start, long length) : Stream
    {
        private long _position;
        public override bool CanRead => true; public override bool CanSeek => true; public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _position; set => _position = value >= 0 && value <= length ? value : throw new ArgumentOutOfRangeException(nameof(value)); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
        public override int Read(Span<byte> buffer)
        {
            int take = (int)Math.Min(buffer.Length, length - _position);
            if (take == 0) return 0;
            baseStream.Position = start + _position;
            int read = baseStream.Read(buffer[..take]); _position += read; return read;
        }
        public override long Seek(long offset, SeekOrigin origin) => Position = origin switch { SeekOrigin.Begin => offset, SeekOrigin.Current => _position + offset, SeekOrigin.End => length + offset, _ => throw new ArgumentOutOfRangeException(nameof(origin)) };
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}

/// <summary>
/// Outcome of a single verification check.
/// <list type="bullet">
/// <item><see cref="Pass"/> — the check ran and succeeded.</item>
/// <item><see cref="Fail"/> — the data was available and the check ran, but the content/format/integrity was wrong.</item>
/// <item><see cref="Unavailable"/> — required key material or input (e.g. a retail key, a patch reference) is genuinely absent.</item>
/// <item><see cref="Unsupported"/> — this implementation does not currently perform that check.</item>
/// <item><see cref="Error"/> — an I/O, decode, crypto, or malformed-data failure prevented the check from completing.</item>
/// <item><see cref="NotPresent"/> — the optional structure the check targets is absent (not a failure).</item>
/// </list>
/// </summary>
public enum VerificationState { Pass, Fail, Unavailable, Unsupported, Error, NotPresent }

/// <summary>Selects which checks are mandatory, so acceptance cannot be claimed from a partial report.</summary>
public enum VerificationPolicy
{
    /// <summary>Envelope level only: structural bounds, FIH digest, CNT digests.</summary>
    Structural,
    /// <summary>Default: the structural checks plus the full inner-payload decode.</summary>
    DebugPackage,
    /// <summary>Build acceptance: everything <see cref="DebugPackage"/> requires, at the same depth.</summary>
    BuildAcceptance,
    /// <summary>Every available check, including the ones not yet implemented (so the report stays incomplete).</summary>
    FullAvailableChecks,
}

/// <summary>Overall package verdict derived from the individual checks.</summary>
public enum VerificationOutcome { Passed, Failed, Incomplete }

/// <summary>
/// A single verification result. <paramref name="Required"/> marks the checks that must be performed
/// for the policy in force; a required check that is merely <see cref="VerificationState.Unavailable"/>
/// or <see cref="VerificationState.Unsupported"/> makes the report
/// <see cref="VerificationOutcome.Incomplete"/> instead of allowing it to look successful.
/// </summary>
public sealed record VerificationCheck(string Name, VerificationState State, string Detail, bool Required = true);

public sealed record ProsperoPackageVerificationReport(IReadOnlyList<VerificationCheck> Checks)
{
    /// <summary>
    /// True when a check ran and failed, or could not complete after the payload was opened
    /// (decode/crypto/I/O). Missing keys are <see cref="VerificationState.Unavailable"/>, not failures.
    /// </summary>
    public bool HasFailure => Checks.Any(c => c.State is VerificationState.Fail or VerificationState.Error);

    /// <summary>True when a check could not complete because of an execution failure rather than a wrong result.</summary>
    public bool HasError => Checks.Any(c => c.State == VerificationState.Error);

    /// <summary>Every required check was actually performed (no required unavailable/unsupported checks).</summary>
    public bool IsComplete => !Checks.Any(c => c.Required &&
        c.State is VerificationState.Unavailable or VerificationState.Unsupported);

    /// <summary>Distinguishes passed / failed / incomplete for callers that gate on acceptance.</summary>
    public VerificationOutcome Outcome =>
        HasFailure ? VerificationOutcome.Failed :
        IsComplete ? VerificationOutcome.Passed : VerificationOutcome.Incomplete;
}

/// <summary>High-level, evidence-labelled verification over independently implemented primitives.</summary>
public static class ProsperoPackageVerifier
{
    // Policy requirement masks: a check is Required when its mask intersects the selected policy.
    private const int ScopeStructural = 1;
    private const int ScopeDebug = 2;
    private const int ScopeBuild = 4;
    private const int ScopeFull = 8;
    private const int ScopeEnvelope = ScopeStructural | ScopeDebug | ScopeBuild | ScopeFull;
    private const int ScopePayload = ScopeDebug | ScopeBuild | ScopeFull;

    /// <summary>Verify using the default <see cref="VerificationPolicy.DebugPackage"/> policy.</summary>
    public static ProsperoPackageVerificationReport Verify(string packagePath, string? passcode = null,
        string? referencePackagePath = null)
        => Verify(packagePath, passcode, referencePackagePath, VerificationPolicy.DebugPackage);

    public static ProsperoPackageVerificationReport Verify(string packagePath, string? passcode,
        string? referencePackagePath, VerificationPolicy policy)
    {
        int scope = policy switch
        {
            VerificationPolicy.Structural => ScopeStructural,
            VerificationPolicy.BuildAcceptance => ScopeBuild,
            VerificationPolicy.FullAvailableChecks => ScopeFull,
            _ => ScopeDebug,
        };
        var checks = new List<VerificationCheck>();
        void Add(string name, VerificationState state, string detail, int mask)
            => checks.Add(new(name, state, detail, (mask & scope) != 0));

        ProsperoPackageInspection inspection;
        try { inspection = ProsperoPackageReader.Read(packagePath); }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
            return new([new("Package structural bounds", VerificationState.Fail, ex.ToString())]);
        }

        Add("Package structural bounds", inspection.Structure.IsValid ? VerificationState.Pass : VerificationState.Fail,
            inspection.Structure.IsValid ? "FIH/CNT ranges are valid" : string.Join("; ", inspection.Structure.Issues.Where(i => i.IsError).Select(i => i.Code)),
            ScopeEnvelope);
        VerifyCnt(packagePath, inspection, Add);
        bool si = ProsperoPackageContent.TryOpenSi(packagePath, inspection, out string? siError);
        Add("SI ZIP readability", si ? VerificationState.Pass : inspection.Segments.Any(s => s.Name == "SI" && s.Size > 0) ? VerificationState.Fail : VerificationState.NotPresent,
            si ? "Stored SI ZIP opens and its directory enumerates (member contents are not parsed)" : siError ?? "No SI segment",
            ScopeFull);
        VerificationCheck fih = VerifyFihDigest(packagePath, inspection);
        Add(fih.Name, fih.State, fih.Detail, ScopeEnvelope);
        Add("RSA signature", VerificationState.Unsupported, "Public-key signature verification is not implemented in this clean-room build", ScopeFull);

        bool retail = inspection.Kind == ProsperoPackageKind.FinalizedRetail;
        bool patchWithoutReference = inspection.Kind == ProsperoPackageKind.FinalizedPatchDebug
            && string.IsNullOrWhiteSpace(referencePackagePath);
        if (retail || patchWithoutReference)
        {
            // The keyed payload cannot even be opened: report the payload checks as genuinely
            // unavailable (a support boundary), never as a corruption/decoder failure.
            string detail = retail
                ? "Retail payload key material is unavailable to this clean-room reader"
                : "Patch payload reconstruction requires a base/reference package path";
            AddPayloadChecks(Add, VerificationState.Unavailable, detail, ScopePayload);
            return new(checks);
        }

        try
        {
            // Multi-GB finalized-debug PFS images cannot be materialized as one byte[]; the
            // in-memory reader rejects them, so mirror img_info and reconstruct via the
            // file-backed reader instead of reporting the whole payload as unavailable.
            bool large = inspection.Kind == ProsperoPackageKind.FinalizedDebug &&
                ProsperoPackageContent.RequiresFileBacked(packagePath, passcode);
            if (large)
            {
                using ProsperoFileBackedPackage fileBacked = ProsperoPackageContent.ReadFileBacked(packagePath, passcode);
                // Verification keeps its full decode pass (validating every stored/Kraken block) but
                // streams it on demand instead of reconstructing a multi-GB temp mount.
                fileBacked.DecodeAllBlocks();
                AddDecodedChecks(Add, fileBacked.Blocks, fileBacked.Entries, fileBacked.OuterPfsIcvValid,
                    ProsperoPackageKind.FinalizedDebug);
            }
            else
            {
                ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(packagePath, passcode, referencePackagePath);
                AddDecodedChecks(Add, decoded.Blocks, ProsperoInnerPfsReader.Enumerate(decoded.Mount),
                    decoded.OuterPfsIcvValid, decoded.Inspection.Kind);
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or CryptographicException or NotSupportedException or ArgumentException)
        {
            // For a debug/patch package the key is derivable, so reaching this catch means the
            // payload was openable and the failure is a real decode/integrity/IO problem. It must
            // be reported as an error (with the original exception preserved) rather than softened
            // into a missing-key "unavailable" state.
            VerificationState state = ex is NotSupportedException
                ? VerificationState.Unsupported
                : VerificationState.Error;
            AddPayloadChecks(Add, state, ex.ToString(), ScopePayload);
        }
        return new(checks);
    }

    /// <summary>
    /// The four keyed payload checks that share a single availability/outcome, plus the two
    /// not-yet-implemented independent checks (which stay <see cref="VerificationState.Unsupported"/>).
    /// </summary>
    private static void AddPayloadChecks(Action<string, VerificationState, string, int> add,
        VerificationState state, string detail, int mask)
    {
        add("Outer PFS superblock ICV", state, detail, mask);
        add("NAPS structure", state, detail, mask);
        add("Kraken decode/reconstruction", state, detail, mask);
        add("Inner PFS structural integrity", state, detail, mask);
        add("PFS block hashes/digests", VerificationState.Unsupported, "Per-block digest verification is not implemented", ScopeFull);
        add("PlayGo CRC", VerificationState.Unsupported, "Independent PlayGo CRC verification is not implemented", ScopeFull);
    }

    private static void AddDecodedChecks(Action<string, VerificationState, string, int> add,
        IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks,
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries, bool icvValid, ProsperoPackageKind kind)
    {
        add("Outer PFS superblock ICV", icvValid ? VerificationState.Pass : VerificationState.Fail,
            icvValid ? "SHA3-256 ICV matches" : "SHA3-256 ICV mismatch", ScopePayload);
        add("NAPS structure", VerificationState.Pass,
            kind == ProsperoPackageKind.FinalizedPatchDebug
                ? "RUN-addressed patch NAPS reconstructed"
                : $"{blocks.Count} CblockInfo data blocks walked", ScopePayload);
        add("Kraken decode/reconstruction", VerificationState.Pass,
            "All stored/Kraken/alias blocks decoded", ScopePayload);
        add("Inner PFS structural integrity", VerificationState.Pass, $"{entries.Count} logical entries", ScopePayload);
        add("PFS block hashes/digests", VerificationState.Unsupported, "Per-block digest verification is not implemented", ScopeFull);
        add("PlayGo CRC", VerificationState.Unsupported, "Independent PlayGo CRC verification is not implemented", ScopeFull);
    }

    /// <summary>
    /// The FIH carries the SHA3-256 of the plaintext outer-PFS superblock block, mirrored at 0x30,
    /// 0x70 and 0xD0. Both the digest and the superblock are stored unencrypted, so this check is
    /// independent of the package passcode and works on foreign (Sony-built) images.
    /// </summary>
    private static VerificationCheck VerifyFihDigest(string packagePath, ProsperoPackageInspection inspection)
    {
        if (inspection.Fih is not { } fih || fih.PfsSize < OuterPfsReader.BlockSize)
            return new("FIH digest", VerificationState.Unavailable, "No usable FIH outer-PFS region");
        try
        {
            long fihOffset = inspection.Lih is { } lih ? (long)lih.FihOffset : 0;
            using var fs = File.OpenRead(packagePath);
            byte[] header = new byte[0x100];
            fs.Position = fihOffset;
            fs.ReadExactly(header);
            byte[] expected = header.AsSpan(0x30, 32).ToArray();
            bool mirrored = header.AsSpan(0x70, 32).SequenceEqual(expected) && header.AsSpan(0xD0, 32).SequenceEqual(expected);
            OuterPfsReader pfs = OuterPfsReader.Open(fs, (long)fih.PfsOffset, (long)fih.PfsSize);
            byte[] superblock = new byte[OuterPfsReader.BlockSize];
            fs.Position = (long)fih.PfsOffset + (long)pfs.SuperblockIndex * OuterPfsReader.BlockSize;
            fs.ReadExactly(superblock);
            bool matches = Sha3.Sha3_256(superblock).AsSpan().SequenceEqual(expected);
            return matches && mirrored
                ? new("FIH digest", VerificationState.Pass, "FIH game digest = SHA3-256(plaintext outer-PFS superblock)")
                : new("FIH digest", VerificationState.Fail,
                    !matches ? "FIH game digest does not match SHA3-256(outer-PFS superblock)" : "FIH digest mirrors at 0x70/0xD0 disagree");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException)
        {
            return new("FIH digest", VerificationState.Error, ex.ToString());
        }
    }

    private static void VerifyCnt(string packagePath, ProsperoPackageInspection inspection,
        Action<string, VerificationState, string, int> add)
    {
        try
        {
            ProsperoCntEntry? digestEntry = inspection.Entries.FirstOrDefault(e => e.Id == (uint)CntEntryId.Digests);
            if (digestEntry is null) { add("CNT body/entry digests", VerificationState.NotPresent, "DIGESTS entry is absent", ScopeEnvelope); return; }
            byte[] digests = ProsperoPackageContent.ReadCntEntry(packagePath, inspection, digestEntry);
            ProsperoCntEntry[] sorted = inspection.Entries.OrderBy(e => e.Id).ToArray();
            if (digests.Length != sorted.Length * 32) throw new InvalidDataException("DIGESTS length does not match the CNT entry count.");
            for (int i = 0; i < sorted.Length; i++)
            {
                if (sorted[i].Id == (uint)CntEntryId.Digests) continue;
                bool matched = false;
                foreach (long length in ProsperoPackageContent.CntDigestLengths(sorted[i]))
                {
                    byte[] body;
                    try { body = ProsperoPackageContent.ReadCntEntry(packagePath, inspection, sorted[i], length); }
                    catch (InvalidDataException) { continue; }
                    if (Sha3.Sha3_256(body).AsSpan().SequenceEqual(digests.AsSpan(i * 32, 32)))
                    {
                        matched = true;
                        break;
                    }
                }
                if (!matched)
                    throw new InvalidDataException($"Digest mismatch for CNT entry 0x{sorted[i].Id:X8}.");
            }
            add("CNT body/entry digests", VerificationState.Pass, $"{sorted.Length - 1} entry digests match", ScopeEnvelope);
            add("GeneralDigests", VerifyGeneral(packagePath, inspection) ? VerificationState.Pass : VerificationState.Fail,
                "Verified param/playgo slots supported by the clean-room writer", ScopeEnvelope);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            add("CNT body/entry digests", VerificationState.Fail, ex.Message, ScopeEnvelope);
            add("GeneralDigests", VerificationState.Unavailable, "CNT digest table is invalid", ScopeEnvelope);
        }
    }

    private static bool VerifyGeneral(string path, ProsperoPackageInspection inspection)
    {
        ProsperoCntEntry? general = inspection.Entries.FirstOrDefault(e => e.Id == (uint)CntEntryId.GeneralDigests);
        if (general is null) return false;
        byte[] value = ProsperoPackageContent.ReadCntEntry(path, inspection, general);
        if (value.Length != 0x1E0) return false;
        ProsperoCntEntry? param = inspection.Entries.FirstOrDefault(e => e.Id == (uint)CntEntryId.ParamJson);
        if (param is not null && !Sha3.Sha3_256(ProsperoPackageContent.ReadCntEntry(path, inspection, param)).AsSpan().SequenceEqual(value.AsSpan(0xC0, 32))) return false;
        uint[] ids = [(uint)CntEntryId.PlaygoChunkDat, (uint)CntEntryId.PlaygoHashTable, (uint)CntEntryId.PlaygoFicm];
        byte[] joined = ids.SelectMany(id => inspection.Entries.Where(e => e.Id == id)
            .Select(e => Sha3.Sha3_256(ProsperoPackageContent.ReadCntEntry(path, inspection, e))))
            .SelectMany(digest => digest).ToArray();
        return joined.Length == 0 || Sha3.Sha3_256(joined).AsSpan().SequenceEqual(value.AsSpan(0xE0, 32));
    }
}
