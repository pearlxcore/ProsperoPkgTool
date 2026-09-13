using System.Buffers.Binary;
using System.Text;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>Well-known PS5 CNT entry ids.</summary>
public enum CntEntryId : uint
{
    Digests = 0x0001,
    EntryKeys = 0x0010,
    ImageKey = 0x0020,
    GeneralDigests = 0x0080,
    Metas = 0x0100,
    EntryNames = 0x0200,
    LicenseDat = 0x0400,
    LicenseInfo = 0x0401,
    NptitleDat = 0x0402,
    NpbindDat = 0x0403,
    SelfinfoDat = 0x0404,
    ImageinfoDat = 0x0406,
    TargetDeltainfoDat = 0x0407,
    OriginDeltainfoDat = 0x0408,
    PsreservedDat = 0x0409,
    Imagedigs = 0x040A,
    ParamSfo = 0x1000,
    PlaygoChunkDat = 0x1001,
    PlaygoChunkSha = 0x1002,
    PlaygoManifestXml = 0x1003,
    PronunciationXml = 0x1004,
    PronunciationSig = 0x1005,
    Pic1Png = 0x1006,
    PubtoolinfoDat = 0x1007,
    AppPlaygoChunkDat = 0x1008,
    AppPlaygoChunkSha = 0x1009,
    AppPlaygoManifestXml = 0x100A,
    ShareparamJson = 0x100B,
    ShareoverlayimagePng = 0x100C,
    SaveDataPng = 0x100D,
    ShareprivacyguardimagePng = 0x100E,
    Icon0Png = 0x1200,
    Pic0Png = 0x1220,
    Snd0At9 = 0x1240,
    ChangeinfoXml = 0x1260,
    Icon0Dds = 0x1280,
    Pic0Dds = 0x12A0,
    Pic1Dds = 0x12C0,
    Trophy2Ucp = 0x1480,
    UdsUcp = 0x14A0,
    UdsNpbind = 0x2020,
    Trophy2Npbind = 0x2021,
    Pic2Png = 0x2040,
    Pic2Dds = 0x2060,
    ParamJson = 0x2000,
    PlaygoHashTable = 0x2010,
    PlaygoFicm = 0x2011,
}

/// <summary>The general-digest slots of the GENERAL_DIGESTS entry (bit order of set_digests).</summary>
[Flags]
public enum GeneralDigest : int
{
    ContentDigest = 1 << 1,
    GameDigest = 1 << 2,
    HeaderDigest = 1 << 3,
    SystemDigest = 1 << 4,
    MajorParamDigest = 1 << 5,
    ParamDigest = 1 << 6,
    PlaygoDigest = 1 << 7,
    TrophyDigest = 1 << 8,
    ManualDigest = 1 << 9,
    KeymapDigest = 1 << 10,
    OriginDigest = 1 << 11,
    TargetDigest = 1 << 12,
    OriginGameDigest = 1 << 13,
    TargetGameDigest = 1 << 14,
}

/// <summary>Build parameters for a CNT container.</summary>
public sealed class CntBuildParameters
{
    /// <summary>The 36-character content id.</summary>
    public required string ContentId { get; init; }

    /// <summary>The 32-character passcode (all-zero is the default).</summary>
    public string Passcode { get; init; } = new string('0', 32);

    /// <summary>Content type code (0x20 = game data).</summary>
    public uint ContentType { get; init; } = 0x20;

    /// <summary>Content flags (GD_AC | GD_BASE for a game).</summary>
    public uint ContentFlags { get; init; } = 0x02020000;

    /// <summary>Version date (fixed package-format constant 0x20200722).</summary>
    public uint VersionDate { get; init; } = 0x20200722;

    /// <summary>Version hash (fixed constant 0x01FE52E9; must be nonzero).</summary>
    public uint VersionHash { get; init; } = 0x01FE52E9;
}

/// <summary>
/// Clean-room writer for the PS5 <c>\x7FCNT</c> metadata container — the big-endian header +
/// entry-table + body that carries the package metadata entries (entry keys, image key, general
/// digests, metas, name table, digests) plus the file-class entries (param.json, imagedigs.dat,
/// PlayGo descriptors, media) and the embedded outer-PFS image.
///
/// Layout (big-endian header fields; FINDINGS.md §04):
///   0x0000: magic "\x7FCNT" | 0x0004: u16 version (2) | 0x0006: u16 flags (1)
///   0x0008: u32 unk (0x80000000, high bit set) | 0x000C: u32 constant 0x0C
///   0x0010: u32 entry count | 0x0014: u16 sc-entry count (6) | 0x0016: u16 entry count 2
///   0x0018: u32 entry-table offset | 0x001C: u32 main-ent data size
///   0x0020: u64 body offset (0x2000) | 0x0028: u64 body size
///   0x0030: u64 BE mandatory size (= imagedigs entry offset) | 0x0040: content id (36)
///   0x0070: u32 drm type | 0x0074: u32 content type | 0x0078: u32 content flags
///   0x007C: u32 promote size | 0x0080: u32 version date | 0x0084: u32 version hash
///   0x0098: u32 iro tag | 0x009C: u32 ekc version
///   0x0100: sc-entries1 hash (32) | 0x0120: sc-entries2 hash (32)
///   0x0140: digest-table hash (32) | 0x0160: body digest (32)
///   0x0200: content id copy
///   0x0400: u32 unk (1) | 0x0404: u32 pfs image count (1) | 0x0408: u64 pfs flags
///   0x0410: u64 pfs image offset | 0x0418: u64 pfs image size
///   0x0420: u64 mount image offset | 0x0428: u64 mount image size | 0x0430: u64 package size
///   0x0438: u32 pfs signed size (0x10000) | 0x043C: u32 pfs cache size
///   0x0440: pfs image digest (32) | 0x0460: pfs signed digest (32)
///   0x0480: u64 split size 0 | 0x0488: u64 split size 1
///   0x04A0: image seed (16) | 0x04B0: u64 cnt region offset | 0x04B8: u64 cnt region size
///   0x0510: descriptor { u32 image-key offset, u32 size, u32 mandatory offset, u32 size }
///   0x0520: descriptor digests (2 × 32)
///   0x0FE0: package digest (32) | 0x1000: header signature (384)
///   0x2000: body (entries, 16-byte aligned) ... then the PFS image.
///
/// Protected entries (<c>Flags1</c> high bit, e.g. <c>nptitle.dat</c>) are stored AES-128-CBC
/// encrypted over their 16-byte-padded payload via <see cref="Crypto.ProsperoEntryCipher"/>, keyed
/// by their finalized 32-byte meta row; the meta row keeps the logical <c>DataSize</c> and the body
/// layout advances by the padded stored length. The per-entry digest table covers the stored bytes.
/// </summary>
public sealed class ProsperoCntBuilder
{
    private const uint FlagsPs5 = 0x00020001;
    private const uint Unk08Ps5 = 0x80000000;
    private const uint Unk0CPs5 = 0x0C;
    private const ulong PfsFlags = 0xA00000000000030C;
    public const ulong BodyOffset = 0x2000;
    private const int HeaderSize = 0x5A0;
    public const int PackageDigestStoredOffset = 0xFE0;
    public const int HeaderSignatureOffset = 0x1000;
    private const int FihRelativeImageOffset = 0x10000;
    public const int BlockSize = 0x10000;

    /// <summary>An entry payload plus its name and the flags that determine its meta row.</summary>
    public sealed class Entry
    {
        public required CntEntryId Id { get; init; }
        public string? Name { get; init; }
        public required byte[] Data { get; set; }
        public uint Flags1 { get; init; }
        public uint Flags2 { get; init; }
        public uint DataOffset { get; internal set; }
        public uint DataSize => (uint)Data.Length;
    }

    /// <summary>
    /// Build the CNT container bytes for the given entries and outer PFS image. The entries must
    /// already include the six SC entries (ids 0x1/0x10/0x20/0x80/0x100/0x200) — use
    /// <see cref="BuildStandardEntries"/> to produce them — plus the file-class entries.
    /// </summary>
    public static byte[] Build(
        IReadOnlyList<Entry> entries, CntBuildParameters parameters,
        byte[] pfsImage, byte[] imageSeed, byte[] pfsImageDigest,
        byte[]? nestedImageDigest = null, long nestedImageSize = 0,
        byte[]? pfsSignedDigest = null)
    {
        ArgumentNullException.ThrowIfNull(pfsImage);
        (byte[] prefix, ulong pfsImageOffset) = BuildPrefix(
            entries, parameters, pfsImage.LongLength, imageSeed, pfsImageDigest, pfsSignedDigest);
        byte[] cnt = new byte[checked((long)pfsImageOffset + pfsImage.LongLength)];
        prefix.CopyTo(cnt, 0);
        Buffer.BlockCopy(pfsImage, 0, cnt, checked((int)pfsImageOffset), pfsImage.Length);
        return cnt;
    }

    /// <summary>
    /// File-backed variant: the metadata prefix is assembled in memory and the outer-PFS image is
    /// streamed from <paramref name="pfsImagePath"/> to <paramref name="outputPath"/>, so the
    /// container may exceed the in-memory array limit.
    /// </summary>
    public static void BuildToFile(
        IReadOnlyList<Entry> entries, CntBuildParameters parameters,
        string pfsImagePath, long pfsImageLength, string outputPath,
        byte[] imageSeed, byte[] pfsImageDigest, byte[]? pfsSignedDigest = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pfsImagePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        (byte[] prefix, ulong pfsImageOffset) = BuildPrefix(
            entries, parameters, pfsImageLength, imageSeed, pfsImageDigest, pfsSignedDigest);
        string full = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(full) ?? Directory.GetCurrentDirectory());
        using var outFs = new FileStream(full, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20, FileOptions.SequentialScan);
        using var src = new FileStream(pfsImagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
        outFs.SetLength(checked((long)pfsImageOffset + pfsImageLength));
        outFs.Write(prefix, 0, prefix.Length);
        src.CopyTo(outFs, 1 << 20);
        outFs.Flush();
    }

    /// <summary>
    /// Builds only the CNT metadata region (header + entry table + body) for an <b>external</b> PFS
    /// image and returns it, without copying the image. Used by the prepositioned file-backed
    /// pipeline, where the outer PFS is written directly into its final FIH range and this metadata
    /// is appended immediately after it. The 0x410 pfs-image offset is rewritten by the FIH finalizer.
    /// </summary>
    public static byte[] BuildMetadata(
        IReadOnlyList<Entry> entries, CntBuildParameters parameters, long pfsImageLength,
        byte[] imageSeed, byte[] pfsImageDigest, byte[]? pfsSignedDigest = null)
    {
        (byte[] prefix, _) = BuildPrefix(entries, parameters, pfsImageLength, imageSeed, pfsImageDigest, pfsSignedDigest);
        return prefix;
    }

    private static (byte[] Prefix, ulong PfsImageOffset) BuildPrefix(
        IReadOnlyList<Entry> entries, CntBuildParameters parameters, long pfsImageLength,
        byte[] imageSeed, byte[] pfsImageDigest, byte[]? pfsSignedDigest)
    {
        ArgumentNullException.ThrowIfNull(entries);
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentNullException.ThrowIfNull(imageSeed);
        ArgumentNullException.ThrowIfNull(pfsImageDigest);

        if (parameters.ContentId.Length != 36)
            throw new ArgumentException("Content id must be exactly 36 characters.", nameof(parameters));

        // The metas entry (id 0x100) carries the serialized entry table; size it up front so its
        // DataOffset is assigned in the layout pass. Its payload is filled after all offsets are known.
        Entry metas = entries.First(e => e.Id == CntEntryId.Metas);
        metas.Data = new byte[entries.Count * 32];

        // The digests entry (id 0x1) carries the per-entry digest table; size it up front too.
        Entry digests = entries.First(e => e.Id == CntEntryId.Digests);
        digests.Data = new byte[entries.Count * 32];

        // The name table (id 0x200) is a sequence of NUL-terminated ASCII names. Offset 0 is the
        // empty string (unnamed entries point here); named entries are sorted by ordinal and appended.
        // Build it before the offset pass so its own DataSize is accounted for.
        Entry nameTableEntry = entries.First(e => e.Id == CntEntryId.EntryNames);
        var nameOffsets = BuildNameTable(entries, nameTableEntry);

        // 1. Assign data offsets (16-byte aligned, from body_offset). Protected entries are stored
        // AES-encrypted over their 16-byte-padded payload, so the layout advances by the *stored*
        // length (the meta row still records the logical DataSize, matching the reference).
        ulong cursor = BodyOffset;
        foreach (Entry e in entries)
        {
            e.DataOffset = (uint)cursor;
            cursor = Align(cursor + (ulong)StoredLength(e), 16);
        }
        ulong bodyEnd = cursor;
        ulong bodySize = Align(BodyOffset + (bodyEnd - BodyOffset), (ulong)BlockSize) - BodyOffset;
        ulong pfsImageOffset = BodyOffset + bodySize;

        // 2. Serialize the metas entry (the entry table) — sorted by id, one 32-byte row each.
        var sorted = entries.OrderBy(e => (uint)e.Id).ToList();
        byte[] metaTable = new byte[entries.Count * 32];
        for (int i = 0; i < sorted.Count; i++)
        {
            Entry e = sorted[i];
            Span<byte> row = metaTable.AsSpan(i * 32, 32);
            BinaryPrimitives.WriteUInt32BigEndian(row, (uint)e.Id);
            uint nameOffset = nameOffsets.TryGetValue(e, out uint no) ? no : 0u;
            BinaryPrimitives.WriteUInt32BigEndian(row[4..], nameOffset); // name offset
            BinaryPrimitives.WriteUInt32BigEndian(row[8..], e.Flags1);
            BinaryPrimitives.WriteUInt32BigEndian(row[12..], e.Flags2);
            BinaryPrimitives.WriteUInt32BigEndian(row[16..], e.DataOffset);
            BinaryPrimitives.WriteUInt32BigEndian(row[20..], e.DataSize);
        }
        metas.Data = metaTable;

        // 2b. Stored payloads. A protected entry (Flags1 high bit) is written AES-encrypted over its
        // 16-byte-padded payload, keyed by its finalized meta row; every other entry is verbatim.
        // The body and the per-entry digest table both use these bytes.
        var stored = new Dictionary<Entry, byte[]>();
        byte[] GetStored(Entry e)
        {
            if (stored.TryGetValue(e, out byte[]? bytes))
                return bytes;
            if (!IsEncrypted(e))
            {
                stored[e] = e.Data;
                return e.Data;
            }
            ReadOnlySpan<byte> row = metaTable.AsSpan(sorted.IndexOf(e) * 32, 32);
            uint keyIndex = (e.Flags2 & 0xF000u) >> 12;
            byte[] cipher = ProsperoEntryCipher.Encrypt(
                e.Data, row, parameters.ContentId, parameters.Passcode, keyIndex, publisherProfile: true);
            stored[e] = cipher;
            return cipher;
        }

        uint entryTableOffset = metas.DataOffset;

        // The image-key entry (id 0x20) and the mandatory (imagedigs) entry locate the descriptor.
        Entry imageKey = entries.First(e => e.Id == CntEntryId.ImageKey);
        Entry mandatory = entries.First(e => e.Id == CntEntryId.Imagedigs);
        ulong mandatorySize = mandatory.DataOffset;

        ulong containerSize = pfsImageOffset;
        ulong mountImageSize = FihRelativeImageOffset + (ulong)pfsImageLength + containerSize;
        ulong cntRegionOffset = FihRelativeImageOffset + (ulong)pfsImageLength;
        ulong cntRegionSize = containerSize;

        // 3. Write a SKELETON header first (zero sc1/sc2/bodyDigest/digestTableHash) so the
        // header-digest preimage ([0x00:0x40] ‖ [0x400:0x480]) can be read back from the on-disk
        // bytes. The general-digests entry (including its header/system/playgo slots) is then
        // finalized against this skeleton, and the body serializes the finalized GD payload — so
        // every subsequent digest (per-entry table, sc-rollups, body-digest, digest-table-hash)
        // covers the final GD bytes, matching the reference build order.
        byte[] cnt = new byte[checked((long)pfsImageOffset)];
        byte[] zeroes = new byte[32];
        WriteHeader(
            cnt, entries, parameters, pfsImageLength, pfsImageOffset, bodySize,
            imageSeed, pfsImageDigest, mandatorySize, entryTableOffset,
            zeroes, zeroes, zeroes, zeroes,
            imageKey, mandatory, mountImageSize, cntRegionOffset, cntRegionSize,
            pfsSignedDigest);

        // 4. Finalize the general-digests entry payload against the skeleton header (reads the
        // header-digest preimage from cnt and writes the full GD payload into the body + genDigests.Data).
        byte[] contentDigest = BuildContentDigest(parameters, pfsImageDigest);
        WriteGeneralDigestsEntry(cnt, entries, parameters, pfsImageDigest, contentDigest);

        // 5. Compute per-entry digest table (slot k = SHA3-256(entry k's *stored* payload, i.e. the
        // 16-byte-padded ciphertext for protected entries); the digests entry's own slot is zero.
        // The table is the digests entry's payload. GD is now finalized.
        int digestSlot = sorted.IndexOf(digests);
        byte[] digestTable = new byte[entries.Count * 32];
        for (int i = 0; i < sorted.Count; i++)
        {
            if (i == digestSlot)
                continue;
            Sha3.Sha3_256(GetStored(sorted[i])).CopyTo(digestTable.AsSpan(i * 32));
        }
        digests.Data = digestTable;

        // 6. Serialize the body (now that metas, digests and general-digests have their final payloads).
        var bodyBytes = new byte[bodyEnd - BodyOffset];
        foreach (Entry e in entries)
        {
            int off = (int)(e.DataOffset - (uint)BodyOffset);
            byte[] payload = GetStored(e);
            payload.CopyTo(bodyBytes.AsSpan(off, payload.Length));
        }
        Buffer.BlockCopy(bodyBytes, 0, cnt, (int)BodyOffset, bodyBytes.Length);

        // 7. sc-entry rollup hashes + body digest + digest-table hash, over the finalized body.
        // body_digest covers the PADDED body region [BodyOffset, BodyOffset+bodySize) — trailing
        // zero padding up to the 0x10000 block boundary is included (fixture-validated).
        byte[] scEntries1Hash = ComputeScEntries1Hash(entries);
        byte[] scEntries2Hash = ComputeScEntries2Hash(entries);
        byte[] bodyBytesPadded = new byte[bodySize];
        Buffer.BlockCopy(bodyBytes, 0, bodyBytesPadded, 0, bodyBytes.Length);
        byte[] bodyDigest = Sha3.Sha3_256(bodyBytesPadded);
        byte[] digestTableHash = Sha3.Sha3_256(digestTable);

        // 8. Second WriteHeader — now with the real sc1/sc2/bodyDigest/digestTableHash.
        WriteHeader(
            cnt, entries, parameters, pfsImageLength, pfsImageOffset, bodySize,
            imageSeed, pfsImageDigest, mandatorySize, entryTableOffset,
            scEntries1Hash, scEntries2Hash, bodyDigest, digestTableHash,
            imageKey, mandatory, mountImageSize, cntRegionOffset, cntRegionSize,
            pfsSignedDigest);

        // 10. Package digest (self-seal over CNT[0:0xFE0]) and header signature.
        // The preimage is taken over the finalized header (including the real sc1/sc2/body/dt hashes
        // written in step 8). The pfs_image_offset field is forced to the FIH-relative 0x10000 — which
        // WriteHeader already wrote — so no further patching is needed for that field. The package
        // digest is stamped into the preimage clone BEFORE the header-digest is computed, so the
        // signature covers the package-digest too (matching the reference).
        byte[] headerForDigest = (byte[])cnt.Clone();
        byte[] packageDigest = Sha3.Sha3_256(headerForDigest.AsSpan(0, PackageDigestStoredOffset));
        packageDigest.CopyTo(headerForDigest.AsSpan(PackageDigestStoredOffset));
        packageDigest.CopyTo(cnt.AsSpan(PackageDigestStoredOffset));

        byte[] signature = ProsperoRsaKeys.BuildCntHeaderWrap(headerForDigest.AsSpan(0, HeaderSignatureOffset));
        signature.CopyTo(cnt.AsSpan(HeaderSignatureOffset, ProsperoRsaKeys.HeaderSignatureSize));

        return (cnt, pfsImageOffset);
    }

    /// <summary>
    /// Produce the six standard SC entries (entry keys, image key, general digests, metas,
    /// name table, digests placeholder). The metas/name-table/digests payloads are placeholders
    /// filled during <see cref="Build"/>.
    /// </summary>
    public static List<Entry> BuildStandardEntries(string contentId, string passcode, byte[] ekpfs, bool deterministicEntryKeys = false)
    {
        return
        [
            new Entry { Id = CntEntryId.EntryKeys, Name = null, Data = ProsperoRsaKeys.BuildEntryKeysEntry(contentId, passcode, deterministicEntryKeys), Flags1 = 0x60000000 },
            new Entry { Id = CntEntryId.ImageKey, Name = null, Data = ProsperoRsaKeys.BuildImageKeyEntry(ekpfs, deterministicEntryKeys), Flags1 = 0x60000000 },
            new Entry { Id = CntEntryId.GeneralDigests, Name = null, Data = new byte[0x1E0], Flags1 = 0x60000000 },
            new Entry { Id = CntEntryId.Metas, Name = null, Data = new byte[0], Flags1 = 0x60000000 },
            new Entry { Id = CntEntryId.Digests, Name = null, Data = new byte[0], Flags1 = 0x40000000 },
            new Entry { Id = CntEntryId.EntryNames, Name = null, Data = new byte[1], Flags1 = 0x40000000 },
        ];
    }

    /// <summary>The PS5 Flags1 word for a file-class entry id.</summary>
    public static uint Flags1For(CntEntryId id) => id switch
    {
        CntEntryId.Digests => 0x40000000,
        CntEntryId.EntryKeys => 0x60000000,
        CntEntryId.ImageKey => 0x60000000,
        CntEntryId.GeneralDigests => 0x60000000,
        CntEntryId.Metas => 0x60000000,
        CntEntryId.EntryNames => 0x40000000,
        CntEntryId.ParamJson => 0x00000000,
        _ => 0x08000000,
    };

    // ------------------------------------------------------------------ internals

    private static int IndexOf(IReadOnlyList<Entry> entries, Entry e)
    {
        for (int i = 0; i < entries.Count; i++)
            if (ReferenceEquals(entries[i], e))
                return i;
        return -1;
    }

    private static ulong Align(ulong value, ulong align)
    {
        ulong rem = value % align;
        return rem == 0 ? value : value + align - rem;
    }

    /// <summary>True when the entry's <c>Flags1</c> marks it as protected (stored AES-encrypted).</summary>
    private static bool IsEncrypted(Entry entry) => (entry.Flags1 & 0x80000000u) != 0;

    /// <summary>
    /// Bytes an entry occupies in the body: the 16-byte-padded length for a protected entry (the
    /// stored ciphertext), otherwise the logical payload length.
    /// </summary>
    private static int StoredLength(Entry entry) =>
        IsEncrypted(entry) ? ProsperoEntryCipher.PaddedLength(entry.Data.Length) : entry.Data.Length;

    /// <summary>
    /// Builds the name-table payload (offset 0 = empty string) and returns each entry's name offset.
    /// Named entries are sorted by ordinal so the table is deterministic and matches the reference
    /// builder's ordering. Unnamed entries resolve to offset 0 (the empty string).
    /// </summary>
    private static Dictionary<Entry, uint> BuildNameTable(IReadOnlyList<Entry> entries, Entry nameTableEntry)
    {
        var offsets = new Dictionary<Entry, uint>();
        using var ms = new MemoryStream();
        ms.WriteByte(0); // offset 0 = empty string

        var named = entries
            .Where(e => !string.IsNullOrEmpty(e.Name))
            .OrderBy(e => e.Name, StringComparer.Ordinal)
            .ToList();

        foreach (Entry e in named)
        {
            offsets[e] = (uint)ms.Length;
            byte[] bytes = Encoding.ASCII.GetBytes(e.Name!);
            ms.Write(bytes, 0, bytes.Length);
            ms.WriteByte(0);
        }

        nameTableEntry.Data = ms.ToArray();
        return offsets;
    }

    /// <summary>
    /// System-media entry ids whose payloads are concatenated (each per-entry SHA3-256'd) to form
    /// the general-digests System slot. Order is ascending id, matching the reference rollup.
    /// </summary>
    private static readonly uint[] SystemMediaIds =
    [
        0x1006, 0x100D, 0x1200, 0x1220, 0x1240, 0x1280, 0x12A0, 0x12C0, 0x2040, 0x2060
    ];

    /// <summary>
    /// PlayGo entry ids whose payloads are concatenated (each per-entry SHA3-256'd) to form the
    /// general-digests Playgo slot. Order is ascending id.
    /// </summary>
    private static readonly uint[] PlaygoIds = [0x1001, 0x2010, 0x2011];

    /// <summary>
    /// Reference rollup: for each id in <paramref name="ids"/> that is present in <paramref name="entries"/>,
    /// append SHA3-256(entry payload) to the concatenation; return SHA3-256 of the concatenation.
    /// Returns null when no matching entries are present (caller leaves the slot zero).
    /// Entries are taken in ascending-id order.
    /// </summary>
    private static byte[]? ComputeConcatOverEntries(IReadOnlyList<Entry> entries, uint[] ids)
    {
        // Collect present ids in ascending order (ids[] is already ascending but entries may be
        // in any order — iterate ids[] so output order is guaranteed ascending).
        var present = new List<Entry>();
        foreach (uint id in ids)
        {
            for (int i = 0; i < entries.Count; i++)
            {
                if ((uint)entries[i].Id == id)
                {
                    present.Add(entries[i]);
                    break;
                }
            }
        }
        if (present.Count == 0)
            return null;

        using var ms = new MemoryStream();
        foreach (Entry e in present)
            ms.Write(Sha3.Sha3_256(e.Data));
        return Sha3.Sha3_256(ms.ToArray());
    }

    /// <summary>
    /// sc_entries1_hash: SHA3-256 over the concatenated payloads of ENTRY_KEYS, IMAGE_KEY,
    /// GENERAL_DIGESTS, METAS and DIGESTS — in id order 0x10, 0x20, 0x80, 0x100, 0x1 (the entry
    /// names table is NOT included). Validated byte-exact against the debug fixture's stored
    /// sc_entries1_hash.
    /// </summary>
    private static byte[] ComputeScEntries1Hash(IReadOnlyList<Entry> entries)
    {
        using var ms = new MemoryStream();
        foreach (uint id in new uint[] { 0x0010, 0x0020, 0x0080, 0x0100, 0x0001 })
        {
            Entry? e = FindById(entries, id);
            if (e is not null)
                ms.Write(e.Data);
        }
        return Sha3.Sha3_256(ms.ToArray());
    }

    /// <summary>
    /// sc_entries2_hash: SHA3-256 over ENTRY_KEYS, IMAGE_KEY, GENERAL_DIGESTS and the first
    /// <c>sc_entry_count × 0x20</c> bytes of METAS (the six SC rows only; DIGESTS is not included).
    /// Validated byte-exact against the debug fixture's stored sc_entries2_hash.
    /// </summary>
    private static byte[] ComputeScEntries2Hash(IReadOnlyList<Entry> entries)
    {
        using var ms = new MemoryStream();
        foreach (uint id in new uint[] { 0x0010, 0x0020, 0x0080 })
        {
            Entry? e = FindById(entries, id);
            if (e is not null)
                ms.Write(e.Data);
        }
        // The metas entry's SC prefix: sc_entry_count (6) rows of 32 bytes each.
        Entry metas = entries.First(e => e.Id == CntEntryId.Metas);
        ms.Write(metas.Data.AsSpan(0, ScEntryCount * 32));
        return Sha3.Sha3_256(ms.ToArray());
    }

    private const int ScEntryCount = 6;

    private static Entry? FindById(IReadOnlyList<Entry> entries, uint id)
    {
        for (int i = 0; i < entries.Count; i++)
        {
            if ((uint)entries[i].Id == id)
                return entries[i];
        }
        return null;
    }

    private static byte[] BuildContentDigest(CntBuildParameters parameters, byte[] gameDigest)
    {
        // content-digest = SHA3-256( CNT[0x40:0x78] ‖ game-digest(32) ‖ major-param-digest(32, all-zero) ).
        var descriptor = new byte[0x38];
        Encoding.ASCII.GetBytes(parameters.ContentId).AsSpan(0, 36).CopyTo(descriptor);
        BinaryPrimitives.WriteUInt32BigEndian(descriptor.AsSpan(0x30), 0); // drm type = none
        BinaryPrimitives.WriteUInt32BigEndian(descriptor.AsSpan(0x34), parameters.ContentType);

        using var ms = new MemoryStream();
        ms.Write(descriptor);
        ms.Write(gameDigest);
        ms.Write(new byte[32]);
        return Sha3.Sha3_256(ms.ToArray());
    }

    private static void WriteGeneralDigestsEntry(
        byte[] cnt, IReadOnlyList<Entry> entries, CntBuildParameters parameters,
        byte[] gameDigest, byte[] contentDigest)
    {
        Entry genDigests = entries.First(e => e.Id == CntEntryId.GeneralDigests);
        byte[] payload = genDigests.Data;
        if (payload.Length != 0x1E0)
            return;

        // u16 unk1 (0xD256), u16 type (0x0102), 24 reserved, u32 BE set_digests (0x10DE).
        Span<byte> p = payload;
        BinaryPrimitives.WriteUInt16BigEndian(p, 0xD256);
        BinaryPrimitives.WriteUInt16BigEndian(p[2..], 0x0102);
        BinaryPrimitives.WriteUInt32BigEndian(p[0x1C..], 0x10DE);

        // 14 × 32-byte slots in enum bit order.
        int off = 0x20;
        contentDigest.CopyTo(p.Slice(off, 32)); off += 32;     // Content
        gameDigest.CopyTo(p.Slice(off, 32)); off += 32;       // Game
        // header-digest = SHA3-256(CNT[0x00:0x40] ‖ CNT[0x400:0x480]) with pfs_image_offset forced.
        byte[] headerPrefix = cnt.AsSpan(0, 0x40).ToArray();
        byte[] mountDescriptor = cnt.AsSpan(0x400, 0x80).ToArray();
        byte[] mountForDigest = (byte[])mountDescriptor.Clone();
        BinaryPrimitives.WriteUInt64BigEndian(
            mountForDigest.AsSpan(0x10), FihRelativeImageOffset);
        using var hd = new MemoryStream();
        hd.Write(headerPrefix);
        hd.Write(mountForDigest);
        byte[] headerDigest = Sha3.Sha3_256(hd.ToArray());
        headerDigest.CopyTo(p.Slice(off, 32)); off += 32;       // Header
        // system-digest = SHA3-256(concat of per-entry SHA3-256 payloads) over the system-media
        // ids (sce_sys visual/audio media + their *.dds re-encodes), ascending id order. Zero
        // when no such entries are present (self-consistent — matches the fixture's all-zero
        // slot for packages with no media).
        byte[]? systemDigest = ComputeConcatOverEntries(entries, SystemMediaIds);
        if (systemDigest is not null)
            systemDigest.CopyTo(p.Slice(off, 32));
        off += 32;                                                // System
        off += 32;                                                // MajorParam (zero for nwonly)
        // param-digest = SHA3-256(param.json entry payload).
        Entry? param = entries.FirstOrDefault(e => e.Id == CntEntryId.ParamJson);
        if (param is not null)
            Sha3.Sha3_256(param.Data).CopyTo(p.Slice(off, 32));
        off += 32;                                                // Param
        // playgo-digest = SHA3-256(concat of per-entry SHA3-256 payloads) over the PlayGo stream
        // ids (playgo-chunk.dat / playgo-hash-table.dat / playgo-ficm.dat), ascending. Zero when
        // no such entries are present.
        byte[]? playgoDigest = ComputeConcatOverEntries(entries, PlaygoIds);
        if (playgoDigest is not null)
            playgoDigest.CopyTo(p.Slice(off, 32));
        off += 32;                                                // Playgo
        off += 32;                                                // Trophy
        off += 32;                                                // Manual
        off += 32;                                                // Keymap
        off += 32;                                                // Origin
        gameDigest.CopyTo(p.Slice(off, 32));                     // Target (== game for nwonly)
        off += 32;
        off += 32;                                                // OriginGame
        off += 32;                                                // TargetGame

        // Store the finalized payload on the entry; Build serializes it into the body in the
        // digest-table/body pass that follows.
        return;
    }

    private static void WriteHeader(
        byte[] cnt, IReadOnlyList<Entry> entries, CntBuildParameters parameters,
        long pfsImageSize, ulong pfsImageOffset, ulong bodySize,
        byte[] imageSeed, byte[] pfsImageDigest, ulong mandatorySize, uint entryTableOffset,
        byte[] scEntries1Hash, byte[] scEntries2Hash, byte[] bodyDigest, byte[] digestTableHash,
        Entry imageKey, Entry mandatory,
        ulong mountImageSize, ulong cntRegionOffset, ulong cntRegionSize,
        byte[]? pfsSignedDigest)
    {
        Span<byte> h = cnt.AsSpan(0, HeaderSize);

        // 0x00: magic.
        h[0] = 0x7F; h[1] = (byte)'C'; h[2] = (byte)'N'; h[3] = (byte)'T';
        BinaryPrimitives.WriteUInt16BigEndian(h[0x04..], 2);             // version
        BinaryPrimitives.WriteUInt16BigEndian(h[0x06..], 1);             // flags
        BinaryPrimitives.WriteUInt32BigEndian(h[0x08..], Unk08Ps5);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x0C..], Unk0CPs5);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x10..], (uint)entries.Count);
        BinaryPrimitives.WriteUInt16BigEndian(h[0x14..], 6);             // sc-entry count
        BinaryPrimitives.WriteUInt16BigEndian(h[0x16..], (ushort)entries.Count);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x18..], entryTableOffset);
        // 0x1C: main-ent data size = sum of the six SC entry sizes.
        uint mainEntSize = 0;
        foreach (Entry e in entries)
        {
            if ((uint)e.Id is 0x0001 or 0x0010 or 0x0020 or 0x0080 or 0x0100)
                mainEntSize += e.DataSize;
        }
        BinaryPrimitives.WriteUInt32BigEndian(h[0x1C..], mainEntSize);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x20..], BodyOffset);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x28..], bodySize);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x30..], mandatorySize);
        Encoding.ASCII.GetBytes(parameters.ContentId).AsSpan(0, 36).CopyTo(h[0x40..]);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x70..], 0);            // drm type = none
        BinaryPrimitives.WriteUInt32BigEndian(h[0x74..], parameters.ContentType);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x78..], parameters.ContentFlags);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x7C..], (uint)pfsImageOffset);   // promote size
        BinaryPrimitives.WriteUInt32BigEndian(h[0x80..], parameters.VersionDate);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x84..], parameters.VersionHash);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x98..], 0);             // iro tag
        BinaryPrimitives.WriteUInt32BigEndian(h[0x9C..], 0);            // ekc version

        scEntries1Hash.CopyTo(h[0x100..]);
        scEntries2Hash.CopyTo(h[0x120..]);
        digestTableHash.CopyTo(h[0x140..]);
        bodyDigest.CopyTo(h[0x160..]);

        Encoding.ASCII.GetBytes(parameters.ContentId).AsSpan(0, 36).CopyTo(h[0x200..]);

        BinaryPrimitives.WriteUInt32BigEndian(h[0x400..], 1);           // unk_0x400
        BinaryPrimitives.WriteUInt32BigEndian(h[0x404..], 1);           // pfs image count
        BinaryPrimitives.WriteUInt64BigEndian(h[0x408..], PfsFlags);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x410..], FihRelativeImageOffset); // FIH-relative
        BinaryPrimitives.WriteUInt64BigEndian(h[0x418..], (ulong)pfsImageSize);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x420..], 0);            // mount image offset
        BinaryPrimitives.WriteUInt64BigEndian(h[0x428..], mountImageSize);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x430..], mountImageSize); // package size
        BinaryPrimitives.WriteUInt32BigEndian(h[0x438..], BlockSize);  // pfs signed size
        BinaryPrimitives.WriteUInt32BigEndian(h[0x43C..], 0);           // pfs cache size
        pfsImageDigest.CopyTo(h[0x440..]);
        // 0x460 pfs_signed_digest = SHA3-256(final FIH header block). The reference stamps it
        // BEFORE computing the GeneralDigests header slot (whose preimage spans 0x400..0x480) and
        // the package self-seal at 0xFE0, so it must be supplied on the skeleton header pass too.
        if (pfsSignedDigest is { Length: 32 })
            pfsSignedDigest.CopyTo(h[0x460..]);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x480..], 0);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x488..], 0);
        imageSeed.CopyTo(h[0x4A0..]);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x4B0..], cntRegionOffset);
        BinaryPrimitives.WriteUInt64BigEndian(h[0x4B8..], cntRegionSize);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x510..], imageKey.DataOffset);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x514..], imageKey.DataSize);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x518..], mandatory.DataOffset);
        BinaryPrimitives.WriteUInt32BigEndian(h[0x51C..], mandatory.DataSize);

        // 0x520 descriptor digests: SHA3-256 of the image-key payload and the mandatory payload.
        Sha3.Sha3_256(imageKey.Data).CopyTo(h[0x520..]);
        Sha3.Sha3_256(mandatory.Data).CopyTo(h[0x540..]);
    }
}
