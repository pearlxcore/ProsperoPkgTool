using System.Buffers.Binary;
using ProsperoPkgTool.Compression;
using ProsperoPkgTool.Content;
using ProsperoPkgTool.Crypto;
using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Console/progress surface for a package build. The CLI maps this to its live console progress;
/// library callers can ignore it, forward <see cref="Log"/> to a logger, or supply their own
/// <see cref="IProgress{T}"/>.
/// </summary>
public sealed class DebugPackageBuildLog
{
    /// <summary>Progress sink passed to the inner/outer encoders. Optional.</summary>
    public IProgress<ProsperoBuildProgress>? Progress { get; init; }

    /// <summary>Human-readable stage messages. Optional.</summary>
    public Action<string> Log { get; init; } = _ => { };

    /// <summary>Called after a progress phase completes so live progress lines can be ended.</summary>
    public Action Finish { get; init; } = () => { };
}

/// <summary>Inputs for <see cref="ProsperoDebugPackageBuilder.Build"/>.</summary>
public sealed class DebugPackageBuildOptions
{
    /// <summary>Destination package path.</summary>
    public required string OutputPath { get; init; }

    /// <summary>36-character content id.</summary>
    public required string ContentId { get; init; }

    /// <summary>32-character package passcode.</summary>
    public required string Passcode { get; init; }

    /// <summary>Raw <c>sce_sys/param.json</c> bytes; the builder normalizes and stamps them.</summary>
    public required byte[] ParamJson { get; init; }

    /// <summary>
    /// Inner-image compression policy. Defaults to <see cref="ProsperoInnerCompressionMode.Auto"/>
    /// (Kraken where it helps), matching the publisher-built Sony container's compressed metadata.
    /// </summary>
    public ProsperoInnerCompressionMode Compression { get; init; } = ProsperoInnerCompressionMode.Auto;

    /// <summary>Kraken level recorded in the compressed metadata header.</summary>
    public int KrakenLevel { get; init; } = KrakenTuning.DefaultLevel;

    /// <summary>Blocks encoded concurrently; 0 selects the processor count.</summary>
    public int KrakenThreads { get; init; }

    /// <summary>POSIX seconds stamped into inodes and the publisher param.json.</summary>
    public long TimestampSeconds { get; init; } = 0x6A31A5B9;

    /// <summary>Nanosecond fraction stamped into inodes.</summary>
    public uint TimestampNanoseconds { get; init; } = 0x14DC9380;

    /// <summary>16-byte outer-PFS crypt seed; null selects a fresh random seed per build.</summary>
    public byte[]? OuterSeed { get; init; }

    /// <summary>
    /// Use deterministic RSA-PKCS#1 padding for the CNT entry-key wraps. Together with a fixed
    /// <see cref="OuterSeed"/> and timestamps this makes the whole package byte-reproducible;
    /// defaults to false (fresh random padding, standard PKCS#1 behavior).
    /// </summary>
    public bool DeterministicEntryKeys { get; init; }

    /// <summary>Workspace for the file-backed (multi-GiB) path; null uses the system temp folder.</summary>
    public string? TempDirectory { get; init; }

    /// <summary>
    /// Reclaim orphaned build workspaces (left by a killed run) in the temp root before starting.
    /// Live workspaces are never touched. Defaults to true.
    /// </summary>
    public bool SweepStaleTempWorkspaces { get; init; } = true;

    /// <summary>Age in hours after which an orphaned (owner no longer running) workspace is reclaimed.</summary>
    public int StaleWorkspaceHours { get; init; } = 12;

    /// <summary>Skip the free-space preflight (power users/tests); defaults to false.</summary>
    public bool SkipFreeSpaceCheck { get; init; }

    /// <summary>
    /// Assembled inner-image size above which the file-backed pipeline is used (peak memory bounded by
    /// a single file). Larger titles may lower it; tests force the streaming path by setting it to 1.
    /// Defaults to 1 GiB.
    /// </summary>
    public long FileBackedInnerImageThreshold { get; init; } = 1L << 30;

    /// <summary>Explicit PlayGo project; when null a source <c>playgo-chunk.dat</c> is parsed, else a default is generated.</summary>
    public PlayGoProject? PlayGo { get; init; }

    /// <summary>
    /// Number of PlayGo chunks to generate when neither <see cref="PlayGo"/> nor a source
    /// <c>playgo-chunk.dat</c> is supplied. 1 (the default) reproduces the verified single-chunk
    /// source-folder model; higher counts are structural and unverified against a publisher
    /// reference, and every inner file still defaults to chunk zero.
    /// </summary>
    public int PlayGoChunkCount { get; init; } = 1;

    /// <summary>Files under <c>sce_sys</c> (path relative to <c>sce_sys</c>) for outer CNT media entries.</summary>
    public IReadOnlyDictionary<string, byte[]>? SceSysFiles { get; init; }

    /// <summary>Convert raw ELF application modules to debug fake-SELF containers.</summary>
    public bool FakeSignModules { get; init; } = true;

    /// <summary>Inject the debug <c>sce_sys/pfs-version.dat</c> marker when absent.</summary>
    public bool InjectPfsVersionDat { get; init; } = true;

    /// <summary>Inject the debug <c>sce_sys/keystone</c> when absent.</summary>
    public bool InjectKeystone { get; init; } = true;

    /// <summary>Inject the fixed debug <c>sce_sys/about/right.sprx</c> when absent.</summary>
    public bool InjectRightSprx { get; init; } = true;

    /// <summary>
    /// Full 64-bit executable SDK identifier to stamp into <c>sce_sys/param.json</c> (<c>sdkVersion</c>
    /// and clamped <c>requiredSystemSoftwareVersion</c>) and into every fake-signed module's
    /// <c>.sceversion</c> metadata. Null preserves the source metadata verbatim.
    /// </summary>
    public ulong? SdkVersionOverride { get; init; }

    /// <summary>
    /// Explicit <c>applicationDrmType</c> token to stamp into the packaged <c>sce_sys/param.json</c>.
    /// Null (the default) preserves the source token verbatim; set it (for example <c>standard</c>)
    /// to override a source value the console would otherwise show as locked.
    /// </summary>
    public string? DrmTypeOverride { get; init; }

    /// <summary>Console/progress surface. Optional.</summary>
    public DebugPackageBuildLog? Log { get; init; }
}

/// <summary>Outcome of a successful package build.</summary>
public sealed record DebugPackageBuildResult(
    string OutputPath, long PackageLength, string ContentId, int InnerFileCount, bool FileBacked);

/// <summary>
/// Builds a debug (FIH) base/application package from a flat list of inner files. This is the
/// engine behind <c>img_create</c>: it assembles the inner PFS, NAPS layout, AES-XTS outer PFS,
/// self-sealed CNT and finalized FIH, and writes the package to <see cref="DebugPackageBuildOptions.OutputPath"/>.
/// Callers supply paths already made root-relative (for example <c>/sce_sys/keystone</c>) and may
/// back each file by memory, a disk path, or an <see cref="IProsperoFileSource"/>.
/// </summary>
public static class ProsperoDebugPackageBuilder
{
    /// <summary>Build the package described by <paramref name="options"/>.</summary>
    public static DebugPackageBuildResult Build(
        IReadOnlyList<ProsperoInnerImageAssembler.InnerFile> files, DebugPackageBuildOptions options)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(options);
        if (files.Count == 0)
            throw new ArgumentException("At least one inner file is required.", nameof(files));
        if (options.ContentId.Length != 36)
            throw new ArgumentException("Content id must be exactly 36 characters.", nameof(options));
        if (options.Passcode.Length != 32)
            throw new ArgumentException("Passcode must be exactly 32 characters.", nameof(options));
        if (options.OuterSeed is { Length: not 16 })
            throw new ArgumentException("OuterSeed must be 16 bytes when supplied.", nameof(options));

        var console = options.Log ?? new DebugPackageBuildLog();
        long tsSec = options.TimestampSeconds;
        uint tsNsec = options.TimestampNanoseconds;

        // Reclaim workspaces orphaned by a killed/crashed run before starting a new one, so a failed
        // multi-GiB build cannot silently leak tens of gigabytes in the temp folder.
        if (options.SweepStaleTempWorkspaces)
        {
            string sweepRoot = options.TempDirectory ?? Path.GetTempPath();
            TempWorkspace.SweepOrphans(sweepRoot, TimeSpan.FromHours(Math.Max(1, options.StaleWorkspaceHours)), console.Log);
        }

        // Fail fast when the temp/output volumes cannot hold the build's peak, instead of losing
        // hours and dying mid-write on a multi-GiB package.
        if (!options.SkipFreeSpaceCheck)
        {
            long rawPayload = 0;
            foreach (ProsperoInnerImageAssembler.InnerFile file in files)
                rawPayload += file.PayloadLength;
            DiskSpaceReport space = DiskSpaceGuard.Check(DiskSpaceGuard.Estimate(rawPayload, options.OutputPath, options.TempDirectory));
            if (space.Status == DiskSpaceStatus.Insufficient)
                throw new ProsperoInsufficientSpaceException(
                    DiskSpaceGuard.Describe(space), space.RequiredBytes, space.AvailableBytes, space.Root);
            if (space.Status == DiskSpaceStatus.NearLimit)
                console.Log($"  warning: {DiskSpaceGuard.Describe(space)}");
        }

        ProsperoParam param = ProsperoParamReader.Read(options.ParamJson);

        // The source param.json is packaged verbatim: the Sony fixture carries the publisher document
        // unchanged, so the builder does not re-serialize, reorder, or stamp any field. An explicit SDK
        // override is the one opt-in exception: it rewrites only the SDK fields.
        byte[] paramJson = options.ParamJson;
        if (options.SdkVersionOverride is { } sdkVersion)
        {
            paramJson = ProsperoPublisherParamJson.ApplySdkOverride(paramJson, sdkVersion);
            console.Log($"  SDK override: executable 0x{sdkVersion:X16}, package 0x{ProsperoSdkVersions.ToPackageVersion(sdkVersion):X16}");
        }

        // An explicit DRM override is the other opt-in exception: it rewrites only applicationDrmType
        // so a source token the console treats as locked can be forced to a launchable value.
        if (!string.IsNullOrWhiteSpace(options.DrmTypeOverride))
        {
            paramJson = ProsperoPublisherParamJson.ApplyDrmType(paramJson, options.DrmTypeOverride);
            console.Log($"  DRM type override: {options.DrmTypeOverride}");
        }

        var innerFiles = new List<ProsperoInnerImageAssembler.InnerFile>(files);

        // Convert raw ELF application modules to debug fake-SELF containers (scene method).
        if (options.FakeSignModules)
            FakeSignInnerModules(innerFiles, console, options.SdkVersionOverride);

        // Inject the debug pfs-version marker if the source doesn't ship one (scene method): ASCII
        // content-version string, e.g. "01.000.000".
        if (options.InjectPfsVersionDat && !innerFiles.Any(f => f.Path == "/sce_sys/pfs-version.dat"))
        {
            innerFiles.Add(new ProsperoInnerImageAssembler.InnerFile
            {
                Path = "/sce_sys/pfs-version.dat",
                Data = System.Text.Encoding.ASCII.GetBytes(param.ContentVersion ?? "01.000.000"),
                PlayGoChunkId = 0,
            });
        }

        // Inject the debug keystone if the source doesn't ship one.
        if (options.InjectKeystone && !innerFiles.Any(f => f.Path == "/sce_sys/keystone"))
        {
            innerFiles.Add(new ProsperoInnerImageAssembler.InnerFile
            {
                Path = "/sce_sys/keystone",
                Data = Keystone.Create(options.Passcode),
                PlayGoChunkId = 0,
            });
        }

        // Inject the fixed debug rights module when the source doesn't ship one (LibProsperoPkg behavior).
        if (options.InjectRightSprx && !innerFiles.Any(f => f.Path == "/sce_sys/about/right.sprx"))
        {
            byte[]? rightSprx = ProsperoRightSprx.Get();
            if (rightSprx is { Length: > 0 })
            {
                innerFiles.Add(new ProsperoInnerImageAssembler.InnerFile
                {
                    Path = "/sce_sys/about/right.sprx",
                    Data = rightSprx,
                    PlayGoChunkId = 0,
                });
                console.Log($"  Injected sce_sys/about/right.sprx ({rightSprx.Length} bytes)");
            }
            else
            {
                console.Log("  warning: sce_sys/about/right.sprx is absent and the embedded module is unavailable.");
            }
        }

        if (innerFiles.Count == 0)
            throw new ArgumentException("No inner files were supplied.", nameof(files));

        IReadOnlyDictionary<string, byte[]> sceSysFiles =
            options.SceSysFiles ?? new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        PlayGoProject playGoProject = options.PlayGo ?? ResolvePlayGoProject(sceSysFiles, options.ContentId, options.PlayGoChunkCount, console);

        // Large inputs use a file-backed pipeline (temp workspace) so the assembled inner/outer
        // images never materialize as a single byte[]; small inputs keep the in-memory path.
        long totalInnerBytes = 0;
        foreach (ProsperoInnerImageAssembler.InnerFile file in innerFiles)
            totalInnerBytes += file.PayloadLength;
        return totalInnerBytes > options.FileBackedInnerImageThreshold
            ? RunFileBacked(innerFiles, options, param, paramJson, sceSysFiles, playGoProject, tsSec, tsNsec, console)
            : RunInMemory(innerFiles, options, param, paramJson, sceSysFiles, playGoProject, tsSec, tsNsec, console);
    }

    /// <summary>Parses a source PLGX when present, otherwise generates the observed default project.</summary>
    private static PlayGoProject ResolvePlayGoProject(
        IReadOnlyDictionary<string, byte[]> sceSysFiles, string contentId, int chunkCount, DebugPackageBuildLog console)
    {
        if (!sceSysFiles.TryGetValue("playgo-chunk.dat", out byte[]? bytes))
            return ProsperoPlayGoChunkBuilder.CreateProject(contentId, chunkCount);
        try
        {
            return PlayGoChunkReader.Read(bytes);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException)
        {
            console.Log($"  warning: sce_sys/playgo-chunk.dat could not be parsed ({ex.Message}); using the generated PlayGo project.");
            return ProsperoPlayGoChunkBuilder.CreateProject(contentId, chunkCount);
        }
    }

    /// <summary>
    /// The DRM token used for the SI/CNT-derived metadata: the explicit override when set, otherwise
    /// the source <c>param.json</c> value (or null when absent).
    /// </summary>
    private static string? EffectiveDrmType(DebugPackageBuildOptions options, ProsperoParam param) =>
        string.IsNullOrWhiteSpace(options.DrmTypeOverride) ? param.ApplicationDrmType : options.DrmTypeOverride;

    /// <summary>
    /// FIH 0x9C: the content-version major encoded as BCD in the top byte of the high dword
    /// (01.000.000 -> 0x01000000), derived from param.json. Returns zero when malformed.
    /// </summary>
    private static uint ContentVersionHigh(string? contentVersion)
    {
        if (string.IsNullOrWhiteSpace(contentVersion))
            return 0;
        string major = contentVersion.Split('.')[0].Trim();
        if (major.Length is 0 or > 2 ||
            !byte.TryParse(major, System.Globalization.NumberStyles.None,
                System.Globalization.CultureInfo.InvariantCulture, out byte value))
            return 0;
        uint bcd = (uint)(((value / 10) << 4) | (value % 10));
        return bcd << 24;
    }

    /// <summary>
    /// Builds the PlayGo descriptor family (chunk/hash-table/ficm), falling back to the observed
    /// single-chunk default model when the source project cannot describe this tree (for example a
    /// dump's stale chunk assignments or an unsupported scenario model).
    /// </summary>
    private static (ProsperoPlayGoChunkBuildResult Chunk, byte[] HashTable, byte[] Ficm) BuildPlayGoFamily(
        string contentId, PlayGoProject project, ProsperoInnerImageAssembler.InnerImageResult inner,
        ulong fihPfsOffset, ulong fihCntOffset, DebugPackageBuildLog console)
    {
        try
        {
            return Build(project);
        }
        catch (InvalidDataException ex)
        {
            console.Log($"  warning: PlayGo project is not usable ({ex.Message}); using the default single-chunk project.");
            return Build(ProsperoPlayGoChunkBuilder.CreateDefaultProject(contentId));
        }

        (ProsperoPlayGoChunkBuildResult, byte[], byte[]) Build(PlayGoProject p)
        {
            ProsperoPlayGoChunkBuildResult chunk = ProsperoPlayGoChunkBuilder.Build(
                contentId, p, inner, fihPfsOffset, fihCntOffset);
            IReadOnlyList<ProsperoPlayGoFileRecord> records = ProsperoPlayGoRecordBuilder.Build(
                inner, p.FileChunkAssignments);
            return (chunk, ProsperoPlayGoHashTableBuilder.Build(records), ProsperoPlayGoFicmBuilder.Build(records));
        }
    }

    private static DebugPackageBuildResult RunInMemory(
        List<ProsperoInnerImageAssembler.InnerFile> innerFiles,
        DebugPackageBuildOptions buildOptions,
        ProsperoParam param, byte[] paramJson,
        IReadOnlyDictionary<string, byte[]> sceSysFiles, PlayGoProject playGoProject,
        long tsSec, uint tsNsec, DebugPackageBuildLog console)
    {
        string output = buildOptions.OutputPath;
        string contentId = buildOptions.ContentId;
        string passcode = buildOptions.Passcode;
        ProsperoInnerCompressionMode compressionMode = buildOptions.Compression;
        int krakenLevel = buildOptions.KrakenLevel;
        int krakenThreads = buildOptions.KrakenThreads;
        uint contentVersionHi = ContentVersionHigh(param.ContentVersion);

        var assembler = new ProsperoInnerImageAssembler(tsSec, tsNsec);
        ProsperoInnerImageAssembler.InnerImageResult innerResult = assembler.Build(
            innerFiles, compressionMode, console.Progress, krakenLevel, krakenThreads);
        console.Finish();
        console.Log($"  Inner image: {innerResult.Image.Length} bytes, {innerResult.Ndblock} mount blocks, {innerResult.InodeCount} inodes");
        ProsperoCompressionMetrics compression = innerResult.CompressionMetrics;
        console.Log($"  Inner payload: {compression.RawBytes} raw -> {compression.EncodedBytes} encoded; " +
            $"Kraken {compression.KrakenBlocks}, stored {compression.StoredBlocks}, ratio {compression.Ratio:P2}");

        // ---- 3. Generate NAPS from the assembled source geometry. ----
        ProsperoNapsPlanGenerator.PlanResult napsPlan = ProsperoNapsPlanGenerator.Generate(innerResult);
        byte[] naps = ProsperoNapsLayoutBuilder.Build(napsPlan.ToRequest(
            compressionMode == ProsperoInnerCompressionMode.Stored ? (byte)0 : (byte)2));
        console.Log($"  NAPS layout: {naps.Length} bytes");

        // ---- 4. Build the outer PFS. ----
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(contentId, passcode);
        byte[] outerSeed = buildOptions.OuterSeed ?? System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        long innerImageSize = innerResult.Image.Length;
        long innerImageBlocks = (innerImageSize + ProsperoOuterPfsBuilder.BlockSize - 1) / ProsperoOuterPfsBuilder.BlockSize;
        var outerFiles = new List<OuterPfsFile>
        {
            new()
            {
                Name = "pfs_image.dat",
                Data = innerResult.Image,
                SizeCompressed = innerResult.Ndblock * ProsperoOuterPfsBuilder.BlockSize,
                Signed = false,
            },
            new()
            {
                Name = "naps_pkg_layout.dat",
                Data = naps,
                Signed = true,
            },
        };
        var outerParams = new OuterPfsBuildParameters { TimestampSeconds = tsSec, TimestampNanoseconds = tsNsec, Seed = outerSeed };
        OuterPfsBuildResult outerBuild = ProsperoOuterPfsBuilder.BuildPlaintext(outerFiles, outerParams, console.Progress);
        // Per-block digest table for the container imagedigs entry (same SHA3-256-per-plaintext-block
        // table the file-backed path writes).
        (byte[] imageDigests, byte[] superblockIcv) = ProsperoOuterPfsBuilder.ComputeImageDigests(outerBuild);
        ProsperoOuterPfsBuilder.Encrypt(outerBuild, ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, outerSeed).TweakKey,
            ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, outerSeed).DataKey, progress: console.Progress);
        console.Finish();
        byte[] outerImage = outerBuild.Plaintext;
        byte[] pfsImageDigest = Sha3.Sha3_256(outerBuild.Plaintext.AsSpan(outerBuild.SuperblockIndex * ProsperoOuterPfsBuilder.BlockSize, ProsperoOuterPfsBuilder.BlockSize));
        console.Log($"  Outer PFS: {outerImage.Length} bytes, {outerBuild.BlockCount} blocks, superblock at block {outerBuild.SuperblockIndex}");

        // ---- 5. Build the CNT container. ----
        var cntParams = new CntBuildParameters { ContentId = contentId, Passcode = passcode, ContentType = 0x20, ContentFlags = 0x02020000 };
        List<ProsperoCntBuilder.Entry> entries = ProsperoCntBuilder.BuildStandardEntries(contentId, passcode, ekpfs, buildOptions.DeterministicEntryKeys);

        // param.json entry.
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.ParamJson, Name = "param.json", Data = paramJson,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.ParamJson),
        });

        // imagedigs entry: SHA3-256 of each plaintext outer-PFS block, in block order. The on-disk
        // table stores each 32-byte digest byte-reversed (the Sony fixture and the reference writer
        // both do), so the internal forward digests are reversed for the container entry only.
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.Imagedigs, Name = null, Data = ReverseDigests(imageDigests),
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.Imagedigs),
        });

        // PlayGo: build the complete observed debug/nwonly family from semantic final-image data.
        // A GP5 supplies the supported explicit assignment model. Without one, a source PLGX is
        // optional compatibility input for chunk/scenario vocabulary; it is parsed, never copied.
        ulong fihPfsOffset = ProsperoFihBuilder.HeaderRegionSize;
        ulong fihCntOffset = checked(fihPfsOffset + (ulong)outerImage.Length);
        (ProsperoPlayGoChunkBuildResult playGoChunk, byte[] playGoHashTable, byte[] playGoFicm) =
            BuildPlayGoFamily(contentId, playGoProject, innerResult, fihPfsOffset, fihCntOffset, console);

        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.PlaygoChunkDat, Name = "playgo-chunk.dat", Data = playGoChunk.Data,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoChunkDat),
        });

        // sce_sys media/system files are outer CNT entries (never inner-PFS files). PNG icons and
        // pictures also get a generated BC7 DDS companion when the source does not ship one.
        // Generated entries (PlayGo family, param.json) win over a source-supplied duplicate id.
        // The media entries sit between playgo-chunk.dat and the hash-table/ficm pair, matching the
        // Sony container's on-disk entry order.
        foreach (ProsperoSceSysMedia.Entry media in ProsperoSceSysMedia.Collect(sceSysFiles, EffectiveDrmType(buildOptions, param)))
        {
            if (entries.Any(e => (uint)e.Id == (uint)media.Id))
                continue;
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = media.Id, Name = media.Name, Data = media.Data,
                Flags1 = media.Flags1, Flags2 = media.Flags2,
            });
        }

        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.PlaygoHashTable, Name = "playgo-hash-table.dat", Data = playGoHashTable,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoHashTable),
        });
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.PlaygoFicm, Name = "playgo-ficm.dat", Data = playGoFicm,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoFicm),
        });

        // FIH geometry + accounting are needed before the CNT so the embedded CNT can carry
        // pfs_signed_digest = SHA3-256(FIH header) at 0x460. The reference stamps 0x460 before it
        // computes the GeneralDigests header slot (whose preimage spans 0x400..0x480) and the
        // package self-seal at 0xFE0. The FIH header is independent of the CNT, so a preview of the
        // exact final header can be hashed first.
        byte[] nestedDigest = Sha3.Sha3_256(naps);
        long nestedMetaBaseBlocks = innerResult.MetaBaseLogical / ProsperoOuterPfsBuilder.BlockSize;
        // FIH 0x94 is the NAPS FIDX file count (NumFiles - 1); 0x98 = 0x94 + zero-length files.
        int emptyFileCount = innerFiles.Count(f => f.PayloadLength == 0);
        int fihMetaBlockCount = napsPlan.FileLogicalOffsets.Count - 1;
        int fihMetaBlockCountMirror = fihMetaBlockCount + emptyFileCount;
        byte[] fihHeaderPreview = ProsperoFihBuilder.BuildHeaderBlock(
            FihVariant.Debug,
            (ulong)outerImage.Length,
            (ulong)(ProsperoFihBuilder.HeaderRegionSize + outerImage.Length),
            outerImage,
            nestedImageDigest: nestedDigest,
            nestedImageSize: naps.Length,
            nestedMetaBaseBlocks: nestedMetaBaseBlocks,
            contentVersionHi: contentVersionHi,
            innerContentInodes: innerResult.InnerContentInodes,
            appFileCount: innerResult.AppFileCount,
            metaBlockCount: fihMetaBlockCount,
            metaBlockCountMirror: fihMetaBlockCountMirror,
            emptyFileCount: emptyFileCount);
        byte[] pfsSignedDigest = Sha3.Sha3_256(fihHeaderPreview);

        byte[] cnt = ProsperoCntBuilder.Build(entries, cntParams, outerImage, outerSeed, pfsImageDigest,
            nestedImageDigest: nestedDigest, nestedImageSize: naps.Length,
            pfsSignedDigest: pfsSignedDigest);
        console.Log($"  CNT container: {cnt.Length} bytes");

        // ---- 6. Build the FIH image with the SI (install-metadata) segment. ----
        // Three-phase build: the SI segment carries the fixed-info-digest = SHA3-256 of the FIH
        // header block, so the FIH is first built WITHOUT the SI; the SI is then assembled from
        // the (header-only) mount image and the already-produced CNT/outer geometry; finally the
        // FIH is rebuilt with the SI appended. The header bytes are identical between the two
        // phases (the SI trails the CNT and never feeds back into the 0x10000-byte header region),
        // so the fixed-info-digest stays self-consistent.
        byte[] fihNoSi = ProsperoFihBuilder.BuildFromCnt(
            cnt, FihVariant.Debug,
            nestedImageDigest: nestedDigest, nestedImageSize: naps.Length,
            nestedMetaBaseBlocks: nestedMetaBaseBlocks,
            contentVersionHi: contentVersionHi,
            innerContentInodes: innerResult.InnerContentInodes,
            appFileCount: innerResult.AppFileCount,
            metaBlockCount: fihMetaBlockCount,
            metaBlockCountMirror: fihMetaBlockCountMirror,
            emptyFileCount: emptyFileCount);

        byte[]? playGoChunkDat = entries.FirstOrDefault(e => e.Id == CntEntryId.PlaygoChunkDat)?.Data;
        byte[] siSegment = BuildSiSegment(
            contentId, EffectiveDrmType(buildOptions, param) ?? "free", param, cnt, entries, outerFiles, outerBuild, outerSeed, superblockIcv,
            innerResult, fihNoSi, paramJson, playGoChunkDat);

        byte[] fih = ProsperoFihBuilder.BuildFromCnt(
            cnt, FihVariant.Debug,
            nestedImageDigest: nestedDigest, nestedImageSize: naps.Length,
            nestedMetaBaseBlocks: nestedMetaBaseBlocks,
            contentVersionHi: contentVersionHi,
            innerContentInodes: innerResult.InnerContentInodes,
            appFileCount: innerResult.AppFileCount,
            metaBlockCount: fihMetaBlockCount,
            metaBlockCountMirror: fihMetaBlockCountMirror,
            emptyFileCount: emptyFileCount,
            siSegment: siSegment);

        // ---- 7. Write the output. ----
        string outDir = Path.GetDirectoryName(Path.GetFullPath(output))!;
        Directory.CreateDirectory(outDir);
        File.WriteAllBytes(output, fih);
        console.Log($"Wrote: {output} ({fih.Length} bytes)");
        return new DebugPackageBuildResult(Path.GetFullPath(output), fih.Length, contentId, innerFiles.Count, false);
    }

    /// <summary>
    /// File-backed companion to the in-memory pipeline: assembles the inner image, outer PFS, CNT
    /// and finalized FIH as temporary files (with the SI computed by streaming the mount image), so
    /// a multi-GiB package never materializes as one <c>byte[]</c>. Every temp artifact is removed
    /// in a <c>finally</c>.
    /// </summary>
    private static DebugPackageBuildResult RunFileBacked(
        List<ProsperoInnerImageAssembler.InnerFile> innerFiles,
        DebugPackageBuildOptions buildOptions,
        ProsperoParam param, byte[] paramJson,
        IReadOnlyDictionary<string, byte[]> sceSysFiles, PlayGoProject playGoProject,
        long tsSec, uint tsNsec, DebugPackageBuildLog console)
    {
        string output = buildOptions.OutputPath;
        string contentId = buildOptions.ContentId;
        string passcode = buildOptions.Passcode;
        ProsperoInnerCompressionMode compressionMode = buildOptions.Compression;
        int krakenLevel = buildOptions.KrakenLevel;
        int krakenThreads = buildOptions.KrakenThreads;
        uint contentVersionHi = ContentVersionHigh(param.ContentVersion);

        string tempRoot = TempWorkspace.Create(buildOptions.TempDirectory ?? Path.GetTempPath());
        try
        {
            string innerImagePath = Path.Combine(tempRoot, "pfs_image.dat");
            string napsPath = Path.Combine(tempRoot, "naps_pkg_layout.dat");

            var assembler = new ProsperoInnerImageAssembler(tsSec, tsNsec);
            ProsperoInnerImageAssembler.InnerImageResult innerResult =
                assembler.BuildToFile(innerFiles, innerImagePath, compressionMode, console.Progress, krakenLevel, krakenThreads);
            console.Finish();
            console.Log($"  Inner image (file-backed): {innerResult.ImageSize} bytes, {innerResult.Ndblock} mount blocks, {innerResult.InodeCount} inodes");
            ProsperoCompressionMetrics compression = innerResult.CompressionMetrics;
            console.Log($"  Inner payload: {compression.RawBytes} raw -> {compression.EncodedBytes} encoded; " +
                $"Kraken {compression.KrakenBlocks}, stored {compression.StoredBlocks}, ratio {compression.Ratio:P2}");

            ProsperoNapsPlanGenerator.PlanResult napsPlan = ProsperoNapsPlanGenerator.Generate(innerResult);
            byte[] naps = ProsperoNapsLayoutBuilder.Build(napsPlan.ToRequest(
                compressionMode == ProsperoInnerCompressionMode.Stored ? (byte)0 : (byte)2));
            File.WriteAllBytes(napsPath, naps);
            console.Log($"  NAPS layout: {naps.Length} bytes");

            byte[] ekpfs = ProsperoKeys.ComputeEkpfs(contentId, passcode);
            byte[] outerSeed = buildOptions.OuterSeed ?? System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
            var outerSources = new List<OuterPfsFileSource>
            {
                new()
                {
                    Name = "pfs_image.dat",
                    Path = innerImagePath,
                    SizeCompressed = innerResult.Ndblock * ProsperoOuterPfsBuilder.BlockSize,
                    Signed = false,
                },
                new()
                {
                    Name = "naps_pkg_layout.dat",
                    Path = napsPath,
                    Signed = true,
                },
            };
            var outerParams = new OuterPfsBuildParameters { TimestampSeconds = tsSec, TimestampNanoseconds = tsNsec, Seed = outerSeed, BlockParallelism = krakenThreads };
            (byte[] outerTweakKey, byte[] outerDataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, outerSeed);
            // Write the outer PFS directly into its final FIH range (0x10000) so it is never copied.
            OuterPfsFileBuildResult outerBuild = ProsperoOuterPfsBuilder.BuildForPackageToFile(
                outerSources, outerParams, output, encryptOutput: true, outerTweakKey, outerDataKey,
                progress: console.Progress, outputOffset: ProsperoFihBuilder.HeaderRegionSize);
            console.Finish();
            byte[] pfsImageDigest = Sha3.Sha3_256(outerBuild.SuperblockPlaintext);
            long outerLength = outerBuild.ImageLength;
            console.Log($"  Outer PFS (file-backed): {outerLength} bytes, {outerBuild.BlockCount} blocks, superblock at block {outerBuild.SuperblockIndex}");

            var cntParams = new CntBuildParameters { ContentId = contentId, Passcode = passcode, ContentType = 0x20, ContentFlags = 0x02020000 };
            List<ProsperoCntBuilder.Entry> entries = ProsperoCntBuilder.BuildStandardEntries(contentId, passcode, ekpfs, buildOptions.DeterministicEntryKeys);
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.ParamJson, Name = "param.json", Data = paramJson,
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.ParamJson),
            });
            // The streamed outer build already produced the per-block digest table; each 32-byte
            // digest is stored byte-reversed on disk (the container's imagedigs convention).
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.Imagedigs, Name = null, Data = ReverseDigests(outerBuild.ImageDigests),
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.Imagedigs),
            });

            ulong fihPfsOffset = ProsperoFihBuilder.HeaderRegionSize;
            ulong fihCntOffset = checked(fihPfsOffset + (ulong)outerLength);
            (ProsperoPlayGoChunkBuildResult playGoChunk, byte[] playGoHashTable, byte[] playGoFicm) =
                BuildPlayGoFamily(contentId, playGoProject, innerResult, fihPfsOffset, fihCntOffset, console);

            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.PlaygoChunkDat, Name = "playgo-chunk.dat", Data = playGoChunk.Data,
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoChunkDat),
            });

            // Media entries sit between playgo-chunk.dat and the hash-table/ficm pair, matching the
            // Sony container's on-disk entry order.
            foreach (ProsperoSceSysMedia.Entry media in ProsperoSceSysMedia.Collect(sceSysFiles, EffectiveDrmType(buildOptions, param)))
            {
                if (entries.Any(e => (uint)e.Id == (uint)media.Id))
                    continue;
                entries.Add(new ProsperoCntBuilder.Entry
                {
                    Id = media.Id, Name = media.Name, Data = media.Data,
                    Flags1 = media.Flags1, Flags2 = media.Flags2,
                });
            }

            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.PlaygoHashTable, Name = "playgo-hash-table.dat", Data = playGoHashTable,
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoHashTable),
            });
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.PlaygoFicm, Name = "playgo-ficm.dat", Data = playGoFicm,
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoFicm),
            });

            byte[] nestedDigest = Sha3.Sha3_256(naps);
            long nestedMetaBaseBlocks = innerResult.MetaBaseLogical / ProsperoOuterPfsBuilder.BlockSize;
            int emptyFileCount = innerFiles.Count(f => f.PayloadLength == 0);
            int fihMetaBlockCount = napsPlan.FileLogicalOffsets.Count - 1;
            int fihMetaBlockCountMirror = fihMetaBlockCount + emptyFileCount;
            byte[] fihHeaderPreview = ProsperoFihBuilder.BuildHeaderBlockFromSuperblock(
                FihVariant.Debug,
                (ulong)outerLength,
                (ulong)(ProsperoFihBuilder.HeaderRegionSize + outerLength),
                outerBuild.SuperblockPlaintext,
                (long)outerBuild.SuperblockIndex * ProsperoOuterPfsBuilder.BlockSize,
                nestedImageDigest: nestedDigest,
                nestedImageSize: naps.Length,
                nestedMetaBaseBlocks: nestedMetaBaseBlocks,
                contentVersionHi: contentVersionHi,
                innerContentInodes: innerResult.InnerContentInodes,
                appFileCount: innerResult.AppFileCount,
                metaBlockCount: fihMetaBlockCount,
                metaBlockCountMirror: fihMetaBlockCountMirror,
                emptyFileCount: emptyFileCount);
            byte[] pfsSignedDigest = Sha3.Sha3_256(fihHeaderPreview);

            byte[] cntMetadata = ProsperoCntBuilder.BuildMetadata(
                entries, cntParams, outerLength, outerSeed, pfsImageDigest, pfsSignedDigest);
            console.Log($"  CNT metadata (file-backed): {cntMetadata.Length} bytes");

            byte[]? playGoChunkDat = entries.First(e => e.Id == CntEntryId.PlaygoChunkDat).Data;
            Func<Stream, long, byte[]> siFactory = (stream, mountLength) =>
            {
                long pfsImageSize = outerLength;
                long cntOffset = ProsperoFihBuilder.HeaderRegionSize + pfsImageSize;
                long containerSize = mountLength - cntOffset;

                byte[] cntHead = ReadStreamRange(stream, cntOffset, 0x5A0);
                long bodyOffset = (long)BinaryPrimitives.ReadUInt64BigEndian(cntHead.AsSpan(0x20));
                long bodySize = (long)BinaryPrimitives.ReadUInt64BigEndian(cntHead.AsSpan(0x28));
                long mandatorySize = (long)BinaryPrimitives.ReadUInt64BigEndian(cntHead.AsSpan(0x30));
                long packageSize = ProsperoFihBuilder.HeaderRegionSize + pfsImageSize + containerSize;

                byte[] headerBlock = ReadStreamRange(stream, 0, ProsperoFihBuilder.HeaderRegionSize);
                ulong innerImageSize = BinaryPrimitives.ReadUInt64LittleEndian(headerBlock.AsSpan(0xA0));

                long mountTotalToCnt = ProsperoFihBuilder.HeaderRegionSize + pfsImageSize;
                long chunkInfoOuter0 = (long)outerBuild.FileBlockCount[0] * ProsperoOuterPfsBuilder.BlockSize;

                byte[] packageDigest = ReadStreamRange(stream, cntOffset + ProsperoCntBuilder.PackageDigestStoredOffset, 32);
                byte[] bodyBytes = ReadStreamRange(stream, cntOffset + bodyOffset, checked((int)bodySize));
                byte[] bodyDigest = Sha3.Sha3_256(bodyBytes);
                byte[] fixedInfoDigest = Sha3.Sha3_256(headerBlock);

                byte[]? generalDigests = entries.FirstOrDefault(e => e.Id == CntEntryId.GeneralDigests)?.Data;
                byte[]? Dig(int slotOff) => generalDigests is { Length: >= 0x1E0 }
                    ? generalDigests.AsSpan(slotOff, 32).ToArray() : null;
                byte[]? contentDigest = Dig(0x20);
                byte[]? headerDigest = Dig(0x60);
                byte[]? systemDigest = Dig(0x80);
                byte[] gameDigest = Sha3.Sha3_256(outerBuild.SuperblockPlaintext);
                byte[] paramDigest = Sha3.Sha3_256(paramJson);
                byte[] pfsImageSeed = outerBuild.SuperblockPlaintext.AsSpan(0x370, 16).ToArray();

                List<ProsperoPfsImageEntry> xmlEntries = entries
                    .Where(e => (uint)e.Id >= 0x400)
                    .Select(e => new ProsperoPfsImageEntry(
                        (uint)e.Id == (uint)CntEntryId.Imagedigs ? "imagedigs.dat" : (e.Name ?? $"0x{(uint)e.Id:x4}.bin"),
                        e.DataOffset, e.DataSize))
                    .OrderBy(e => e.Offset)
                    .ToList();

                List<(string Path, long Size)> contentFiles = innerResult.Nodes
                    .Where(n => !n.IsDirectory && n.ParentInode >= 0)
                    .OrderBy(n => n.Afid)
                    .Select(n => (n.FullPath.TrimStart('/'), n.Size))
                    .ToList();

                string applicationDrmType = EffectiveDrmType(buildOptions, param) ?? "free";
                var xmlOptions = new ProsperoPfsImageXmlOptions
                {
                    ContentId = contentId,
                    TitleName = param.TitleName ?? "",
                    ContentVersion = param.ContentVersion ?? "01.000.000",
                    DrmType = "none",
                    ApplicationDrmType = applicationDrmType,
                    ContentType = "PS5GD",
                    ApplicationType = applicationDrmType,
                    MasterVersion = "01.00",
                    PackageSize = packageSize,
                    PfsImageOffset = ProsperoFihBuilder.HeaderRegionSize,
                    PfsImageSize = pfsImageSize,
                    PfsImageSeed = pfsImageSeed,
                    ContainerSize = containerSize,
                    MandatorySize = mandatorySize,
                    BodyOffset = bodyOffset,
                    SupplementalOffset = containerSize,
                    Entries = xmlEntries,
                    ContentDigest = contentDigest,
                    GameDigest = gameDigest,
                    HeaderDigest = headerDigest,
                    SystemDigest = systemDigest,
                    ParamDigest = paramDigest,
                    PackageDigest = packageDigest,
                    BodyDigest = bodyDigest,
                    SblockDigest = gameDigest,
                    FixedInfoDigest = fixedInfoDigest,
                    NestedInner = innerResult,
                    OuterPfsTree = new OuterPfsTreeInfo
                    {
                        BlockSize = ProsperoOuterPfsBuilder.BlockSize,
                        ImageBlocks = outerBuild.BlockCount,
                        InodeCount = 3 + outerSources.Count,
                        DinodeBlockCount = 1,
                        DinodeBlock = outerBuild.InodeTableIndex,
                        DinodeSize = ProsperoOuterPfsBuilder.BlockSize,
                        DinodeFlags = 0,
                        RootInode = 0,
                        Seed = outerSeed,
                        SuperblockIcv = outerBuild.SuperblockIcv,
                        Signed = true,
                        Encrypted = true,
                        Root = BuildOuterPfsTreeRoot(
                            outerBuild.SuperRootDirentIndex, outerBuild.FltIndex, outerBuild.UrootDirentIndex,
                            outerBuild.FileFirstBlock,
                            new List<(string, long, long)>
                            {
                                ("pfs_image.dat", innerResult.ImageLength, innerResult.Ndblock * ProsperoOuterPfsBuilder.BlockSize),
                                ("naps_pkg_layout.dat", naps.Length, naps.Length),
                            }),
                    },
                    ChunkInfo = new ProsperoChunkInfoModel
                    {
                        PlayGoChunkDatSize = playGoChunkDat?.Length ?? 0,
                        TotalSize = mountTotalToCnt,
                        Outer0Size = chunkInfoOuter0,
                        Outer1Size = mountTotalToCnt - chunkInfoOuter0,
                    },
                };

                return ProsperoSiArchive.BuildDebugSiSegmentFromStream(
                    xmlOptions, playGoChunkDat, stream, mountLength, innerImageSize, contentFiles,
                    outerBuild.SuperblockPlaintext, includePfsImageXml: false);
            };

            ProsperoFihBuilder.FinalizePrepositionedToFile(
                cntMetadata, output, outerLength, FihVariant.Debug, outerBuild.SuperblockIndex,
                outerBuild.SuperblockPlaintext,
                nestedDigest, naps.Length, nestedMetaBaseBlocks, contentVersionHi,
                innerResult.InnerContentInodes, innerResult.AppFileCount,
                fihMetaBlockCount, fihMetaBlockCountMirror, emptyFileCount, 0,
                siFactory);

            long packageLength = new FileInfo(output).Length;
            console.Log($"Wrote: {output} ({packageLength} bytes)");
            return new DebugPackageBuildResult(Path.GetFullPath(output), packageLength, contentId, innerFiles.Count, true);
        }
        finally
        {
            TempWorkspace.Delete(tempRoot);
        }
    }

    /// <summary>
    /// Reverses each 32-byte digest on a copy: the on-disk imagedigs entry stores every per-block
    /// digest byte-reversed (verified against the Sony fixture and the reference writer).
    /// </summary>
    private static byte[] ReverseDigests(byte[] digests)
    {
        byte[] reversed = (byte[])digests.Clone();
        for (int off = 0; off + 32 <= reversed.Length; off += 32)
            Array.Reverse(reversed, off, 32);
        return reversed;
    }

    private static byte[] ReadStreamRange(Stream stream, long offset, int length)
    {
        var buffer = new byte[length];
        stream.Position = offset;
        int read = 0;
        while (read < length)
        {
            int n = stream.Read(buffer, read, length - read);
            if (n <= 0)
                throw new EndOfStreamException("Unexpected end of the mount stream.");
            read += n;
        }
        return buffer;
    }

    /// <summary>
    /// Build the debug SI (install-metadata) segment from values the package build has already
    /// produced. The SI is a STORED ZIP whose members are: <c>naps_meta_18.dat</c>,
    /// <c>naps_meta_300/301/302/308.dat</c>, <c>common/etc/pfsimage.xml</c>, the copied
    /// <c>playgo-chunk.dat</c> (when present), and the per-content-id <c>playgo-chunk.crc</c>
    /// computed by CRC-32C over the finalized mount image. Every reproducible digest and geometry
    /// field of <c>pfsimage.xml</c> is sourced from the produced CNT/outer image — keyed digests
    /// that the builder has already written are read back; nothing is fabricated.
    /// </summary>
    private static byte[] BuildSiSegment(
        string contentId, string applicationDrmType, ProsperoParam param,
        byte[] cnt, IReadOnlyList<ProsperoCntBuilder.Entry> entries,
        IReadOnlyList<OuterPfsFile> outerFiles, OuterPfsBuildResult outerBuild, byte[] outerSeed,
        byte[] superblockIcv,
        ProsperoInnerImageAssembler.InnerImageResult innerResult,
        byte[] fihNoSi, byte[] paramJson, byte[]? playGoChunkDat)
    {
        long pfsImageSize = (long)BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x418));
        // CNT+0x410 stores the FIH-relative pfs_image_offset (0x10000); the CNT-internal container
        // size = body end = total CNT length − embedded PFS image size.
        long containerSize = cnt.Length - pfsImageSize;
        long bodyOffset = (long)BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x20));
        ulong bodySizeU = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x28));
        long mandatorySize = (long)BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x30));
        long packageSize = (long)ProsperoFihBuilder.HeaderRegionSize + pfsImageSize + containerSize;

        // The inner-image size the SI records describe MUST be the FIH 0xA0 value the produced
        // package carries (phdr/meta300/pgpl all state it), so read it back from the finalized
        // header rather than recomputing it.
        ulong innerImageSize = BinaryPrimitives.ReadUInt64LittleEndian(fihNoSi.AsSpan(0xA0));
        // chunkinfo tiles the mount image [0, cnt_offset): outer 0 = the block-aligned stored
        // pfs_image.dat, outer 1 = the remainder of the PFS region up to the CNT.
        long mountTotalToCnt = (long)ProsperoFihBuilder.HeaderRegionSize + pfsImageSize;
        long chunkInfoOuter0 = (long)outerBuild.FileBlockCount[0] * ProsperoOuterPfsBuilder.BlockSize;

        // Reproducible digests already stamped into the CNT/outer image.
        byte[] packageDigest = cnt.AsSpan(ProsperoCntBuilder.PackageDigestStoredOffset, 32).ToArray();
        byte[] bodyDigest = Sha3.Sha3_256(cnt.AsSpan((int)bodyOffset, (int)bodySizeU));
        byte[] fixedInfoDigest = Sha3.Sha3_256(fihNoSi.AsSpan(0, ProsperoFihBuilder.HeaderRegionSize));

        // General-digests payload slots (CntBuilder order): +0x20 content, +0x40 game,
        // +0x60 header, +0x80 system, +0xC0 param.
        byte[]? generalDigests = entries.FirstOrDefault(e => e.Id == CntEntryId.GeneralDigests)?.Data;
        byte[]? Dig(int slotOff) => generalDigests is { Length: >= 0x1E0 }
            ? generalDigests.AsSpan(slotOff, 32).ToArray() : null;
        byte[]? contentDigest = Dig(0x20);
        byte[]? headerDigest = Dig(0x60);
        byte[]? systemDigest = Dig(0x80);

        // Game/sblock digest = SHA3-256 of the plaintext outer superblock block (= the value the
        // FIH stamps at 0x30/0x70/0xD0); param-digest = SHA3-256(param.json).
        int sbOff = outerBuild.SuperblockIndex * ProsperoOuterPfsBuilder.BlockSize;
        byte[] gameDigest = Sha3.Sha3_256(outerBuild.Plaintext.AsSpan(sbOff, ProsperoOuterPfsBuilder.BlockSize));
        byte[] paramDigest = Sha3.Sha3_256(paramJson);

        // pfs-image seed: 16 bytes at superblock+0x370.
        byte[] pfsImageSeed = outerBuild.Plaintext.AsSpan(sbOff + 0x370, 16).ToArray();

        // The <entries> table = the file-class CNT entries (id >= 0x400), ordered by container offset.
        // imagedigs (0x040A) is stored UNNAMED in the CNT, so special-case its display name.
        List<ProsperoPfsImageEntry> xmlEntries = entries
            .Where(e => (uint)e.Id >= 0x400)
            .Select(e => new ProsperoPfsImageEntry(
                (uint)e.Id == (uint)CntEntryId.Imagedigs ? "imagedigs.dat" : (e.Name ?? $"0x{(uint)e.Id:x4}.bin"),
                e.DataOffset, e.DataSize))
            .OrderBy(e => e.Offset)
            .ToList();

        // Content files for naps_meta_18's file/fstr table: real inner content files in afid order
        // (non-directory nodes with ParentInode >= 0), each FullPath made root-relative.
        List<(string Path, long Size)> contentFiles = innerResult.Nodes
            .Where(n => !n.IsDirectory && n.ParentInode >= 0)
            .OrderBy(n => n.Afid)
            .Select(n => (n.FullPath.TrimStart('/'), n.Size))
            .ToList();

        string contentVersion = param.ContentVersion ?? "01.000.000";
        string titleName = param.TitleName ?? "";
        string masterVersion = "01.00";

        var xmlOptions = new ProsperoPfsImageXmlOptions
        {
            ContentId = contentId,
            TitleName = titleName,
            ContentVersion = contentVersion,
            DrmType = "none",
            ApplicationDrmType = applicationDrmType,
            ContentType = "PS5GD",
            ApplicationType = applicationDrmType,
            MasterVersion = masterVersion,
            PackageSize = packageSize,
            PfsImageOffset = ProsperoFihBuilder.HeaderRegionSize,
            PfsImageSize = pfsImageSize,
            PfsImageSeed = pfsImageSeed,
            ContainerSize = containerSize,
            MandatorySize = mandatorySize,
            BodyOffset = bodyOffset,
            SupplementalOffset = containerSize,
            Entries = xmlEntries,
            ContentDigest = contentDigest,
            GameDigest = gameDigest,
            HeaderDigest = headerDigest,
            SystemDigest = systemDigest,
            ParamDigest = paramDigest,
            PackageDigest = packageDigest,
            BodyDigest = bodyDigest,
            SblockDigest = gameDigest,
            FixedInfoDigest = fixedInfoDigest,
            NestedInner = innerResult,
            OuterPfsTree = new OuterPfsTreeInfo
            {
                BlockSize = ProsperoOuterPfsBuilder.BlockSize,
                ImageBlocks = outerBuild.BlockCount,
                InodeCount = 3 + outerFiles.Count,
                DinodeBlockCount = 1,
                DinodeBlock = outerBuild.InodeTableIndex,
                DinodeSize = ProsperoOuterPfsBuilder.BlockSize,
                DinodeFlags = 0,
                RootInode = 0,
                Seed = outerSeed,
                SuperblockIcv = superblockIcv,
                Signed = true,
                Encrypted = true,
                Root = BuildOuterPfsTreeRoot(outerBuild, outerFiles),
            },
            ChunkInfo = new ProsperoChunkInfoModel
            {
                PlayGoChunkDatSize = playGoChunkDat?.Length ?? 0,
                TotalSize = mountTotalToCnt,
                Outer0Size = chunkInfoOuter0,
                Outer1Size = mountTotalToCnt - chunkInfoOuter0,
            },
        };

        // The mount image passed for the playgo-chunk.crc must cover [0, mountImageSize) WITHOUT
        // the trailing SI — i.e. the header-only finalized bytes fihNoSi (FIH + PFS + CNT). The
        // fixture CRC file = 16 blocks × u32 over [0, 0x100000).
        // innerImageSize here is the FIH 0xA0 value read back from the header above.
        return ProsperoSiArchive.BuildDebugSiSegment(
            xmlOptions, playGoChunkDat, fihNoSi, innerImageSize, contentFiles,
            includePfsImageXml: false);
    }

    /// <summary>
    /// Builds the outer-PFS inode tree snapshot for the <c>pfs-image</c> XML section, mirroring the
    /// fixed data-first inode template the outer builder writes: super-root →
    /// inode_flat_path_table + uroot → the outer files in order.
    /// </summary>
    private static OuterPfsTreeNode BuildOuterPfsTreeRoot(OuterPfsBuildResult outerBuild, IReadOnlyList<OuterPfsFile> outerFiles)
    {
        var files = new List<(string Name, long StoredSize, long PlainSize)>(outerFiles.Count);
        foreach (OuterPfsFile f in outerFiles)
            files.Add((f.Name, f.Data.Length, f.SizeCompressed ?? (long)f.Data.Length));
        return BuildOuterPfsTreeRoot(
            outerBuild.SuperRootDirentIndex, outerBuild.FltIndex, outerBuild.UrootDirentIndex,
            outerBuild.FileFirstBlock, files);
    }

    private static OuterPfsTreeNode BuildOuterPfsTreeRoot(
        int superRootDirentIndex, int fltIndex, int urootDirentIndex, int[] fileFirstBlock,
        IReadOnlyList<(string Name, long StoredSize, long PlainSize)> files)
    {
        const ushort ModeDir = 0x416D;
        const ushort ModeFile = 0x816D;
        const uint FlagsInternalMeta = 0x0002000C;
        const uint FlagsDir = 0x0000000C;
        const uint FlagsFile = 0x0000000D;
        const string FlatPathTableName = "inode_flat_path_table";
        const string UrootName = "uroot";
        const long FltDataOffset = 0x40;

        long fltSize = FltDataOffset + (long)files.Count * 16;
        var root = new OuterPfsTreeNode
        {
            Name = "",
            IsDirectory = true,
            Inode = 0,
            StartBlock = superRootDirentIndex,
            StoredSize = ProsperoOuterPfsBuilder.BlockSize,
            PlainSize = ProsperoOuterPfsBuilder.BlockSize,
            Flags = FlagsInternalMeta,
            Mode = ModeDir,
            Nlink = 1,
        };
        root.Children.Add(new OuterPfsTreeNode
        {
            Name = FlatPathTableName,
            IsDirectory = false,
            Inode = 1,
            StartBlock = fltIndex,
            StoredSize = fltSize,
            PlainSize = fltSize,
            Flags = FlagsInternalMeta,
            Mode = ModeFile,
            Nlink = 1,
            Internal = true,
        });
        var uroot = new OuterPfsTreeNode
        {
            Name = UrootName,
            IsDirectory = true,
            Inode = 2,
            StartBlock = urootDirentIndex,
            StoredSize = ProsperoOuterPfsBuilder.BlockSize,
            PlainSize = ProsperoOuterPfsBuilder.BlockSize,
            Flags = FlagsDir,
            Mode = ModeDir,
            Nlink = 3,
        };
        for (int i = 0; i < files.Count; i++)
        {
            (string name, long storedSize, long plainSize) = files[i];
            uroot.Children.Add(new OuterPfsTreeNode
            {
                Name = name,
                IsDirectory = false,
                Inode = (uint)(3 + i),
                StartBlock = fileFirstBlock[i],
                StoredSize = storedSize,
                PlainSize = plainSize,
                Flags = FlagsFile,
                Mode = ModeFile,
                Nlink = 1,
            });
        }
        root.Children.Add(uroot);
        return root;
    }

    /// <summary>
    /// Converts raw ELF application modules (<c>eboot.bin</c>, <c>sce_module/*</c>,
    /// <c>sce_sys/about/*</c>) into debug fake-SELF containers, matching the scene method. Modules
    /// that are already SELF images are left untouched. A stripped library module inherits the
    /// application's <c>.sceversion</c> record so the console can validate the SDK version.
    /// </summary>
    private static void FakeSignInnerModules(
        List<ProsperoInnerImageAssembler.InnerFile> innerFiles, DebugPackageBuildLog console,
        ulong? sdkVersionOverride)
    {
        byte[]? applicationSceVersion = null;
        int ebootIndex = innerFiles.FindIndex(file =>
            string.Equals(file.Path, "/eboot.bin", StringComparison.Ordinal));
        if (ebootIndex >= 0)
        {
            try
            {
                if (ProsperoSelfBuilder.TryGetSceVersionRecord(ReadInnerFileBytes(innerFiles[ebootIndex]), out byte[] ebootRecord))
                    applicationSceVersion = ebootRecord;
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException)
            {
                console.Log($"  warning: could not read the eboot sceversion record ({ex.Message}).");
            }
        }

        // An explicit SDK override replaces the module record with the requested identifier, both for
        // modules that already carry a .sceversion and for stripped ones that inherit the app record.
        if (sdkVersionOverride is { } overrideVersion)
            applicationSceVersion = ProsperoSelfBuilder.BuildSdkVersionTuple(overrideVersion);

        for (int i = 0; i < innerFiles.Count; i++)
        {
            ProsperoInnerImageAssembler.InnerFile file = innerFiles[i];
            // Fake-signing is the one transformation that may target file-backed sources, so read
            // the payload here and replace the entry with an in-memory transformed result. A module
            // that cannot be converted is packed unchanged with a warning instead of failing the build.
            if (!IsFakeSignTarget(file.Path))
                continue;
            try
            {
                byte[] source = ReadInnerFileBytes(file);
                if (!ProsperoSelfBuilder.IsElf(source))
                    continue;

                FselfOptions? options = null;
                if (sdkVersionOverride is { } sdkOverride)
                {
                    options = new FselfOptions
                    {
                        SdkVersionOverride = sdkOverride,
                        SceVersionName = Path.GetFileNameWithoutExtension(file.Path),
                        SceVersionRecord = applicationSceVersion,
                    };
                }
                else if (!string.Equals(file.Path, "/eboot.bin", StringComparison.Ordinal) &&
                    applicationSceVersion is not null &&
                    !ProsperoSelfBuilder.TryGetSceVersionRecord(source, out _))
                {
                    options = new FselfOptions
                    {
                        SceVersionName = Path.GetFileNameWithoutExtension(file.Path),
                        SceVersionRecord = applicationSceVersion,
                    };
                }

                byte[] signed = ProsperoSelfBuilder.MakeFself(source, options);
                innerFiles[i] = new ProsperoInnerImageAssembler.InnerFile
                {
                    Path = file.Path,
                    Data = signed,
                    PlayGoChunkId = file.PlayGoChunkId,
                };
                console.Log($"  Fake-signed module: {file.Path} ({source.Length} -> {signed.Length} bytes)");
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or ArgumentException or NotSupportedException)
            {
                console.Log($"  warning: could not fake-sign {file.Path}: {ex.Message}; packing it unchanged.");
            }
        }
    }

    private static byte[] ReadInnerFileBytes(ProsperoInnerImageAssembler.InnerFile file)
    {
        if (file.Source is not null)
        {
            using Stream stream = file.Source.Open();
            using var buffer = new MemoryStream();
            stream.CopyTo(buffer);
            return buffer.ToArray();
        }
        return file.SourcePath is not null ? File.ReadAllBytes(file.SourcePath) : file.Data;
    }

    private static bool IsFakeSignTarget(string path)
    {
        string fileName = Path.GetFileName(path);
        return fileName.Equals("eboot.bin", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".elf", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".prx", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".sprx", StringComparison.OrdinalIgnoreCase);
    }
}
