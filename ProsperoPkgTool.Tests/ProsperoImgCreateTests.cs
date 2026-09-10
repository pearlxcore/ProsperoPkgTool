using System.Buffers.Binary;
using System.IO.Compression;
using BCnEncoder.Decoder;
using BCnEncoder.Shared;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Content;
using ProsperoPkgTool.Crypto;
using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// End-to-end coverage for the <c>img_create</c> pipeline: build a debug (FIH) package from a
/// small source folder, then round-trip it through the package reader, the outer-PFS reader, and
/// the inner-image assembler reader to prove the container chain (FIH → PFS → CNT → inner image)
/// is self-consistent.
/// </summary>
public sealed class ProsperoImgCreateTests
{
    private const string ContentId = "IV0001-PPSA01234_00-TESTPACKAGE00001";
    private const string Passcode = "12345678923456789102123901202333";

    [Fact]
    public async Task ImgCreate_RoundTripsThroughAllReaders()
    {
        using var fixture = new SourceFixture();

        // A tiny eboot and an about/right.sprx so the tree exercises nested directories.
        byte[] eboot = [0x7F, (byte)'E', (byte)'L', (byte)'F', 0x02, 0x01, 0x01, 0x00];
        byte[] sprx = Enumerable.Range(0, 256).Select(i => (byte)(i * 7)).ToArray();
        byte[] large = Enumerable.Range(0, 0xE1000).Select(i => (byte)((i * 17 + 3) & 0xff)).ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Root, "eboot.bin"), eboot);
        File.WriteAllBytes(Path.Combine(fixture.Root, "large.bin"), large);
        Directory.CreateDirectory(Path.Combine(fixture.Root, "sce_sys", "about"));
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "about", "right.sprx"), sprx);

        string output = Path.Combine(fixture.Root, "out.pkg");
        int result = await CliApplication.RunAsync(
            ["img_create", fixture.Root, "--out", output, "--passcode", Passcode]);
        Assert.Equal(0, result);
        Assert.True(File.Exists(output));

        // ---- 1. Package reader: kind, content id, and segment geometry. ----
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(output);
        Assert.Equal(ProsperoPackageKind.FinalizedDebug, inspection.Kind);
        Assert.Equal(ContentId, inspection.Cnt.ContentId);
        Assert.NotNull(inspection.Fih);
        Assert.Equal(0x10000UL, inspection.Fih!.PfsOffset);
        Assert.Equal(inspection.Fih.PfsOffset + inspection.Fih.PfsSize, inspection.Fih.CntOffset);

        // CNT+0x460 = SHA3-256(FIH header) — the finalized-image signed digest (reference-verified).
        byte[] packageBytes = File.ReadAllBytes(output);
        byte[] fihHeader = packageBytes.AsSpan(0, ProsperoFihBuilder.HeaderRegionSize).ToArray();
        byte[] cntHeader = packageBytes.AsSpan((int)inspection.Fih.CntOffset, 0x1000).ToArray();
        Assert.Equal(Sha3.Sha3_256(fihHeader), cntHeader.AsSpan(0x460, 32).ToArray());

        // param.json and imagedigs.dat must be present as CNT entries.
        Assert.Contains(inspection.Entries, e => e.Name == "param.json");
        Assert.Contains(inspection.Entries, e => e.Id == (uint)CntEntryId.Imagedigs); // imagedigs.dat
        Assert.Contains(inspection.Entries, e => e.Id == (uint)CntEntryId.PlaygoChunkDat);
        Assert.Contains(inspection.Entries, e => e.Id == (uint)CntEntryId.PlaygoHashTable);
        Assert.Contains(inspection.Entries, e => e.Id == (uint)CntEntryId.PlaygoFicm);

        // ---- 2. Outer PFS: read naps + inner image with the derived keys. ----
        using (var stream = File.OpenRead(output))
        {
            OuterPfsReader pfs = OuterPfsReader.Open(
                stream, (long)inspection.Fih.PfsOffset, (long)inspection.Fih.PfsSize);
            byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
            (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
            using var xts = new AesXts(dataKey, tweakKey);
            byte[] naps = pfs.ReadNaps(xts);
            byte[] innerImage = pfs.ReadInnerImage(xts);
            Assert.NotEmpty(naps);
            Assert.NotEmpty(innerImage);

            // FIH 0x94 is the NAPS FIDX file count (NumFiles - 1); 0x98 = 0x94 + empty files.
            NapsLayoutDocument napsDoc = ProsperoNapsLayout.Parse(naps);
            Assert.Equal((uint)(napsDoc.Counts.NumFiles - 1),
                BinaryPrimitives.ReadUInt32LittleEndian(fihHeader.AsSpan(0x94)));

            // ---- 3. Inner image: walk the block geometry and reconstruct the mount. ----
            IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks =
                ProsperoPs5InnerImageReader.WalkBlocks(naps, innerImage.Length);
            Assert.NotEmpty(blocks);

            byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(innerImage, naps);
            Assert.NotEmpty(mount);
            Assert.True(ContainsSequence(mount, large), "The >256KiB img_create source file must round-trip through NAPS.");
        }

        // ---- 4. img_extract also succeeds on the same output. ----
        string extractDir = Path.Combine(fixture.Root, "extracted");
        int extract = await CliApplication.RunAsync(
            ["img_extract", output, extractDir, "--passcode", Passcode]);
        Assert.Equal(0, extract);
    }

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle)) return true;
        return false;
    }

    [Fact]
    public async Task ImgCreate_NoPasscode_UsesDefault()
    {
        using var fixture = new SourceFixture();
        string output = Path.Combine(fixture.Root, "out.pkg");
        int result = await CliApplication.RunAsync(
            ["img_create", fixture.Root, "--out", output, "--no_passcode"]);
        Assert.Equal(0, result);

        // The default passcode is all-zero; the keystone it injects must validate against it.
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(output);
        Assert.Equal(ProsperoPackageKind.FinalizedDebug, inspection.Kind);
    }

    [Fact]
    public async Task ImgCreate_BasePackage_ListsExtractsAndVerifiesLogicalFiles()
    {
        using var fixture = new SourceFixture();
        Directory.CreateDirectory(Path.Combine(fixture.Root, "nested", "deep"));
        byte[] payload = Enumerable.Range(0, 0xE1000).Select(i => (byte)(i * 13)).ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Root, "nested", "deep", "large.bin"), payload);
        File.WriteAllBytes(Path.Combine(fixture.Root, "empty.dat"), []);
        string package = Path.Combine(fixture.Root, "base.pkg");
        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--type", "base", "--out", package, "--passcode", Passcode]));

        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(package);
        Assert.Equal(ProsperoPackageCategory.BaseGame, inspection.Category().Category);
        Assert.Equal(PackageCategoryEvidence.PubCmdConfirmed, inspection.Category().Evidence);
        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        ProsperoInnerPfsReader.Entry large = Assert.Single(entries, e => e.Path == "/uroot/nested/deep/large.bin");
        Assert.Equal(payload, ProsperoInnerPfsReader.ReadFile(decoded.Mount, large));
        Assert.Contains(entries, e => e.Path == "/uroot/empty.dat" && e.Size == 0);

        string extracted = Path.Combine(fixture.Root, "extracted");
        Assert.Equal(0, await CliApplication.RunAsync(["img_info", package, "--passcode", Passcode]));
        Assert.Equal(0, await CliApplication.RunAsync(["img_file_list", package, "--path", "/nested", "--passcode", Passcode]));
        Assert.Equal(0, await CliApplication.RunAsync(["img_extract", package, extracted, "--passcode", Passcode]));
        Assert.Equal(payload, File.ReadAllBytes(Path.Combine(extracted, "nested", "deep", "large.bin")));
        Assert.Equal(0, new FileInfo(Path.Combine(extracted, "empty.dat")).Length);

        string single = Path.Combine(fixture.Root, "single.bin");
        Assert.Equal(0, await CliApplication.RunAsync(["img_extract", package + ":/nested/deep/large.bin", single, "--passcode", Passcode]));
        Assert.Equal(payload, File.ReadAllBytes(single));

        ProsperoPackageVerificationReport report = ProsperoPackageVerifier.Verify(package, Passcode);
        Assert.False(report.HasFailure);
        Assert.Contains(report.Checks, c => c.Name == "Inner PFS structural integrity" && c.State == VerificationState.Pass);
        Assert.Equal(0, await CliApplication.RunAsync(["img_verify", package, "--passcode", Passcode]));
    }

    [Fact]
    public async Task ImgVerify_DetectsCorruptedCntBody()
    {
        using var fixture = new SourceFixture();
        string package = Path.Combine(fixture.Root, "corrupt.pkg");
        Assert.Equal(0, await CliApplication.RunAsync(
            ["img_create", fixture.Root, "--out", package, "--passcode", Passcode]));
        Assert.False(ProsperoPackageVerifier.Verify(package, Passcode).HasFailure);

        // Flip one byte inside the param.json CNT body (non-encrypted; covered by the DIGESTS table).
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(package);
        ProsperoCntEntry param = Assert.Single(inspection.Entries, e => e.Id == (uint)CntEntryId.ParamJson);
        byte[] bytes = File.ReadAllBytes(package);
        int bodyOffset = checked((int)((long)inspection.Fih!.CntOffset + param.DataOffset));
        bytes[bodyOffset + (int)param.DataSize / 2] ^= 0xFF;
        File.WriteAllBytes(package, bytes);

        ProsperoPackageVerificationReport report = ProsperoPackageVerifier.Verify(package, Passcode);
        Assert.True(report.HasFailure);
        Assert.Contains(report.Checks,
            c => c.Name == "CNT body/entry digests" && c.State == VerificationState.Fail);
    }

    [Fact]
    public async Task ImgCreate_InnerFileOrder_FilesPrecedeSubdirectories()
    {
        using var fixture = new SourceFixture();

        // A root file that sorts AFTER a subdirectory name; the native (reference) order is
        // files-first-then-subdirectories at each level, not alphabetical by full path.
        File.WriteAllBytes(Path.Combine(fixture.Root, "zeta.bin"), [1, 2, 3]);
        Directory.CreateDirectory(Path.Combine(fixture.Root, "aaa"));
        File.WriteAllBytes(Path.Combine(fixture.Root, "aaa", "a.bin"), [4, 5, 6]);

        string package = Path.Combine(fixture.Root, "order.pkg");
        Assert.Equal(0, await CliApplication.RunAsync(
            ["img_create", fixture.Root, "--out", package, "--passcode", Passcode]));

        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        int IndexOf(string path)
        {
            for (int i = 0; i < entries.Count; i++)
                if (entries[i].Path == path)
                    return i;
            return -1;
        }

        int rootFile = IndexOf("/uroot/zeta.bin");
        int subdirFile = IndexOf("/uroot/aaa/a.bin");
        Assert.True(rootFile >= 0, "the root file must be enumerated");
        Assert.True(subdirFile >= 0, "the subdirectory file must be enumerated");
        Assert.True(rootFile < subdirFile,
            "sibling files must precede subdirectory contents (native files-first order)");
    }

    [Fact]
    public async Task ImgCreate_DlcRequest_RefusesUnverifiedCategoryInsteadOfGuessing()
    {
        using var fixture = new SourceFixture();
        string package = Path.Combine(fixture.Root, "dlc.pkg");
        Assert.Equal(2, await CliApplication.RunAsync(["img_create", fixture.Root, "--type", "dlc", "--out", package, "--passcode", Passcode]));
        Assert.False(File.Exists(package));
        ProsperoPackageCategoryInfo unknown = ProsperoPackageCategories.Classify(0xDEADBEEF);
        Assert.Equal(ProsperoPackageCategory.Unknown, unknown.Category);
        Assert.Equal(0xDEADBEEFu, unknown.RawContentType);
    }

    [Fact]
    public async Task ImgInfo_SyntheticRetailEnvelope_RemainsStructuralWhenPayloadIsLocked()
    {
        using var fixture = new SourceFixture();
        string package = Path.Combine(fixture.Root, "debug.pkg");
        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--out", package, "--passcode", Passcode]));
        byte[] bytes = File.ReadAllBytes(package);
        bytes[5] = 0x80; // Envelope-only test; it makes no claim about a retail payload.
        string retail = Path.Combine(fixture.Root, "retail-envelope.pkg");
        File.WriteAllBytes(retail, bytes);
        Assert.Equal(ProsperoPackageKind.FinalizedRetail, ProsperoPackageReader.Read(retail).Kind);
        Assert.Equal(0, await CliApplication.RunAsync(["img_info", retail]));
        Assert.Equal(0, await CliApplication.RunAsync(["img_file_list", retail]));
    }

    [Fact]
    public async Task ImgCreate_KrakenOptIn_MixesCompressedAndStoredBlocks()
    {
        using var fixture = new SourceFixture();
        byte[] large = Enumerable.Range(0, 0xE1000).Select(i => (byte)(i % 3)).ToArray();
        byte[] uniform = Enumerable.Repeat((byte)0x5A, 0x40000).ToArray();
        byte[] random = new byte[0x10000]; new Random(123).NextBytes(random);
        Directory.CreateDirectory(Path.Combine(fixture.Root, "nested"));
        File.WriteAllBytes(Path.Combine(fixture.Root, "large.bin"), large);
        File.WriteAllBytes(Path.Combine(fixture.Root, "uniform.bin"), uniform);
        File.WriteAllBytes(Path.Combine(fixture.Root, "random.bin"), random);
        File.WriteAllBytes(Path.Combine(fixture.Root, "nested", "structured.dat"),
            Enumerable.Range(0, 0x10000).Select(i => (byte)(i % 2)).ToArray());
        string output = Path.Combine(fixture.Root, "kraken.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(
            ["img_create", fixture.Root, "--compression", "kraken", "--out", output, "--passcode", Passcode]));
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(output);
        using var stream = File.OpenRead(output);
        OuterPfsReader pfs = OuterPfsReader.Open(stream, (long)inspection.Fih!.PfsOffset, (long)inspection.Fih.PfsSize);
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);
        byte[] naps = pfs.ReadNaps(xts);
        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(pfs.ReadInnerImage(xts), naps);
        IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks = ProsperoPs5InnerImageReader.WalkBlocks(naps, mount.Length);
        Assert.Contains(blocks, b => b.IsKraken);
        Assert.Contains(blocks, b => !b.IsKraken && !b.IsAlias && !b.IsZeroHole);
        Assert.True(ContainsSequence(mount, large));
        Assert.True(ContainsSequence(mount, uniform));
        Assert.True(ContainsSequence(mount, random));
    }

    [Fact]
    public async Task ImgCreate_WithSuppliedPlgx_EmitsCompleteScopedPlayGoCntFamily()
    {
        using var fixture = new SourceFixture();
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "playgo-chunk.dat"), BuildMinimalPlgx());
        string output = Path.Combine(fixture.Root, "out.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--out", output, "--passcode", Passcode]));
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(output);
        byte[] package = File.ReadAllBytes(output);
        byte[] Payload(CntEntryId id)
        {
            ProsperoCntEntry entry = Assert.Single(inspection.Entries, e => e.Id == (uint)id);
            return package.AsSpan(checked((int)inspection.Fih!.CntOffset + (int)entry.DataOffset), (int)entry.DataSize).ToArray();
        }

        byte[] plgx = Payload(CntEntryId.PlaygoChunkDat);
        byte[] hash = Payload(CntEntryId.PlaygoHashTable);
        byte[] ficm = Payload(CntEntryId.PlaygoFicm);
        Assert.Equal(0x38u, BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(8)));
        int count = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(0x24)));
        Assert.Equal(0x10 + 2 * count, ficm.Length);
        Assert.All(Enumerable.Range(0, count), i => Assert.Equal(0, ficm[0x11 + 2 * i]));

        byte[] expectedRollup = Sha3.Sha3_256(Sha3.Sha3_256(plgx)
            .Concat(Sha3.Sha3_256(hash)).Concat(Sha3.Sha3_256(ficm)).ToArray());
        Assert.Equal(expectedRollup, Payload(CntEntryId.GeneralDigests).AsSpan(0xe0, 32).ToArray());

        ProsperoPackageSegment si = Assert.Single(inspection.Segments, s => s.Name == "SI");
        using var zip = new ZipArchive(new MemoryStream(package, (int)si.Offset, (int)si.Size, writable: false), ZipArchiveMode.Read);
        ZipArchiveEntry siPlgx = zip.GetEntry("common/etc/playgo-chunk.dat")!;
        Assert.NotNull(siPlgx);
        using var stream = siPlgx.Open();
        using var copied = new MemoryStream();
        stream.CopyTo(copied);
        Assert.Equal(plgx, copied.ToArray());
        Assert.Null(zip.GetEntry("common/etc/playgo-hash-table.dat"));
        Assert.Null(zip.GetEntry("common/etc/playgo-ficm.dat"));
    }

    [Fact]
    public async Task ImgCreate_WithGp5Assignments_GeneratesSplitPlayGoFamily()
    {
        using var fixture = new SourceFixture();
        File.WriteAllBytes(Path.Combine(fixture.Root, "a.bin"), [1]);
        File.WriteAllBytes(Path.Combine(fixture.Root, "b.bin"), [2]);
        File.WriteAllBytes(Path.Combine(fixture.Root, "c.bin"), [3]);
        string gp5Path = Path.Combine(fixture.Root, "playgo.gp5");
        Gp5Xml.Write(BuildAssignedGp5(), gp5Path);
        string output = Path.Combine(fixture.Root, "out.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--gp5", gp5Path, "--out", output, "--passcode", Passcode]));
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(output);
        byte[] package = File.ReadAllBytes(output);
        byte[] Payload(CntEntryId id)
        {
            ProsperoCntEntry entry = Assert.Single(inspection.Entries, e => e.Id == (uint)id);
            return package.AsSpan(checked((int)inspection.Fih!.CntOffset + (int)entry.DataOffset), (int)entry.DataSize).ToArray();
        }

        byte[] plgx = Payload(CntEntryId.PlaygoChunkDat);
        PlayGoProject project = PlayGoChunkReader.Read(plgx);
        Assert.Equal(["Base", "OnDemand", "Unused"], project.Chunks.Select(c => c.Label));
        Assert.Equal([0], project.Scenarios[0].Chunks);
        Assert.Equal([0, 1], project.Scenarios[1].Chunks);
        int c8 = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(plgx.AsSpan(0xc8)));
        int d8 = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(plgx.AsSpan(0xd8)));
        Assert.True(BinaryPrimitives.ReadUInt32LittleEndian(plgx.AsSpan(0x100 + 4)) >= 2); // c0 data + separate tail
        Assert.True(BinaryPrimitives.ReadUInt32LittleEndian(plgx.AsSpan(0x120 + 4)) >= 1); // c1 owns mapped leaves
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(plgx.AsSpan(0x140 + 4))); // unused c2
        Assert.True(BinaryPrimitives.ReadUInt32LittleEndian(plgx.AsSpan(0xc8 + 4)) >= 4);
        Assert.True(BinaryPrimitives.ReadUInt64LittleEndian(plgx.AsSpan(d8 + 8)) > 0); // first D8 length
        Assert.Equal(0x100 + 3 * 0x20, c8);

        byte[] ficm = Payload(CntEntryId.PlaygoFicm);
        int ficmCount = checked((int)BinaryPrimitives.ReadUInt32LittleEndian(ficm.AsSpan(0x0c)) / 2);
        Assert.Equal(0x10 + ficmCount * 2, ficm.Length);
        Assert.Contains((byte)1, Enumerable.Range(0, ficmCount).Select(i => ficm[0x10 + 2 * i]));
        Assert.All(Enumerable.Range(0, ficmCount), i => Assert.Equal(0, ficm[0x11 + 2 * i]));
        byte[] hash = Payload(CntEntryId.PlaygoHashTable);
        Assert.Equal((uint)ficmCount, BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(0x24)));

        byte[] expectedRollup = Sha3.Sha3_256(Sha3.Sha3_256(plgx)
            .Concat(Sha3.Sha3_256(hash)).Concat(Sha3.Sha3_256(ficm)).ToArray());
        Assert.Equal(expectedRollup, Payload(CntEntryId.GeneralDigests).AsSpan(0xe0, 32).ToArray());
        ProsperoPackageSegment si = Assert.Single(inspection.Segments, s => s.Name == "SI");
        using var zip = new ZipArchive(new MemoryStream(package, (int)si.Offset, (int)si.Size, writable: false), ZipArchiveMode.Read);
        using Stream siStream = zip.GetEntry("common/etc/playgo-chunk.dat")!.Open();
        using var copied = new MemoryStream(); siStream.CopyTo(copied);
        Assert.Equal(plgx, copied.ToArray());
        Assert.NotNull(zip.GetEntry("config/" + ContentId + "/playgo-chunk.crc"));
    }

    [Fact]
    public async Task ImgCreate_FromGp5Manifest_UsesManifestFileListOnly()
    {
        using var fixture = new SourceFixture();
        byte[] listed = Enumerable.Range(0, 0x3000).Select(i => (byte)(i * 31)).ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Root, "manifest-only.bin"), listed);
        // A file present on disk but absent from the manifest must NOT enter the package.
        File.WriteAllBytes(Path.Combine(fixture.Root, "unlisted.bin"), [0xDE, 0xAD, 0xBE, 0xEF]);

        string gp5Path = Path.Combine(fixture.Root, "project.gp5");
        Gp5Xml.Write(BuildManifestGp5(), gp5Path);
        string output = Path.Combine(fixture.Root, "manifest.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(
            ["img_create", gp5Path, "--out", output, "--passcode", Passcode]));

        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(output);
        Assert.Equal(ProsperoPackageKind.FinalizedDebug, inspection.Kind);
        Assert.Equal(ContentId, inspection.Cnt.ContentId);

        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(output, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        ProsperoInnerPfsReader.Entry manifestOnly = Assert.Single(entries, e => e.Path == "/uroot/manifest-only.bin");
        Assert.Equal(listed, ProsperoInnerPfsReader.ReadFile(decoded.Mount, manifestOnly));
        Assert.Contains(entries, e => e.Path == "/uroot/eboot.bin");
        Assert.DoesNotContain(entries, e => e.Path == "/uroot/unlisted.bin");
        // param.json is an outer CNT entry, never an inner file, even when the manifest lists it.
        Assert.DoesNotContain(entries, e => e.Path == "/uroot/sce_sys/param.json");
        Assert.Contains(inspection.Entries, e => e.Name == "param.json");
    }

    [Fact]
    public async Task ImgCreate_ManifestMissingParamJson_Throws()
    {
        using var fixture = new SourceFixture();
        File.WriteAllBytes(Path.Combine(fixture.Root, "manifest-only.bin"), [1, 2, 3]);
        string gp5Path = Path.Combine(fixture.Root, "no-param.gp5");
        Gp5Project project = BuildManifestGp5();
        project.Files.RemoveAll(file => file.DestinationPath.EndsWith("param.json", StringComparison.OrdinalIgnoreCase));
        Gp5Xml.Write(project, gp5Path);

        int result = await CliApplication.RunAsync(
            ["img_create", gp5Path, "--out", Path.Combine(fixture.Root, "no-param.pkg"), "--passcode", Passcode]);

        Assert.Equal(2, result);
        Assert.False(File.Exists(Path.Combine(fixture.Root, "no-param.pkg")));
    }

    [Fact]
    public async Task ImgCreate_FakeSignsRawElfModules()
    {
        using var fixture = new SourceFixture();
        byte[] rawElf = BuildMinimalRawElf();
        File.WriteAllBytes(Path.Combine(fixture.Root, "eboot.bin"), rawElf);
        string package = Path.Combine(fixture.Root, "fself.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--out", package, "--passcode", Passcode]));

        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        ProsperoInnerPfsReader.Entry eboot = Assert.Single(entries, e => e.Path == "/uroot/eboot.bin");
        byte[] stored = ProsperoInnerPfsReader.ReadFile(decoded.Mount, eboot);

        Assert.True(ProsperoSelfBuilder.IsSelf(stored));
        Assert.Equal(ProsperoSelfBuilder.MakeFself(rawElf), stored);
    }

    [Fact]
    public async Task ImgCreate_NoFself_LeavesRawElfUntouched()
    {
        using var fixture = new SourceFixture();
        byte[] rawElf = BuildMinimalRawElf();
        File.WriteAllBytes(Path.Combine(fixture.Root, "eboot.bin"), rawElf);
        string package = Path.Combine(fixture.Root, "raw.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--out", package, "--no_fself", "--passcode", Passcode]));

        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        ProsperoInnerPfsReader.Entry eboot = Assert.Single(entries, e => e.Path == "/uroot/eboot.bin");
        Assert.Equal(rawElf, ProsperoInnerPfsReader.ReadFile(decoded.Mount, eboot));
    }

    [Fact]
    public async Task ImgCreate_EmitsSceSysMediaEntriesAndExcludesThemFromInner()
    {
        const string tinyPng = "iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAGklEQVR4XmNk+M/wX+AD+w8YZnE4IPOANAEAMSwf9B7uakAAAAAASUVORK5CYII=";
        using var fixture = new SourceFixture();
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "icon0.png"), Convert.FromBase64String(tinyPng));
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "nptitle.dat"), new byte[160]);
        string package = Path.Combine(fixture.Root, "media.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--out", package, "--passcode", Passcode]));

        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(package);
        byte[] packageBytes = File.ReadAllBytes(package);
        byte[] Payload(CntEntryId id)
        {
            ProsperoCntEntry entry = Assert.Single(inspection.Entries, e => e.Id == (uint)id);
            return packageBytes.AsSpan(checked((int)inspection.Fih!.CntOffset + (int)entry.DataOffset), (int)entry.DataSize).ToArray();
        }

        // PNG media plus the generated BC7 DDS companion and the protected system file.
        Assert.Equal(Convert.FromBase64String(tinyPng), Payload(CntEntryId.Icon0Png));
        ProsperoCntEntry nptitle = Assert.Single(inspection.Entries, e => e.Id == (uint)CntEntryId.NptitleDat);
        Assert.Equal(0x80000000u, nptitle.Flags1);
        Assert.Equal(3u << 12, nptitle.Flags2);

        byte[] dds = Payload(CntEntryId.Icon0Dds);
        Assert.Equal("DDS ", System.Text.Encoding.ASCII.GetString(dds, 0, 4));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(16)));
        ColorRgba32[] decoded = new BcDecoder().DecodeRaw(dds[ProsperoDdsEncoder.HeaderSize..], 4, 4, CompressionFormat.Bc7);
        Assert.Equal(16, decoded.Length);

        // The system-digest slot rolls up the media entries (ids 0x1200 and 0x1280 present).
        byte[] expectedSystem = Sha3.Sha3_256(Sha3.Sha3_256(Payload(CntEntryId.Icon0Png))
            .Concat(Sha3.Sha3_256(dds)).ToArray());
        Assert.Equal(expectedSystem, Payload(CntEntryId.GeneralDigests).AsSpan(0x80, 32).ToArray());

        // Media/system files are outer CNT entries, never inner-PFS files.
        ProsperoDecodedPackage decodedPkg = ProsperoPackageContent.Read(package, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> inner = ProsperoInnerPfsReader.Enumerate(decodedPkg.Mount);
        Assert.DoesNotContain(inner, e => e.Path == "/uroot/sce_sys/icon0.png");
        Assert.DoesNotContain(inner, e => e.Path == "/uroot/sce_sys/nptitle.dat");
    }

    [Fact]
    public async Task ImgCreate_InjectsRightSprxWhenAbsent()
    {
        using var fixture = new SourceFixture();
        Assert.False(File.Exists(Path.Combine(fixture.Root, "sce_sys", "about", "right.sprx")));
        string package = Path.Combine(fixture.Root, "inject.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--out", package, "--passcode", Passcode]));

        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        ProsperoInnerPfsReader.Entry right = Assert.Single(entries, e => e.Path == "/uroot/sce_sys/about/right.sprx");
        Assert.Equal(ProsperoRightSprx.Get(), ProsperoInnerPfsReader.ReadFile(decoded.Mount, right));
    }

    [Fact]
    public async Task ImgCreate_NoRightSprxOption_SkipsInjection()
    {
        using var fixture = new SourceFixture();
        string package = Path.Combine(fixture.Root, "no-right.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(
            ["img_create", fixture.Root, "--out", package, "--no_right_sprx", "--passcode", Passcode]));

        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        Assert.DoesNotContain(entries, e => e.Path == "/uroot/sce_sys/about/right.sprx");
    }

    [Fact]
    public async Task ImgCreate_KeepsSourceSuppliedRightSprx()
    {
        using var fixture = new SourceFixture();
        byte[] supplied = Enumerable.Range(0, 256).Select(i => (byte)(i * 3)).ToArray();
        Directory.CreateDirectory(Path.Combine(fixture.Root, "sce_sys", "about"));
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "about", "right.sprx"), supplied);
        string package = Path.Combine(fixture.Root, "keep-right.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--out", package, "--passcode", Passcode]));

        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        ProsperoInnerPfsReader.Entry right = Assert.Single(entries, e => e.Path == "/uroot/sce_sys/about/right.sprx");
        Assert.Equal(supplied, ProsperoInnerPfsReader.ReadFile(decoded.Mount, right));
    }

    [Fact]
    public async Task ImgCreate_RepairsTrophyAndUdsUcpDigests()
    {
        using var fixture = new SourceFixture();
        Directory.CreateDirectory(Path.Combine(fixture.Root, "sce_sys", "trophy2"));
        Directory.CreateDirectory(Path.Combine(fixture.Root, "sce_sys", "uds"));
        byte[] trophy = CorruptDigest(ProsperoUcpArchive.Build([new("TROPCONF.UTF8", [1, 2, 3])]));
        byte[] uds = CorruptDigest(ProsperoUcpArchive.Build([new("UDSDATA.BIN", [4, 5, 6, 7])]));
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "trophy2", "trophy00.ucp"), trophy);
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "uds", "uds00.ucp"), uds);
        string package = Path.Combine(fixture.Root, "ucp.pkg");

        Assert.Equal(0, await CliApplication.RunAsync(["img_create", fixture.Root, "--out", package, "--passcode", Passcode]));

        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(package);
        byte[] packageBytes = File.ReadAllBytes(package);
        byte[] Payload(CntEntryId id)
        {
            ProsperoCntEntry entry = Assert.Single(inspection.Entries, e => e.Id == (uint)id);
            return packageBytes.AsSpan(checked((int)inspection.Fih!.CntOffset + (int)entry.DataOffset), (int)entry.DataSize).ToArray();
        }

        Assert.False(ProsperoUcpArchive.VerifyDigest(trophy));
        byte[] storedTrophy = Payload(CntEntryId.Trophy2Ucp);
        Assert.True(ProsperoUcpArchive.VerifyDigest(storedTrophy));
        Assert.Equal([1, 2, 3], ProsperoUcpArchive.Read(storedTrophy)[0].Data);
        byte[] storedUds = Payload(CntEntryId.UdsUcp);
        Assert.True(ProsperoUcpArchive.VerifyDigest(storedUds));

        // The repaired archives are outer CNT entries, never inner-PFS files.
        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> inner = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        Assert.DoesNotContain(inner, e => e.Path == "/uroot/sce_sys/trophy2/trophy00.ucp");
        Assert.DoesNotContain(inner, e => e.Path == "/uroot/sce_sys/uds/uds00.ucp");
    }

    private static byte[] CorruptDigest(byte[] archive)
    {
        byte[] corrupted = (byte[])archive.Clone();
        corrupted[0x1C] ^= 0xFF;
        return corrupted;
    }

    private static byte[] BuildMinimalRawElf()
    {
        byte[] elf = new byte[0x180];
        byte[] ident = [0x7F, (byte)'E', (byte)'L', (byte)'F', 0x02, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        ident.CopyTo(elf, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x10), 2);       // e_type = ET_EXEC
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x12), 0x3E);    // e_machine = x86-64
        BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(0x14), 1);       // e_version
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x18), 0x1000);  // e_entry
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x20), 0x40);    // e_phoff
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x34), 0x40);    // e_ehsize
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x36), 0x38);    // e_phentsize
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x38), 1);       // e_phnum
        BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(0x40), 1);       // PT_LOAD
        BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(0x44), 5);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x48), 0x100);   // p_offset
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x50), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x58), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x60), 0x40);    // p_filesz
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x68), 0x40);    // p_memsz
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x70), 0x1000);
        for (int i = 0; i < 0x40; i++)
            elf[0x100 + i] = (byte)(0xD0 + i);
        return elf;
    }

    private static Gp5Project BuildManifestGp5()
    {
        var project = new Gp5Project { Layout = Gp5ContentLayout.FlatFiles };
        project.Volume.Package.ContentId = ContentId;
        project.Volume.Package.Passcode = Passcode;
        project.Volume.ChunkInfo = new Gp5ChunkInfo { ChunkCount = 1, ScenarioCount = 1, DefaultScenarioId = 0 };
        project.Volume.ChunkInfo.Chunks.Add(new Gp5Chunk { Id = 0, Label = "Chunk #0" });
        project.Volume.ChunkInfo.Scenarios.Add(new Gp5Scenario { Id = 0, Label = "Scenario #0", InitialChunkCount = 1, Sequence = "0" });
        foreach (string relative in new[] { "eboot.bin", "manifest-only.bin", "sce_sys/param.json" })
            project.Files.Add(new Gp5FileEntry
            {
                DestinationPath = Gp5Path.ToProjectRelative(relative),
                SourcePath = Gp5Path.ToProjectRelative(relative),
            });
        return project;
    }

    private static Gp5Project BuildAssignedGp5()
    {
        var project = new Gp5Project { Layout = Gp5ContentLayout.FlatFiles };
        project.Volume.Package.ContentId = ContentId;
        project.Volume.ChunkInfo = new Gp5ChunkInfo { ChunkCount = 3, ScenarioCount = 2, DefaultScenarioId = 0 };
        project.Volume.ChunkInfo.Chunks.Add(new Gp5Chunk { Id = 0, Label = "Base", Languages = "0xFFFFFFFFFFFFFFFF" });
        project.Volume.ChunkInfo.Chunks.Add(new Gp5Chunk { Id = 1, Label = "OnDemand", Languages = "1" });
        project.Volume.ChunkInfo.Chunks.Add(new Gp5Chunk { Id = 2, Label = "Unused", Languages = "0" });
        project.Volume.ChunkInfo.Scenarios.Add(new Gp5Scenario { Id = 0, Label = "Initial", InitialChunkCount = 1, Sequence = "0" });
        project.Volume.ChunkInfo.Scenarios.Add(new Gp5Scenario { Id = 1, Label = "Full", InitialChunkCount = 1, Sequence = "0 1" });
        foreach ((string path, int chunk) in new[] { ("a.bin", 0), ("b.bin", 1), ("c.bin", 0) })
            project.Files.Add(new Gp5FileEntry { DestinationPath = "\\" + path.Replace('/', '\\'), SourcePath = "\\" + path.Replace('/', '\\'), Chunk = chunk });
        return project;
    }

    private static byte[] BuildMinimalPlgx()
    {
        byte[] data = new byte[0x160];
        "plgx"u8.CopyTo(data);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(4), 0x1000);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(8), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(10), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(14), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x10), (uint)data.Length);
        System.Text.Encoding.ASCII.GetBytes(ContentId).CopyTo(data, 0x40);
        void Section(int at, uint offset, uint size) { BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at), offset); BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(at + 4), size); }
        Section(0xc0, 0x100, 0x20); Section(0xd0, 0x120, 8); Section(0xe0, 0x128, 0x20);
        Section(0xe8, 0x148, 2); Section(0xf0, 0x150, 8);
        "Chunk0\0"u8.CopyTo(data.AsSpan(0x120));
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x128 + 0x14), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x128 + 0x16), 1);
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(0x148), 0);
        "Default\0"u8.CopyTo(data.AsSpan(0x150));
        return data;
    }

    private sealed class SourceFixture : IDisposable
    {
        public SourceFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "ProsperoPkgTool-ImgCreate-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path.Combine(Root, "sce_sys"));
            File.WriteAllBytes(Path.Combine(Root, "eboot.bin"), [0x7F, (byte)'E', (byte)'L', (byte)'F']);
            File.WriteAllBytes(Path.Combine(Root, "sce_sys", "icon0.png"), [0x89, (byte)'P', (byte)'N', (byte)'G']);
            File.WriteAllText(Path.Combine(Root, "sce_sys", "param.json"), $$"""
                {
                  "titleId": "PPSA01234",
                  "contentId": "{{ContentId}}",
                  "contentVersion": "01.000.000",
                  "applicationCategoryType": 0,
                  "pubtools": { "creationDate": "2026-08-25 12:00:00" }
                }
                """);
        }

        public string Root { get; }

        public void Dispose()
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }
}
