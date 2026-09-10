using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Round-trip validation of the clean-room NAPS layout parser against a real Sony package
/// (PPSA03530-bd-nw.pkg, a ~10.8 GB retail GTA Vice City package).
///
/// The layout record (<c>naps_pkg_layout.dat</c>, inode 4 of the outer PFS) is a 28-block
/// file (1,774,448 bytes) read through the outer PFS S32 inode table. Its blocks are signed
/// metadata (XTS sector = 0x800000000000 | block index), unlike the <c>pfs_image.dat</c>
/// data blocks (sector = block index). Header ground truth (decoded byte-exact):
///   NumFiles=22, compType=2 (Kraken), Keys=1, Shuffle=0, UBlocks=41750,
///   OuterBlocks=165120, CblockInfo=44570.
/// </summary>
public sealed class ProsperoNapsLayoutTests
{
    [Fact]
    public void BuildLayout_WritesEveryDigestAndShuffleSlot()
    {
        var counts = new NapsLayoutCounts(1, 0, 1, 3, 1, 3, 2);
        var document = new NapsLayoutDocument
        {
            Counts = counts, Map = ProsperoNapsLayout.SectionMap(counts),
            OuterBlockDigests = new[] { new byte[] { 1,1,1,1,1,1,1,1 }, new byte[] { 2,2,2,2,2,2,2,2 }, new byte[] { 3,3,3,3,3,3,3,3 } },
            ShufflePatterns = new[] { new byte[] { 4,4,4,4,4,4,4,4 }, new byte[] { 5,5,5,5,5,5,5,5 }, new byte[] { 6,6,6,6,6,6,6,6 } },
            FileOffsets = new[] { new NapsFileOffsetEntry(0x40, 0) },
            CblockInfoOffsetByUblock = new[] { new NapsU2cEntry(0, new byte[7]) },
            CblockInfos = new[] { new NapsCblockInfoEntry { Raw = new byte[9] }, new NapsCblockInfoEntry { Raw = new byte[9] } },
        };
        NapsLayoutDocument parsed = ProsperoNapsLayout.Parse(ProsperoNapsLayout.BuildLayout(document));
        Assert.Equal(document.OuterBlockDigests, parsed.OuterBlockDigests);
        Assert.Equal(document.ShufflePatterns, parsed.ShufflePatterns);
    }
    // Ground-truth retail package (user-selected test fixture).
    private const string PackagePath = @"C:\Users\User\Desktop\New folder\ps5 pkg\PPSA03530-bd-nw.pkg";
    private const string ContentId = "UP1004-PPSA03530_00-GTAVICECITY00001";
    private const string Passcode = "00000000000000000000000000000000";

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    [Fact(Skip = "Opt-in retail fixture test: PPSA03530-bd-nw.pkg is not a repository fixture.")]
    public void RetailPackage_NapsLayout_RoundTripsByteExact()
    {
        byte[] naps = ReadNapsRecordFromRetailPackage();

        NapsLayoutDocument doc = ProsperoNapsLayout.Parse(naps);

        // Header ground truth for PPSA03530-bd-nw.pkg (decoded from the real record):
        Assert.Equal(22, doc.Counts.NumFiles);
        Assert.Equal(2, doc.Counts.CompressionType);
        Assert.Equal(1, doc.Counts.NumKeys);
        Assert.Equal(0, doc.Counts.NumShufflePatterns);
        Assert.Equal(41750, doc.Counts.NumUBlocks);
        Assert.Equal(165120, doc.Counts.NumOuterBlocks);
        Assert.Equal(44570, doc.Counts.NumCblockInfo);

        // The fidx section carries NumFiles semantic entries (21 files + 1 mount-size sentinel),
        // immediately followed by u2c (no trailer). CblockInfo begins at the align8 native offset.
        Assert.Equal(22, doc.FileOffsets.Count);
        Assert.Equal(22, doc.Map.UncompressedOffsetStartByFileIdx.Count);

        // Authoritative section offsets (FINDINGS.md §5): u2c at 1321108, cbi at 1373304,
        // leaving a 6-byte alignment pad between u2c and cbi, and 14 bytes trailing pad.
        Assert.Equal(1_321_108, doc.Map.CblockInfoOffsetByUblockIdxCompressed.Offset);
        Assert.Equal(1_373_304, doc.Map.CblockInfo.Offset);
        Assert.Equal(6, doc.Map.CblockInfoPad);

        // CblockInfo ends at 1774434; the blob is padded to 1774448 (16-byte alignment).
        Assert.Equal(1_774_434, doc.Map.TotalSize);
        Assert.Equal(1_774_448, naps.Length);

        // Round-trip the section content byte-exact (default 16-byte trailing alignment matches
        // the real blob's 14-byte trailing pad).
        byte[] rebuilt = ProsperoNapsLayout.BuildLayout(doc);
        Assert.Equal(naps, rebuilt);
    }

    [Fact(Skip = "Opt-in retail fixture test: PPSA03530-bd-nw.pkg is not a repository fixture.")]
    public void RetailPackage_CblockInfo_AllEntriesRoundTripByteExact()
    {
        byte[] naps = ReadNapsRecordFromRetailPackage();
        NapsLayoutDocument doc = ProsperoNapsLayout.Parse(naps);

        int runBase = 0, nonRunBase = 0;
        for (int i = 0; i < doc.CblockInfos.Count; i++)
        {
            NapsCblockInfoEntry e = doc.CblockInfos[i];
            byte[] enc = ProsperoNapsLayout.EncodeCblockInfoEntry(e);
            Assert.True(enc.AsSpan().SequenceEqual(e.Raw),
                $"CblockInfo[{i}] did not round-trip byte-exact (raw={Convert.ToHexString(e.Raw)} enc={Convert.ToHexString(enc)})");

            if (e.IsRunBase) runBase++;
            else nonRunBase++;
        }

        // A real data-first image uses both run-base anchors and per-block entries.
        Assert.True(runBase > 0, "Expected at least one run-base CblockInfo entry.");
        Assert.True(nonRunBase > 0, "Expected at least one per-block CblockInfo entry.");
    }

    [Fact]
    public void Parse_PreservesPackageSpecificTrailingFooterOnRebuild()
    {
        // The native writer emits align8(CblockInfoEnd) + footer, where the all-zero footer size
        // is package-dependent (0/8/12 observed). Parse must capture it so Parse/Build round-trips
        // byte-exact; otherwise a footer of 8 would be truncated to the 8-aligned end.
        var counts = new NapsLayoutCounts(1, 0, 1, 0, 24, 1, 2);
        var document = new NapsLayoutDocument
        {
            Counts = counts,
            Map = ProsperoNapsLayout.SectionMap(counts),
            OuterBlockDigests = new[] { new byte[8] },
            ShufflePatterns = Array.Empty<byte[]>(),
            FileOffsets = new[] { new NapsFileOffsetEntry(0x40, 0) },
            CblockInfoOffsetByUblock = new[]
            {
                new NapsU2cEntry(0, new byte[7]), new NapsU2cEntry(0, new byte[7]),
                new NapsU2cEntry(0, new byte[7]), new NapsU2cEntry(1, new byte[7]),
            },
            CblockInfos = new[] { new NapsCblockInfoEntry { Raw = new byte[9] }, new NapsCblockInfoEntry { Raw = new byte[9] } },
            TrailingZeroBytes = 8,
        };

        byte[] blob = ProsperoNapsLayout.BuildLayout(document);
        NapsLayoutDocument parsed = ProsperoNapsLayout.Parse(blob);

        Assert.Equal(8, parsed.TrailingZeroBytes);
        Assert.Equal(blob.Length, ((parsed.Map.TotalSize + 7) & ~7L) + parsed.TrailingZeroBytes);
        Assert.Equal(blob, ProsperoNapsLayout.BuildLayout(parsed));
    }

    [Fact]
    public void Header_EncodeDecode_RoundTrips()
    {
        var counts = new NapsLayoutCounts(
            NumFiles: 22, CompressionType: 2, NumKeys: 1, NumShufflePatterns: 0,
            NumUBlocks: 41750, NumOuterBlocks: 165120, NumCblockInfo: 44570);

        byte[] header = ProsperoNapsLayout.EncodeHeader(counts);
        NapsLayoutCounts decoded = ProsperoNapsLayout.DecodeHeader(header);

        Assert.Equal(counts, decoded);
    }

    /// <summary>
    /// Open the retail package and read <c>naps_pkg_layout.dat</c> through the outer PFS
    /// S32 inode-table walker (multi-block, signed-sector classification).
    /// </summary>
    private static byte[] ReadNapsRecordFromRetailPackage()
    {
        using var stream = File.OpenRead(PackagePath);
        stream.Position = 0x10;
        Span<byte> fih = stackalloc byte[16];
        stream.ReadExactly(fih);
        long pfsOffset = BitConverter.ToInt64(fih[..8]);
        long pfsSize = BitConverter.ToInt64(fih.Slice(8, 8));

        var pfs = OuterPfsReader.Open(stream, pfsOffset, pfsSize);
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);

        return pfs.ReadNaps(xts);
    }
}
