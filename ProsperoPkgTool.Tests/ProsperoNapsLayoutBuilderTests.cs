using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Validates the clean-room NAPS builder (<see cref="ProsperoNapsLayoutBuilder"/>) against the
/// real Sony-built debug package (content id IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX, passcode
/// 12345678923456789102123901202333). The debug package's <c>naps_pkg_layout.dat</c> is a
/// 488-byte blob with 41 CblockInfo entries (22 STD + 19 RUN), 5 fidx entries and 3 u2c entries.
///
/// Reproducing it byte-exact exercises every byte-unit field the builder emits: the RUN cursor
/// re-base, the STD <c>coff/uoff/clen</c> math, the dedup stream-length (16 bytes per aliased
/// block), the terminator's <c>clen=0</c>/bit-19 marker, and the u2c index mapping.
/// </summary>
public sealed class ProsperoNapsLayoutBuilderTests
{
    private const string ContentId = "IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX";
    private const string Passcode = "12345678923456789102123901202333";

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    [Fact]
    public void DebugPlan_ReproducesSonyNapsByteExact()
    {
        byte[] expected = ReadDebugNaps();

        // Sony's debug naps_pkg_layout.dat is 488 bytes (8-byte trailing alignment); the cbi
        // content itself is 481 bytes. The builder reproduces it byte-for-byte at alignment 8.
        byte[] actual = ProsperoNapsLayoutBuilder.Build(DebugPlan(), alignment: 8);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void DebugPlan_HasExpectedCountsAndSections()
    {
        NapsLayoutDocument doc = ProsperoNapsLayoutBuilder.BuildDocument(DebugPlan());

        Assert.Equal(5, doc.Counts.NumFiles);
        Assert.Equal(2, doc.Counts.CompressionType);
        Assert.Equal(1, doc.Counts.NumKeys);
        Assert.Equal(0, doc.Counts.NumShufflePatterns);
        Assert.Equal(19, doc.Counts.NumUBlocks);
        Assert.Equal(4, doc.Counts.NumOuterBlocks);
        Assert.Equal(41, doc.Counts.NumCblockInfo);

        // 22 STD + 19 RUN = 41 cbi entries.
        int std = doc.CblockInfos.Count(e => !e.IsRunBase);
        int run = doc.CblockInfos.Count(e => e.IsRunBase);
        Assert.Equal(22, std);
        Assert.Equal(19, run);

        // Section layout: header 16, no outer digests (0), no shuffles (0), fidx 30 (5×6),
        // u2c at 78 (0x4E, immediately after fidx), 4-byte pad, cbi at 112 (0x70, align8).
        Assert.Equal(5, doc.FileOffsets.Count);
        Assert.Equal(3, doc.CblockInfoOffsetByUblock.Count);
        Assert.Equal(0x4E, doc.Map.CblockInfoOffsetByUblockIdxCompressed.Offset);
        Assert.Equal(0x70, doc.Map.CblockInfo.Offset);
        Assert.Equal(4, doc.Map.CblockInfoPad);
        Assert.Equal(481, doc.Map.TotalSize);
    }

    [Fact]
    public void Terminator_SetsLastBlockBit()
    {
        NapsLayoutDocument doc = ProsperoNapsLayoutBuilder.BuildDocument(DebugPlan());

        NapsCblockInfoEntry terminator = doc.CblockInfos[^1];
        Assert.False(terminator.IsRunBase);
        Assert.Equal(0u, terminator.ClenEvenMinus1);
        Assert.Equal(0x20000u, terminator.UoffsetStart); // mount size (0x4A0000) & 0x3FFFF

        // Bit 19 (lo byte 2 bit 3) is the last-block marker and must round-trip.
        byte[] enc = ProsperoNapsLayout.EncodeCblockInfoEntry(terminator);
        Assert.Equal(0x08, enc[2] & 0x08);
    }

    [Fact]
    public void U2c_ReproducesDebugStartIndices()
    {
        NapsLayoutDocument doc = ProsperoNapsLayoutBuilder.BuildDocument(DebugPlan());

        // Ground truth (FINDINGS.md §9.7): the three u2c entries map ublocks to the first STD
        // cbi index at or after each 256 KiB logical boundary.
        IReadOnlyList<uint> starts0 = doc.CblockInfoOffsetByUblock[0].StartCblockInfoIndex;
        IReadOnlyList<uint> starts1 = doc.CblockInfoOffsetByUblock[1].StartCblockInfoIndex;
        IReadOnlyList<uint> starts2 = doc.CblockInfoOffsetByUblock[2].StartCblockInfoIndex;

        Assert.Equal(new uint[] { 1, 7, 9, 11, 13, 15, 17, 19 }, starts0);
        Assert.Equal(new uint[] { 21, 23, 25, 27, 29, 31, 33, 34 }, starts1);
        Assert.Equal(new uint[] { 36, 37, 38, 40, 40, 40, 40, 40 }, starts2);
    }

    [Fact]
    public void MinimalStoredPlan_RoundTrips()
    {
        // A single 256 KiB raw block plus a terminator: no dedup, no Kraken, no RUN re-basing
        // surprises. Exercises the simplest stored path end-to-end.
        var blocks = new List<NapsCblockPlanEntry>
        {
            new()
            {
                StartRun = true,
                OnDiskOffset = 0,
                LogicalOffset = 0,
                EvenChunkCompressedLength = 0x20000,
                StreamLength = 0x40000,
                Even = 1,
                Odd = 1,
                KdePredictor = 0,
                StoredRaw = true,
                ShuffleIndex = 0,
            },
            new()
            {
                StartRun = true,
                OnDiskOffset = 0x40000,
                LogicalOffset = 0x40000,
                Terminator = true,
            },
        };

        var request = new NapsGenerationRequest
        {
            CompressionType = 0,
            NumUBlocks = 1,
            NumOuterBlocks = 1,
            FileLogicalOffsets = new long[] { 0, 0x40000 },
            Blocks = blocks,
        };

        byte[] blob = ProsperoNapsLayoutBuilder.Build(request);
        NapsLayoutDocument doc = ProsperoNapsLayout.Parse(blob);

        Assert.Equal(2, doc.CblockInfos.Count(e => !e.IsRunBase));
        Assert.Equal(2, doc.CblockInfos.Count(e => e.IsRunBase));
        Assert.Equal(blob, ProsperoNapsLayout.BuildLayout(doc));
    }

    [Theory]
    [InlineData(1, 1)]
    [InlineData(7, 1)]
    [InlineData(8, 2)]
    [InlineData(9, 2)]
    [InlineData(16, 3)]
    [InlineData(24, 4)]
    public void U2c_EmitsFloorGroupsPlusOneTrailingGroup(int ublocks, int groups)
    {
        var blocks = new List<NapsCblockPlanEntry>();
        for (int i = 0; i < ublocks; i++)
            blocks.Add(new NapsCblockPlanEntry { StartRun = i == 0, OnDiskOffset = i * 0x40000L,
                LogicalOffset = i * 0x40000L, EvenChunkCompressedLength = 0x20000,
                StreamLength = 0x40000, Even = 1, Odd = 1, StoredRaw = true });
        blocks.Add(new NapsCblockPlanEntry { StartRun = true, OnDiskOffset = ublocks * 0x40000L,
            LogicalOffset = ublocks * 0x40000L, Terminator = true });
        var request = new NapsGenerationRequest { NumUBlocks = ublocks, NumOuterBlocks = 1,
            FileLogicalOffsets = new long[] { 0, ublocks * 0x40000L }, Blocks = blocks };
        NapsLayoutDocument doc = ProsperoNapsLayoutBuilder.BuildDocument(request);
        Assert.Equal(groups, doc.Counts.NumU2cEntries);
        Assert.Equal(groups, doc.CblockInfoOffsetByUblock.Count);
        Assert.Equal(doc.Map.CblockInfo.Offset, ProsperoNapsLayout.ComputeCblockInfoBase(doc.Counts));
    }

    [Fact]
    public void U2c_ExactMultipleOfEight_EmitsClampedTrailingGroup()
    {
        // Oracle ground truth: at 24 ublocks the original tool writes a 4th u2c entry whose base
        // is the terminator CblockInfo index and whose seven deltas are zero. This is the
        // floor(NumUBlocks/8)+1 convention, not ceil.
        const int ublocks = 24;
        var blocks = new List<NapsCblockPlanEntry>();
        for (int i = 0; i < ublocks; i++)
            blocks.Add(new NapsCblockPlanEntry { StartRun = i == 0, OnDiskOffset = i * 0x40000L,
                LogicalOffset = i * 0x40000L, EvenChunkCompressedLength = 0x20000,
                StreamLength = 0x40000, Even = 1, Odd = 1, StoredRaw = true });
        blocks.Add(new NapsCblockPlanEntry { StartRun = true, OnDiskOffset = ublocks * 0x40000L,
            LogicalOffset = ublocks * 0x40000L, Terminator = true });
        var request = new NapsGenerationRequest { NumUBlocks = ublocks, NumOuterBlocks = 1,
            FileLogicalOffsets = new long[] { 0, ublocks * 0x40000L }, Blocks = blocks };

        NapsLayoutDocument doc = ProsperoNapsLayoutBuilder.BuildDocument(request);

        Assert.Equal(4, doc.Counts.NumU2cEntries);
        NapsU2cEntry trailing = doc.CblockInfoOffsetByUblock[^1];
        Assert.Equal((uint)(doc.Counts.NumCblockInfo - 1), trailing.InfoOffset9BBase);
        Assert.All(trailing.DeltaFromBase, d => Assert.Equal(0, d));
        Assert.Equal(doc.Map.CblockInfo.Offset, ProsperoNapsLayout.ComputeCblockInfoBase(doc.Counts));
    }

    /// <summary>Build the 22-block plan that reproduces the debug package's NAPS exactly.</summary>
    private static NapsGenerationRequest DebugPlan()
    {
        var blocks = new List<NapsCblockPlanEntry>();

        // keystone (raw): 96 bytes at logical 0 / on-disk 0.
        blocks.Add(new NapsCblockPlanEntry
        {
            StartRun = true, OnDiskOffset = 0x00000, LogicalOffset = 0x00000,
            EvenChunkCompressedLength = 96, StreamLength = 96, Even = 1, Odd = 0,
        });

        // right.sprx (raw): 12752 bytes at logical 0x60 / on-disk 0x10000.
        blocks.Add(new NapsCblockPlanEntry
        {
            StartRun = true, OnDiskOffset = 0x10000, LogicalOffset = 0x00060,
            EvenChunkCompressedLength = 12752, StreamLength = 12752, Even = 1, Odd = 0,
        });

        // big.bin: 16 blocks (1 first + 14 dedup + 1 tail), 8+8 compressed bytes each.
        blocks.Add(new NapsCblockPlanEntry
        {
            StartRun = true, OnDiskOffset = 0x20000, LogicalOffset = 0x03230,
            EvenChunkCompressedLength = 8, StreamLength = 16, Even = 1, Odd = 1,
        });
        for (int k = 1; k <= 14; k++)
        {
            blocks.Add(new NapsCblockPlanEntry
            {
                StartRun = true, OnDiskOffset = 0x20000,
                LogicalOffset = 0x03230 + (long)k * 0x40000,
                EvenChunkCompressedLength = 8, StreamLength = 16, Even = 1, Odd = 1,
            });
        }
        blocks.Add(new NapsCblockPlanEntry
        {
            StartRun = false,
            LogicalOffset = 0x03230 + 15L * 0x40000, // 0x3F3230
            EvenChunkCompressedLength = 8, StreamLength = 16, Even = 1, Odd = 1,
        });

        // PFS metadata: three Kraken-ish blocks (even=5), only the first opens a RUN.
        blocks.Add(new NapsCblockPlanEntry
        {
            StartRun = true, OnDiskOffset = 0x30000, LogicalOffset = 0x400000,
            EvenChunkCompressedLength = 240, StreamLength = 459, Even = 5, Odd = 4,
        });
        blocks.Add(new NapsCblockPlanEntry
        {
            StartRun = false, LogicalOffset = 0x440000,
            EvenChunkCompressedLength = 111, StreamLength = 227, Even = 5, Odd = 4,
        });
        blocks.Add(new NapsCblockPlanEntry
        {
            StartRun = false, LogicalOffset = 0x480000,
            EvenChunkCompressedLength = 77, StreamLength = 77, Even = 5, Odd = 0,
        });

        // Terminator (mount end): opens its own RUN; tweak is forced to 0.
        blocks.Add(new NapsCblockPlanEntry
        {
            StartRun = true, OnDiskOffset = 0x302FB, LogicalOffset = 0x4A0000, Terminator = true,
        });

        return new NapsGenerationRequest
        {
            CompressionType = 2,
            NumUBlocks = 19,
            NumOuterBlocks = 4,
            FileLogicalOffsets = new long[] { 0x0, 0x60, 0x3230, 0x400000, 0x4A0000 },
            FinalFileOffsetType = 0x40,
            Blocks = blocks,
        };
    }

    private static byte[] ReadDebugNaps()
    {
        using var stream = File.OpenRead(Fixture("test.pkg"));
        stream.Position = 0x10;
        Span<byte> fih = stackalloc byte[16];
        stream.ReadExactly(fih);
        long pfsOffset = BitConverter.ToInt64(fih[..8]);
        long pfsSize = BitConverter.ToInt64(fih.Slice(8, 8));

        OuterPfsReader pfs = OuterPfsReader.Open(stream, pfsOffset, pfsSize);
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);

        return pfs.ReadNaps(xts);
    }
}
