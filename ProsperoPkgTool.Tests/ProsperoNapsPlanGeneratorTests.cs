using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class ProsperoNapsPlanGeneratorTests
{
    [Fact]
    public void StoredPlan_MultiUblockFilesHolesAndMetadata_RoundTripByteExact()
    {
        byte[] small = Pattern(4096, 1);
        byte[] medium = Pattern(0x20001, 2);
        byte[] large = Pattern(0xE1000, 3); // > 256KiB and spans several NAPS ublocks
        var assembler = new ProsperoInnerImageAssembler(1, 2);
        ProsperoInnerImageAssembler.InnerImageResult inner = assembler.Build(new[]
        {
            new ProsperoInnerImageAssembler.InnerFile { Path = "/sce_sys/keystone", Data = small },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/a.bin", Data = medium },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/b.bin", Data = large },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/z.txt", Data = Pattern(71, 4) },
        });

        ProsperoNapsPlanGenerator.PlanResult plan = ProsperoNapsPlanGenerator.Generate(inner);
        byte[] naps = ProsperoNapsLayoutBuilder.Build(plan.ToRequest());
        IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks =
            ProsperoPs5InnerImageReader.WalkBlocks(naps, inner.Image.Length);
        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(inner.Image, naps);

        Assert.Equal(plan.NumUBlocks, ProsperoNapsLayout.Parse(naps).Counts.NumUBlocks);
        Assert.Equal((plan.NumUBlocks + 7) / 8, ProsperoNapsLayout.Parse(naps).CblockInfoOffsetByUblock.Count);
        Assert.Contains(blocks, b => b.IsZeroHole);
        foreach (ProsperoInnerImageAssembler.Placement p in inner.Placements)
            Assert.Equal(inner.Image.AsSpan((int)p.OnDiskOffset, (int)p.OnDiskSize).ToArray(),
                mount.AsSpan((int)p.LogicalOffset, (int)p.UncompressedSize).ToArray());
        Assert.Equal(inner.MetadataPlaintext,
            mount.AsSpan((int)inner.MetaBaseLogical, inner.MetadataPlaintext.Length).ToArray());
    }

    [Fact]
    public void AutoPlan_MixedKrakenAndStoredBlocks_ReconstructsMount()
    {
        byte[] uniform = new byte[0x10000];
        byte[] alternating = Enumerable.Range(0, 0x10000).Select(i => (byte)(i % 2)).ToArray();
        byte[] random = new byte[0x10000]; new Random(17).NextBytes(random);
        byte[] large = Enumerable.Range(0, 0xE1000).Select(i => (byte)(i % 3)).ToArray();
        var assembler = new ProsperoInnerImageAssembler(1, 2);
        ProsperoInnerImageAssembler.InnerImageResult inner = assembler.Build(new[]
        {
            new ProsperoInnerImageAssembler.InnerFile { Path = "/sce_sys/keystone", Data = uniform },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/nested/alternating.bin", Data = alternating },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/random.bin", Data = random },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/large.bin", Data = large },
        }, ProsperoInnerCompressionMode.Auto);

        Assert.Equal(7, inner.CompressionMetrics.KrakenBlocks);
        Assert.Equal(4, inner.CompressionMetrics.StoredBlocks);
        // The metadata region is wrapped in the compressed PFSv3 container under Kraken/Auto, so at
        // least one metadata chunk must carry non-zero container flags and shrink.
        Assert.Contains(inner.MetadataBlocks, b => b.Flags != 0 && b.CompressedSize < b.UncompressedSize);
        byte[] naps = ProsperoNapsLayoutBuilder.Build(ProsperoNapsPlanGenerator.Generate(inner).ToRequest(2));
        IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> walked = ProsperoPs5InnerImageReader.WalkBlocks(naps, inner.Image.Length);
        Assert.Equal(inner.EncodedBlocks.Where(b => b.UncompressedLength > 0).Select(b => b.StoredLength),
            walked.Take(inner.EncodedBlocks.Count(b => b.UncompressedLength > 0)).Select(b => b.CompressedLength));
        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(inner.Image, naps);
        foreach (byte[] data in new[] { uniform, alternating, random, large })
            Assert.True(ContainsSequence(mount, data));
        Assert.Equal(inner.MetadataPlaintext, mount.AsSpan((int)inner.MetaBaseLogical, inner.MetadataPlaintext.Length).ToArray());
    }

    [Fact]
    public void Fidx_ExcludesZeroLengthFilesAndEmitsSingleDataEndBoundary()
    {
        // A zero-length file shares the dataEnd boundary. Sony's fidx collapses it into the single
        // trailing dataEnd entry; emitting a duplicate would create a zero-length NAPS span that the
        // mount rejects. Confirmed against the original tool (base/variant/zero-length oracles).
        var assembler = new ProsperoInnerImageAssembler(1, 2);
        ProsperoInnerImageAssembler.InnerImageResult inner = assembler.Build(new[]
        {
            new ProsperoInnerImageAssembler.InnerFile { Path = "/sce_sys/keystone", Data = Pattern(96, 1) },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/sce_sys/about/right.sprx", Data = Pattern(12752, 2) },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/eboot.bin", Data = Array.Empty<byte>() },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/vary.bin", Data = Pattern(1024, 3) },
        });

        ProsperoNapsPlanGenerator.PlanResult plan = ProsperoNapsPlanGenerator.Generate(inner);

        Assert.Equal(new long[] { 0x0, 0x60, 0x3230, 0x3630, 0x400000, 0x4A0000 }, plan.FileLogicalOffsets);
        Assert.Equal(plan.FileLogicalOffsets.OrderBy(o => o).ToArray(), plan.FileLogicalOffsets);
        Assert.Equal(plan.FileLogicalOffsets.Distinct().Count(), plan.FileLogicalOffsets.Count);
        Assert.Equal(inner.DataEndLogical, plan.FileLogicalOffsets[^3]);
        Assert.Equal(inner.MetaBaseLogical, plan.FileLogicalOffsets[^2]);
        Assert.Equal(plan.MountSize, plan.FileLogicalOffsets[^1]);
    }

    [Fact]
    public void Kraken_LargeCompressiblePayload_ReservesMetadataAfterLogicalData()
    {
        // 12 MiB of zeros compresses to far less than the ~4 MiB metadata reserve. Before the
        // logical-mount fix, metaBase was derived from the physical block count and landed before
        // the uncompressed data end, producing a non-monotonic fidx (and an unbuildable mount).
        // Regression for the real ~3.5 GiB `convert --compression kraken` package build.
        byte[] large = new byte[12 * 1024 * 1024];

        var assembler = new ProsperoInnerImageAssembler(1, 2);
        ProsperoInnerImageAssembler.InnerImageResult inner = assembler.Build(new[]
        {
            new ProsperoInnerImageAssembler.InnerFile { Path = "/sce_sys/keystone", Data = Pattern(96, 1) },
            new ProsperoInnerImageAssembler.InnerFile { Path = "/big.bin", Data = large },
        }, ProsperoInnerCompressionMode.Kraken);

        Assert.True(inner.ImageSize < inner.Ndblock * ProsperoInnerImageAssembler.BlockSize);
        Assert.True(inner.MetaBaseLogical >= inner.DataEndLogical);

        ProsperoNapsPlanGenerator.PlanResult plan = ProsperoNapsPlanGenerator.Generate(inner);
        Assert.Equal(plan.FileLogicalOffsets.OrderBy(o => o).ToArray(), plan.FileLogicalOffsets);
        byte[] naps = ProsperoNapsLayoutBuilder.Build(plan.ToRequest(2));
        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(inner.Image, naps);

        long offset = inner.Placements.Single(p => p.UncompressedSize == large.Length).LogicalOffset;
        Assert.Equal(large, mount.AsSpan((int)offset, large.Length).ToArray());
        Assert.Equal(inner.MetadataPlaintext,
            mount.AsSpan((int)inner.MetaBaseLogical, inner.MetadataPlaintext.Length).ToArray());
    }

    private static byte[] Pattern(int length, int seed) => Enumerable.Range(0, length)
        .Select(i => (byte)((i * 31 + seed) & 0xff)).ToArray();

    private static bool ContainsSequence(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i <= haystack.Length - needle.Length; i++)
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle)) return true;
        return false;
    }
}
