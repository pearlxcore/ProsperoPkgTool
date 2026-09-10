using ProsperoPkgTool.Compression;
using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class KrakenEncoderTests
{
    [Theory]
    [InlineData(1024, 0)]
    [InlineData(0x10000, 0xA5)]
    [InlineData(0x20000, 0)]
    [InlineData(0x40000, 0x5A)]
    public void UniformBlocks_RoundTripThroughExistingDecoder(int size, byte value)
    {
        byte[] input = Enumerable.Repeat(value, size).ToArray();
        KrakenEncoder.EncodedBlock encoded = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncode(input));
        byte[] output = new byte[input.Length];

        Assert.Equal(KrakenDecoder.KrakenDecodeStatus.Success,
            KrakenDecoder.DecodeBlock(encoded.Payload, encoded.Flags, encoded.FirstChunkCompressedLength, output));
        Assert.Equal(input, output);
        Assert.True(encoded.Payload.Length < input.Length);
    }

    [Fact]
    public void MixedAndIncompressibleInputs_SelectStoredFallback()
    {
        Assert.Null(KrakenEncoder.TryEncode([0]));
        Assert.Null(KrakenEncoder.TryEncode([]));
        Assert.Null(KrakenEncoder.TryEncode("repeated strings repeated strings"u8));
        byte[] random = new byte[0x20000];
        new Random(12345).NextBytes(random);
        Assert.Null(KrakenEncoder.TryEncode(random));
    }

    [Fact]
    public void Output_IsDeterministic()
    {
        byte[] input = new byte[0x40000];
        KrakenEncoder.EncodedBlock a = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncode(input));
        KrakenEncoder.EncodedBlock b = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncode(input));
        Assert.Equal(a.Payload, b.Payload);
        Assert.Equal(a.Flags, b.Flags);
        Assert.Equal(a.FirstChunkCompressedLength, b.FirstChunkCompressedLength);
    }

    [Fact]
    public void TwoSymbolLiteralArray_RoundTripsThroughExistingDecoder()
    {
        byte[] input = Enumerable.Range(0, 4096).Select(i => (byte)(i % 2 == 0 ? 0x31 : 0xE2)).ToArray();
        KrakenEncoder.EncodedBlock encoded = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncode(input));
        Assert.Equal(KrakenEncoder.LiteralMode.FixedWidthHuffman, encoded.Mode);
        byte[] output = new byte[input.Length];
        Assert.Equal(KrakenDecoder.KrakenDecodeStatus.Success,
            KrakenDecoder.DecodeBlock(encoded.Payload, encoded.Flags, encoded.FirstChunkCompressedLength, output));
        Assert.Equal(input, output);
    }

    public static IEnumerable<object[]> LiteralRoundTripCases()
    {
        yield return ["all-byte-values", Enumerable.Range(0, 256).Select(i => (byte)i).ToArray(), false];
        yield return ["ascending-repeated", Enumerable.Range(0, 256 * 1024).Select(i => (byte)(i % 8)).ToArray(), true];
        yield return ["alternating", Enumerable.Range(0, 64 * 1024).Select(i => (byte)(i % 2)).ToArray(), true];
        yield return ["short-text", Enumerable.Repeat("literal literal literal\n", 80).SelectMany(s => s).Select(c => (byte)c).ToArray(), true];
        yield return ["english", Enumerable.Repeat("The deterministic literal stream contains no LZ matches. ", 300).SelectMany(s => s).Select(c => (byte)c).ToArray(), true];
        yield return ["json", Enumerable.Repeat("{\"kind\":\"metadata\",\"version\":1,\"enabled\":true}\n", 300).SelectMany(s => s).Select(c => (byte)c).ToArray(), true];
        yield return ["elf-like", Enumerable.Range(0, 16 * 1024).Select(i => (byte)(i % 11 == 0 ? 0x7F : i % 11 == 1 ? (byte)'E' : 0)).ToArray(), true];
        yield return ["mixed-regions", Enumerable.Range(0, 96 * 1024).Select(i => (byte)(i < 32 * 1024 ? 0 : i < 64 * 1024 ? i % 3 : 0xFF)).ToArray(), true];
        yield return ["random-1k", RandomBytes(1024, 1), false];
        yield return ["random-64k", RandomBytes(0x10000, 2), false];
        yield return ["random-128k", RandomBytes(0x20000, 3), false];
        yield return ["random-256k", RandomBytes(0x40000, 4), false];
    }

    [Theory]
    [MemberData(nameof(LiteralRoundTripCases))]
    public void LiteralMatrix_RoundTripsWhenCompressionIsSelected(string _, byte[] input, bool expectKraken)
    {
        KrakenEncoder.EncodedBlock? encoded = KrakenEncoder.TryEncode(input);
        KrakenEncoder.EncodedBlock? repeated = KrakenEncoder.TryEncode(input);
        Assert.Equal(expectKraken, encoded is not null);
        Assert.Equal(encoded is null, repeated is null);
        if (encoded is null) return;
        Assert.Equal(encoded.Payload, repeated!.Payload);
        Assert.Equal(encoded.Mode, repeated.Mode);
        Assert.Equal(encoded.Flags, repeated.Flags);
        Assert.Equal(encoded.FirstChunkCompressedLength, repeated.FirstChunkCompressedLength);
        byte[] output = new byte[input.Length];
        Assert.Equal(KrakenDecoder.KrakenDecodeStatus.Success,
            KrakenDecoder.DecodeBlock(encoded.Payload, encoded.Flags, encoded.FirstChunkCompressedLength, output));
        Assert.Equal(input, output);
        Assert.True(encoded.Payload.Length < input.Length);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(16)]
    [InlineData(17)]
    [InlineData(255)]
    [InlineData(256)]
    [InlineData(257)]
    [InlineData(1023)]
    [InlineData(1024)]
    [InlineData(1025)]
    [InlineData(0x10000 - 1)]
    [InlineData(0x10000)]
    [InlineData(0x10000 + 1)]
    [InlineData(0x20000)]
    [InlineData(0x40000)]
    public void BoundarySizes_AreDeterministicAndRoundTripWhenSelected(int size)
    {
        byte[] input = Enumerable.Range(0, size).Select(i => (byte)(i % 3)).ToArray();
        KrakenEncoder.EncodedBlock? a = KrakenEncoder.TryEncode(input);
        KrakenEncoder.EncodedBlock? b = KrakenEncoder.TryEncode(input);
        Assert.Equal(a is null, b is null);
        if (a is null) return;
        Assert.Equal(a.Payload, b!.Payload);
        Assert.Equal(a.Mode, b.Mode);
        Assert.Equal(a.Flags, b.Flags);
        Assert.Equal(a.FirstChunkCompressedLength, b.FirstChunkCompressedLength);
        byte[] output = new byte[size];
        Assert.Equal(KrakenDecoder.KrakenDecodeStatus.Success,
            KrakenDecoder.DecodeBlock(a.Payload, a.Flags, a.FirstChunkCompressedLength, output));
        Assert.Equal(input, output);
    }

    [Fact]
    public void UnsupportedSizesAndData_UseStoredFallback()
    {
        Assert.Null(KrakenEncoder.TryEncode([]));
        Assert.Null(KrakenEncoder.TryEncode([0]));
        Assert.Null(KrakenEncoder.TryEncode(new byte[KrakenEncoder.MaxBlockSize + 1]));
        Assert.Null(KrakenEncoder.TryEncode(Enumerable.Range(0, 255).Select(i => (byte)i).ToArray()));
    }

    [Fact]
    public void MixedGeneratedNaps_ReconstructsUniformLiteralAndStoredBlocks()
    {
        byte[] uniform = Enumerable.Repeat((byte)0x5A, 0x10000).ToArray();
        byte[] literal = Enumerable.Range(0, 0x10000).Select(i => (byte)(i % 3)).ToArray();
        byte[] stored = RandomBytes(0x10000, 9);
        KrakenEncoder.EncodedBlock uniformEncoded = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncode(uniform));
        KrakenEncoder.EncodedBlock literalEncoded = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncode(literal));
        Assert.Equal(KrakenEncoder.LiteralMode.FixedWidthHuffman, literalEncoded.Mode);
        byte[] innerImage = uniformEncoded.Payload.Concat(literalEncoded.Payload).Concat(stored).ToArray();
        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            CompressionType = 2, NumUBlocks = 3, NumOuterBlocks = 1,
            FileLogicalOffsets = [0, 0x10000, 0x20000, 0x30000],
            Blocks = [
                new NapsCblockPlanEntry { StartRun = true, OnDiskOffset = 0, LogicalOffset = 0,
                    EvenChunkCompressedLength = uniformEncoded.Payload.Length, StreamLength = uniformEncoded.Payload.Length, Even = 5, Odd = 4, KdePredictor = 0 },
                new NapsCblockPlanEntry { StartRun = true, OnDiskOffset = uniformEncoded.Payload.Length, LogicalOffset = 0x10000,
                    EvenChunkCompressedLength = literalEncoded.Payload.Length, StreamLength = literalEncoded.Payload.Length, Even = 5, Odd = 4, KdePredictor = 0 },
                new NapsCblockPlanEntry { StartRun = true, OnDiskOffset = uniformEncoded.Payload.Length + literalEncoded.Payload.Length, LogicalOffset = 0x20000,
                    EvenChunkCompressedLength = stored.Length, StreamLength = stored.Length, Even = 1, Odd = 0, StoredRaw = true },
                new NapsCblockPlanEntry { LogicalOffset = 0x30000, Terminator = true },
            ],
        });
        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(innerImage, naps);
        Assert.Equal(uniform.Concat(literal).Concat(stored), mount);
    }

    [Fact]
    public void MetadataLikeLiteralData_RoundTripsOrUsesStoredFallback()
    {
        byte[] inodeTable = Enumerable.Range(0, 4096).Select(i => (byte)(i % 64 == 0 ? 1 : 0)).ToArray();
        byte[] pathStrings = Enumerable.Repeat("/sce_sys/param.json\0/sce_module/right.sprx\0", 400).SelectMany(s => s).Select(c => (byte)c).ToArray();
        byte[] structured = Enumerable.Range(0, 32768).Select(i => (byte)(i % 7 == 0 ? i : 0)).ToArray();
        foreach (byte[] input in new[] { inodeTable, pathStrings, structured })
        {
            KrakenEncoder.EncodedBlock? encoded = KrakenEncoder.TryEncode(input);
            if (encoded is null) continue;
            byte[] output = new byte[input.Length];
            Assert.Equal(KrakenDecoder.KrakenDecodeStatus.Success,
                KrakenDecoder.DecodeBlock(encoded.Payload, encoded.Flags, encoded.FirstChunkCompressedLength, output));
            Assert.Equal(input, output);
        }
    }

    private static byte[] RandomBytes(int length, int seed)
    {
        byte[] data = new byte[length];
        new Random(seed).NextBytes(data);
        return data;
    }

    [Fact]
    public void MixedGeneratedNaps_ReconstructsUniformKrakenAndStoredBlocks()
    {
        byte[] uniform = Enumerable.Repeat((byte)0x5A, 0x40000).ToArray();
        KrakenEncoder.EncodedBlock encoded = Assert.IsType<KrakenEncoder.EncodedBlock>(KrakenEncoder.TryEncode(uniform));
        byte[] stored = Enumerable.Range(0, 0x10000).Select(i => (byte)i).ToArray();
        byte[] innerImage = encoded.Payload.Concat(stored).ToArray();
        byte[] naps = ProsperoNapsLayoutBuilder.Build(new NapsGenerationRequest
        {
            // These Cblock fields are the scoped generated-reader contract: Even=5/Odd=4 select
            // newLZ with raw literals and KDE=0, which the console/reference decoder requires.
            CompressionType = 2, NumUBlocks = 2, NumOuterBlocks = 1,
            FileLogicalOffsets = [0, 0x40000, 0x50000],
            Blocks = [
                new NapsCblockPlanEntry { StartRun = true, OnDiskOffset = 0, LogicalOffset = 0,
                    EvenChunkCompressedLength = encoded.FirstChunkCompressedLength, StreamLength = encoded.Payload.Length,
                    Even = 5, Odd = 4, KdePredictor = 0 },
                new NapsCblockPlanEntry { StartRun = true, OnDiskOffset = encoded.Payload.Length, LogicalOffset = 0x40000,
                    EvenChunkCompressedLength = stored.Length, StreamLength = stored.Length, Even = 1, Odd = 0, StoredRaw = true },
                new NapsCblockPlanEntry { LogicalOffset = 0x50000, Terminator = true },
            ],
        });

        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(innerImage, naps);
        Assert.Equal(uniform, mount.AsSpan(0, uniform.Length).ToArray());
        Assert.Equal(stored, mount.AsSpan(uniform.Length, stored.Length).ToArray());
    }
}
