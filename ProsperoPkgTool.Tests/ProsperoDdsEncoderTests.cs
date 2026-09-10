using System.Buffers.Binary;
using BCnEncoder.Decoder;
using BCnEncoder.Shared;
using ProsperoPkgTool.Content;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Coverage for the clean-room PNG decoder and BC7 DDS encoder. The BC7 blocks are validated with
/// an independent decoder (<c>BCnEncoder.Net</c>), and the 148-byte DDS header is checked against
/// the layout of the reference <c>sce_sys</c> DDS files.
/// </summary>
public sealed class ProsperoDdsEncoderTests
{
    // A 4x4 RGBA PNG; pixel i = (i*16, 255-i*16, i*7, 255-i*8).
    private const string TinyPngBase64 =
        "iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAGklEQVR4XmNk+M/wX+AD+w8YZnE4IPOANAEAMSwf9B7uakAAAAAASUVORK5CYII=";

    private static byte[] BuildRgba(int width, int height)
    {
        // A smooth gradient so a single mode-6 endpoint pair per block reconstructs well.
        byte[] rgba = new byte[width * height * 4];
        for (int y = 0; y < height; y++)
        {
            for (int x = 0; x < width; x++)
            {
                int i = (y * width + x) * 4;
                rgba[i] = (byte)(x * 255 / Math.Max(1, width - 1));
                rgba[i + 1] = (byte)(y * 255 / Math.Max(1, height - 1));
                rgba[i + 2] = (byte)((x + y) * 255 / Math.Max(1, width + height - 2));
                rgba[i + 3] = 255;
            }
        }
        return rgba;
    }

    [Fact]
    public void DecodeToRgba_ReconstructsKnownPixels()
    {
        byte[] rgba = ProsperoPngReader.DecodeToRgba(Convert.FromBase64String(TinyPngBase64), out int width, out int height);

        Assert.Equal(4, width);
        Assert.Equal(4, height);
        for (int i = 0; i < 16; i++)
        {
            Assert.Equal((byte)(i * 16), rgba[i * 4]);
            Assert.Equal((byte)(255 - i * 16), rgba[i * 4 + 1]);
            Assert.Equal((byte)(i * 7), rgba[i * 4 + 2]);
            Assert.Equal((byte)(255 - i * 8), rgba[i * 4 + 3]);
        }
    }

    [Fact]
    public void EncodeRgbaToDds_HeaderMatchesDx10Bc7Layout()
    {
        byte[] dds = ProsperoDdsEncoder.EncodeRgbaToDds(BuildRgba(8, 4), 8, 4);

        Assert.Equal("DDS ", System.Text.Encoding.ASCII.GetString(dds, 0, 4));
        Assert.Equal(124u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(4)));
        Assert.Equal(0x000A1007u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(8)));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(12)));   // height
        Assert.Equal(8u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(16)));   // width
        Assert.Equal(2u * 16u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(20))); // linear size
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(28)));   // mip count
        Assert.Equal("DX10", System.Text.Encoding.ASCII.GetString(dds, 84, 4));
        Assert.Equal(4096u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(108)));
        Assert.Equal(98u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(128))); // BC7_UNORM
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(132)));  // TEXTURE2D
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(140)));  // array size
        Assert.Equal(ProsperoDdsEncoder.HeaderSize + 2 * 16, dds.Length);
    }

    [Fact]
    public void EncodeRgbaToDds_ClampsPartialBlocksToFourTexelBoundary()
    {
        byte[] dds = ProsperoDdsEncoder.EncodeRgbaToDds(BuildRgba(5, 3), 5, 3);

        // ceil(5/4) * ceil(3/4) = 2 blocks.
        Assert.Equal(ProsperoDdsEncoder.HeaderSize + 2 * 16, dds.Length);
        Assert.Equal(5u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(16)));
        Assert.Equal(3u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(12)));
    }

    [Fact]
    public void EncodeRgbaToDds_ProducesDecodableBc7Blocks()
    {
        const int width = 64, height = 32;
        byte[] rgba = BuildRgba(width, height);
        byte[] dds = ProsperoDdsEncoder.EncodeRgbaToDds(rgba, width, height);

        // Every block must start with the mode-6 selector (bit 6 set in the low seven bits).
        for (int block = 0; block < (width / 4) * (height / 4); block++)
            Assert.Equal(0x40, dds[ProsperoDdsEncoder.HeaderSize + block * 16] & 0x7F);

        ColorRgba32[] decoded = new BcDecoder().DecodeRaw(dds[ProsperoDdsEncoder.HeaderSize..], width, height, CompressionFormat.Bc7);
        Assert.Equal(width * height, decoded.Length);

        double error = 0;
        for (int i = 0; i < width * height; i++)
        {
            error += Square(decoded[i].r, rgba[i * 4]);
            error += Square(decoded[i].g, rgba[i * 4 + 1]);
            error += Square(decoded[i].b, rgba[i * 4 + 2]);
            error += Square(decoded[i].a, rgba[i * 4 + 3]);
        }
        double psnr = 10 * Math.Log10(255.0 * 255.0 / (error / (width * height * 4)));
        Assert.True(psnr > 35.0, $"Expected BC7 round-trip PSNR above 35 dB, got {psnr:F2} dB.");
    }

    [Fact]
    public void EncodePngToDds_DecodesPngThenEncodesDds()
    {
        byte[] dds = ProsperoDdsEncoder.EncodePngToDds(Convert.FromBase64String(TinyPngBase64));

        Assert.Equal("DDS ", System.Text.Encoding.ASCII.GetString(dds, 0, 4));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(16)));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(dds.AsSpan(12)));
        Assert.Equal(ProsperoDdsEncoder.HeaderSize + 16, dds.Length);
    }

    [Fact]
    public void DecodeToRgba_RejectsUnsupportedInterlacing()
    {
        byte[] png = (byte[])Convert.FromBase64String(TinyPngBase64).Clone();
        // Signature (8) + length (4) + type (4) + IHDR data; interlace is IHDR byte 12 => file 0x1C.
        png[0x1C] = 1;
        Assert.Throws<NotSupportedException>(() => ProsperoPngReader.DecodeToRgba(png, out _, out _));
    }

    private static double Square(int a, int b)
    {
        double d = a - b;
        return d * d;
    }
}
