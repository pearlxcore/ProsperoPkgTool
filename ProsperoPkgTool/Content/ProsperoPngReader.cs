using System.Buffers.Binary;
using System.IO.Compression;

namespace ProsperoPkgTool.Content;

/// <summary>
/// Minimal clean-room PNG decoder for the <c>sce_sys</c> icon/picture sources. It supports the
/// non-interlaced 8-bit and 16-bit truecolour, greyscale, palette and alpha variants that PS5
/// application icons use, and returns a tightly-packed top-down RGBA8 buffer.
///
/// Only the chunks required to reconstruct pixels are consumed: <c>IHDR</c>, <c>PLTE</c>,
/// <c>tRNS</c>, <c>IDAT</c> and <c>IEND</c>. The zlib stream is inflated with
/// <see cref="ZLibStream"/>; scanline filters are reversed with the standard PNG predictor set.
/// Unsupported encodings (Adam7 interlacing, sub-byte bit depths) throw <see cref="NotSupportedException"/>
/// so callers can fall back instead of emitting corrupt pixels.
/// </summary>
public static class ProsperoPngReader
{
    private static ReadOnlySpan<byte> Signature => [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// <summary>Decodes a PNG image into a top-down, tightly-packed RGBA8 buffer.</summary>
    /// <exception cref="InvalidDataException">The byte stream is not a well-formed supported PNG.</exception>
    /// <exception cref="NotSupportedException">The PNG uses an unsupported colour type, bit depth or interlace mode.</exception>
    public static byte[] DecodeToRgba(byte[] png, out int width, out int height)
    {
        ArgumentNullException.ThrowIfNull(png);
        if (png.Length < Signature.Length || !png.AsSpan(0, Signature.Length).SequenceEqual(Signature))
            throw new InvalidDataException("Not a PNG file (bad signature).");

        width = 0;
        height = 0;
        int bitDepth = 0;
        int colorType = -1;
        bool interlace = false;
        byte[]? palette = null;
        byte[]? paletteAlpha = null;
        var idat = new MemoryStream();

        int pos = Signature.Length;
        while (pos + 8 <= png.Length)
        {
            int length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(pos)));
            string type = System.Text.Encoding.ASCII.GetString(png, pos + 4, 4);
            int dataStart = pos + 8;
            if (length < 0 || dataStart + length + 4 > png.Length)
                throw new InvalidDataException($"PNG chunk '{type}' is truncated.");
            ReadOnlySpan<byte> data = png.AsSpan(dataStart, length);

            switch (type)
            {
                case "IHDR":
                    if (length != 13)
                        throw new InvalidDataException("PNG IHDR must be 13 bytes.");
                    width = checked((int)BinaryPrimitives.ReadUInt32BigEndian(data));
                    height = checked((int)BinaryPrimitives.ReadUInt32BigEndian(data[4..]));
                    bitDepth = data[8];
                    colorType = data[9];
                    if (data[10] != 0)
                        throw new InvalidDataException("PNG uses an unknown compression method.");
                    if (data[11] != 0)
                        throw new InvalidDataException("PNG uses an unknown filter method.");
                    interlace = data[12] != 0;
                    if (width <= 0 || height <= 0)
                        throw new InvalidDataException("PNG has invalid dimensions.");
                    break;
                case "PLTE":
                    if (length % 3 != 0)
                        throw new InvalidDataException("PNG PLTE length must be a multiple of 3.");
                    palette = data.ToArray();
                    break;
                case "tRNS":
                    if (colorType == 3)
                        paletteAlpha = data.ToArray();
                    break;
                case "IDAT":
                    idat.Write(data);
                    break;
                case "IEND":
                    pos = png.Length;
                    continue;
            }
            pos = dataStart + length + 4;
        }

        if (width <= 0 || height <= 0)
            throw new InvalidDataException("PNG is missing its IHDR chunk.");
        if (interlace)
            throw new NotSupportedException("Adam7-interlaced PNG images are not supported.");
        if (bitDepth is not (8 or 16))
            throw new NotSupportedException($"PNG bit depth {bitDepth} is not supported (only 8 and 16).");

        int channels = colorType switch
        {
            0 => 1, // greyscale
            2 => 3, // truecolour
            3 => 1, // palette index
            4 => 2, // greyscale + alpha
            6 => 4, // truecolour + alpha
            _ => throw new NotSupportedException($"PNG colour type {colorType} is not supported."),
        };
        if (colorType == 3 && palette is null)
            throw new InvalidDataException("Palette PNG is missing its PLTE chunk.");

        int bitsPerPixel = channels * bitDepth;
        int bytesPerPixel = Math.Max(1, bitsPerPixel / 8);
        int stride = (width * bitsPerPixel + 7) / 8;
        byte[] raw = Inflate(idat.ToArray(), checked((stride + 1) * height));
        byte[] unfiltered = Unfilter(raw, height, stride, bytesPerPixel);

        return ToRgba(unfiltered, width, height, bitDepth, colorType, channels, palette, paletteAlpha);
    }

    private static byte[] Inflate(byte[] zlib, int expected)
    {
        using var input = new MemoryStream(zlib, writable: false);
        using var inflater = new ZLibStream(input, CompressionMode.Decompress);
        using var output = expected > 0 ? new MemoryStream(expected) : new MemoryStream();
        inflater.CopyTo(output);
        return output.ToArray();
    }

    private static byte[] Unfilter(byte[] raw, int height, int stride, int bpp)
    {
        if (raw.Length < checked(height * (stride + 1)))
            throw new InvalidDataException("PNG pixel data is shorter than the declared dimensions.");
        var result = new byte[height * stride];
        int src = 0;
        for (int y = 0; y < height; y++)
        {
            int filter = raw[src++];
            int rowStart = y * stride;
            int priorStart = rowStart - stride;
            for (int x = 0; x < stride; x++)
            {
                int value = raw[src + x];
                int left = x >= bpp ? result[rowStart + x - bpp] : 0;
                int up = y > 0 ? result[priorStart + x] : 0;
                int upLeft = (y > 0 && x >= bpp) ? result[priorStart + x - bpp] : 0;
                int reconstructed = filter switch
                {
                    0 => value,
                    1 => value + left,
                    2 => value + up,
                    3 => value + ((left + up) >> 1),
                    4 => value + Paeth(left, up, upLeft),
                    _ => throw new InvalidDataException($"PNG uses unknown scanline filter {filter}."),
                };
                result[rowStart + x] = (byte)reconstructed;
            }
            src += stride;
        }
        return result;
    }

    private static int Paeth(int a, int b, int c)
    {
        int p = a + b - c;
        int pa = Math.Abs(p - a);
        int pb = Math.Abs(p - b);
        int pc = Math.Abs(p - c);
        if (pa <= pb && pa <= pc) return a;
        return pb <= pc ? b : c;
    }

    private static byte[] ToRgba(
        byte[] data, int width, int height, int bitDepth, int colorType, int channels,
        byte[]? palette, byte[]? paletteAlpha)
    {
        var rgba = new byte[checked(width * height * 4)];
        int sampleBytes = bitDepth / 8;
        int rowBytes = width * channels * sampleBytes;
        for (int y = 0; y < height; y++)
        {
            int row = y * rowBytes;
            for (int x = 0; x < width; x++)
            {
                int s = row + x * channels * sampleBytes;
                int d = (y * width + x) * 4;
                switch (colorType)
                {
                    case 0: // greyscale
                    {
                        byte g = data[s];
                        rgba[d] = g; rgba[d + 1] = g; rgba[d + 2] = g; rgba[d + 3] = 255;
                        break;
                    }
                    case 2: // truecolour
                    {
                        rgba[d] = data[s];
                        rgba[d + 1] = data[s + sampleBytes];
                        rgba[d + 2] = data[s + 2 * sampleBytes];
                        rgba[d + 3] = 255;
                        break;
                    }
                    case 3: // palette
                    {
                        int index = data[s];
                        int p = index * 3;
                        if (p + 2 >= palette!.Length)
                            throw new InvalidDataException("PNG palette index is out of range.");
                        rgba[d] = palette[p]; rgba[d + 1] = palette[p + 1]; rgba[d + 2] = palette[p + 2];
                        rgba[d + 3] = paletteAlpha is not null && index < paletteAlpha.Length ? paletteAlpha[index] : (byte)255;
                        break;
                    }
                    case 4: // greyscale + alpha
                    {
                        byte g = data[s], a = data[s + sampleBytes];
                        rgba[d] = g; rgba[d + 1] = g; rgba[d + 2] = g; rgba[d + 3] = a;
                        break;
                    }
                    case 6: // truecolour + alpha
                    {
                        rgba[d] = data[s];
                        rgba[d + 1] = data[s + sampleBytes];
                        rgba[d + 2] = data[s + 2 * sampleBytes];
                        rgba[d + 3] = data[s + 3 * sampleBytes];
                        break;
                    }
                }
            }
        }
        return rgba;
    }
}
