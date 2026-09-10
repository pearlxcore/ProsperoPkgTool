using System.Buffers.Binary;

namespace ProsperoPkgTool.Content;

/// <summary>
/// Clean-room PNG-to-DDS re-encoder for the PS5 <c>sce_sys</c> icon/picture media. It produces a
/// DX10 <c>DXGI_FORMAT_BC7_UNORM</c> DDS with a single surface and no mipmaps, matching the header
/// layout of the reference <c>icon0.dds</c>/<c>pic0.dds</c>/<c>pic1.dds</c>/<c>pic2.dds</c>.
///
/// The block codec is a self-contained BC7 mode-6 encoder (one subset, two RGBA endpoints with
/// per-channel P-bits, sixteen 4-bit interpolation indices). Mode 6 is the only BC7 mode with a
/// 7-bit alpha channel, which is what the icon surfaces use. Endpoints are the per-channel min/max
/// of the 4x4 texel block quantized to 7 bits + P-bit, and each index selects the weight that
/// minimises squared error against the interpolated endpoint pair. This is an approximation
/// encoder: it is not bit-identical to any particular publisher encoder, but every emitted block is
/// a spec-valid BC7 block.
/// </summary>
public static class ProsperoDdsEncoder
{
    /// <summary>DDS magic + DDS_HEADER (124) + DDS_HEADER_DXT10 (20).</summary>
    public const int HeaderSize = 148;

    /// <summary>DXGI_FORMAT_BC7_UNORM, the texture format used by the PS5 <c>sce_sys</c> DDS files.</summary>
    private const uint DxgiFormatBc7Unorm = 98;

    /// <summary>DDS magic "DDS " (little-endian).</summary>
    private const uint DdsMagic = 0x20534444;

    // 4-bit index weights scaled to 0..64; the table is symmetric (w[i] + w[15-i] == 64).
    private static readonly int[] Weights4 =
    [
        0, 4, 9, 13, 17, 21, 26, 30, 34, 38, 43, 47, 51, 55, 60, 64
    ];

    /// <summary>Decodes a PNG image and re-encodes it as a BC7 DX10 DDS (full resolution, no mipmaps).</summary>
    public static byte[] EncodePngToDds(byte[] pngBytes)
    {
        if (pngBytes is null || pngBytes.Length == 0)
            throw new ArgumentException("Empty image.", nameof(pngBytes));
        byte[] rgba = ProsperoPngReader.DecodeToRgba(pngBytes, out int width, out int height);
        return EncodeRgbaToDds(rgba, width, height);
    }

    /// <summary>
    /// Encodes a tightly-packed top-down RGBA8 buffer (<paramref name="width"/>x<paramref name="height"/>,
    /// 4 bytes/pixel) into a BC7 DX10 DDS file. Dimensions are rounded up to a multiple of four for
    /// block alignment (edge pixels are repeated), matching how DDS surfaces store partial blocks.
    /// </summary>
    public static byte[] EncodeRgbaToDds(byte[] rgba, int width, int height)
    {
        ArgumentNullException.ThrowIfNull(rgba);
        if (width <= 0 || height <= 0)
            throw new ArgumentOutOfRangeException(nameof(width), "Invalid image dimensions.");
        if (rgba.Length < checked(width * height * 4))
            throw new ArgumentException("RGBA buffer is smaller than width*height*4.", nameof(rgba));

        int blocksX = (width + 3) / 4;
        int blocksY = (height + 3) / 4;
        int blockBytes = checked(blocksX * blocksY * 16);
        byte[] dds = new byte[HeaderSize + blockBytes];
        WriteHeader(dds, width, height, (uint)blockBytes);

        Span<byte> block = stackalloc byte[64];
        for (int by = 0; by < blocksY; by++)
        {
            for (int bx = 0; bx < blocksX; bx++)
            {
                GatherBlock(rgba, width, height, bx * 4, by * 4, block);
                EncodeBlockMode6(block, dds.AsSpan(HeaderSize + (by * blocksX + bx) * 16, 16));
            }
        }
        return dds;
    }

    private static void WriteHeader(byte[] dst, int width, int height, uint linearSize)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(dst, DdsMagic);
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(4), 124);       // DDS_HEADER size
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(8), 0x000A1007); // caps|height|width|pitch|mipcount
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(12), (uint)height);
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(16), (uint)width);
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(20), linearSize);
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(24), 0);        // depth
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(28), 1);        // mipmap count
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(76), 32);       // DDS_PIXELFORMAT size
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(80), 4);        // DDPF_FOURCC
        "DX10"u8.CopyTo(dst.AsSpan(84));
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(108), 4096);    // DDSCAPS_TEXTURE
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(128), DxgiFormatBc7Unorm);
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(132), 3);       // D3D10_RESOURCE_DIMENSION_TEXTURE2D
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(136), 0);       // misc flag
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(140), 1);       // array size
        BinaryPrimitives.WriteUInt32LittleEndian(dst.AsSpan(144), 0);       // misc flags 2
    }

    private static void GatherBlock(byte[] rgba, int width, int height, int x0, int y0, Span<byte> block)
    {
        for (int y = 0; y < 4; y++)
        {
            int sy = Math.Min(y0 + y, height - 1);
            for (int x = 0; x < 4; x++)
            {
                int sx = Math.Min(x0 + x, width - 1);
                int si = (sy * width + sx) * 4;
                int di = (y * 4 + x) * 4;
                block[di] = rgba[si];
                block[di + 1] = rgba[si + 1];
                block[di + 2] = rgba[si + 2];
                block[di + 3] = rgba[si + 3];
            }
        }
    }

    private static void EncodeBlockMode6(ReadOnlySpan<byte> block, Span<byte> dst)
    {
        Span<byte> min = stackalloc byte[4];
        min.Fill(255);
        Span<byte> max = stackalloc byte[4];
        for (int i = 0; i < 16; i++)
        {
            for (int c = 0; c < 4; c++)
            {
                byte v = block[i * 4 + c];
                if (v < min[c]) min[c] = v;
                if (v > max[c]) max[c] = v;
            }
        }

        QuantizeEndpoint(min, out byte[] q0, out int p0, out int[] r0);
        QuantizeEndpoint(max, out byte[] q1, out int p1, out int[] r1);

        Span<byte> indices = stackalloc byte[16];
        for (int i = 0; i < 16; i++)
            indices[i] = BestIndex(r0, r1, block, i * 4);

        // Mode 6 stores index 0 in 3 bits, so it must be 0..7. Swapping the endpoints and inverting
        // every index preserves the reconstruction exactly (the weight table is symmetric).
        if (indices[0] >= 8)
        {
            (q0, q1) = (q1, q0);
            (p0, p1) = (p1, p0);
            (r0, r1) = (r1, r0);
            for (int i = 0; i < 16; i++)
                indices[i] = (byte)(15 - indices[i]);
        }

        ulong lo = 0, hi = 0;
        int pos = 0;
        Put(ref lo, ref hi, ref pos, 0x40, 7); // mode 6 = 0b1000000
        Put(ref lo, ref hi, ref pos, q0[0], 7);
        Put(ref lo, ref hi, ref pos, q1[0], 7);
        Put(ref lo, ref hi, ref pos, q0[1], 7);
        Put(ref lo, ref hi, ref pos, q1[1], 7);
        Put(ref lo, ref hi, ref pos, q0[2], 7);
        Put(ref lo, ref hi, ref pos, q1[2], 7);
        Put(ref lo, ref hi, ref pos, q0[3], 7);
        Put(ref lo, ref hi, ref pos, q1[3], 7);
        Put(ref lo, ref hi, ref pos, (uint)p0, 1);
        Put(ref lo, ref hi, ref pos, (uint)p1, 1);
        Put(ref lo, ref hi, ref pos, indices[0], 3);
        for (int i = 1; i < 16; i++)
            Put(ref lo, ref hi, ref pos, indices[i], 4);

        for (int i = 0; i < 8; i++)
            dst[i] = (byte)(lo >> (i * 8));
        for (int i = 0; i < 8; i++)
            dst[8 + i] = (byte)(hi >> (i * 8));
    }

    /// <summary>
    /// Quantizes four 8-bit channel values to a 7-bit endpoint plus a shared P-bit, minimising the
    /// squared error of the reconstructed 8-bit value <c>(q &lt;&lt; 1) | p</c>.
    /// </summary>
    private static void QuantizeEndpoint(ReadOnlySpan<byte> v, out byte[] q, out int p, out int[] recon)
    {
        q = new byte[4];
        recon = new int[4];
        long bestError = long.MaxValue;
        p = 0;
        Span<byte> candidateQ = stackalloc byte[4];
        Span<int> candidateR = stackalloc int[4];
        for (int candidate = 0; candidate <= 1; candidate++)
        {
            long error = 0;
            for (int c = 0; c < 4; c++)
            {
                int qv = Math.Clamp((v[c] - candidate + 1) >> 1, 0, 127);
                int rv = (qv << 1) | candidate;
                int diff = rv - v[c];
                error += (long)diff * diff;
                candidateQ[c] = (byte)qv;
                candidateR[c] = rv;
            }
            if (error < bestError)
            {
                bestError = error;
                p = candidate;
                candidateQ.CopyTo(q);
                candidateR.CopyTo(recon);
            }
        }
    }

    private static byte BestIndex(int[] e0, int[] e1, ReadOnlySpan<byte> block, int offset)
    {
        int best = 0;
        long bestError = long.MaxValue;
        for (int i = 0; i < 16; i++)
        {
            int w = Weights4[i];
            long error = 0;
            for (int c = 0; c < 4; c++)
            {
                int interp = (e0[c] * (64 - w) + e1[c] * w + 32) >> 6;
                int diff = interp - block[offset + c];
                error += (long)diff * diff;
            }
            if (error < bestError)
            {
                bestError = error;
                best = i;
            }
        }
        return (byte)best;
    }

    private static void Put(ref ulong lo, ref ulong hi, ref int pos, uint value, int count)
    {
        for (int i = 0; i < count; i++)
        {
            if (((value >> i) & 1) != 0)
            {
                int bit = pos + i;
                if (bit < 64)
                    lo |= 1UL << bit;
                else
                    hi |= 1UL << (bit - 64);
            }
        }
        pos += count;
    }
}
