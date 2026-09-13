using System.Buffers.Binary;
using System.Runtime.Intrinsics.X86;

namespace ProsperoPkgTool.Crypto;

/// <summary>
/// Reflected CRC-32 helper shared by <see cref="ZipCrc32"/> and <see cref="ProsperoCrc32C"/>.
/// Uses a slicing-by-8 table (the classic 8-table reflected-CRC speed-up) so multi-gigabyte
/// reductions are not byte-at-a-time; the result is bit-identical to the bytewise form.
/// </summary>
internal static class ReflectedCrc32
{
    /// <summary>Builds the 8 slicing tables for a reflected polynomial (e.g. 0xEDB88320).</summary>
    public static uint[][] BuildTables(uint polynomial)
    {
        var tables = new uint[8][];
        tables[0] = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? polynomial ^ (c >> 1) : c >> 1;
            tables[0][n] = c;
        }
        for (int k = 1; k < 8; k++)
        {
            tables[k] = new uint[256];
            for (uint n = 0; n < 256; n++)
                tables[k][n] = (tables[k - 1][n] >> 8) ^ tables[0][tables[k - 1][n] & 0xFF];
        }
        return tables;
    }

    /// <summary>Continues a running reflected CRC over <paramref name="data"/> (register, not finalized).</summary>
    public static uint Update(uint crc, ReadOnlySpan<byte> data, uint[][] tables)
    {
        uint c = crc;
        uint[] t0 = tables[0];
        int i = 0;

        // Slicing-by-8: fold eight input bytes per step using the precomputed tables.
        for (; i + 8 <= data.Length; i += 8)
        {
            uint one = c ^ BinaryPrimitives.ReadUInt32LittleEndian(data[i..]);
            uint two = BinaryPrimitives.ReadUInt32LittleEndian(data[(i + 4)..]);
            c = tables[7][(byte)one] ^ tables[6][(byte)(one >> 8)]
              ^ tables[5][(byte)(one >> 16)] ^ tables[4][(byte)(one >> 24)]
              ^ tables[3][(byte)two] ^ tables[2][(byte)(two >> 8)]
              ^ tables[1][(byte)(two >> 16)] ^ t0[(byte)(two >> 24)];
        }

        for (; i < data.Length; i++)
            c = t0[(c ^ data[i]) & 0xFF] ^ (c >> 8);
        return c;
    }
}

/// <summary>
/// Standard reflected CRC-32 (polynomial 0xEDB88320, init/xorout 0xFFFFFFFF) — the checksum the
/// ZIP container of the SI (install-metadata) segment stores in each member header. Slicing-by-8,
/// incremental (<see cref="Update"/>) plus one-shot (<see cref="Compute"/>) forms.
/// </summary>
public static class ZipCrc32
{
    /// <summary>The reflected CRC-32 generator polynomial (0x04C11DB7 reflected).</summary>
    public const uint ReflectedPolynomial = 0xEDB88320u;

    private static readonly uint[][] Tables = ReflectedCrc32.BuildTables(ReflectedPolynomial);

    /// <summary>
    /// Continues a running CRC-32 over <paramref name="data"/>. Pass
    /// <see cref="uint.MaxValue"/> for a fresh checksum; the returned value is the internal
    /// running register (NOT yet finalized).
    /// </summary>
    public static uint Update(uint crc, ReadOnlySpan<byte> data) => ReflectedCrc32.Update(crc, data, Tables);

    /// <summary>Computes the finalized standard CRC-32 of <paramref name="data"/>.</summary>
    public static uint Compute(ReadOnlySpan<byte> data) => ~Update(uint.MaxValue, data);
}

/// <summary>
/// Standard reflected CRC-32C (Castagnoli, polynomial 0x1EDC6F41 / reflected 0x82F63B78,
/// init/xorout 0xFFFFFFFF) — the reducer used to build the SI's
/// <c>config/&lt;content-id&gt;/playgo-chunk.crc</c>: each 64 KiB block of the finalized mount
/// image is reduced and appended as a little-endian u32, in block order. Known-answer:
/// CRC-32C("123456789") == 0xE3069283.
/// </summary>
public static class ProsperoCrc32C
{
    /// <summary>The reflected CRC-32C generator polynomial (0x1EDC6F41 reflected).</summary>
    public const uint ReflectedPolynomial = 0x82F63B78u;

    private static readonly uint[][] Tables = ReflectedCrc32.BuildTables(ReflectedPolynomial);

    /// <summary>
    /// Continues a running CRC-32C over <paramref name="data"/>. Pass
    /// <see cref="uint.MaxValue"/> for a fresh checksum; the returned value is the internal
    /// running register (NOT yet finalized). Uses the SSE4.2 CRC32 instruction when available
    /// (the instruction's Castagnoli/reflected convention matches this register), else slicing-by-8.
    /// </summary>
    public static uint Update(uint crc, ReadOnlySpan<byte> data)
    {
        if (Sse42.IsSupported)
            return UpdateHardware(crc, data);
        return ReflectedCrc32.Update(crc, data, Tables);
    }

    private static uint UpdateHardware(uint crc, ReadOnlySpan<byte> data)
    {
        uint c = crc;
        int i = 0;
        for (; i + 8 <= data.Length; i += 8)
            c = (uint)Sse42.X64.Crc32(c, BinaryPrimitives.ReadUInt64LittleEndian(data[i..]));
        if (i + 4 <= data.Length)
        {
            c = Sse42.Crc32(c, BinaryPrimitives.ReadUInt32LittleEndian(data[i..]));
            i += 4;
        }
        if (i + 2 <= data.Length)
        {
            c = Sse42.Crc32(c, BinaryPrimitives.ReadUInt16LittleEndian(data[i..]));
            i += 2;
        }
        if (i < data.Length)
            c = Sse42.Crc32(c, data[i]);
        return c;
    }

    /// <summary>Computes the finalized standard CRC-32C of <paramref name="data"/>.</summary>
    public static uint Compute(ReadOnlySpan<byte> data) => ~Update(uint.MaxValue, data);
}
