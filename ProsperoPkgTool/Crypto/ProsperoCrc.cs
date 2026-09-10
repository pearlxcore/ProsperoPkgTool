namespace ProsperoPkgTool.Crypto;

/// <summary>
/// Standard reflected CRC-32 (polynomial 0xEDB88320, init/xorout 0xFFFFFFFF) — the checksum the
/// ZIP container of the SI (install-metadata) segment stores in each member header. Table-driven,
/// incremental (<see cref="Update"/>) plus one-shot (<see cref="Compute"/>) forms.
/// </summary>
public static class ZipCrc32
{
    /// <summary>The reflected CRC-32 generator polynomial (0x04C11DB7 reflected).</summary>
    public const uint ReflectedPolynomial = 0xEDB88320u;

    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? ReflectedPolynomial ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        return table;
    }

    /// <summary>
    /// Continues a running CRC-32 over <paramref name="data"/>. Pass
    /// <see cref="uint.MaxValue"/> for a fresh checksum; the returned value is the internal
    /// running register (NOT yet finalized).
    /// </summary>
    public static uint Update(uint crc, ReadOnlySpan<byte> data)
    {
        uint c = crc;
        foreach (byte b in data)
            c = Table[(c ^ b) & 0xFF] ^ (c >> 8);
        return c;
    }

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

    private static readonly uint[] Table = BuildTable();

    private static uint[] BuildTable()
    {
        var table = new uint[256];
        for (uint n = 0; n < 256; n++)
        {
            uint c = n;
            for (int k = 0; k < 8; k++)
                c = (c & 1) != 0 ? ReflectedPolynomial ^ (c >> 1) : c >> 1;
            table[n] = c;
        }
        return table;
    }

    /// <summary>
    /// Continues a running CRC-32C over <paramref name="data"/>. Pass
    /// <see cref="uint.MaxValue"/> for a fresh checksum; the returned value is the internal
    /// running register (NOT yet finalized).
    /// </summary>
    public static uint Update(uint crc, ReadOnlySpan<byte> data)
    {
        uint c = crc;
        foreach (byte b in data)
            c = Table[(c ^ b) & 0xFF] ^ (c >> 8);
        return c;
    }

    /// <summary>Computes the finalized standard CRC-32C of <paramref name="data"/>.</summary>
    public static uint Compute(ReadOnlySpan<byte> data) => ~Update(uint.MaxValue, data);
}
