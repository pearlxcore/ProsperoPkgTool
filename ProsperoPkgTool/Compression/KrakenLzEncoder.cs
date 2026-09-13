using System.Numerics;

namespace ProsperoPkgTool.Compression;

/// <summary>
/// Clean-room producer for the headerless Kraken "newLZ" sub-chunk accepted by
/// <see cref="KrakenDecoder"/>. Emits one or two 128 KiB "excess mode" chunks per block, each with
/// raw (memcpy) literal/command/offset/length arrays and a forward/backward bit region carrying the
/// offset extra bits.
///
/// <para>
/// Unlike the first version of this encoder (distance-1 run expansion only), this one performs a
/// general LZ77 parse: a hash-chain match finder finds matches at any distance &gt;= 8 over the
/// already-decoded bytes of the block, so repeated structures - not just runs of one byte - are
/// captured. It shares the newLZ framing with the decoder it inverts; no GPL/Oodle source was used.
/// </para>
/// </summary>
internal static class KrakenLzEncoder
{
    private const int SeedSize = 8;

    /// <summary>Shortest match worth a command (command byte + offset byte(s) cost more than literals).</summary>
    private const int MinMatch = 4;

    /// <summary>A match may not start within this many bytes of the chunk end.</summary>
    private const int NoMatchZone = 16;

    /// <summary>The final bytes of a chunk must be literal tail (a match may not cover them).</summary>
    private const int LiteralTail = 8;

    /// <summary>Hard cap on 255-escaped length entries per sub-chunk (matches the decoder's guard).</summary>
    private const int MaxLengthEscapes = 512;

    private const int ChunkSize = KrakenEncoder.ChunkSize;
    private const int MaxBlockSize = KrakenEncoder.MaxBlockSize;

    // Hash-chain match finder parameters.
    private const int HashBits = 16;
    private const int HashSize = 1 << HashBits;
    private const int MaxChain = 48;

    // Per-thread scratch reused across blocks. A 64K-entry head table and an n-entry chain array were
    // allocated for every 128/256 KiB block, which dominated large builds' allocation/GC. The finder
    // fully re-initialises head each call and never reads stale prev entries, so reuse is byte-identical.
    [System.ThreadStatic] private static int[]? t_head;
    [System.ThreadStatic] private static int[]? t_prev;

    internal static KrakenEncoder.EncodedBlock? Encode(ReadOnlySpan<byte> input)
    {
        // A seeded chunk must carry SeedSize literal bytes before any match; shorter inputs fall
        // back to a stored block.
        if (input.Length is < SeedSize or > MaxBlockSize)
            return null;

        byte[] data = input.ToArray();
        int n = data.Length;
        int[] head = t_head ??= new int[HashSize];
        Array.Fill(head, -1);
        int[] prev = t_prev is { } cached && cached.Length >= n ? cached : (t_prev = new int[n]);
        int nextInsert = 0;

        int firstEnd = Math.Min(n, ChunkSize);
        byte[]? first = EncodeChunk(data, head, prev, ref nextInsert, 0, firstEnd, withSeed: true);
        if (first is null)
            return null;

        if (n <= ChunkSize)
        {
            if (first.Length >= n)
                return null;
            return new KrakenEncoder.EncodedBlock
            {
                Payload = first,
                Flags = 0x02,
                FirstChunkCompressedLength = 0,
                UncompressedLength = n,
                Mode = KrakenEncoder.LiteralMode.NewLz,
            };
        }

        byte[]? second = EncodeChunk(data, head, prev, ref nextInsert, ChunkSize, n, withSeed: false);
        if (second is null)
            return null;
        if (first.Length + second.Length >= n)
            return null;

        var payload = new byte[first.Length + second.Length];
        first.CopyTo(payload, 0);
        second.CopyTo(payload, first.Length);
        return new KrakenEncoder.EncodedBlock
        {
            Payload = payload,
            Flags = 0x22,
            FirstChunkCompressedLength = first.Length,
            UncompressedLength = n,
            Mode = KrakenEncoder.LiteralMode.NewLz,
        };
    }

    private static byte[]? EncodeChunk(byte[] data, int[] head, int[] prev, ref int nextInsert,
        int chunkStart, int chunkEnd, bool withSeed)
    {
        int parseStart = withSeed ? SeedSize : chunkStart;
        int matchStartLimit = chunkEnd - NoMatchZone;
        int matchEndLimit = chunkEnd - LiteralTail;

        var literal = new List<byte>(chunkEnd - chunkStart);
        var command = new List<byte>();
        var packedOffs = new List<byte>();
        var lengths = new List<byte>();
        var escapes = new List<uint>();
        var forwardBits = new MsbBitWriter();
        var backwardBits = new MsbBitWriter();
        int offsetIndex = 0;

        int literalStart = parseStart;
        int pos = parseStart;

        while (pos < matchStartLimit)
        {
            EnsureInserted(data, head, prev, ref nextInsert, pos);
            FindMatch(data, head, prev, pos, matchEndLimit, out int matchLen, out int matchDistance);
            if (matchLen < MinMatch)
            {
                pos++;
                continue;
            }

            // Lazy matching: if a noticeably longer match starts at pos+1, drop one literal at pos
            // and take the longer match instead.
            if (pos + 1 < matchStartLimit)
            {
                EnsureInserted(data, head, prev, ref nextInsert, pos + 1);
                FindMatch(data, head, prev, pos + 1, matchEndLimit, out int lazyLength, out _);
                if (lazyLength > matchLen + 1)
                {
                    pos++;
                    continue;
                }
            }

            int litLength = pos - literalStart;
            for (int k = literalStart; k < pos; k++)
                literal.Add(data[k]);
            byte litField = litLength <= 2 ? (byte)litLength : (byte)3;
            byte matchField = matchLen <= 16 ? (byte)(matchLen - 2) : (byte)15;
            command.Add((byte)(0xC0 | (matchField << 2) | litField));

            EncodeOffset(matchDistance, out byte offByte, out int extraBits, out uint extraValue);
            packedOffs.Add(offByte);
            if (extraBits > 0)
            {
                if ((offsetIndex & 1) == 0)
                    forwardBits.WriteBits(extraValue, extraBits);
                else
                    backwardBits.WriteBits(extraValue, extraBits);
            }
            offsetIndex++;

            if (litLength >= 3)
                AppendLiteralLength(lengths, escapes, litLength);
            if (matchLen > 16)
                AppendMatchLength(lengths, escapes, matchLen);
            if (escapes.Count > MaxLengthEscapes)
                return null;

            pos += matchLen;
            literalStart = pos;
        }

        // Trailing literal tail (at least LiteralTail bytes by construction of matchEndLimit).
        EnsureInserted(data, head, prev, ref nextInsert, chunkEnd);
        for (int k = literalStart; k < chunkEnd; k++)
            literal.Add(data[k]);

        if (command.Count != packedOffs.Count)
            return null;

        byte[] excess = EncodeExcess(escapes);
        byte[] excessFlag = EncodeExcessCount(excess.Length);
        byte[] literalArray = EncodeArray(literal);
        byte[] commandArray = EncodeArray(command);
        byte[] offsArray = EncodeArray(packedOffs);
        byte[] lenArray = EncodeArray(lengths);

        byte[] forward = forwardBits.ToArray();
        byte[] backward = backwardBits.ToArray();
        var region = new byte[forward.Length + backward.Length];
        forward.CopyTo(region, 0);
        for (int i = 0; i < backward.Length; i++)
            region[region.Length - 1 - i] = backward[i];

        int total = (withSeed ? SeedSize : 0) + excessFlag.Length + literalArray.Length
            + commandArray.Length + 1 + offsArray.Length + lenArray.Length + region.Length + excess.Length;
        var payload = new byte[total];
        int p = 0;
        if (withSeed)
        {
            data.AsSpan(0, SeedSize).CopyTo(payload.AsSpan(p));
            p += SeedSize;
        }
        excessFlag.CopyTo(payload.AsSpan(p)); p += excessFlag.Length;
        literalArray.CopyTo(payload.AsSpan(p)); p += literalArray.Length;
        commandArray.CopyTo(payload.AsSpan(p)); p += commandArray.Length;
        payload[p++] = 0x80; // offsets: single table, scaling 1
        offsArray.CopyTo(payload.AsSpan(p)); p += offsArray.Length;
        lenArray.CopyTo(payload.AsSpan(p)); p += lenArray.Length;
        region.CopyTo(payload.AsSpan(p)); p += region.Length;
        excess.CopyTo(payload.AsSpan(p));
        return payload;
    }

    // ---- Match finder ----

    private static void EnsureInserted(byte[] data, int[] head, int[] prev, ref int nextInsert, int upto)
    {
        int n = data.Length;
        while (nextInsert < upto && nextInsert + 2 < n)
        {
            int h = Hash(data, nextInsert);
            prev[nextInsert] = head[h];
            head[h] = nextInsert;
            nextInsert++;
        }
        if (nextInsert < upto)
            nextInsert = upto;
    }

    private static int Hash(byte[] data, int p)
    {
        uint v = (uint)(data[p] | (data[p + 1] << 8) | (data[p + 2] << 16));
        return (int)((v * 2654435761u) >> (32 - HashBits));
    }

    private static void FindMatch(byte[] data, int[] head, int[] prev, int pos,
        int matchEndLimit, out int bestLength, out int bestDistance)
    {
        bestLength = 0;
        bestDistance = 0;
        // Matches may run to the end of the literal tail; long matches use the length-escape path.
        int maxLength = matchEndLimit - pos;
        if (maxLength < MinMatch)
            return;

        int h = Hash(data, pos);
        int candidate = head[h];
        int chain = 0;
        while (candidate >= 0 && chain < MaxChain)
        {
            int distance = pos - candidate;
            // A usable match needs at least MinMatch (4) bytes, and the 3-byte hash collides freely.
            // Gate on a 4-byte prefix before measuring the run: this is a pure speed-up and yields the
            // same result, because a length below MinMatch is reported as "no match" either way.
            if (distance >= SeedSize
                && data[candidate] == data[pos] && data[candidate + 1] == data[pos + 1]
                && data[candidate + 2] == data[pos + 2] && data[candidate + 3] == data[pos + 3])
            {
                int length = MinMatch;
                while (length < maxLength && data[candidate + length] == data[pos + length])
                    length++;
                if (length > bestLength)
                {
                    bestLength = length;
                    bestDistance = distance;
                    if (length >= maxLength)
                        break;
                }
            }
            candidate = prev[candidate];
            chain++;
        }
    }

    // ---- Offset encoding (inverts BitReader.ReadExtra + UnpackOffsets) ----

    private static void EncodeOffset(int distance, out byte packedOffs, out int extraBits, out uint extraValue)
    {
        int off = distance + SeedSize; // decoder: offs = -(off - 8), distance = off - 8
        int n = 0;
        while ((off >> n) >= 16)
            n++;
        int baseValue = (off >> n) - 8; // 0..7
        extraValue = (uint)(off - ((8 + baseValue) << n));
        extraBits = n;
        packedOffs = (byte)((n << 3) | baseValue);
    }

    // ---- Length streams ----

    private static void AppendLiteralLength(List<byte> lengths, List<uint> escapes, int litLength)
    {
        int b = litLength - 3;
        if (b < 255)
            lengths.Add((byte)b);
        else
        {
            lengths.Add(255);
            escapes.Add((uint)(litLength - 258));
        }
    }

    private static void AppendMatchLength(List<byte> lengths, List<uint> escapes, int matchLength)
    {
        int b = matchLength - 17;
        if (b < 255)
            lengths.Add((byte)b);
        else
        {
            lengths.Add(255);
            escapes.Add((uint)(matchLength - 272));
        }
    }

    /// <summary>
    /// Prefers a Huffman-coded (type 2) array when it is smaller than the raw (type 0) form; the
    /// decoder accepts either. Falls back to raw for tiny or incompressible arrays.
    /// </summary>
    private static byte[] EncodeArray(IReadOnlyList<byte> data)
    {
        byte[] raw = RawArray(data);
        if (data.Count < 2)
            return raw;
        var source = new byte[data.Count];
        for (int i = 0; i < source.Length; i++)
            source[i] = data[i];
        byte[]? huffman = KrakenHuffmanArrayEncoder.TryEncode(source);
        return huffman is not null && huffman.Length < raw.Length ? huffman : raw;
    }

    /// <summary>Raw (type 0) entropy array: a 3-byte big-endian byte length followed by the data.</summary>
    private static byte[] RawArray(IReadOnlyList<byte> data)
    {
        var result = new byte[3 + data.Count];
        result[0] = (byte)(data.Count >> 16);
        result[1] = (byte)(data.Count >> 8);
        result[2] = (byte)data.Count;
        for (int i = 0; i < data.Count; i++)
            result[3 + i] = data[i];
        return result;
    }

    /// <summary>
    /// Encodes the post-seed excess length. The decoder reads a low 6-bit count and, when that value
    /// exceeds 31, adds a second byte scaled by 32.
    /// </summary>
    private static byte[] EncodeExcessCount(int count)
    {
        if (count <= 31)
            return [(byte)(0x80 | count)];
        int high = (count - 32) / 32;
        int low = count - high * 32; // 32..63
        return [(byte)(0x80 | low), (byte)high];
    }

    /// <summary>Packs the escaped length values into the forward/backward bit region.</summary>
    private static byte[] EncodeExcess(IReadOnlyList<uint> values)
    {
        var forward = new MsbBitWriter();
        var backward = new MsbBitWriter();
        for (int i = 0; i < values.Count; i++)
        {
            if ((i & 1) == 0)
                WriteLength(forward, values[i]);
            else
                WriteLength(backward, values[i]);
        }

        byte[] f = forward.ToArray();
        byte[] b = backward.ToArray();
        var region = new byte[f.Length + b.Length];
        f.CopyTo(region, 0);
        for (int i = 0; i < b.Length; i++)
            region[region.Length - 1 - i] = b[i];
        return region;
    }

    /// <summary>Inverts <see cref="KrakenDecoder"/>'s forward/backward length reader.</summary>
    private static void WriteLength(MsbBitWriter writer, uint value)
    {
        uint code = value + 64;
        int leadingZeros = BitOperations.Log2(code) - 6;
        if (leadingZeros < 0 || leadingZeros > 12)
            throw new InvalidOperationException("Kraken length value is outside the encodable range.");
        for (int i = 0; i < leadingZeros; i++)
            writer.WriteBit(0);
        writer.WriteBit(1);
        int width = leadingZeros + 6;
        writer.WriteBits(code - (1u << width), width);
    }

    private sealed class MsbBitWriter
    {
        private readonly List<byte> _bytes = [];
        private int _current;
        private int _bits;

        public void WriteBit(int bit)
        {
            _current = (_current << 1) | (bit & 1);
            if (++_bits == 8)
            {
                _bytes.Add((byte)_current);
                _current = 0;
                _bits = 0;
            }
        }

        public void WriteBits(uint value, int count)
        {
            for (int i = count - 1; i >= 0; i--)
                WriteBit((int)((value >> i) & 1));
        }

        public byte[] ToArray()
        {
            if (_bits == 0)
                return _bytes.ToArray();
            var result = new byte[_bytes.Count + 1];
            _bytes.CopyTo(result, 0);
            result[^1] = (byte)(_current << (8 - _bits));
            return result;
        }
    }
}
