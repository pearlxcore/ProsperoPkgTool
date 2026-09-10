using System.Numerics;

namespace ProsperoPkgTool.Compression;

/// <summary>
/// Clean-room producer for the headerless Kraken "newLZ" sub-chunk accepted by
/// <see cref="KrakenDecoder"/>. It emits raw (memcpy) literal/command arrays, a single-distance
/// table, and 255-escaped lengths carried in the post-seed excess region.
///
/// The only match form produced is a distance-1 run expansion: a byte that equals its predecessor
/// is emitted as a match whose source is the immediately preceding output byte. This models the
/// long zero runs and repeated fields that dominate an inner-image metadata block. No GPL/Oodle
/// encoder code, table, or naming choice was used; the framing was derived by inverting the reads
/// in <see cref="KrakenDecoder"/> and is validated by round-tripping through it.
/// </summary>
internal static class KrakenLzEncoder
{
    private const int SeedSize = 8;

    /// <summary>Shortest repeated-byte run worth a match (below this a run is kept as literals).</summary>
    private const int MinRun = 4;

    /// <summary>Hard cap on 255-escaped length entries per sub-chunk (matches the decoder's guard).</summary>
    private const int MaxLengthEscapes = 512;

    private const int ChunkSize = KrakenEncoder.ChunkSize;
    private const int MaxBlockSize = KrakenEncoder.MaxBlockSize;

    /// <summary>A literal length &gt;= this value needs a 255-escaped length entry.</summary>
    private const int LiteralEscapeThreshold = 258; // lenStream = u32 + 258

    /// <summary>A match length &gt;= this value needs a 255-escaped length entry (actual = u32 + 272).</summary>
    private const int MatchEscapeThreshold = 272;

    internal static KrakenEncoder.EncodedBlock? Encode(ReadOnlySpan<byte> input)
    {
        if (input.Length is <= 0 or > MaxBlockSize)
            return null;

        int firstLength = Math.Min(input.Length, ChunkSize);
        byte[]? first = EncodeChunk(input[..firstLength], withSeed: true);
        if (first is null)
            return null;

        if (input.Length <= ChunkSize)
        {
            if (first.Length >= input.Length)
                return null;
            return new KrakenEncoder.EncodedBlock
            {
                Payload = first,
                Flags = 0x02,
                FirstChunkCompressedLength = 0,
                UncompressedLength = input.Length,
                Mode = KrakenEncoder.LiteralMode.NewLz,
            };
        }

        byte[]? second = EncodeChunk(input[ChunkSize..], withSeed: false);
        if (second is null)
            return null;

        int total = first.Length + second.Length;
        if (total >= input.Length)
            return null;

        var payload = new byte[total];
        first.CopyTo(payload, 0);
        second.CopyTo(payload, first.Length);
        return new KrakenEncoder.EncodedBlock
        {
            Payload = payload,
            Flags = 0x22,
            FirstChunkCompressedLength = first.Length,
            UncompressedLength = input.Length,
            Mode = KrakenEncoder.LiteralMode.NewLz,
        };
    }

    private static byte[]? EncodeChunk(ReadOnlySpan<byte> data, bool withSeed)
    {
        int start = withSeed ? SeedSize : 0;
        var literalStream = new List<byte>(data.Length);
        var commandStream = new List<byte>();
        var distanceStream = new List<byte>();
        var lengthStream = new List<byte>();
        var escapeValues = new List<uint>();

        int literalStart = start;
        int pos = start;

        while (pos < data.Length)
        {
            int i = Math.Max(pos, 1);
            while (i < data.Length && data[i] != data[i - 1])
                i++;
            if (i >= data.Length)
                break;

            byte value = data[i - 1];
            int end = i;
            while (end < data.Length && data[end] == value)
                end++;
            int runLength = end - i;
            if (runLength < MinRun)
            {
                pos = end;
                continue;
            }

            int literalLength = i - literalStart;
            for (int k = literalStart; k < i; k++)
                literalStream.Add(data[k]);

            byte literalField = literalLength <= 2 ? (byte)literalLength : (byte)3;
            int matchField = runLength <= 16 ? runLength - 2 : 15;
            commandStream.Add((byte)(0xC0 | (matchField << 2) | literalField));
            distanceStream.Add(0x01);

            if (literalLength >= 3)
            {
                if (literalLength < LiteralEscapeThreshold)
                    lengthStream.Add((byte)(literalLength - 3));
                else
                {
                    lengthStream.Add(255);
                    escapeValues.Add((uint)(literalLength - LiteralEscapeThreshold));
                }
            }
            if (runLength > 16)
            {
                if (runLength < MatchEscapeThreshold)
                    lengthStream.Add((byte)(runLength - 17));
                else
                {
                    lengthStream.Add(255);
                    escapeValues.Add((uint)(runLength - MatchEscapeThreshold));
                }
            }

            if (escapeValues.Count > MaxLengthEscapes)
                return null;

            pos = end;
            literalStart = end;
        }

        if (commandStream.Count != distanceStream.Count)
            return null;

        for (int k = literalStart; k < data.Length; k++)
            literalStream.Add(data[k]);

        byte[] excess = EncodeExcess(escapeValues);
        byte[] excessFlag = EncodeExcessCount(excess.Length);
        byte[] literalArray = RawArray(literalStream);
        byte[] commandArray = RawArray(commandStream);
        byte[] distanceArray = RawArray(distanceStream);
        byte[] lengthArray = RawArray(lengthStream);

        int total = (withSeed ? SeedSize : 0) + excessFlag.Length + literalArray.Length
            + commandArray.Length + 1 + distanceArray.Length + lengthArray.Length + excess.Length;
        var payload = new byte[total];
        int p = 0;
        if (withSeed)
        {
            data[..SeedSize].CopyTo(payload.AsSpan(p));
            p += SeedSize;
        }
        excessFlag.CopyTo(payload.AsSpan(p)); p += excessFlag.Length;
        literalArray.CopyTo(payload.AsSpan(p)); p += literalArray.Length;
        commandArray.CopyTo(payload.AsSpan(p)); p += commandArray.Length;
        payload[p++] = 0x80; // offsets: single table, no scaling
        distanceArray.CopyTo(payload.AsSpan(p)); p += distanceArray.Length;
        lengthArray.CopyTo(payload.AsSpan(p)); p += lengthArray.Length;
        excess.CopyTo(payload.AsSpan(p));
        return payload;
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
    /// exceeds 31, adds a second byte scaled by 32; the low field is chosen so the arithmetic yields
    /// <paramref name="count"/> exactly.
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
