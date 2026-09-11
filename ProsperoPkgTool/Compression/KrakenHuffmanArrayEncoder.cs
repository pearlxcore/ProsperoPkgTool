namespace ProsperoPkgTool.Compression;

/// <summary>
/// Clean-room producer for a Kraken entropy "array" (DecodeBytes chunk-type 2, single 3-stream
/// split) that <see cref="KrakenDecoder"/> decodes back to the original bytes. Emits the "simple"
/// sub-mode of <c>HuffReadCodeLengthsOld</c> (a per-symbol code-length list), a length-limited
/// canonical Huffman code, and the three interleaved low-bit-first symbol streams that the decoder's
/// scalar core reads.
///
/// <para>
/// The decoder only accepts code lengths in 1..11 and a complete prefix code. Code lengths are
/// produced by a package-merge length-limited Huffman; the result is rejected (returns null) unless
/// it is complete and actually smaller than the raw array, so the caller can always fall back to a
/// stored array. No GPL/Oodle source was used; the framing was derived by inverting
/// <see cref="KrakenDecoder"/> and validated by round-tripping through it.
/// </para>
/// </summary>
internal static class KrakenHuffmanArrayEncoder
{
    private const int Alphabet = 256;
    private const int MaxBits = 11;
    private const int ChunkType = 2;

    private static readonly uint[] CodePrefixBase =
        { 0, 0, 2, 6, 0xE, 0x1E, 0x3E, 0x7E, 0xFE, 0x1FE, 0x2FE, 0x3FE };

    /// <summary>
    /// Encodes one byte array into a DecodeBytes entropy record (5-byte header + table + streams),
    /// or null when it is not representable or would not be smaller than the raw array.
    /// </summary>
    public static byte[]? TryEncode(ReadOnlySpan<byte> data)
    {
        int d = data.Length;
        if (d < 2 || d > 0x3FFFF)
            return null;

        Span<int> freq = stackalloc int[Alphabet];
        for (int i = 0; i < d; i++)
            freq[data[i]]++;
        int distinct = 0;
        for (int s = 0; s < Alphabet; s++)
            if (freq[s] != 0)
                distinct++;

        if (distinct == 1)
        {
            // The decoder rejects a single-symbol top-level array; synthesize a phantom second
            // symbol so the two-symbol path is used. Only the real symbol appears in the body.
            int realSymbol = 0;
            for (int s = 0; s < Alphabet; s++)
                if (freq[s] != 0)
                {
                    realSymbol = s;
                    break;
                }
            int phantom = realSymbol == 0 ? 1 : 0;
            freq[phantom] = 1;
            distinct = 2;
        }

        byte[]? codeLengths = BuildLengthLimitedLengths(freq.ToArray());
        if (codeLengths is null)
            return null;

        ushort[] codes = BuildCanonicalCodes(codeLengths);
        var reversed = new ushort[Alphabet];
        for (int s = 0; s < Alphabet; s++)
            if (codeLengths[s] != 0)
                reversed[s] = (ushort)ReverseBits(codes[s], codeLengths[s]);

        byte[]? table = BuildSimpleCodeLengthTable(codeLengths, distinct);
        if (table is null)
            return null;

        var streamA = new LsbBitWriter();
        var streamB = new LsbBitWriter();
        var streamC = new LsbBitWriter();
        for (int i = 0; i < d; i++)
        {
            byte symbol = data[i];
            uint rev = reversed[symbol];
            int len = codeLengths[symbol];
            switch (i % 3)
            {
                case 0: streamA.Write(rev, len); break;
                case 1: streamB.Write(rev, len); break;
                default: streamC.Write(rev, len); break;
            }
        }

        byte[] a = streamA.ToBytesPadded();
        byte[] b = streamB.ToBytesPadded();
        byte[] c = streamC.ToBytesPadded();
        if (a.Length > 0xFFFF)
            return null; // the type-2 split field is 16 bits

        int bodySize = table.Length + 2 + a.Length + c.Length + b.Length;
        if (bodySize >= d)
            return null;

        byte[] array = BuildEntropyArray(bodySize, d, out int bodyOffset);
        int p = bodyOffset;
        table.CopyTo(array, p); p += table.Length;
        array[p++] = (byte)(a.Length & 0xFF);
        array[p++] = (byte)((a.Length >> 8) & 0xFF);
        a.CopyTo(array, p); p += a.Length;
        c.CopyTo(array, p); p += c.Length;
        for (int i = 0; i < b.Length; i++)
            array[p + i] = b[b.Length - 1 - i];
        return array;
    }

    // Long-form DecodeBytes entropy header: { chunkType, (dstSize-1), srcSize } packed as the
    // decoder reads it (src[0] = chunkType<<4 | high4(dstSize-1); src[1..4] = BE(srcSize | low14(dstSize-1)<<18)).
    private static byte[] BuildEntropyArray(int srcSize, int dstSize, out int bodyOffset)
    {
        const int headerSize = 5;
        var array = new byte[headerSize + srcSize];
        int dstMinusOne = dstSize - 1;
        array[0] = (byte)((ChunkType << 4) | ((dstMinusOne >> 14) & 0xF));
        uint bits = (uint)(srcSize | ((dstMinusOne & 0x3FFF) << 18));
        array[1] = (byte)(bits >> 24);
        array[2] = (byte)(bits >> 16);
        array[3] = (byte)(bits >> 8);
        array[4] = (byte)bits;
        bodyOffset = headerSize;
        return array;
    }

    // [0][0][numSymbols:8][codeLenBits:3] then per present symbol {sym:8, (len-1):codeLenBits}.
    private static byte[]? BuildSimpleCodeLengthTable(byte[] codeLengths, int distinct)
    {
        if (distinct < 2 || distinct >= Alphabet)
            return null;
        int maxLength = 0;
        for (int s = 0; s < Alphabet; s++)
            if (codeLengths[s] > maxLength)
                maxLength = codeLengths[s];
        int codeLenBits = BitWidth(maxLength - 1);
        if (codeLenBits > 4)
            return null;

        var header = new MsbBitWriter();
        header.Write(0, 1);              // Old code-length form
        header.Write(0, 1);              // simple list sub-mode
        header.Write((uint)distinct, 8);
        header.Write((uint)codeLenBits, 3);
        for (int s = 0; s < Alphabet; s++)
        {
            if (codeLengths[s] == 0)
                continue;
            header.Write((uint)s, 8);
            if (codeLenBits > 0)
                header.Write((uint)(codeLengths[s] - 1), codeLenBits);
        }
        return header.ToBytesPadded();
    }

    // ---- Length-limited Huffman (package-merge) ----

    private static byte[]? BuildLengthLimitedLengths(int[] freq)
    {
        var present = new List<int>();
        for (int s = 0; s < Alphabet; s++)
            if (freq[s] > 0)
                present.Add(s);
        int n = present.Count;
        if (n == 0)
            return null;
        if (n == 1)
        {
            var single = new byte[Alphabet];
            single[present[0]] = 1;
            return single;
        }

        present.Sort((a, b) => freq[a] != freq[b] ? freq[a].CompareTo(freq[b]) : a.CompareTo(b));

        var weight = new List<long>();
        var left = new List<int>();
        var right = new List<int>();
        var leafOf = new List<int>();
        var leaves = new List<int>();
        for (int i = 0; i < n; i++)
        {
            weight.Add(freq[present[i]]);
            left.Add(-1);
            right.Add(-1);
            leafOf.Add(present[i]);
            leaves.Add(weight.Count - 1);
        }

        var current = new List<int>(leaves);
        for (int level = 1; level < MaxBits; level++)
        {
            var packages = new List<int>();
            for (int i = 0; i + 1 < current.Count; i += 2)
            {
                int a = current[i], b = current[i + 1];
                weight.Add(weight[a] + weight[b]);
                left.Add(a);
                right.Add(b);
                leafOf.Add(-1);
                packages.Add(weight.Count - 1);
            }
            current = MergeByWeight(leaves, packages, weight);
        }

        int select = 2 * n - 2;
        var counts = new int[Alphabet];
        for (int i = 0; i < select && i < current.Count; i++)
            AddLeafCounts(current[i], left, right, leafOf, counts);

        var lengths = new byte[Alphabet];
        long kraft = 0;
        for (int s = 0; s < Alphabet; s++)
        {
            int length = counts[s];
            if (freq[s] > 0 && (length < 1 || length > MaxBits))
                return null;
            lengths[s] = (byte)length;
            if (freq[s] > 0)
                kraft += 1L << (MaxBits - length);
        }
        return kraft == (1L << MaxBits) ? lengths : null;
    }

    private static List<int> MergeByWeight(List<int> a, List<int> b, List<long> weight)
    {
        var result = new List<int>(a.Count + b.Count);
        int i = 0, j = 0;
        while (i < a.Count && j < b.Count)
            result.Add(weight[a[i]] <= weight[b[j]] ? a[i++] : b[j++]);
        while (i < a.Count)
            result.Add(a[i++]);
        while (j < b.Count)
            result.Add(b[j++]);
        return result;
    }

    private static void AddLeafCounts(int item, List<int> left, List<int> right, List<int> leafOf, int[] counts)
    {
        var stack = new Stack<int>();
        stack.Push(item);
        while (stack.Count > 0)
        {
            int current = stack.Pop();
            if (leafOf[current] >= 0)
                counts[leafOf[current]]++;
            else
            {
                stack.Push(left[current]);
                stack.Push(right[current]);
            }
        }
    }

    // Canonical code assignment matching HuffBuildLookup: symbols grouped by (length asc, symbol asc),
    // with codes taken from a running 11-bit slot (not a fixed per-length base).
    private static ushort[] BuildCanonicalCodes(byte[] codeLengths)
    {
        var codes = new ushort[Alphabet];
        uint currentSlot = 0;
        for (int length = 1; length <= MaxBits; length++)
        {
            int step = 1 << (MaxBits - length);
            for (int s = 0; s < Alphabet; s++)
            {
                if (codeLengths[s] != length)
                    continue;
                codes[s] = (ushort)(currentSlot >> (MaxBits - length));
                currentSlot += (uint)step;
            }
        }
        return codes;
    }

    private static uint ReverseBits(uint value, int bitCount)
    {
        uint result = 0;
        for (int i = 0; i < bitCount; i++)
        {
            result = (result << 1) | (value & 1);
            value >>= 1;
        }
        return result;
    }

    private static int BitWidth(int value)
    {
        int width = 0;
        while (value > 0)
        {
            width++;
            value >>= 1;
        }
        return width;
    }

    // ---- Bit writers ----

    private sealed class MsbBitWriter
    {
        private readonly List<byte> _bytes = [];
        private uint _accumulator;
        private int _bits;

        public void Write(uint value, int count)
        {
            for (int i = count - 1; i >= 0; i--)
            {
                _accumulator = (_accumulator << 1) | ((value >> i) & 1u);
                if (++_bits == 8)
                {
                    _bytes.Add((byte)_accumulator);
                    _accumulator = 0;
                    _bits = 0;
                }
            }
        }

        public byte[] ToBytesPadded()
        {
            if (_bits > 0)
            {
                _bytes.Add((byte)(_accumulator << (8 - _bits)));
                _accumulator = 0;
                _bits = 0;
            }
            return _bytes.ToArray();
        }
    }

    private sealed class LsbBitWriter
    {
        private readonly List<byte> _bytes = [];
        private uint _accumulator;
        private int _bits;

        public void Write(uint value, int count)
        {
            if (count == 0)
                return;
            _accumulator |= (value & ((1u << count) - 1)) << _bits;
            _bits += count;
            while (_bits >= 8)
            {
                _bytes.Add((byte)_accumulator);
                _accumulator >>= 8;
                _bits -= 8;
            }
        }

        public byte[] ToBytesPadded()
        {
            if (_bits > 0)
            {
                _bytes.Add((byte)_accumulator);
                _accumulator = 0;
                _bits = 0;
            }
            return _bytes.ToArray();
        }
    }
}
