namespace ProsperoPkgTool.Compression;

/// <summary>
/// Minimal clean-room producer for the decoder-confirmed headerless Kraken entropy subset.
/// This deliberately supports only uniform 128-KiB-or-smaller sub-chunks; all other input must
/// use the caller's stored fallback. It is not an Oodle/NewLZ encoder or an optimisation engine.
/// </summary>
public static class KrakenEncoder
{
    public const int ChunkSize = KrakenDecoder.ChunkSize;
    public const int MaxBlockSize = KrakenDecoder.MaxBlockSize;

    /// <summary>One self-describing result for a payload accepted by <see cref="KrakenDecoder"/>.</summary>
    public sealed class EncodedBlock
    {
        public required byte[] Payload { get; init; }
        public required int Flags { get; init; }
        public required int FirstChunkCompressedLength { get; init; }
        public required int UncompressedLength { get; init; }
        public required LiteralMode Mode { get; init; }
    }

    /// <summary>Decoder-confirmed headerless entropy representations produced by this class.</summary>
    public enum LiteralMode
    {
        UniformHuffman,
        FixedWidthHuffman,
        NewLz,
    }

    /// <summary>
    /// Attempts a headerless newLZ representation (raw literals, distance-1 run matches, escaped
    /// lengths in the excess region) that <see cref="KrakenDecoder.DecodeBlock"/> accepts. Returns
    /// null whenever the input is empty, larger than one 256-KiB block, uses more than 512 escaped
    /// lengths per sub-chunk, or does not shrink below the stored size. The caller keeps the stored
    /// fallback in every declined case.
    /// </summary>
    public static EncodedBlock? TryEncodeNewLz(ReadOnlySpan<byte> input) => KrakenLzEncoder.Encode(input);

    /// <summary>
    /// Attempts a deterministic representation. Each sub-chunk must contain exactly one byte
    /// value, encoded as the decoder's single-symbol Huffman-array form. The return value is null
    /// whenever the input cannot be reduced below stored size.
    /// </summary>
    public static EncodedBlock? TryEncode(ReadOnlySpan<byte> input)
    {
        if (input.Length is <= 0 or > MaxBlockSize)
            return null;
        int firstLength = Math.Min(input.Length, ChunkSize);
        byte[]? first = EncodeLiteralArray(input[..firstLength], out LiteralMode firstMode);
        if (first is null) return null;
        if (input.Length <= ChunkSize)
        {
            if (first.Length >= input.Length)
                return null;
            // A bare 8-byte even chunk exactly matches the NAPS dedup zero-hole signature
            // (Even=1/Odd=0/Clen=8), which native and reference readers decode as zeros. Route
            // uniform content through the newLZ representation instead (its Even selector is 5,
            // so it can never be mistaken for a hole) — this still compresses but is unambiguous.
            if (first.Length == 8)
                return KrakenLzEncoder.Encode(input);
            return new EncodedBlock { Payload = first, Flags = 0, FirstChunkCompressedLength = 0, UncompressedLength = input.Length, Mode = firstMode };
        }

        byte[]? second = EncodeLiteralArray(input[ChunkSize..], out LiteralMode secondMode);
        if (second is null) return null;
        byte[] payload = new byte[first.Length + second.Length];
        first.CopyTo(payload, 0);
        second.CopyTo(payload, first.Length);
        if (payload.Length >= input.Length)
            return null;
        // A two-chunk stream whose first chunk is 8 bytes and whose total is 16 exactly matches the
        // native dedup zero-hole signature; route it through newLZ for the same reason as above.
        if (first.Length == 8 && payload.Length == 16)
            return KrakenLzEncoder.Encode(input);
        return new EncodedBlock { Payload = payload, Flags = 0, FirstChunkCompressedLength = first.Length, UncompressedLength = input.Length, Mode = firstMode == LiteralMode.UniformHuffman && secondMode == LiteralMode.UniformHuffman ? LiteralMode.UniformHuffman : LiteralMode.FixedWidthHuffman };
    }

    private static byte[]? EncodeLiteralArray(ReadOnlySpan<byte> input, out LiteralMode mode)
    {
        byte[]? uniform = EncodeUniformArray(input);
        if (uniform is not null)
        {
            mode = LiteralMode.UniformHuffman;
            return uniform;
        }

        mode = LiteralMode.FixedWidthHuffman;
        return EncodeFixedWidthArray(input);
    }

    private static byte[]? EncodeUniformArray(ReadOnlySpan<byte> input)
    {
        if (input.Length == 0 || input.Length > ChunkSize)
            return null;
        byte symbol = input[0];
        if (input.IndexOfAnyExcept(symbol) >= 0)
            return null;

        // The following three bytes are derived directly from KrakenDecoder's old Huffman
        // one-symbol reader: old-table selector 0, one symbol, then that symbol. They are packed
        // MSB first by this independent writer, not borrowed from any encoder implementation.
        byte[] huffman = [0x00, (byte)(0x40 | (symbol >> 2)), (byte)((symbol & 3) << 6)];
        int dstMinusOne = input.Length - 1;
        int sourceLength = huffman.Length;
        byte header = (byte)(0x20 | (dstMinusOne >> 14)); // entropy type 2 + destination high bits
        uint sizes = (uint)sourceLength | ((uint)(dstMinusOne & 0x3fff) << 18);
        return [header, (byte)(sizes >> 24), (byte)(sizes >> 16), (byte)(sizes >> 8), (byte)sizes, .. huffman];
    }

    // This is intentionally a fixed-width literal representation, not a Huffman optimizer.
    // The old-table branch in KrakenDecoder accepts a canonical complete alphabet. Completing
    // the observed alphabet to a power of two gives every emitted literal the same code width,
    // which makes the bit packing independently straightforward and deterministic.
    private static byte[]? EncodeFixedWidthArray(ReadOnlySpan<byte> input)
    {
        if (input.Length == 0 || input.Length > ChunkSize)
            return null;

        Span<bool> present = stackalloc bool[256];
        int observed = 0;
        foreach (byte value in input)
            if (!present[value]) { present[value] = true; observed++; }
        if (observed < 2)
            return null;

        int alphabetSize = 2;
        int width = 1;
        while (alphabetSize < observed)
        {
            alphabetSize <<= 1;
            width++;
        }
        // A byte-sized old-table symbol count cannot represent 256 (zero is invalid).
        if (alphabetSize >= 256)
            return null;

        byte[] alphabet = new byte[alphabetSize];
        int at = 0;
        for (int value = 0; value < 256 && at < alphabetSize; value++)
            if (present[value]) alphabet[at++] = (byte)value;
        for (int value = 0; value < 256 && at < alphabetSize; value++)
            if (!present[value]) alphabet[at++] = (byte)value;

        Span<int> codeByByte = stackalloc int[256];
        codeByByte.Fill(-1);
        for (int i = 0; i < alphabet.Length; i++) codeByByte[alphabet[i]] = i;

        var tableBits = new MsbBitWriter();
        tableBits.Write(0, 1); // old code-length reader
        tableBits.Write(0, 1); // simple old-table form
        tableBits.Write((uint)alphabetSize, 8);
        tableBits.Write(4, 3); // enough bits for code lengths through eleven
        foreach (byte symbol in alphabet)
        {
            tableBits.Write(symbol, 8);
            tableBits.Write((uint)(width - 1), 4);
        }
        byte[] table = tableBits.ToPaddedBytes();

        var stream0 = new LsbBitWriter();
        var stream1 = new LsbBitWriter();
        var stream2 = new LsbBitWriter();
        for (int i = 0; i < input.Length; i++)
        {
            int reversedCode = ReverseLowBits(codeByByte[input[i]], width);
            switch (i % 3)
            {
                case 0: stream0.Write((uint)reversedCode, width); break;
                case 1: stream1.Write((uint)reversedCode, width); break;
                default: stream2.Write((uint)reversedCode, width); break;
            }
        }
        byte[] forward = stream0.ToPaddedBytes();
        byte[] middle = stream2.ToPaddedBytes();
        byte[] backward = stream1.ToPaddedBytes();
        Array.Reverse(backward);

        if (forward.Length > ushort.MaxValue)
            return null;
        byte[] entropy = new byte[table.Length + 2 + forward.Length + middle.Length + backward.Length];
        table.CopyTo(entropy, 0);
        int p = table.Length;
        entropy[p++] = (byte)forward.Length;
        entropy[p++] = (byte)(forward.Length >> 8);
        forward.CopyTo(entropy, p); p += forward.Length;
        middle.CopyTo(entropy, p); p += middle.Length;
        backward.CopyTo(entropy, p);
        return FrameEntropyArray(entropy, input.Length);
    }

    private static byte[]? FrameEntropyArray(byte[] entropy, int outputLength)
    {
        if (entropy.Length >= outputLength || entropy.Length > 0x3ffff || outputLength is <= 0 or > ChunkSize)
            return null;
        int dstMinusOne = outputLength - 1;
        byte header = (byte)(0x20 | (dstMinusOne >> 14));
        uint sizes = (uint)entropy.Length | ((uint)(dstMinusOne & 0x3fff) << 18);
        return [header, (byte)(sizes >> 24), (byte)(sizes >> 16), (byte)(sizes >> 8), (byte)sizes, .. entropy];
    }

    private static int ReverseLowBits(int value, int count)
    {
        int result = 0;
        for (int i = 0; i < count; i++) { result = (result << 1) | (value & 1); value >>= 1; }
        return result;
    }

    private sealed class MsbBitWriter
    {
        private readonly List<byte> _bytes = [];
        private byte _current;
        private int _used;
        public void Write(uint value, int count)
        {
            for (int i = count - 1; i >= 0; i--)
            {
                _current |= (byte)(((value >> i) & 1) << (7 - _used++));
                if (_used == 8) { _bytes.Add(_current); _current = 0; _used = 0; }
            }
        }
        public byte[] ToPaddedBytes()
        {
            if (_used != 0) _bytes.Add(_current);
            return _bytes.ToArray();
        }
    }

    private sealed class LsbBitWriter
    {
        private readonly List<byte> _bytes = [];
        private byte _current;
        private int _used;
        public void Write(uint value, int count)
        {
            for (int i = 0; i < count; i++)
            {
                _current |= (byte)(((value >> i) & 1) << _used++);
                if (_used == 8) { _bytes.Add(_current); _current = 0; _used = 0; }
            }
        }
        public byte[] ToPaddedBytes()
        {
            if (_used != 0) _bytes.Add(_current);
            return _bytes.ToArray();
        }
    }
}
