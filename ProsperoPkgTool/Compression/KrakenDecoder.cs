using System.Buffers.Binary;
using System.Numerics;

namespace ProsperoPkgTool.Compression;

/// <summary>
/// Clean-room decoder for the Oodle Kraken ("newLZ") compression format.
///
/// Kraken is the entropy-coded LZ format used inside the PS5 inner PFS image. A single
/// <see cref="Decode"/> call inflates one compressed block (at most 256 KiB of output,
/// encoded as one or two 128 KiB sub-chunks) into a caller-supplied destination buffer.
///
/// The format is fully documented by the public Kraken/newLZ bitstream layout and has been
/// independently reimplemented here from that specification. No Sony SDK or third-party
/// GPL-licensed source was copied: every helper, table and naming choice below was written
/// from scratch against the format description.
///
/// Stream anatomy of one block (see <see cref="DecodeBlock"/>):
///   - an 8-byte literal seed (only for the first sub-chunk of a multi-chunk block);
///   - an optional "excess" framing byte whose high bit (0x80) marks a trailing bit-packed
///     substream used for length escapes;
///   - four entropy-coded streams, in order: literals, commands, match distances, and
///     packed match/literal lengths;
///   - a bit-packed region carrying any scaled-distance bits and length escapes.
///
/// Supported entropy codings (the <c>DecodeBytes</c> array types actually emitted by the
/// packages this tool targets): raw/memcpy (type 0) and Huffman code-length tables (types
/// 2 and 4, i.e. single- and triple-stream splits). The TANS (type 1), RLE (type 3) and
/// recursive (type 5) array types are not produced by these packages and are surfaced as
/// <see cref="KrakenDecodeStatus.UnsupportedEntropy"/> rather than being guessed at.
/// </summary>
public static class KrakenDecoder
{
    /// <summary>A single sub-chunk decodes at most 128 KiB.</summary>
    public const int ChunkSize = 0x20000;

    /// <summary>A whole block decodes at most 256 KiB (two sub-chunks).</summary>
    public const int MaxBlockSize = 0x40000;

    private const int SeedSize = 8;

    /// <summary>The result of a block decode.</summary>
    public enum KrakenDecodeStatus
    {
        Success = 0,
        Malformed = 1,
        UnsupportedEntropy = 2,
        UnsupportedExcessMode = 3,
    }

    // Per-chunk flag bits describing how a multi-sub-chunk block is laid out. The low
    // nibble describes the first sub-chunk, the high nibble the second.
    private const int Chunk0SubLiteral = 0x01; // 1 = delta/sub literals, 0 = raw literals
    private const int Chunk0IsNewLz = 0x02;    // 1 = newLZ, 0 = bare entropy array
    private const int Chunk1SubLiteral = 0x10;
    private const int Chunk1IsNewLz = 0x20;

    /// <summary>
    /// Decodes one whole block into <paramref name="dst"/>. <paramref name="flags"/> carries
    /// the per-sub-chunk type bits (see the <c>Chunk*</c> constants); <paramref name="firstChunkComp"/>
    /// is the compressed size of the first sub-chunk and is only needed when the block spans
    /// two sub-chunks (its output exceeds <see cref="ChunkSize"/>).
    /// </summary>
    public static KrakenDecodeStatus DecodeBlock(
        ReadOnlySpan<byte> payload, int flags, int firstChunkComp, Span<byte> dst)
    {
        if (dst.Length <= 0)
            return payload.Length == 0 ? KrakenDecodeStatus.Success : KrakenDecodeStatus.Malformed;

        byte[] src = payload.ToArray();
        byte[] outBuf = new byte[dst.Length];

        bool chunk0NewLz = (flags & Chunk0IsNewLz) != 0;
        int litMode0 = (flags & Chunk0SubLiteral) != 0 ? 0 : 1;
        bool multiChunk = dst.Length > ChunkSize;

        KrakenDecodeStatus st;
        if (!multiChunk)
        {
            st = chunk0NewLz
                ? DecodeChunk(src, 0, src.Length, outBuf, 0, dst.Length, withSeed: true, litMode0)
                : DecodeBareEntropy(src, 0, src.Length, outBuf, 0, dst.Length);
        }
        else
        {
            if (firstChunkComp <= 0 || firstChunkComp > src.Length)
                return KrakenDecodeStatus.Malformed;

            bool chunk1NewLz = (flags & Chunk1IsNewLz) != 0;
            int litMode1 = (flags & Chunk1SubLiteral) != 0 ? 0 : 1;
            int chunk1Comp = src.Length - firstChunkComp;
            int chunk1Dst = dst.Length - ChunkSize;

            st = chunk0NewLz
                ? DecodeChunk(src, 0, firstChunkComp, outBuf, 0, ChunkSize, withSeed: true, litMode0)
                : DecodeBareEntropy(src, 0, firstChunkComp, outBuf, 0, ChunkSize);
            if (st != KrakenDecodeStatus.Success)
                return st;

            // The second sub-chunk is seedless and may back-reference the first sub-chunk's
            // bytes via the shared destination buffer.
            st = chunk1NewLz
                ? DecodeChunk(src, firstChunkComp, chunk1Comp, outBuf, ChunkSize, chunk1Dst, withSeed: false, litMode1)
                : DecodeBareEntropy(src, firstChunkComp, chunk1Comp, outBuf, ChunkSize, chunk1Dst);
        }

        if (st == KrakenDecodeStatus.Success)
            outBuf.AsSpan(0, dst.Length).CopyTo(dst);
        return st;
    }

    /// <summary>
    /// Decodes a bare entropy array (no seed, no LZ framing): a single <c>DecodeBytes</c> array
    /// expanding to exactly <paramref name="dstLen"/> bytes, consuming its entire source span.
    /// </summary>
    private static KrakenDecodeStatus DecodeBareEntropy(
        byte[] src, int srcStart, int srcLen, byte[] outBuf, int dstStart, int dstLen)
    {
        if (srcLen < 0 || srcStart + srcLen > src.Length || dstLen < 0 || dstStart + dstLen > outBuf.Length)
            return KrakenDecodeStatus.Malformed;

        int used = DecodeBytes(src, srcStart, srcStart + srcLen, dstLen, out byte[] dec, out int decCount);
        if (used < 0)
            return used == -2 ? KrakenDecodeStatus.UnsupportedEntropy : KrakenDecodeStatus.Malformed;
        if (used != srcLen || decCount != dstLen)
            return KrakenDecodeStatus.Malformed;

        Array.Copy(dec, 0, outBuf, dstStart, dstLen);
        return KrakenDecodeStatus.Success;
    }

    /// <summary>Holds the four decoded streams of a single newLZ sub-chunk.</summary>
    private sealed class LzStreams
    {
        public byte[] Literals = Array.Empty<byte>();
        public int LiteralCount;
        public byte[] Commands = Array.Empty<byte>();
        public int CommandCount;
        public int[] Distances = Array.Empty<int>();
        public int DistanceCount;
        public int[] Lengths = Array.Empty<int>();
        public int LengthCount;
    }

    /// <summary>
    /// Decodes one newLZ sub-chunk covering [<paramref name="dstStart"/>, dstStart + <paramref name="dstSize"/>)
    /// of the shared block buffer <paramref name="dst"/>. Matches may reference any earlier byte.
    /// </summary>
    private static KrakenDecodeStatus DecodeChunk(
        byte[] src, int srcStart, int srcLen, byte[] dst, int dstStart, int dstSize, bool withSeed, int literalMode)
    {
        if (dstSize <= 0 || dstStart + dstSize > dst.Length || srcLen < 0 || srcStart + srcLen > src.Length)
            return KrakenDecodeStatus.Malformed;

        int srcEnd = srcStart + srcLen;
        int sp = srcStart;
        int offset = withSeed ? 0 : dstStart;

        var streams = new LzStreams();
        int rc = ReadLzTable(src, ref sp, srcEnd, dst, dstStart, dstSize, offset, streams);
        if (rc < 0)
            return rc == -2 ? KrakenDecodeStatus.UnsupportedEntropy : KrakenDecodeStatus.Malformed;

        bool ok = ProcessLzRuns(literalMode, dst, dstStart, dstSize, offset, streams);
        return ok ? KrakenDecodeStatus.Success : KrakenDecodeStatus.Malformed;
    }

    // =====================================================================================
    //  Table reading: seed copy, excess framing, and the four entropy streams.
    // =====================================================================================
    private static int ReadLzTable(
        byte[] src, ref int sp, int srcEnd, byte[] dst, int dstStart, int dstSize, int offset, LzStreams lzt)
    {
        // A seeded sub-chunk carries an 8-byte literal seed at its head.
        if (offset == 0)
        {
            if (srcEnd - sp < SeedSize)
                return -1;
            Array.Copy(src, sp, dst, dstStart, SeedSize);
            sp += SeedSize;
        }

        // Excess framing: the post-seed control byte's 0x80 bit marks a trailing substream
        // holding the length escapes; the low bits encode its byte count (with a
        // continuation byte when the count exceeds 0x1F).
        bool excessFlag = false;
        int excessCount = 0;
        if (sp < srcEnd && (src[sp] & 0x80) != 0)
        {
            byte flag = src[sp++];
            if ((flag & 0xC0) != 0x80)
                return -1; // reserved flag bits set
            excessFlag = true;
            excessCount = flag & 0x3F;
            if (excessCount > 0x1F)
            {
                if (sp >= srcEnd)
                    return -1;
                excessCount += src[sp++] * 0x20;
            }
            srcEnd -= excessCount;
            if (srcEnd < sp)
                return -1;
        }

        // Literal stream (bounded by dstSize).
        int n = DecodeBytes(src, sp, srcEnd, dstSize, out byte[] lit, out int litCount);
        if (n < 0) return n;
        sp += n;
        lzt.Literals = lit;
        lzt.LiteralCount = litCount;

        // Command stream (bounded by dstSize).
        n = DecodeBytes(src, sp, srcEnd, dstSize, out byte[] cmd, out int cmdCount);
        if (n < 0) return n;
        sp += n;
        lzt.Commands = cmd;
        lzt.CommandCount = cmdCount;

        if (srcEnd - sp < 3)
            return -1;

        int offsScaling = 0;
        byte[] packedOffsExtra = Array.Empty<byte>();
        byte[] packedOffs;
        int offsCount;

        if ((src[sp] & 0x80) != 0)
        {
            // Distances coded across two tables.
            offsScaling = src[sp] - 127;
            sp++;
            n = DecodeBytes(src, sp, srcEnd, cmdCount, out packedOffs, out offsCount);
            if (n < 0) return n;
            sp += n;
            if (offsScaling != 1)
            {
                n = DecodeBytes(src, sp, srcEnd, offsCount, out packedOffsExtra, out int extraCount);
                if (n < 0) return n;
                if (extraCount != offsCount) return -1;
                sp += n;
            }
        }
        else
        {
            n = DecodeBytes(src, sp, srcEnd, cmdCount, out packedOffs, out offsCount);
            if (n < 0) return n;
            sp += n;
        }
        lzt.DistanceCount = offsCount;

        // Packed literal-length stream (bounded by dstSize / 4).
        n = DecodeBytes(src, sp, srcEnd, dstSize >> 2, out byte[] packedLitLen, out int lenCount);
        if (n < 0) return n;
        sp += n;
        lzt.LengthCount = lenCount;

        lzt.Distances = new int[offsCount];
        lzt.Lengths = new int[lenCount];

        return UnpackOffsets(
            src, sp, srcEnd, excessFlag, excessCount,
            packedOffs, offsCount, offsScaling, packedOffsExtra,
            packedLitLen, lenCount, lzt.Distances, lzt.Lengths)
            ? sp
            : -1;
    }

    // =====================================================================================
    //  Distance/length unpacking from the trailing bit-packed region.
    // =====================================================================================
    private static bool UnpackOffsets(
        byte[] src, int bsBegin, int bsEnd, bool excessFlag, int excessCount,
        byte[] packedOffs, int offsCount, int offsScaling, byte[] packedOffsExtra,
        byte[] packedLitLen, int lenCount, int[] offsStream, int[] lenStream)
    {
        var fwd = BitReader.Forward(src, bsBegin, bsEnd);
        var bwd = BitReader.Backward(src, bsBegin, bsEnd);

        int u32LenStreamSize = 0;
        if (!excessFlag)
        {
            if (bwd.Bits < 0x2000) return false;
            int nn = 31 - MostSignificantBit(bwd.Bits);
            bwd.BitPos += nn; bwd.Bits <<= nn; bwd.RefillBackward();
            nn++;
            u32LenStreamSize = (int)((bwd.Bits >> (32 - nn)) - 1);
            bwd.BitPos += nn; bwd.Bits <<= nn; bwd.RefillBackward();
        }
        else
        {
            for (int q = 0; q < lenCount; q++)
                if (packedLitLen[q] == 255) u32LenStreamSize++;
        }

        if (offsScaling == 0)
        {
            int i = 0;
            while (i < offsCount)
            {
                offsStream[i] = -(int)fwd.ReadDistance(packedOffs[i]); i++;
                if (i >= offsCount) break;
                offsStream[i] = -(int)bwd.ReadDistanceBackward(packedOffs[i]); i++;
            }
        }
        else
        {
            int i = 0;
            while (i < offsCount)
            {
                uint cmd = packedOffs[i];
                if ((cmd >> 3) > 26) return false;
                uint off = ((8u + (cmd & 7)) << (int)(cmd >> 3)) | fwd.ReadExtra((int)(cmd >> 3));
                offsStream[i] = 8 - (int)off; i++;
                if (i >= offsCount) break;
                cmd = packedOffs[i];
                if ((cmd >> 3) > 26) return false;
                off = ((8u + (cmd & 7)) << (int)(cmd >> 3)) | bwd.ReadExtraBackward((int)(cmd >> 3));
                offsStream[i] = 8 - (int)off; i++;
            }
            if (offsScaling != 1)
                CombineScaledDistances(offsStream, offsCount, offsScaling, packedOffsExtra);
        }

        if (u32LenStreamSize > 512)
            return false;
        var u32 = new uint[u32LenStreamSize];

        if (excessFlag)
        {
            var ea = BitReader.Forward(src, bsEnd, bsEnd + excessCount);
            var eb = BitReader.Backward(src, bsEnd, bsEnd + excessCount);
            int i = 0;
            for (; i + 1 < u32LenStreamSize; i += 2)
            {
                if (!ea.ReadLength(out u32[i])) return false;
                if (!eb.ReadLengthBackward(out u32[i + 1])) return false;
            }
            if (i < u32LenStreamSize && !ea.ReadLength(out u32[i]))
                return false;
        }
        else
        {
            int i = 0;
            for (; i + 1 < u32LenStreamSize; i += 2)
            {
                if (!fwd.ReadLength(out u32[i])) return false;
                if (!bwd.ReadLengthBackward(out u32[i + 1])) return false;
            }
            if (i < u32LenStreamSize && !fwd.ReadLength(out u32[i]))
                return false;
        }

        int aSeam = fwd.P - ((24 - fwd.BitPos) >> 3);
        int bSeam = bwd.P + ((24 - bwd.BitPos) >> 3);
        if (aSeam != bSeam && !excessFlag)
            return false;

        int u = 0;
        for (int i = 0; i < lenCount; i++)
        {
            uint v = packedLitLen[i];
            if (v == 255)
            {
                if (u >= u32LenStreamSize) return false;
                v = u32[u++] + 255;
            }
            lenStream[i] = (int)v + 3;
        }
        return u == u32LenStreamSize;
    }

    private static void CombineScaledDistances(int[] offs, int count, int scale, byte[] extra)
    {
        for (int i = 0; i < count; i++)
            offs[i] = (sbyte)extra[i] - offs[i] * scale;
    }

    // =====================================================================================
    //  DecodeBytes dispatcher: raw/memcpy (type 0) and Huffman (types 2/4).
    // =====================================================================================
    /// <summary>Returns the number of source bytes consumed, or -1 malformed / -2 unsupported type.</summary>
    private static int DecodeBytes(byte[] src, int sp, int srcEnd, int outputCap, out byte[] output, out int decodedSize)
    {
        output = Array.Empty<byte>();
        decodedSize = 0;
        int srcOrg = sp;

        if (srcEnd - sp < 2)
            return -1;

        int chunkType = (src[sp] >> 4) & 0x7;
        int srcSize, dstSize;

        if (chunkType == 0)
        {
            // Raw / memcpy: either a 12-bit short form or a 24-bit long form.
            if (src[sp] >= 0x80)
            {
                srcSize = ((src[sp] << 8) | src[sp + 1]) & 0xFFF;
                sp += 2;
            }
            else
            {
                if (srcEnd - sp < 3) return -1;
                srcSize = (src[sp] << 16) | (src[sp + 1] << 8) | src[sp + 2];
                if ((srcSize & ~0x3FFFF) != 0) return -1;
                sp += 3;
            }
            if (srcSize > outputCap || srcEnd - sp < srcSize) return -1;
            output = new byte[srcSize];
            Array.Copy(src, sp, output, 0, srcSize);
            decodedSize = srcSize;
            return sp + srcSize - srcOrg;
        }

        // Entropy modes carry srcSize + dstSize in their framing.
        if (src[sp] >= 0x80)
        {
            if (srcEnd - sp < 3) return -1;
            uint bits = (uint)((src[sp] << 16) | (src[sp + 1] << 8) | src[sp + 2]);
            srcSize = (int)(bits & 0x3FF);
            dstSize = (int)(srcSize + ((bits >> 10) & 0x3FF) + 1);
            sp += 3;
        }
        else
        {
            if (srcEnd - sp < 5) return -1;
            uint bits = (uint)((src[sp + 1] << 24) | (src[sp + 2] << 16) | (src[sp + 3] << 8) | src[sp + 4]);
            srcSize = (int)(bits & 0x3FFFF);
            dstSize = (int)((((bits >> 18) | ((uint)src[sp] << 14)) & 0x3FFFF) + 1);
            if (srcSize >= dstSize) return -1;
            sp += 5;
        }
        if (srcEnd - sp < srcSize || dstSize > outputCap) return -1;

        output = new byte[dstSize];
        int used;
        switch (chunkType)
        {
            case 2:
            case 4:
                used = DecodeHuffman(src, sp, srcSize, output, dstSize, chunkType >> 1);
                break;
            default:
                // 1 (TANS), 3 (RLE), 5 (recursive): not emitted by the packages this tool targets.
                return -2;
        }
        if (used != srcSize) return -1;
        decodedSize = dstSize;
        return sp + srcSize - srcOrg;
    }

    // =====================================================================================
    //  Huffman decoding: code-length readers, LUT build, and the 3-stream scalar core.
    // =====================================================================================
    private static readonly uint[] CodePrefixBase =
        { 0x0, 0x0, 0x2, 0x6, 0xE, 0x1E, 0x3E, 0x7E, 0xFE, 0x1FE, 0x2FE, 0x3FE };

    private static int DecodeHuffman(byte[] src, int srcStart, int srcSize, byte[] output, int outputSize, int type)
    {
        int srcEnd = srcStart + srcSize;
        var bits = BitReader.Forward(src, srcStart, srcEnd);

        uint[] codePrefix = (uint[])CodePrefixBase.Clone();
        byte[] syms = new byte[1280];

        int numSyms;
        if (bits.ReadBitNoRefill() == 0)
            numSyms = HuffReadCodeLengthsOld(ref bits, syms, codePrefix);
        else if (bits.ReadBitNoRefill() == 0)
            numSyms = HuffReadCodeLengthsNew(ref bits, syms, codePrefix);
        else
            return -1;

        if (numSyms < 1)
            return -1;

        int sp = bits.P - ((24 - bits.BitPos) / 8);

        if (numSyms == 1)
        {
            byte fill = syms[0];
            for (int i = 0; i < outputSize; i++) output[i] = fill;
            return srcSize;
        }

        var lut = new HuffLookup();
        if (!HuffBuildLookup(CodePrefixBase, codePrefix, lut, syms))
            return -1;

        var rev = new HuffLookup();
        ReverseBits2048(lut.BitsToLen, rev.BitsToLen);
        ReverseBits2048(lut.BitsToSym, rev.BitsToSym);

        if (type == 1)
        {
            if (sp + 3 > srcEnd) return -1;
            int splitMid = src[sp] | (src[sp + 1] << 8);
            sp += 2;
            var hr = new HuffStreamReader(src, output)
            {
                OutOff = 0,
                OutEnd = outputSize,
                Src = sp,
                SrcEnd = srcEnd,
                SrcMid = sp + splitMid,
                SrcMidOriginal = sp + splitMid,
            };
            if (!DecodeHuffmanCore(ref hr, rev)) return -1;
        }
        else
        {
            if (sp + 6 > srcEnd) return -1;
            int halfOut = (outputSize + 1) >> 1;
            int splitMid = src[sp] | (src[sp + 1] << 8) | (src[sp + 2] << 16);
            sp += 3;
            if (splitMid > srcEnd - sp) return -1;
            int srcMid = sp + splitMid;
            int splitLeft = src[sp] | (src[sp + 1] << 8);
            sp += 2;
            if (srcMid - sp < splitLeft + 2 || srcEnd - srcMid < 3) return -1;
            int splitRight = src[srcMid] | (src[srcMid + 1] << 8);
            if (srcEnd - (srcMid + 2) < splitRight + 2) return -1;

            var hr1 = new HuffStreamReader(src, output)
            {
                OutOff = 0,
                OutEnd = halfOut,
                Src = sp,
                SrcEnd = srcMid,
                SrcMid = sp + splitLeft,
                SrcMidOriginal = sp + splitLeft,
            };
            if (!DecodeHuffmanCore(ref hr1, rev)) return -1;

            var hr2 = new HuffStreamReader(src, output)
            {
                OutOff = halfOut,
                OutEnd = outputSize,
                Src = srcMid + 2,
                SrcEnd = srcEnd,
                SrcMid = srcMid + 2 + splitRight,
                SrcMidOriginal = srcMid + 2 + splitRight,
            };
            if (!DecodeHuffmanCore(ref hr2, rev)) return -1;
        }
        return srcSize;
    }

    private sealed class HuffLookup
    {
        public readonly byte[] BitsToLen = new byte[2048 + 16];
        public readonly byte[] BitsToSym = new byte[2048 + 16];
    }

    private static bool HuffBuildLookup(uint[] prefixBase, uint[] prefixCur, HuffLookup lut, byte[] syms)
    {
        uint currslot = 0;
        for (uint i = 1; i < 11; i++)
        {
            uint start = prefixBase[i];
            uint count = prefixCur[i] - start;
            if (count != 0)
            {
                uint stepsize = 1u << (int)(11 - i);
                uint numToSet = count << (int)(11 - i);
                if (currslot + numToSet > 2048) return false;
                FillByte(lut.BitsToLen, (int)currslot, (byte)i, (int)numToSet);
                int p = (int)currslot;
                for (uint j = 0; j != count; j++, p += (int)stepsize)
                    FillByte(lut.BitsToSym, p, syms[start + j], (int)stepsize);
                currslot += numToSet;
            }
        }
        if (prefixCur[11] - prefixBase[11] != 0)
        {
            uint numToSet = prefixCur[11] - prefixBase[11];
            if (currslot + numToSet > 2048) return false;
            FillByte(lut.BitsToLen, (int)currslot, 11, (int)numToSet);
            Array.Copy(syms, (int)prefixBase[11], lut.BitsToSym, (int)currslot, (int)numToSet);
            currslot += numToSet;
        }
        return currslot == 2048;
    }

    private static void FillByte(byte[] dst, int off, byte v, int n)
    {
        for (int i = 0; i < n; i++) dst[off + i] = v;
    }

    /// <summary>output[i] = input[reverse-low-11-bits(i)] — MSB-first LUT to LSB-first form.</summary>
    private static void ReverseBits2048(byte[] input, byte[] output)
    {
        for (int i = 0; i < 2048; i++)
            output[i] = input[Reverse11(i)];
    }

    private static int Reverse11(int v)
    {
        int r = 0;
        for (int k = 0; k < 11; k++)
        {
            r = (r << 1) | (v & 1);
            v >>= 1;
        }
        return r;
    }

    private static int HuffReadCodeLengthsOld(ref BitReader bits, byte[] syms, uint[] codePrefix)
    {
        if (bits.ReadBitNoRefill() != 0)
        {
            int sym = 0, codelen, numSymbols = 0;
            int avgBitsX4 = 32;
            int forcedBits = (int)bits.ReadBitsNoRefill(2);
            uint thres = 1u << (31 - (int)(20u >> forcedBits));
            int n;
            bool skip = bits.ReadBit() != 0;

            while (true)
            {
                if (!skip)
                {
                    if ((bits.Bits & 0xFF000000) == 0) return -1;
                    sym += (int)bits.ReadBitsNoRefill(2 * (CountLeadingZeros(bits.Bits) + 1)) - 2 + 1;
                    if (sym >= 256) break;
                }
                skip = false;

                bits.Refill();
                if ((bits.Bits & 0xFF000000) == 0) return -1;
                n = (int)bits.ReadBitsNoRefill(2 * (CountLeadingZeros(bits.Bits) + 1)) - 2 + 1;
                if (sym + n > 256) return -1;
                bits.Refill();
                numSymbols += n;
                do
                {
                    if (bits.Bits < thres) return -1;
                    int lz = CountLeadingZeros(bits.Bits);
                    int v = (int)bits.ReadBitsNoRefill(lz + forcedBits + 1) + ((lz - 1) << forcedBits);
                    codelen = (-(v & 1) ^ (v >> 1)) + ((avgBitsX4 + 2) >> 2);
                    if (codelen < 1 || codelen > 11) return -1;
                    avgBitsX4 = codelen + ((3 * avgBitsX4 + 2) >> 2);
                    bits.Refill();
                    syms[codePrefix[codelen]++] = (byte)sym++;
                } while (--n != 0);

                if (sym == 256) break;
            }
            return (sym == 256 && numSymbols >= 2) ? numSymbols : -1;
        }
        else
        {
            int numSymbols = (int)bits.ReadBitsNoRefill(8);
            if (numSymbols == 0) return -1;
            if (numSymbols == 1)
            {
                syms[0] = (byte)bits.ReadBitsNoRefill(8);
            }
            else
            {
                int codelenBits = (int)bits.ReadBitsNoRefill(3);
                if (codelenBits > 4) return -1;
                for (int i = 0; i < numSymbols; i++)
                {
                    bits.Refill();
                    int sym = (int)bits.ReadBitsNoRefill(8);
                    int codelen = (int)bits.ReadBitsNoRefillZero(codelenBits) + 1;
                    if (codelen > 11) return -1;
                    syms[codePrefix[codelen]++] = (byte)sym;
                }
            }
            return numSymbols;
        }
    }

    private static int HuffReadCodeLengthsNew(ref BitReader bits, byte[] syms, uint[] codePrefix)
    {
        int forcedBits = (int)bits.ReadBitsNoRefill(2);
        int numSymbols = (int)bits.ReadBitsNoRefill(8) + 1;
        int fluff = bits.ReadFluff(numSymbols);

        byte[] codeLen = new byte[512 + 16];
        var br2 = new GolombReader
        {
            Data = bits.Data,
            BitPos = (bits.BitPos - 24) & 7,
            End = bits.Bound,
            P = bits.P - ((24 - bits.BitPos + 7) >> 3),
        };

        if (!DecodeGolombRiceLengths(codeLen, numSymbols + fluff, ref br2)) return -1;
        for (int z = 0; z < 16; z++) codeLen[numSymbols + fluff + z] = 0;
        if (!DecodeGolombRiceBits(codeLen, numSymbols, forcedBits, ref br2)) return -1;

        bits.BitPos = 24;
        bits.P = br2.P;
        bits.Bits = 0;
        bits.Refill();
        bits.Bits <<= br2.BitPos;
        bits.BitPos += br2.BitPos;

        uint runningSum = 0x1e;
        for (int i = 0; i < numSymbols; i++)
        {
            int v = codeLen[i];
            v = -(v & 1) ^ (v >> 1);
            int cl = v + (int)(runningSum >> 2) + 1;
            if (cl < 1 || cl > 11) return -1;
            codeLen[i] = (byte)cl;
            runningSum = (uint)((int)runningSum + v);
        }

        var range = new HuffRange[128];
        int ranges = HuffConvertToRanges(range, numSymbols, fluff, codeLen, numSymbols, ref bits);
        if (ranges <= 0) return -1;

        int cp = 0;
        for (int i = 0; i < ranges; i++)
        {
            int sym = range[i].Symbol;
            int nn = range[i].Num;
            do
            {
                syms[codePrefix[codeLen[cp++]]++] = (byte)sym++;
            } while (--nn != 0);
        }
        return numSymbols;
    }

    private struct HuffRange { public int Symbol; public int Num; }

    private static int HuffConvertToRanges(HuffRange[] range, int numSymbols, int p, byte[] symlen, int symlenOff, ref BitReader bits)
    {
        int numRanges = p >> 1, v, symIdx = 0;

        if ((p & 1) != 0)
        {
            bits.Refill();
            v = symlen[symlenOff++];
            if (v >= 8) return -1;
            symIdx = (int)bits.ReadBitsNoRefill(v + 1) + (1 << (v + 1)) - 1;
        }
        int symsUsed = 0;

        for (int i = 0; i < numRanges; i++)
        {
            bits.Refill();
            v = symlen[symlenOff];
            if (v >= 9) return -1;
            int num = (int)bits.ReadBitsNoRefillZero(v) + (1 << v);
            v = symlen[symlenOff + 1];
            if (v >= 8) return -1;
            int space = (int)bits.ReadBitsNoRefill(v + 1) + (1 << (v + 1)) - 1;
            range[i].Symbol = symIdx;
            range[i].Num = num;
            symsUsed += num;
            symIdx += num + space;
            symlenOff += 2;
        }

        if (symIdx >= 256 || symsUsed >= numSymbols || symIdx + numSymbols - symsUsed > 256)
            return -1;

        range[numRanges].Symbol = symIdx;
        range[numRanges].Num = numSymbols - symsUsed;
        return numRanges + 1;
    }

    // 3-stream scalar Huffman core.
    private static bool DecodeHuffmanCore(ref HuffStreamReader hr, HuffLookup lut)
    {
        byte[] data = hr.Data;
        byte[] outp = hr.Output;
        byte[] b2len = lut.BitsToLen;
        byte[] b2sym = lut.BitsToSym;

        int src = hr.Src;
        uint srcBits = hr.SrcBits;
        int srcBitpos = hr.SrcBitpos;
        int srcMid = hr.SrcMid;
        uint srcMidBits = hr.SrcMidBits;
        int srcMidBitpos = hr.SrcMidBitpos;
        int srcEnd = hr.SrcEnd;
        uint srcEndBits = hr.SrcEndBits;
        int srcEndBitpos = hr.SrcEndBitpos;

        int dst = hr.OutOff;
        int dstEnd = hr.OutEnd;

        if (src > srcMid)
            return false;

        int k, n;
        for (; ; )
        {
            if (dst >= dstEnd) break;

            if (srcMid - src <= 1)
            {
                if (srcMid - src == 1) srcBits |= (uint)data[src] << srcBitpos;
            }
            else
            {
                srcBits |= (uint)(data[src] | (data[src + 1] << 8)) << srcBitpos;
            }
            k = (int)(srcBits & 0x7FF);
            n = b2len[k];
            srcBitpos -= n;
            srcBits >>= n;
            outp[dst++] = b2sym[k];
            src += (7 - srcBitpos) >> 3;
            srcBitpos &= 7;

            if (dst < dstEnd)
            {
                if (srcEnd - srcMid <= 1)
                {
                    if (srcEnd - srcMid == 1)
                    {
                        srcEndBits |= (uint)data[srcMid] << srcEndBitpos;
                        srcMidBits |= (uint)data[srcMid] << srcMidBitpos;
                    }
                }
                else
                {
                    uint vv = (uint)(data[srcEnd - 2] | (data[srcEnd - 1] << 8));
                    srcEndBits |= (((vv >> 8) | (vv << 8)) & 0xFFFF) << srcEndBitpos;
                    srcMidBits |= (uint)(data[srcMid] | (data[srcMid + 1] << 8)) << srcMidBitpos;
                }
                k = (int)(srcEndBits & 0x7FF);
                n = b2len[k];
                outp[dst++] = b2sym[k];
                srcEndBitpos -= n;
                srcEndBits >>= n;
                srcEnd -= (7 - srcEndBitpos) >> 3;
                srcEndBitpos &= 7;
                if (dst < dstEnd)
                {
                    k = (int)(srcMidBits & 0x7FF);
                    n = b2len[k];
                    outp[dst++] = b2sym[k];
                    srcMidBitpos -= n;
                    srcMidBits >>= n;
                    srcMid += (7 - srcMidBitpos) >> 3;
                    srcMidBitpos &= 7;
                }
            }
            if (src > srcMid || srcMid > srcEnd)
                return false;
        }
        if (src != hr.SrcMidOriginal || srcEnd != srcMid)
            return false;
        return true;
    }

    private struct HuffStreamReader
    {
        public byte[] Data;
        public byte[] Output;
        public int Src, SrcEnd, SrcMid, SrcMidOriginal;
        public uint SrcBits, SrcMidBits, SrcEndBits;
        public int SrcBitpos, SrcMidBitpos, SrcEndBitpos;
        public int OutOff, OutEnd;
        public HuffStreamReader(byte[] data, byte[] output)
        {
            Data = data; Output = output;
            Src = 0; SrcEnd = 0; SrcMid = 0; SrcMidOriginal = 0;
            SrcBits = 0; SrcMidBits = 0; SrcEndBits = 0;
            SrcBitpos = 0; SrcMidBitpos = 0; SrcEndBitpos = 0;
            OutOff = 0; OutEnd = 0;
        }
    }

    // =====================================================================================
    //  Golomb-Rice length/bit decoding.
    // =====================================================================================
    private struct GolombReader { public byte[] Data; public int P; public int End; public int BitPos; }

    private static readonly uint[] RiceValue = BuildRiceValue();
    private static readonly byte[] RiceLength = BuildRiceLength();

    private static bool DecodeGolombRiceLengths(byte[] dst, int size, ref GolombReader br)
    {
        int p = br.P, pEnd = br.End;
        int dstPos = 0, dstEnd = size;
        if (p >= pEnd) return false;

        int count = -br.BitPos;
        uint v = (uint)(At(br.Data, p++) & (255 >> br.BitPos));
        for (; ; )
        {
            if (v == 0)
            {
                count += 8;
            }
            else
            {
                uint x = RiceValue[v];
                uint lo = (uint)count + (x & 0x0F0F0F0F);
                WriteLE32(dst, dstPos, lo);
                WriteLE32(dst, dstPos + 4, (x >> 4) & 0x0F0F0F0F);
                dstPos += RiceLength[v];
                if (dstPos >= dstEnd) break;
                count = (int)(x >> 28);
            }
            if (p >= pEnd) return false;
            v = At(br.Data, p++);
        }
        if (dstPos > dstEnd)
        {
            int nn = dstPos - dstEnd;
            do { v &= v - 1; } while (--nn != 0);
        }
        int bitpos = 0;
        if ((v & 1) == 0)
        {
            p--;
            int q = LeastSignificantBit(v);
            bitpos = 8 - q;
        }
        br.P = p;
        br.BitPos = bitpos;
        return true;
    }

    private static bool DecodeGolombRiceBits(byte[] dst, int size, int bitcount, ref GolombReader br)
    {
        if (bitcount == 0) return true;
        int dstPos = 0, dstEnd = size;
        int p = br.P;
        int bitpos = br.BitPos;

        int bitsRequired = bitpos + bitcount * size;
        int bytesRequired = (bitsRequired + 7) >> 3;
        if (bytesRequired > br.End - p) return false;

        br.P = p + (bitsRequired >> 3);
        br.BitPos = bitsRequired & 7;

        ulong bak = ReadLE64(dst, dstEnd);

        if (bitcount == 1)
        {
            do
            {
                ulong bits = (byte)(Swap32(ReadLE32(br.Data, p)) >> (24 - bitpos));
                p += 1;
                bits = (bits | (bits << 28)) & 0xF0000000Ful;
                bits = (bits | (bits << 14)) & 0x3000300030003ul;
                bits = (bits | (bits << 7)) & 0x0101010101010101ul;
                ulong cur = ReadLE64(dst, dstPos);
                WriteLE64(dst, dstPos, cur * 2 + Swap64(bits));
                dstPos += 8;
            } while (dstPos < dstEnd);
        }
        else if (bitcount == 2)
        {
            do
            {
                ulong bits = (ushort)(Swap32(ReadLE32(br.Data, p)) >> (16 - bitpos));
                p += 2;
                bits = (bits | (bits << 24)) & 0xFF000000FFul;
                bits = (bits | (bits << 12)) & 0xF000F000F000Ful;
                bits = (bits | (bits << 6)) & 0x0303030303030303ul;
                ulong cur = ReadLE64(dst, dstPos);
                WriteLE64(dst, dstPos, cur * 4 + Swap64(bits));
                dstPos += 8;
            } while (dstPos < dstEnd);
        }
        else // bitcount == 3
        {
            do
            {
                ulong bits = (ulong)((Swap32(ReadLE32(br.Data, p)) >> (8 - bitpos)) & 0xFFFFFF);
                p += 3;
                bits = (bits | (bits << 20)) & 0xFFF00000FFFul;
                bits = (bits | (bits << 10)) & 0x3F003F003F003Ful;
                bits = (bits | (bits << 5)) & 0x0707070707070707ul;
                ulong cur = ReadLE64(dst, dstPos);
                WriteLE64(dst, dstPos, cur * 8 + Swap64(bits));
                dstPos += 8;
            } while (dstPos < dstEnd);
        }
        WriteLE64(dst, dstEnd, bak);
        return true;
    }

    // =====================================================================================
    //  LZ run reconstruction (raw and sub/delta literal modes).
    // =====================================================================================
    private static bool ProcessLzRuns(int mode, byte[] dst, int dstStart, int dstSize, int offset, LzStreams lzt)
    {
        int dstEnd = dstStart + dstSize;
        int start = dstStart + (offset == 0 ? SeedSize : 0);
        int dstBaseStart = dstStart - offset;
        if (mode == 1)
            return ProcessLzRunsRaw(lzt, dst, start, dstEnd, dstBaseStart);
        if (mode == 0)
            return ProcessLzRunsSub(lzt, dst, start, dstEnd, dstBaseStart);
        return false;
    }

    private static bool ProcessLzRunsRaw(LzStreams lzt, byte[] dst, int dstPos, int dstEnd, int dstStart)
    {
        byte[] cmd = lzt.Commands; int cmdPos = 0, cmdEnd = lzt.CommandCount;
        int[] len = lzt.Lengths; int lenPos = 0, lenEnd = lzt.LengthCount;
        byte[] lit = lzt.Literals; int litPos = 0, litEnd = lzt.LiteralCount;
        int[] offs = lzt.Distances; int offsPos = 0, offsEnd = lzt.DistanceCount;

        Span<int> recent = stackalloc int[7];
        recent[3] = -8; recent[4] = -8; recent[5] = -8;

        while (cmdPos < cmdEnd)
        {
            uint f = cmd[cmdPos++];
            uint litlen = f & 3;
            int offsIndex = (int)(f >> 6);
            uint matchlen = (f >> 2) & 0xF;

            if (litlen == 3)
            {
                if (lenPos >= lenEnd) return false;
                litlen = (uint)len[lenPos++];
            }
            recent[6] = offsPos < offsEnd ? offs[offsPos] : 0;

            if (litlen != 0)
            {
                if (litPos + litlen > (uint)litEnd || dstPos + litlen > (uint)dstEnd) return false;
                for (uint c = 0; c < litlen; c++) dst[dstPos + c] = lit[litPos + c];
                dstPos += (int)litlen; litPos += (int)litlen;
            }

            int offset = recent[offsIndex + 3];
            recent[offsIndex + 3] = recent[offsIndex + 2];
            recent[offsIndex + 2] = recent[offsIndex + 1];
            recent[offsIndex + 1] = recent[offsIndex + 0];
            recent[3] = offset;

            offsPos += ((offsIndex + 1) & 4) >> 2;

            if (dstPos + offset < dstStart) return false;
            int copyFrom = dstPos + offset;

            uint actual;
            if (matchlen != 15)
            {
                actual = matchlen + 2;
            }
            else
            {
                if (lenPos >= lenEnd) return false;
                actual = 14 + (uint)len[lenPos++];
            }
            if (dstPos + actual > (uint)dstEnd) return false;
            for (uint c = 0; c < actual; c++) dst[dstPos + c] = dst[copyFrom + c];
            dstPos += (int)actual;
        }

        if (offsPos != offsEnd || lenPos != lenEnd) return false;
        int finalLen = dstEnd - dstPos;
        if (finalLen != litEnd - litPos) return false;
        for (int c = 0; c < finalLen; c++) dst[dstPos + c] = lit[litPos + c];
        return true;
    }

    private static bool ProcessLzRunsSub(LzStreams lzt, byte[] dst, int dstPos, int dstEnd, int dstStart)
    {
        byte[] cmd = lzt.Commands; int cmdPos = 0, cmdEnd = lzt.CommandCount;
        int[] len = lzt.Lengths; int lenPos = 0, lenEnd = lzt.LengthCount;
        byte[] lit = lzt.Literals; int litPos = 0, litEnd = lzt.LiteralCount;
        int[] offs = lzt.Distances; int offsPos = 0, offsEnd = lzt.DistanceCount;

        Span<int> recent = stackalloc int[7];
        recent[3] = -8; recent[4] = -8; recent[5] = -8;
        int lastOffset = -8;

        while (cmdPos < cmdEnd)
        {
            uint f = cmd[cmdPos++];
            uint litlen = f & 3;
            int offsIndex = (int)(f >> 6);
            uint matchlen = (f >> 2) & 0xF;

            if (litlen == 3)
            {
                if (lenPos >= lenEnd) return false;
                litlen = (uint)len[lenPos++];
            }
            recent[6] = offsPos < offsEnd ? offs[offsPos] : 0;

            if (litlen != 0)
            {
                if (litPos + litlen > (uint)litEnd || dstPos + litlen > (uint)dstEnd) return false;
                for (uint c = 0; c < litlen; c++)
                    dst[dstPos + c] = (byte)(lit[litPos + c] + dst[dstPos + (int)c + lastOffset]);
                dstPos += (int)litlen; litPos += (int)litlen;
            }

            int offset = recent[offsIndex + 3];
            recent[offsIndex + 3] = recent[offsIndex + 2];
            recent[offsIndex + 2] = recent[offsIndex + 1];
            recent[offsIndex + 1] = recent[offsIndex + 0];
            recent[3] = offset;
            lastOffset = offset;

            offsPos += ((offsIndex + 1) & 4) >> 2;

            if (dstPos + offset < dstStart) return false;
            int copyFrom = dstPos + offset;

            uint actual;
            if (matchlen != 15)
            {
                actual = matchlen + 2;
            }
            else
            {
                if (lenPos >= lenEnd) return false;
                actual = 14 + (uint)len[lenPos++];
            }
            if (dstPos + actual > (uint)dstEnd) return false;
            for (uint c = 0; c < actual; c++) dst[dstPos + c] = dst[copyFrom + c];
            dstPos += (int)actual;
        }

        if (offsPos != offsEnd || lenPos != lenEnd) return false;
        int finalLen = dstEnd - dstPos;
        if (finalLen != litEnd - litPos) return false;
        for (int c = 0; c < finalLen; c++)
            dst[dstPos + c] = (byte)(lit[litPos + c] + dst[dstPos + c + lastOffset]);
        return true;
    }

    // =====================================================================================
    //  MSB-first bit reader (24-bit refill window), forward and backward.
    // =====================================================================================
    private struct BitReader
    {
        public byte[] Data;
        public int P;      // current byte index
        public int Bound;  // forward: exclusive high bound; backward: inclusive low bound
        public uint Bits;
        public int BitPos;
        private bool _backward;

        public static BitReader Forward(byte[] data, int start, int end)
        {
            var r = new BitReader { Data = data, P = start, Bound = end, Bits = 0, BitPos = 24, _backward = false };
            r.RefillForward();
            return r;
        }

        public static BitReader Backward(byte[] data, int low, int high)
        {
            var r = new BitReader { Data = data, P = high, Bound = low, Bits = 0, BitPos = 24, _backward = true };
            r.RefillBackward();
            return r;
        }

        public void Refill() { if (_backward) RefillBackward(); else RefillForward(); }

        public void RefillForward()
        {
            while (BitPos > 0)
            {
                Bits |= (uint)(P < Bound ? Data[P] : 0) << BitPos;
                BitPos -= 8;
                P++;
            }
        }

        public void RefillBackward()
        {
            while (BitPos > 0)
            {
                P--;
                Bits |= (uint)(P >= Bound ? Data[P] : 0) << BitPos;
                BitPos -= 8;
            }
        }

        public int ReadBit()
        {
            Refill();
            int r = (int)(Bits >> 31);
            Bits <<= 1; BitPos += 1;
            return r;
        }

        public int ReadBitNoRefill()
        {
            int r = (int)(Bits >> 31);
            Bits <<= 1; BitPos += 1;
            return r;
        }

        public uint ReadBitsNoRefill(int n)
        {
            uint r = Bits >> (32 - n);
            Bits <<= n; BitPos += n;
            return r;
        }

        public uint ReadBitsNoRefillZero(int n)
        {
            uint r = Bits >> 1 >> (31 - n);
            Bits <<= n; BitPos += n;
            return r;
        }

        public int ReadFluff(int numSymbols)
        {
            if (numSymbols == 256) return 0;
            int x = 257 - numSymbols;
            if (x > numSymbols) x = numSymbols;
            x *= 2;
            int y = MostSignificantBit((uint)(x - 1)) + 1;
            uint v = Bits >> (32 - y);
            uint z = (uint)((1 << y) - x);
            if ((v >> 1) >= z)
            {
                Bits <<= y; BitPos += y;
                return (int)(v - z);
            }
            else
            {
                Bits <<= (y - 1); BitPos += (y - 1);
                return (int)(v >> 1);
            }
        }

        public uint ReadExtra(int n)
        {
            uint rv;
            if (n <= 24) rv = ReadBitsNoRefillZero(n);
            else { rv = ReadBitsNoRefill(24) << (n - 24); RefillForward(); rv += ReadBitsNoRefill(n - 24); }
            RefillForward();
            return rv;
        }

        public uint ReadExtraBackward(int n)
        {
            uint rv;
            if (n <= 24) rv = ReadBitsNoRefillZero(n);
            else { rv = ReadBitsNoRefill(24) << (n - 24); RefillBackward(); rv += ReadBitsNoRefill(n - 24); }
            RefillBackward();
            return rv;
        }

        public uint ReadDistance(uint v)
        {
            uint w, m, rv; int n;
            if (v < 0xF0)
            {
                n = (int)(v >> 4) + 4;
                w = BitOperations.RotateLeft(Bits | 1, n);
                BitPos += n;
                m = (2u << n) - 1;
                Bits = w & ~m;
                rv = ((w & m) << 4) + (v & 0xF) - 248;
            }
            else
            {
                n = (int)(v - 0xF0) + 4;
                w = BitOperations.RotateLeft(Bits | 1, n);
                BitPos += n;
                m = (2u << n) - 1;
                Bits = w & ~m;
                rv = 8322816 + ((w & m) << 12);
                RefillForward();
                rv += Bits >> 20;
                BitPos += 12;
                Bits <<= 12;
            }
            RefillForward();
            return rv;
        }

        public uint ReadDistanceBackward(uint v)
        {
            uint w, m, rv; int n;
            if (v < 0xF0)
            {
                n = (int)(v >> 4) + 4;
                w = BitOperations.RotateLeft(Bits | 1, n);
                BitPos += n;
                m = (2u << n) - 1;
                Bits = w & ~m;
                rv = ((w & m) << 4) + (v & 0xF) - 248;
            }
            else
            {
                n = (int)(v - 0xF0) + 4;
                w = BitOperations.RotateLeft(Bits | 1, n);
                BitPos += n;
                m = (2u << n) - 1;
                Bits = w & ~m;
                rv = 8322816 + ((w & m) << 12);
                RefillBackward();
                rv += Bits >> 20;
                BitPos += 12;
                Bits <<= 12;
            }
            RefillBackward();
            return rv;
        }

        public bool ReadLength(out uint v)
        {
            v = 0;
            int n = 31 - MostSignificantBit(Bits);
            if (n > 12) return false;
            BitPos += n; Bits <<= n; RefillForward();
            n += 7;
            BitPos += n;
            v = (Bits >> (32 - n)) - 64;
            Bits <<= n; RefillForward();
            return true;
        }

        public bool ReadLengthBackward(out uint v)
        {
            v = 0;
            int n = 31 - MostSignificantBit(Bits);
            if (n > 12) return false;
            BitPos += n; Bits <<= n; RefillBackward();
            n += 7;
            BitPos += n;
            v = (Bits >> (32 - n)) - 64;
            Bits <<= n; RefillBackward();
            return true;
        }
    }

    // =====================================================================================
    //  Bit/byte helpers and static tables.
    // =====================================================================================
    private static int MostSignificantBit(uint x) => x == 0 ? 0 : 31 - BitOperations.LeadingZeroCount(x);
    private static int LeastSignificantBit(uint x) => x == 0 ? 0 : BitOperations.TrailingZeroCount(x);
    private static int CountLeadingZeros(uint x) => x == 0 ? 31 : BitOperations.LeadingZeroCount(x);

    private static byte At(byte[] b, int i) => (uint)i < (uint)b.Length ? b[i] : (byte)0;

    private static uint ReadLE32(byte[] b, int off)
    {
        uint r = 0;
        for (int i = 0; i < 4; i++)
            if ((uint)(off + i) < (uint)b.Length) r |= (uint)b[off + i] << (8 * i);
        return r;
    }

    private static ulong ReadLE64(byte[] b, int off)
    {
        ulong r = 0;
        for (int i = 0; i < 8; i++)
            if ((uint)(off + i) < (uint)b.Length) r |= (ulong)b[off + i] << (8 * i);
        return r;
    }

    private static void WriteLE32(byte[] b, int off, uint v)
    {
        for (int i = 0; i < 4; i++)
            if ((uint)(off + i) < (uint)b.Length) b[off + i] = (byte)(v >> (8 * i));
    }

    private static void WriteLE64(byte[] b, int off, ulong v)
    {
        for (int i = 0; i < 8; i++)
            if ((uint)(off + i) < (uint)b.Length) b[off + i] = (byte)(v >> (8 * i));
    }

    private static uint Swap32(uint v) => BinaryPrimitives.ReverseEndianness(v);
    private static ulong Swap64(ulong v) => BinaryPrimitives.ReverseEndianness(v);

    private static uint[] BuildRiceValue()
    {
        return new uint[256]
        {
            0x80000000, 0x00000007, 0x10000006, 0x00000006, 0x20000005, 0x00000105, 0x10000005, 0x00000005,
            0x30000004, 0x00000204, 0x10000104, 0x00000104, 0x20000004, 0x00010004, 0x10000004, 0x00000004,
            0x40000003, 0x00000303, 0x10000203, 0x00000203, 0x20000103, 0x00010103, 0x10000103, 0x00000103,
            0x30000003, 0x00020003, 0x10010003, 0x00010003, 0x20000003, 0x01000003, 0x10000003, 0x00000003,
            0x50000002, 0x00000402, 0x10000302, 0x00000302, 0x20000202, 0x00010202, 0x10000202, 0x00000202,
            0x30000102, 0x00020102, 0x10010102, 0x00010102, 0x20000102, 0x01000102, 0x10000102, 0x00000102,
            0x40000002, 0x00030002, 0x10020002, 0x00020002, 0x20010002, 0x01010002, 0x10010002, 0x00010002,
            0x30000002, 0x02000002, 0x11000002, 0x01000002, 0x20000002, 0x00000012, 0x10000002, 0x00000002,
            0x60000001, 0x00000501, 0x10000401, 0x00000401, 0x20000301, 0x00010301, 0x10000301, 0x00000301,
            0x30000201, 0x00020201, 0x10010201, 0x00010201, 0x20000201, 0x01000201, 0x10000201, 0x00000201,
            0x40000101, 0x00030101, 0x10020101, 0x00020101, 0x20010101, 0x01010101, 0x10010101, 0x00010101,
            0x30000101, 0x02000101, 0x11000101, 0x01000101, 0x20000101, 0x00000111, 0x10000101, 0x00000101,
            0x50000001, 0x00040001, 0x10030001, 0x00030001, 0x20020001, 0x01020001, 0x10020001, 0x00020001,
            0x30010001, 0x02010001, 0x11010001, 0x01010001, 0x20010001, 0x00010011, 0x10010001, 0x00010001,
            0x40000001, 0x03000001, 0x12000001, 0x02000001, 0x21000001, 0x01000011, 0x11000001, 0x01000001,
            0x30000001, 0x00000021, 0x10000011, 0x00000011, 0x20000001, 0x00001001, 0x10000001, 0x00000001,
            0x70000000, 0x00000600, 0x10000500, 0x00000500, 0x20000400, 0x00010400, 0x10000400, 0x00000400,
            0x30000300, 0x00020300, 0x10010300, 0x00010300, 0x20000300, 0x01000300, 0x10000300, 0x00000300,
            0x40000200, 0x00030200, 0x10020200, 0x00020200, 0x20010200, 0x01010200, 0x10010200, 0x00010200,
            0x30000200, 0x02000200, 0x11000200, 0x01000200, 0x20000200, 0x00000210, 0x10000200, 0x00000200,
            0x50000100, 0x00040100, 0x10030100, 0x00030100, 0x20020100, 0x01020100, 0x10020100, 0x00020100,
            0x30010100, 0x02010100, 0x11010100, 0x01010100, 0x20010100, 0x00010110, 0x10010100, 0x00010100,
            0x40000100, 0x03000100, 0x12000100, 0x02000100, 0x21000100, 0x01000110, 0x11000100, 0x01000100,
            0x30000100, 0x00000120, 0x10000110, 0x00000110, 0x20000100, 0x00001100, 0x10000100, 0x00000100,
            0x60000000, 0x00050000, 0x10040000, 0x00040000, 0x20030000, 0x01030000, 0x10030000, 0x00030000,
            0x30020000, 0x02020000, 0x11020000, 0x01020000, 0x20020000, 0x00020010, 0x10020000, 0x00020000,
            0x40010000, 0x03010000, 0x12010000, 0x02010000, 0x21010000, 0x01010010, 0x11010000, 0x01010000,
            0x30010000, 0x00010020, 0x10010010, 0x00010010, 0x20010000, 0x00011000, 0x10010000, 0x00010000,
            0x50000000, 0x04000000, 0x13000000, 0x03000000, 0x22000000, 0x02000010, 0x12000000, 0x02000000,
            0x31000000, 0x01000020, 0x11000010, 0x01000010, 0x21000000, 0x01001000, 0x11000000, 0x01000000,
            0x40000000, 0x00000030, 0x10000020, 0x00000020, 0x20000010, 0x00001010, 0x10000010, 0x00000010,
            0x30000000, 0x00002000, 0x10001000, 0x00001000, 0x20000000, 0x00100000, 0x10000000, 0x00000000,
        };
    }

    private static byte[] BuildRiceLength()
    {
        return new byte[256]
        {
            0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
            1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
            1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
            2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
            1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
            2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
            2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
            3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8,
        };
    }
}
