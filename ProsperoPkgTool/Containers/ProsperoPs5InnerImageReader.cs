using ProsperoPkgTool.Compression;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room reader for the PS5 data-first inner image (<c>pfs_image.dat</c>). The inner
/// image is a raw concatenation of per-block payloads (raw or header-stripped Kraken chunks);
/// its per-block geometry lives ONLY in the sibling <c>naps_pkg_layout.dat</c> CblockInfo
/// section (FINDINGS.md §3.4, §9.7). This class walks that geometry to reconstruct the
/// uncompressed inner mount and to locate individual files.
///
/// The block walk is the disassembly-confirmed native algorithm:
///   * RUN entries (isRunBase) are skipped entirely and carry no payload.
///   * Consecutive STD entries define one block. Its uncompressed length is
///     <c>((next.UoffsetStart - curr.UoffsetStart - 1) &amp; 0x3FFFF) + 1</c> (bounded to
///     256 KiB by the mask); its total compressed length is
///     <c>(next.CoffsetStart - curr.CoffsetStart) &amp; 0x3FFFF</c> (no -1/+1 wrap, so dedup
///     blocks sharing a coff contribute 0 compressed bytes); the even sub-chunk's compressed
///     length is <c>ClenEvenMinus1 + 1</c> and the odd sub-chunk's is the remainder. Dedup
///     blocks (zero compressed delta) still contribute a full 256 KiB uncompressed block.
/// </summary>
public static class ProsperoPs5InnerImageReader
{
    private const int Chunk128K = 0x20000;
    private const int Ublock256K = 0x40000;
    private const int OuterBlock64K = 0x10000;
    private const uint Mod256K = 0x3FFFF;

    /// <summary>One decoded block of the inner image.</summary>
    public readonly record struct InnerBlock(
        long CompressedOffset,   // absolute compressed offset in pfs_image.dat
        int CompressedLength,    // total compressed bytes (0 for dedup)
        int EvenCompressedLength,// even sub-chunk compressed bytes
        long UncompressedOffset, // absolute uncompressed offset in the mount
        int UncompressedLength,  // uncompressed bytes (<= 0x40000)
        bool IsKraken,           // true when the block is Kraken-compressed
        bool IsZeroHole = false,
        bool IsAlias = false,
        int SourceBlockIndex = -1,
        int RunIndex = -1,
        int KrakenFlags = 0);    // decoder selector derived from the NAPS Even/Odd fields

    /// <summary>
    /// Walk the CblockInfo section and return every STD block with its decoded geometry,
    /// in mount order (FINDINGS.md §9.7). RUN entries are skipped entirely; the native walk
    /// pairs consecutive STD entries and computes sizes from the STD fields directly:
    ///   uncompressed = ((next.uoff - curr.uoff - 1) &amp; 0x3FFFF) + 1   (bounded to 256 KiB by the mask)
    ///   compressed   = (next.coff - curr.coff) &amp; 0x3FFFF              (NO -1/+1 wrap)
    ///   evenComp     = curr.clenEvenMinus1 + 1
    /// Dedup blocks share an identical coff (compressed == 0) but still contribute their full
    /// 256 KiB uncompressed size; they carry no payload.
    /// </summary>
    public static IReadOnlyList<InnerBlock> WalkBlocks(
        ReadOnlySpan<byte> naps, long innerImageLength)
    {
        IReadOnlyList<NapsCblockInfoEntry> cb = DecodeCblockInfos(naps);

        var stds = new List<(NapsCblockInfoEntry Entry, NapsCblockInfoEntry? Run, int RunIndex, int EntryIndex, uint EndCoffMod)>();
        NapsCblockInfoEntry? activeRun = null;
        int runIndex = -1;
        for (int i = 0; i < cb.Count; i++)
        {
            if (cb[i].IsRunBase) { activeRun = cb[i]; runIndex = i; }
            else
            {
                // Span end boundary, mirroring the reference: the next raw CblockInfo entry, or —
                // when a RUN follows — that RUN's end offset (the cursor before it re-bases). Using
                // the next STD directly would mis-size the last block before every RUN.
                uint endCoffMod = i + 1 < cb.Count
                    ? (cb[i + 1].IsRunBase ? cb[i + 1].CoffsetEndMod256K : cb[i + 1].CoffsetStartMod256K)
                    : cb[i].CoffsetStartMod256K;
                stds.Add((cb[i], activeRun, runIndex, i, endCoffMod));
            }
        }
        if (stds.Count < 2)
            throw new InvalidDataException("NAPS CblockInfo does not contain a STD block and terminator.");

        // The repository's Sony-built debug fixture predates the clean-room stored marker.
        // Retain its verified legacy traversal while all generated layouts take the RUN-aware path.
        // Compression type alone does not distinguish the old fixture from a generated mixed
        // layout: clean-room Kraken layouts use type 2 too. The old fixture has no explicit
        // stored marker, whereas every generated stored-or-mixed layout has one.
        // The legacy Sony fixture predates the clean-room stored marker and keeps every stored
        // offset below 256 KiB, so both its own heuristic and the absence of any high RUN page
        // distinguish it from a modern data-first layout (which re-bases the compressed cursor at
        // RUN.CoffsetStart256K, including reference-writer packages that omit our private marker).
        bool legacyLayout = ProsperoNapsLayout.DecodeHeader(naps).CompressionType != 0 &&
            !stds.Any(s => (s.Entry.Raw[8] & 0x08) != 0) &&
            !stds.Any(s => s.Run is { CoffsetStart256K: > 0 });

        var result = new List<InnerBlock>(stds.Count - 1);
        long absUoff = 0; // absolute uncompressed cursor (uoff field is mod-256K and wraps)
        long sourceCursor = 0;
        int lastRun = -1;
        var sourceOwners = new Dictionary<long, int>();
        for (int i = 0; i + 1 < stds.Count; i++)
        {
            NapsCblockInfoEntry curr = stds[i].Entry;
            NapsCblockInfoEntry next = stds[i + 1].Entry;

            if (legacyLayout)
            {
                sourceCursor = curr.CoffsetStartMod256K;
            }
            else if (stds[i].Run is NapsCblockInfoEntry run && stds[i].RunIndex != lastRun)
            {
                // A RUN records the absolute 256KiB page.  The following STD supplies its
                // low 18 bits; never mistake that low field for a file offset on its own.
                sourceCursor = ((long)run.CoffsetStart256K << 18) | curr.CoffsetStartMod256K;
                lastRun = stds[i].RunIndex;
            }

            // Uncompressed delta wraps (dedup copies each add a full 256 KiB block); the
            // & 0x3FFFF mask itself bounds the result to 256 KiB (no separate clamp).
            int uncompressed = (int)((uint)((next.UoffsetStart - curr.UoffsetStart - 1) & Mod256K) + 1);

            // Generated layouts size a span to its next boundary, using a following RUN's end offset
            // (the cursor before it re-bases), exactly like the native reader. The Sony debug fixture
            // predates that and keeps its separately verified next-STD delta.
            int totalComp = legacyLayout
                ? (int)((next.CoffsetStartMod256K - curr.CoffsetStartMod256K) & Mod256K)
                : (int)((stds[i].EndCoffMod - curr.CoffsetStartMod256K) & Mod256K);
            int evenComp = (int)(curr.ClenEvenMinus1 + 1);
            // Zero/dedup holes come in two forms: the legacy marker (even=odd=kde=0) and the
            // native 8/16-byte dedup form (even=1, even-chunk 8, odd=1/clen 16 or odd=0/clen 8,
            // kde=0) — mirrors ProsperoNapsImage.IsDeduplicatedZeroSpan.
            bool zeroHole = (curr.Even == 0 && curr.Odd == 0 && curr.KdePredictor == 0)
                || (curr.Even == 1 && curr.KdePredictor == 0 && curr.ClenEvenMinus1 == 7 &&
                    ((curr.Odd == 1 && totalComp == 16 && uncompressed > 16) ||
                     (curr.Odd == 0 && totalComp == 8 && uncompressed > 8)));
            // Stored blocks deliberately use KDE=0 in this clean-room writer. A full 256KiB
            // stored block wraps its modulo Coffset to zero, so derive its stream size from its
            // logical size rather than treating it as a dedup alias.
            bool stored = (curr.Raw[8] & 0x08) != 0 && !zeroHole;
            if (stored)
                totalComp = uncompressed;
            // Legacy debug layouts also use KDE=0 short/zero streams for sparse aliases. This
            // is distinct from an explicitly-marked stored block made by this writer. Generated
            // Kraken blocks also use KDE=0 (the reference/console requires it), so the non-legacy
            // path must identify a dedup alias purely by its zero compressed delta rather than by
            // the predictor; the exact zero-hole shape is already captured by zeroHole above.
            bool isDedup = legacyLayout
                ? !zeroHole && (totalComp == 0 || (curr.KdePredictor == 0 && curr.Even == 1 && curr.Odd == 1 && totalComp < uncompressed))
                : !stored && !zeroHole && totalComp == 0;
            bool kraken = !stored && !isDedup && !zeroHole && totalComp < uncompressed;
            int owner = -1;
            if (isDedup)
                sourceOwners.TryGetValue(sourceCursor, out owner);
            int krakenFlags = kraken ? DeriveKrakenFlags(curr.Even, curr.Odd, uncompressed > Chunk128K) : 0;
            result.Add(new InnerBlock(
                sourceCursor, totalComp, evenComp,
                absUoff, uncompressed, kraken, zeroHole, isDedup, owner, lastRun, krakenFlags));

            if (!zeroHole && !isDedup)
                sourceOwners[sourceCursor] = result.Count - 1;

            absUoff += uncompressed;
            if (!zeroHole && !isDedup)
                sourceCursor += totalComp;
        }

        return result;
    }

    /// <summary>
    /// Decode the CblockInfo entries from a raw NAPS blob using the Sony-native cbi-base formula
    /// (the entries are 9-byte/72-bit little-endian values, tightly packed with no per-entry
    /// padding). This bypasses the higher-level <see cref="NapsLayoutDocument"/> section map whose
    /// fidx-residue model does not reproduce the native cbi offset.
    /// </summary>
    private static IReadOnlyList<NapsCblockInfoEntry> DecodeCblockInfos(ReadOnlySpan<byte> naps)
    {
        NapsLayoutCounts counts = ProsperoNapsLayout.DecodeHeader(naps);
        long cbiBase = ProsperoNapsLayout.ComputeCblockInfoBase(naps);
        int count = counts.NumCblockInfo;

        var entries = new List<NapsCblockInfoEntry>(count);
        for (int i = 0; i < count; i++)
        {
            long byteOffset = cbiBase + ((long)i * 72) / 8;
            if (byteOffset + 9 > naps.Length)
                break;
            entries.Add(ProsperoNapsLayout.DecodeCblockInfoEntry(naps.Slice((int)byteOffset, 9)));
        }
        return entries;
    }

    /// <summary>
    /// Reconstruct the uncompressed inner mount from the data-first inner image and its NAPS
    /// layout. Raw blocks are copied straight through; Kraken blocks are decoded via
    /// <see cref="KrakenDecoder"/>. The flag semantics of <c>m_even</c>/<c>m_odd</c>/
    /// <c>m_KdePredictor</c> are still open (FINDINGS.md §3.4c), so the per-block Kraken flags
    /// are selected by trying the observed combinations; the first that decodes cleanly wins.
    /// </summary>
    public static byte[] ReconstructMount(byte[] innerImage, byte[] naps)
    {
        ArgumentNullException.ThrowIfNull(innerImage);
        ArgumentNullException.ThrowIfNull(naps);

        IReadOnlyList<InnerBlock> blocks = WalkBlocks(naps, innerImage.Length);

        // Mount size = highest uncompressed boundary, 64K-aligned.
        long mountSize = 0;
        foreach (InnerBlock b in blocks)
            mountSize = Math.Max(mountSize, b.UncompressedOffset + b.UncompressedLength);
        mountSize = (mountSize + 0xFFFF) & ~0xFFFFL;
        if (mountSize <= 0 || mountSize > int.MaxValue)
            throw new InvalidDataException($"Implausible inner mount size {mountSize}.");

        var mount = new byte[mountSize];
        foreach (InnerBlock b in blocks)
        {
            int room = (int)Math.Min(b.UncompressedLength, mount.Length - b.UncompressedOffset);
            if (room <= 0)
                continue;

            if (b.IsZeroHole)
                continue;

            if (b.IsAlias)
            {
                // Older observed layouts use zero-length aliases for sparse/zero extents without
                // a materialized source. Preserve that verified behaviour; non-zero aliases made
                // by this writer resolve to an earlier source block below.
                if (b.SourceBlockIndex < 0)
                    continue;
                if (b.SourceBlockIndex >= blocks.Count)
                    throw new InvalidDataException($"Invalid NAPS alias source {b.SourceBlockIndex}.");
                InnerBlock source = blocks[b.SourceBlockIndex];
                if (source.UncompressedLength < room)
                    continue; // legacy sparse alias; no same-sized materialized source exists
                Array.Copy(mount, source.UncompressedOffset, mount, b.UncompressedOffset, room);
                continue;
            }

            if (!b.IsKraken)
            {
                if (b.CompressedOffset < 0 || b.CompressedLength < room ||
                    b.CompressedOffset + room > innerImage.Length)
                    throw new InvalidDataException($"Stored NAPS block at logical 0x{b.UncompressedOffset:X} reads outside pfs_image.dat (source 0x{b.CompressedOffset:X}, length 0x{room:X}).");
                Array.Copy(innerImage, b.CompressedOffset, mount, b.UncompressedOffset, room);
                continue;
            }

            DecodeKrakenBlock(innerImage, b, mount);
        }

        return mount;
    }

    /// <summary>Highest 64 KiB-aligned uncompressed boundary of the mount described by <paramref name="blocks"/>.</summary>
    public static long MountSize(IReadOnlyList<InnerBlock> blocks)
    {
        long mountSize = 0;
        foreach (InnerBlock b in blocks)
            mountSize = Math.Max(mountSize, b.UncompressedOffset + b.UncompressedLength);
        return (mountSize + 0xFFFF) & ~0xFFFFL;
    }

    /// <summary>
    /// File-backed counterpart of <see cref="ReconstructMount(byte[], byte[])"/>: writes the
    /// uncompressed mount to <paramref name="outputPath"/> one block at a time, so a multi-GB
    /// inner image needs neither a whole <c>byte[]</c> source nor destination.
    /// <paramref name="readInnerImage"/> returns <paramref name="length"/> decrypted bytes at the
    /// given <c>pfs_image.dat</c> offset.
    /// </summary>
    public static void ReconstructMountToFile(
        IReadOnlyList<InnerBlock> blocks, long innerImageLength,
        Func<long, int, byte[]> readInnerImage, string outputPath)
    {
        ArgumentNullException.ThrowIfNull(blocks);
        ArgumentNullException.ThrowIfNull(readInnerImage);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);

        long mountSize = MountSize(blocks);
        if (mountSize <= 0)
            throw new InvalidDataException($"Implausible inner mount size {mountSize}.");

        string full = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(full) ?? Directory.GetCurrentDirectory());
        using var destination = new FileStream(full, FileMode.Create, FileAccess.ReadWrite, FileShare.None,
            1 << 20, FileOptions.RandomAccess);
        destination.SetLength(mountSize);

        byte[] scratch = new byte[Ublock256K];
        for (int i = 0; i < blocks.Count; i++)
        {
            InnerBlock b = blocks[i];
            int room = (int)Math.Min(b.UncompressedLength, mountSize - b.UncompressedOffset);
            if (room <= 0 || b.IsZeroHole)
                continue;

            if (b.IsAlias)
            {
                if (b.SourceBlockIndex < 0 || b.SourceBlockIndex >= blocks.Count)
                    continue;
                InnerBlock source = blocks[b.SourceBlockIndex];
                if (source.UncompressedLength < room)
                    continue; // legacy sparse alias; no same-sized materialized source exists
                destination.Position = source.UncompressedOffset;
                ReadFully(destination, scratch, room);
                destination.Position = b.UncompressedOffset;
                destination.Write(scratch, 0, room);
                continue;
            }

            if (!b.IsKraken)
            {
                if (b.CompressedOffset < 0 || b.CompressedLength < room ||
                    b.CompressedOffset + room > innerImageLength)
                    throw new InvalidDataException($"Stored NAPS block at logical 0x{b.UncompressedOffset:X} reads outside pfs_image.dat (source 0x{b.CompressedOffset:X}, length 0x{room:X}).");
                byte[] plain = readInnerImage(b.CompressedOffset, room);
                destination.Position = b.UncompressedOffset;
                destination.Write(plain, 0, room);
                continue;
            }

            if (b.CompressedOffset < 0 || b.CompressedLength <= 0 ||
                b.CompressedOffset + b.CompressedLength > innerImageLength)
                throw new InvalidDataException($"Kraken NAPS block at logical 0x{b.UncompressedOffset:X} has invalid source range 0x{b.CompressedOffset:X}+0x{b.CompressedLength:X}.");

            byte[] compressed = readInnerImage(b.CompressedOffset, b.CompressedLength);
            byte[] decoded = new byte[b.UncompressedLength];
            bool multiChunk = b.UncompressedLength > Chunk128K;
            int firstChunkComp = multiChunk ? b.EvenCompressedLength : 0;
            bool ok = false;
            foreach (int flags in FlagCandidates(multiChunk, b.KrakenFlags))
            {
                KrakenDecoder.KrakenDecodeStatus st;
                try { st = KrakenDecoder.DecodeBlock(compressed, flags, firstChunkComp, decoded); }
                catch { continue; }
                if (st == KrakenDecoder.KrakenDecodeStatus.Success) { ok = true; break; }
            }
            if (!ok)
                throw new InvalidDataException($"Kraken decode failed for NAPS block at logical 0x{b.UncompressedOffset:X}, source 0x{b.CompressedOffset:X}+0x{b.CompressedLength:X}, KDE unknown.");
            destination.Position = b.UncompressedOffset;
            destination.Write(decoded, 0, room);
        }
        destination.Flush();
    }

    private static void ReadFully(Stream stream, byte[] buffer, int length)
    {
        int read = 0;
        while (read < length)
        {
            int n = stream.Read(buffer, read, length - read);
            if (n <= 0)
                throw new EndOfStreamException("The reconstructed mount ended before its declared size.");
            read += n;
        }
    }

    private static void DecodeKrakenBlock(byte[] innerImage, InnerBlock b, byte[] mount)
    {
        if (b.CompressedOffset < 0 || b.CompressedOffset + b.CompressedLength > innerImage.Length ||
            b.CompressedLength <= 0)
            throw new InvalidDataException($"Kraken NAPS block at logical 0x{b.UncompressedOffset:X} has invalid source range 0x{b.CompressedOffset:X}+0x{b.CompressedLength:X}.");

        ReadOnlySpan<byte> src = innerImage.AsSpan(
            (int)b.CompressedOffset, b.CompressedLength);
        Span<byte> dst = mount.AsSpan((int)b.UncompressedOffset, b.UncompressedLength);
        bool multiChunk = b.UncompressedLength > Chunk128K;
        int firstChunkComp = multiChunk ? b.EvenCompressedLength : 0;

        foreach (int flags in FlagCandidates(multiChunk, b.KrakenFlags))
        {
            KrakenDecoder.KrakenDecodeStatus st;
            try { st = KrakenDecoder.DecodeBlock(src, flags, firstChunkComp, dst); }
            catch { continue; }
            if (st == KrakenDecoder.KrakenDecodeStatus.Success)
                return;
        }
        throw new InvalidDataException($"Kraken decode failed for NAPS block at logical 0x{b.UncompressedOffset:X}, source 0x{b.CompressedOffset:X}+0x{b.CompressedLength:X}, KDE unknown.");
    }

    /// <summary>
    /// Inverse of the writer's NAPS <c>Even</c>/<c>Odd</c> selector mapping
    /// (<c>ProsperoNapsPlanGenerator.CodecModes</c>): the even selector carries the first
    /// sub-chunk's newLZ (bit 2) and delta-literal (bit 1) mode; the odd selector carries the
    /// same for the second sub-chunk. Deriving the decoder flags this way distinguishes raw from
    /// delta-literal newLZ blocks, which a blind candidate search cannot (both may "succeed").
    /// </summary>
    private static int DeriveKrakenFlags(byte even, byte odd, bool multiChunk)
    {
        int flags = 0;
        if ((even & 4) != 0) flags |= 0x02;
        if ((even & 2) != 0) flags |= 0x01;
        if (multiChunk)
        {
            if ((odd & 4) != 0) flags |= 0x20;
            if ((odd & 2) != 0) flags |= 0x10;
        }
        return flags;
    }

    private static int[] FlagCandidates(bool multiChunk, int derived)
    {
        int[] baseList = multiChunk
            ? [0x22, 0x02, 0x12, 0x32, 0x23, 0x03, 0x13, 0x33, 0x00, 0x20]
            : [0x02, 0x00, 0x03, 0x01];
        if (baseList[0] == derived)
            return baseList;
        var list = new List<int>(baseList.Length + 1) { derived };
        foreach (int f in baseList)
            if (f != derived) list.Add(f);
        return list.ToArray();
    }

    /// <summary>
    /// Reconstruct a Sony RUN-addressed mount from virtual encrypted PFS blocks. Unlike the
    /// project's generated contiguous images, patch images retain source-sector encryption and
    /// therefore must be decrypted with each RUN's absolute tweak cursor.
    /// </summary>
    public static byte[] ReconstructRunEncryptedMount(byte[] encryptedVirtualImage, byte[] naps, AesXts xts)
    {
        ArgumentNullException.ThrowIfNull(encryptedVirtualImage);
        ArgumentNullException.ThrowIfNull(naps);
        ArgumentNullException.ThrowIfNull(xts);

        NapsLayoutDocument document = ProsperoNapsLayout.Parse(naps);
        var decoded = new List<byte[]>();
        NapsCblockInfoEntry? activeRun = null;
        int activeRunIndex = -1;
        int firstStdIndex = -1;
        long totalLength = 0;

        for (int index = 0; index + 1 < document.CblockInfos.Count; index++)
        {
            NapsCblockInfoEntry item = document.CblockInfos[index];
            if (item.IsRunBase)
            {
                activeRun = item;
                activeRunIndex = index;
                firstStdIndex = index + 1;
                continue;
            }
            if (item.Even == 0)
                continue;
            if (activeRun is not { } run || run.KeyTableIdx != 0 || firstStdIndex < 0 || firstStdIndex >= document.CblockInfos.Count)
                throw new InvalidDataException($"Unsupported or missing NAPS RUN before CblockInfo record {index}.");

            NapsCblockInfoEntry next = document.CblockInfos[index + 1];
            uint end = next.IsRunBase ? next.CoffsetEndMod256K : next.CoffsetStartMod256K;
            int compressedLength = (int)((end - item.CoffsetStartMod256K) & Mod256K);
            int nextStdIndex = next.IsRunBase ? index + 2 : index + 1;
            if (nextStdIndex >= document.CblockInfos.Count || document.CblockInfos[nextStdIndex].IsRunBase)
                throw new InvalidDataException($"NAPS record {index} has no following STD boundary.");
            NapsCblockInfoEntry nextStd = document.CblockInfos[nextStdIndex];
            int outputLength = (int)(((nextStd.UoffsetStart - item.UoffsetStart - 1) & Mod256K) + 1);

            long sourceOffset = ((long)run.CoffsetStart256K << 18) | item.CoffsetStartMod256K;
            NapsCblockInfoEntry runFirstStd = document.CblockInfos[firstStdIndex];
            long runSourceOffset = ((long)run.CoffsetStart256K << 18) | runFirstStd.CoffsetStartMod256K;
            int runStartBlock = checked((int)(runSourceOffset / OuterBlock64K));
            byte[] plainSource = DecryptRunRange(encryptedVirtualImage, xts, sourceOffset,
                compressedLength, run.TweakIdxStart, runStartBlock, activeRunIndex);

            byte[] output;
            if (compressedLength == outputLength)
            {
                output = plainSource;
            }
            else
            {
                if (compressedLength <= 0)
                    throw new InvalidDataException($"Compressed NAPS record {index} has an empty source range.");
                output = new byte[outputLength];
                bool multiChunk = outputLength > Chunk128K;
                int flags = DecodeSonyCodecFlags(item, multiChunk);
                int firstChunkLength = multiChunk ? checked((int)item.ClenEvenMinus1 + 1) : 0;
                KrakenDecoder.KrakenDecodeStatus status = KrakenDecoder.DecodeBlock(
                    plainSource, flags, firstChunkLength, output);
                if (status != KrakenDecoder.KrakenDecodeStatus.Success)
                    throw new InvalidDataException($"Kraken decode failed for NAPS record {index} ({status}, flags 0x{flags:X2}).");
            }
            totalLength = checked(totalLength + output.Length);
            if (totalLength > int.MaxValue)
                throw new InvalidDataException("Reconstructed patch mount exceeds the supported in-memory size.");
            decoded.Add(output);
        }

        var mount = new byte[checked((int)totalLength)];
        int destination = 0;
        foreach (byte[] block in decoded)
        {
            block.CopyTo(mount, destination);
            destination += block.Length;
        }
        return mount;
    }

    private static byte[] DecryptRunRange(byte[] encrypted, AesXts xts, long sourceOffset,
        int length, uint tweakStart, int runStartBlock, int runIndex)
    {
        if (sourceOffset < 0 || length < 0 || sourceOffset > encrypted.Length || length > encrypted.Length - sourceOffset)
            throw new InvalidDataException($"NAPS RUN {runIndex} source range 0x{sourceOffset:X}+0x{length:X} is outside the virtual image.");
        if (length == 0)
            return [];

        int firstBlock = checked((int)(sourceOffset / OuterBlock64K));
        int lastBlock = checked((int)((sourceOffset + length - 1) / OuterBlock64K));
        if (firstBlock < runStartBlock)
            throw new InvalidDataException($"NAPS RUN {runIndex} source precedes its tweak origin.");
        var plainBlocks = new byte[checked((lastBlock - firstBlock + 1) * OuterBlock64K)];
        for (int block = firstBlock; block <= lastBlock; block++)
        {
            byte[] cipher = encrypted.AsSpan(block * OuterBlock64K, OuterBlock64K).ToArray();
            byte[] plain = xts.Decrypt(cipher, checked((ulong)tweakStart + (ulong)(block - runStartBlock)));
            plain.CopyTo(plainBlocks, (block - firstBlock) * OuterBlock64K);
        }
        int withinFirst = checked((int)(sourceOffset - (long)firstBlock * OuterBlock64K));
        return plainBlocks.AsSpan(withinFirst, length).ToArray();
    }

    /// <summary>
    /// Maps the Sony 3-bit <c>Even</c>/<c>Odd</c> NAPS codec selectors onto the decoder's per-sub-chunk
    /// flag bits. The selectors behave as bit flags: bit 2 (value 4) marks a newLZ sub-chunk and bit 1
    /// (value 2) selects delta/sub-mode literals (0) over raw literals (1); value 1 alone is a bare
    /// entropy array. So 4/5 = newLZ raw literals, 6/7 = newLZ sub/delta literals, 1 = bare array.
    /// </summary>
    private static int DecodeSonyCodecFlags(NapsCblockInfoEntry item, bool multiChunk)
    {
        int low = item.Even switch
        {
            1 => 0x00,        // bare entropy array
            4 or 5 => 0x02,   // newLZ, raw literals
            6 or 7 => 0x03,   // newLZ, sub/delta literals
            _ => throw new InvalidDataException($"Unsupported Sony NAPS even codec selector {item.Even}.")
        };
        if (!multiChunk)
            return low;
        int high = item.Odd switch
        {
            1 => 0x00,
            4 or 5 => 0x20,   // newLZ, raw literals
            6 or 7 => 0x30,   // newLZ, sub/delta literals
            _ => throw new InvalidDataException($"Unsupported Sony NAPS odd codec selector {item.Odd}.")
        };
        return low | high;
    }
}
