using System.Buffers.Binary;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room generator for the finalized NAPS block plan of a built inner image. Produces the
/// <see cref="NapsGenerationRequest"/> consumed by <see cref="ProsperoNapsLayoutBuilder"/> from the
/// assembler's placement table, replacing the former per-file hand-built plan in <c>img_create</c>
/// (follow-up roadmap item #1: general NAPS block-plan generator).
///
/// Coverage:
///   * multi-ublock files: each raw file splits into floor(size/256KiB) full ublocks plus a tail
///     (the plan no longer assumes one ublock per file);
///   * hole (inter-file padding) tiling: the logical gap [DataEndLogical, MetaBaseLogical) is
///     tiled by 256 KiB dedup blocks aliased onto the shared zero-block-info payload
///     (8+8 compressed bytes, the <c>*PFSmetadata</c>-class dedup stride);
///   * metadata blocks: the stored PFSv3 container's per-256KiB plaintext chunks at their true
///     on-disk offsets (container-relative data-section offset honored);
///   * run schedule: a RUN base re-anchors the compressed cursor at every file start and whenever
///     a block's on-disk offset does not sit strictly within one 256 KiB window of the previous
///     data block's on-disk end (guaranteeing adjacent STD deltas never alias to dedup under the
///     mod-256K coff encoding), plus at hole/metadata re-anchors and the terminator;
///   * fidx: afid logical offsets + dataEnd + metaBase + mount-size sentinels (Sony order).
///
/// All fields are BYTES (the builder's unit convention). Block flag shapes follow the observed
/// Sony conventions: sub-ublock stored blocks use even=1/odd=0/kde=0 (debug-fixture raw style);
/// full 256 KiB ublocks use even=1/odd=1/kde=0; hole dedup blocks use even-chunk 8 with
/// stream 8 (odd=0) or 16 (odd=1) and kde=0; the terminator opens its own RUN.
/// </summary>
public static class ProsperoNapsPlanGenerator
{
    private const long UBlock = 0x40000;        // 256 KiB uncompressed block
    private const int Block64K = 0x10000;       // on-disk/on-image block granularity

    /// <summary>The PFSC id=7 section directory entry holding the data-section offset.</summary>
    private const int Pfsv3DataOffsetField = 0xAA;

    /// <summary>A generated NAPS block plan ready for serialization.</summary>
    public sealed class PlanResult
    {
        /// <summary>The ordered block plan.</summary>
        public required IReadOnlyList<NapsCblockPlanEntry> Blocks { get; init; }

        /// <summary>fidx logical offsets: afid order + dataEnd + metaBase + mount size.</summary>
        public required IReadOnlyList<long> FileLogicalOffsets { get; init; }

        /// <summary>Total number of mount blocks.</summary>
        public required int NumUBlocks { get; init; }

        /// <summary>Outer image block count (64K granularity).</summary>
        public required int NumOuterBlocks { get; init; }

        /// <summary>The uncompressed mount size in bytes (<see cref="ProsperoInnerImageAssembler.InnerImageResult.Ndblock"/>·64K).</summary>
        public required long MountSize { get; init; }

        /// <summary>Wraps the plan into a generation request (compression type 0).</summary>
        public NapsGenerationRequest ToRequest(byte compressionType = 0, byte finalFileOffsetType = 0x40) => new()
        {
            CompressionType = compressionType,
            NumUBlocks = NumUBlocks,
            NumOuterBlocks = NumOuterBlocks,
            FileLogicalOffsets = FileLogicalOffsets,
            FinalFileOffsetType = finalFileOffsetType,
            Blocks = Blocks,
        };
    }

    /// <summary>
    /// Generates the final block plan for an assembled inner image. Every entry of the plan
    /// is derived from the assembler's placement/chunk tables — no caller-supplied geometry.
    /// </summary>
    public static PlanResult Generate(ProsperoInnerImageAssembler.InnerImageResult inner)
    {
        ArgumentNullException.ThrowIfNull(inner);

        var blocks = new List<NapsCblockPlanEntry>();
        var emitter = new BlockEmitter(blocks);

        // ---- 1. Data region: finalized encoded blocks. ------------------------------------------
        // Compression is decided once by the assembler; this generator only serializes that result.
        if (inner.EncodedBlocks.Count != 0)
        {
            foreach (ProsperoEncodedBlock block in inner.EncodedBlocks.OrderBy(b => b.SourceBlockIndex))
                emitter.EmitEncoded(block);
        }
        else // Compatibility for independently constructed legacy InnerImageResult test snapshots.
        {
            foreach (ProsperoInnerImageAssembler.Placement p in inner.Placements)
            {
                long size = p.UncompressedSize;
                long fullCount = size / UBlock;
                long tail = size - fullCount * UBlock;
                for (long k = 0; k < fullCount; k++)
                    emitter.EmitStoredFull(p.OnDiskOffset + k * UBlock, p.LogicalOffset + k * UBlock);
                if (tail > 0 || fullCount == 0)
                    emitter.EmitStoredTail(p.OnDiskOffset + fullCount * UBlock, p.LogicalOffset + fullCount * UBlock, tail);
            }
        }

        // ---- 2. Hole (padding) region: dedup tiling of [dataEnd, metaBase). ----------------------
        long padding = inner.MetaBaseLogical - inner.DataEndLogical;
        if (padding > 0)
        {
            int holeCount = (int)((padding + UBlock - 1) / UBlock);
            long holeOnDisk = inner.BlockInfoOnDiskOffset;
            for (int k = 0; k < holeCount; k++)
            {
                bool full = Math.Min(UBlock, padding - (long)k * UBlock) > 0x20000;
                long stream = full ? 16L : 8L;
                emitter.EmitHole(holeOnDisk, inner.DataEndLogical + (long)k * UBlock, stream, full);
                holeOnDisk += stream;
            }
        }

        // ---- 3. Metadata region: the PFSv3 container's data-section chunks. ----------------------
        // Each 256 KiB plaintext chunk sits at MetadataOnDiskOffset + dataSectionOffset + cumulative
        // compressed size. Kraken chunks (non-zero container flags) become NAPS Kraken records; stored
        // chunks (compressed == uncompressed) keep their existing stored geometry.
        long metaLogical = inner.MetaBaseLogical;
        long metaOnDisk = inner.MetadataOnDiskOffset + ReadDataSectionOffset(inner.CompressedMetadata);
        foreach (ProsperoPfsv3Writer.CompressedBlock b in inner.MetadataBlocks)
        {
            if (b.Flags != 0 && b.CompressedSize < b.UncompressedSize)
                emitter.EmitEncodedMetadata(metaOnDisk, metaLogical, b);
            else if (b.CompressedSize >= UBlock)
                emitter.EmitStoredFull(metaOnDisk, metaLogical);
            else
                emitter.EmitStoredTail(metaOnDisk, metaLogical, b.UncompressedSize, b.CompressedSize);
            metaLogical += b.UncompressedSize;
            metaOnDisk += b.CompressedSize;
        }

        // ---- 4. Terminator: the mount end. -------------------------------------------------------
        long mountSize = inner.Ndblock * Block64K;
        blocks.Add(new NapsCblockPlanEntry
        {
            StartRun = true,
            OnDiskOffset = metaOnDisk,
            LogicalOffset = mountSize,
            Terminator = true,
        });

        // ---- 5. fidx: non-empty afid offsets + dataEnd + metaBase + mount size. -------------------
        // Zero-length files share the dataEnd boundary. Sony emits a single trailing dataEnd entry
        // for them rather than duplicate zero-length boundaries; a duplicate would create a
        // zero-length NAPS span, which the mount rejects. Independently confirmed against the
        // original tool across the base/variant/zero-length/alignment oracle corpus.
        var fidx = new List<long>(inner.Placements.Count + 3);
        foreach (ProsperoInnerImageAssembler.Placement placement in inner.Placements)
        {
            if (placement.UncompressedSize > 0)
                fidx.Add(placement.LogicalOffset);
        }
        fidx.Add(inner.DataEndLogical);
        fidx.Add(inner.MetaBaseLogical);
        fidx.Add(mountSize);

        return new PlanResult
        {
            Blocks = blocks,
            FileLogicalOffsets = fidx,
            NumUBlocks = (int)((mountSize + UBlock - 1) / UBlock),
            NumOuterBlocks = (int)((inner.ImageSize + Block64K - 1) / Block64K),
            MountSize = mountSize,
        };
    }

    /// <summary>
    /// Tracks the previously emitted data block's on-disk end and decides whether a RUN base must
    /// precede the next STD. The mod-256K coff encoding aliases any on-disk displacement outside
    /// the (0, 0x40000) range to zero (dedup), so blocks that are exact-256K steps apart or
    /// back-anchored (holes, metadata, terminator) always open a fresh RUN.
    /// </summary>
    private sealed class BlockEmitter(IReadOnlyList<NapsCblockPlanEntry> sink)
    {
        private readonly List<NapsCblockPlanEntry> _sink = (List<NapsCblockPlanEntry>)sink;
        private long _prevDataEndOnDisk = -1;
        private bool _first = true;

        public void Emit(NapsCblockPlanEntry entry)
        {
            _sink.Add(entry);
            if (!entry.Terminator)
                _prevDataEndOnDisk = entry.OnDiskOffset + StreamOf(entry);
        }

        public void EmitStoredFull(long onDisk, long logical)
        {
            Emit(new NapsCblockPlanEntry
            {
                StartRun = NeedsRun(onDisk),
                OnDiskOffset = onDisk,
                LogicalOffset = logical,
                // Full ublock: two 128 KiB raw sub-chunks, both present.
                EvenChunkCompressedLength = 0x20000,
                StreamLength = UBlock,
                Even = 1,
                Odd = 1,
                KdePredictor = 0,
                StoredRaw = true,
            });
        }

        public void EmitStoredTail(long onDisk, long logical, long size, long? streamLength = null)
        {
            if (size <= 0 || size > UBlock)
                throw new ArgumentOutOfRangeException(nameof(size), "Stored NAPS tail must fit one 256KiB ublock.");
            Emit(new NapsCblockPlanEntry
            {
                StartRun = NeedsRun(onDisk),
                OnDiskOffset = onDisk,
                LogicalOffset = logical,
                EvenChunkCompressedLength = Math.Min(size, 0x20000),
                StreamLength = streamLength ?? size,
                Even = 1,
                Odd = size > 0x20000 ? (byte)1 : (byte)0,
                StoredRaw = true,
            });
        }

        public void EmitEncoded(ProsperoEncodedBlock block)
        {
            if (block.UncompressedLength <= 0)
                return; // zero-length leaves have no logical ublock payload.
            if (block.UncompressedLength > UBlock)
                throw new ArgumentOutOfRangeException(nameof(block), "Encoded NAPS block exceeds 256 KiB.");
            if (block.IsStored)
            {
                if (block.UncompressedLength == UBlock && block.StoredLength == UBlock)
                    EmitStoredFull(block.PhysicalOffset, block.LogicalOffset);
                else
                    EmitStoredTail(block.PhysicalOffset, block.LogicalOffset, block.UncompressedLength, block.StoredLength);
                return;
            }
            if (block.StoredLength <= 0 || block.StoredLength >= block.UncompressedLength)
                throw new InvalidDataException("Kraken block must be strictly smaller than its raw block.");
            (byte even, byte odd) = CodecModes(block.Flags, block.UncompressedLength > 0x20000);
            Emit(new NapsCblockPlanEntry
            {
                StartRun = NeedsRun(block.PhysicalOffset),
                OnDiskOffset = block.PhysicalOffset,
                LogicalOffset = block.LogicalOffset,
                EvenChunkCompressedLength = block.UncompressedLength > 0x20000
                    ? block.FirstChunkCompressedLength : block.StoredLength,
                StreamLength = block.StoredLength,
                // Even/Odd are derived from the encoder's actual payload mode exactly like the native
                // writer (bare entropy -> 1, newLZ raw -> 5; odd absent for single-chunk; KDE must be 0
                // because the reference/console decoder rejects any other predictor).
                Even = even, Odd = odd, KdePredictor = 0,
            });
        }

        /// <summary>Emits a Kraken-compressed metadata ublock (the clean-room newLZ reader contract).</summary>
        public void EmitEncodedMetadata(long onDisk, long logical, ProsperoPfsv3Writer.CompressedBlock block)
        {
            if (block.UncompressedSize <= 0)
                return;
            (byte even, byte odd) = CodecModes(block.MultiChunk ? 0x22 : 0x02, block.MultiChunk);
            Emit(new NapsCblockPlanEntry
            {
                StartRun = NeedsRun(onDisk),
                OnDiskOffset = onDisk,
                LogicalOffset = logical,
                EvenChunkCompressedLength = block.MultiChunk ? block.FirstChunkCompressedSize : block.CompressedSize,
                StreamLength = block.CompressedSize,
                // KDE must be 0 for the reference/console decoder; Even/Odd bit-flags select the codec.
                Even = even,
                Odd = odd,
                KdePredictor = 0,
            });
        }

        /// <summary>
        /// Maps an encoder payload's boundary flags onto the NAPS <c>Even</c>/<c>Odd</c> selectors,
        /// mirroring the native writer: bit 1 marks newLZ, bit 0 selects sub/delta literals, and a
        /// bare entropy array is <c>1</c>. The odd selector is absent (zero) for a single-chunk block.
        /// </summary>
        private static (byte Even, byte Odd) CodecModes(int flags, bool multiChunk)
        {
            byte even = (byte)(1 | (((flags & 2) != 0) ? 4 : 0) | (((flags & 1) != 0) ? 2 : 0));
            byte odd = multiChunk
                ? (byte)((((flags & 0x20) == 0) ? 1 : 4) | (((flags & 0x10) != 0) ? 2 : 0))
                : (byte)0;
            return (even, odd);
        }

        public void EmitHole(long onDisk, long logical, long stream, bool full)
        {
            Emit(new NapsCblockPlanEntry
            {
                StartRun = NeedsRun(onDisk),
                OnDiskOffset = onDisk,
                LogicalOffset = logical,
                EvenChunkCompressedLength = 8,
                StreamLength = stream,
                Even = 1,
                Odd = full ? (byte)1 : (byte)0,
                KdePredictor = 0,
            });
        }

        private bool NeedsRun(long onDisk)
        {
            bool needed = _first || onDisk != _prevDataEndOnDisk;
            _first = false;
            return needed;
        }

        private static long StreamOf(NapsCblockPlanEntry e) =>
            e.Terminator ? 0 : e.StreamLength;
    }

    /// <summary>Reads the PFSC id=7 section directory offset (the container-relative data start).</summary>
    private static long ReadDataSectionOffset(byte[] container)
    {
        if (container.Length < Pfsv3DataOffsetField + 4)
            return 0;
        return BinaryPrimitives.ReadUInt32LittleEndian(container.AsSpan(Pfsv3DataOffsetField, 4));
    }
}
