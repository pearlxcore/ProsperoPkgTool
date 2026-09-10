using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using ProsperoPkgTool.Compression;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room builder for the PS5 nwonly inner <c>pfs_image.dat</c> — the data-first per-file image
/// that carries the application payload inside the outer PFS. Assembles the file tree, assigns
/// inodes/afids, builds the inode table, dirents, both flat-path tables, the afid_to_ino_table, the
/// inner superblock, and wraps the metadata + file data in a stored PFSv3 compression container.
///
/// Layout (data-first): [file data blocks][block-info table][compressed metadata block]. The metadata
/// region (superblock + inode table + dirents + FLT + afid table) is block-aligned and wrapped in a
/// <see cref="ProsperoPfsv3Writer"/> stored container. Raw files (keystone, ELF modules) are
/// block-aligned; packed files are contiguous.
///
/// Inner inode (0xA8 unsigned): mode@0(u16), nlink@2(u16), flags@4(u32), size@8(i64), sizeCompressed@0x10(i64),
/// times@0x18..0x38 (4×i64 sec + 4×u32 nsec), logicalOffset@0x60(u64), db[0]@0x64=0, db[1]@0x68=afid/-1,
/// db[2]@0x6c=parent_inode, db[3]@0x70=dirent_offset.
/// </summary>
public sealed class ProsperoInnerImageAssembler
{
    public const int BlockSize = 0x10000;

    private const string SceSysDir = "sce_sys";
    private const long MetadataReserveBlocks = 61;

    private readonly long _timeSec;
    private readonly uint _timeNsec;

    public ProsperoInnerImageAssembler(long buildTimeSec, uint buildTimeNsec)
    {
        _timeSec = buildTimeSec;
        _timeNsec = buildTimeNsec;
    }

    /// <summary>One regular file to place in the inner image.</summary>
    public sealed class InnerFile
    {
        public required string Path { get; init; }

        /// <summary>In-memory contents. Empty when the file is sourced lazily from
        /// <see cref="SourcePath"/> (or for a genuinely empty file).</summary>
        public byte[] Data { get; set; } = [];

        /// <summary>Source file to read lazily when <see cref="Data"/> is not retained.</summary>
        public string? SourcePath { get; init; }

        /// <summary>Source length when the payload is provided via <see cref="SourcePath"/>.</summary>
        public long Length { get; init; }

        /// <summary>Clean-room PlayGo owner used only to preserve 64-KiB transition boundaries.</summary>
        public byte PlayGoChunkId { get; init; }

        /// <summary>Uncompressed payload length regardless of representation.</summary>
        public long PayloadLength => SourcePath is not null ? Length : Data.LongLength;
    }

    /// <summary>The assembled inner image result.</summary>
    public sealed class InnerImageResult
    {
        /// <summary>The on-disk <c>pfs_image.dat</c> bytes; empty for a file-backed result.</summary>
        public required byte[] Image { get; init; }
        /// <summary>Physical image path for a file-backed result; otherwise <see langword="null"/>.</summary>
        public string? ImagePath { get; init; }
        /// <summary>Exact block-aligned physical <c>pfs_image.dat</c> length.</summary>
        public long ImageLength { get; init; }

        /// <summary>Physical image size regardless of representation (file-backed or in-memory).</summary>
        public long ImageSize => ImageLength > 0 ? ImageLength : Image.Length;
        /// <summary>The uncompressed metadata-region plaintext (superblock + inodes + dirents + FLT tables).</summary>
        public required byte[] MetadataPlaintext { get; init; }
        /// <summary>The stored-wrapped (PFSv3) metadata bytes as embedded at the image tail.</summary>
        public required byte[] CompressedMetadata { get; init; }
        /// <summary>Per-256KiB-block chunk table of the metadata region. A zero <c>Flags</c> entry is a
        /// stored block (compressed == uncompressed); otherwise it is a Kraken-compressed block carrying
        /// the container boundary flags and, for multi-chunk blocks, the first sub-chunk size.</summary>
        public required IReadOnlyList<ProsperoPfsv3Writer.CompressedBlock> MetadataBlocks { get; init; }
        /// <summary>Finalized data-file blocks, in physical source order, used directly by NAPS.</summary>
        public IReadOnlyList<ProsperoEncodedBlock> EncodedBlocks { get; init; } = [];
        /// <summary>Observed payload metrics for the selected inner-image compression policy.</summary>
        public ProsperoCompressionMetrics CompressionMetrics { get; init; }
        /// <summary>The computed metadata nodes (inode order), for introspection/XML emission.</summary>
        public required IReadOnlyList<MetaNodeInfo> Nodes { get; init; }
        /// <summary>The inner mount logical block count (superblock Ndblock).</summary>
        public required long Ndblock { get; init; }
        /// <summary>Logical base of the metadata region (= Ndblock*64K - metadata length).</summary>
        public required long MetaBaseLogical { get; init; }
        /// <summary>Logical end of the packed data files (first fidx boundary after the last file).</summary>
        public required long DataEndLogical { get; init; }
        /// <summary>On-disk byte offset of the 32-byte block-info table.</summary>
        public required long BlockInfoOnDiskOffset { get; init; }
        /// <summary>On-disk byte offset of the wrapped metadata region.</summary>
        public required long MetadataOnDiskOffset { get; init; }
        /// <summary>Per-file on-disk/logical placement (afid order).</summary>
        public required IReadOnlyList<Placement> Placements { get; init; }
        /// <summary>Per-file logical offsets in afid order.</summary>
        public required IReadOnlyList<long> AfidLogicalOffsets { get; init; }
        /// <summary>Total number of inodes.</summary>
        public required int InodeCount { get; init; }
        /// <summary>Inner content-inode count (dirs + files below uroot).</summary>
        public required int InnerContentInodes { get; init; }
        /// <summary>App-payload (non-sce_sys) regular file count.</summary>
        public required int AppFileCount { get; init; }

        /// <summary>Opens the physical image without materializing it when this is a file-backed result.</summary>
        public Stream OpenImage() => ImagePath is not null
            ? new FileStream(ImagePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.RandomAccess)
            : new MemoryStream(Image, writable: false);
    }

    /// <summary>One file's on-disk + logical placement (afid order), for NAPS/meta18 generation.</summary>
    public readonly record struct Placement(
        long OnDiskOffset,
        long LogicalOffset,
        long OnDiskSize,
        long UncompressedSize,
        bool StoreRaw);

    /// <summary>
    /// Public snapshot of one inner-metadata node (file or directory), inode order. Mirrors what the
    /// writer emits into the inode table so callers can emit XML introspection or naps records without
    /// re-parsing the image.
    /// </summary>
    public sealed class MetaNodeInfo
    {
        public string Name { get; init; } = "";
        /// <summary>Full path from the mount root (e.g. <c>/sce_sys/keystone</c>). Empty for dirs and internal nodes.</summary>
        public string FullPath { get; init; } = "";
        public uint Inode { get; init; }
        public bool IsDirectory { get; init; }
        /// <summary>True for a top-level uroot regular file that also appears in apr_flat_path_table.</summary>
        public bool IsApr { get; init; }
        public uint Afid { get; init; }
        public ulong LogicalOffset { get; init; }
        public long Size { get; init; }
        public ushort Mode { get; init; }
        public ushort Nlink { get; init; } = 1;
        public uint Flags { get; init; }
        /// <summary>Parent inode number, or -1 for the super-root's direct children (and the super-root itself).</summary>
        public int ParentInode { get; init; } = -1;
        public int DirentOffset { get; init; } = -1;
    }

    /// <summary>Assemble the inner image from a flat list of files, returning its bytes.</summary>
    public InnerImageResult Build(IReadOnlyList<InnerFile> files, ProsperoInnerCompressionMode compressionMode = ProsperoInnerCompressionMode.Stored)
        => BuildCore(files, compressionMode, null);

    /// <summary>
    /// File-backed counterpart: the physical <c>pfs_image.dat</c> is written directly to
    /// <paramref name="outputPath"/> and <see cref="InnerImageResult.Image"/> is empty, so the image
    /// may exceed the in-memory array limit. All geometry/metadata remains available in the result.
    /// </summary>
    public InnerImageResult BuildToFile(IReadOnlyList<InnerFile> files, string outputPath, ProsperoInnerCompressionMode compressionMode = ProsperoInnerCompressionMode.Stored)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputPath);
        string full = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(full) ?? Directory.GetCurrentDirectory());
        return BuildCore(files, compressionMode, full);
    }

    private InnerImageResult BuildCore(IReadOnlyList<InnerFile> files, ProsperoInnerCompressionMode compressionMode, string? outputPath)
    {
        ArgumentNullException.ThrowIfNull(files);
        if (files.Count == 0)
            throw new ArgumentException("At least one inner file is required.", nameof(files));

        // ---- 1. Build the directory tree. ----
        Dir uroot = BuildTree(files);
        List<Dir> dirsPreOrder = [];
        CollectDirsPreOrder(uroot, dirsPreOrder);

        // ---- 2. Assign inodes. ----
        uint next = 0;
        uint superRootInode = next++;
        uint inodeFltInode = next++;
        uint aprFltInode = next++;
        uint afidTableInode = next++;
        foreach (Dir d in dirsPreOrder)
            d.Inode = next++;

        List<Dir> dirsPostOrder = [];
        CollectDirsPostOrder(uroot, dirsPostOrder);
        var fileNodes = new List<FileNode>();
        foreach (Dir d in dirsPostOrder)
            foreach (FileNode f in d.Files.OrderBy(f => f.Name, StringComparer.Ordinal))
            {
                f.Inode = next++;
                fileNodes.Add(f);
            }

        // ---- 3. Assign afids (sce_sys first, then the rest). ----
        var afidOrder = new List<FileNode>();
        Dir? sceSys = uroot.SubDirs.FirstOrDefault(d => d.Name == SceSysDir);
        if (sceSys != null) CollectFilesPreOrder(sceSys, afidOrder);
        foreach (Dir d in dirsPreOrder)
            if (d != sceSys && !IsUnder(d, sceSys))
                foreach (FileNode f in d.Files.OrderBy(f => f.Name, StringComparer.Ordinal))
                    afidOrder.Add(f);
        for (uint a = 0; a < afidOrder.Count; a++)
            afidOrder[(int)a].Afid = a;

        // WholeBlockRaw depends only on the PlayGo chunk sequence; resolve it before placement so
        // the alignment rules match the historical two-pass assembly exactly.
        {
            byte? previousChunk = null;
            foreach (FileNode f in afidOrder)
            {
                f.WholeBlockRaw = previousChunk.HasValue && previousChunk.Value != f.PlayGoChunkId;
                previousChunk = f.PlayGoChunkId;
            }
        }

        // ---- 4. Logical offsets, encoded payload assembly and data placement. ----
        // Payloads are rendered one file at a time. The in-memory build retains them (as chunks);
        // the file-backed build writes each rendered payload straight to the image and keeps only
        // the encoded-block metadata, so peak memory is bounded by the largest single file.
        long cursor = 0;
        var afidOffsets = new long[afidOrder.Count];
        var encodedBlocks = new List<ProsperoEncodedBlock>();
        int sourceBlockIndex = 0;
        long pos = 0;

        using FileStream? imageFs = outputPath is not null
            ? new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20, FileOptions.SequentialScan)
            : null;
        List<(long Offset, byte[] Data)>? imageChunks = imageFs is null ? [] : null;

        foreach (FileNode f in afidOrder)
        {
            f.LogicalOffset = cursor;
            afidOffsets[f.Afid] = cursor;
            cursor += f.PayloadLength;
            f.StoreRaw = compressionMode == ProsperoInnerCompressionMode.Stored;

            byte[] payload = RenderFilePayload(f, compressionMode, encodedBlocks, ref sourceBlockIndex,
                retainEncodedBytes: outputPath is null);
            f.EncodedLength = payload.Length;

            bool alignBefore = f.WholeBlockRaw ||
                (f.StoreRaw && pos % BlockSize != 0 && payload.Length > BlockSize - pos % BlockSize);
            if (alignBefore)
                pos = RoundUp(pos, BlockSize);
            f.OnDiskOffset = pos;

            if (imageFs is not null)
            {
                imageFs.Position = pos;
                imageFs.Write(payload, 0, payload.Length);
            }
            else
            {
                imageChunks!.Add((pos, payload));
                f.OnDiskData = payload;
            }

            long physical = pos;
            foreach (ProsperoEncodedBlock block in encodedBlocks.Where(b =>
                b.LogicalOffset >= f.LogicalOffset && b.LogicalOffset < f.LogicalOffset + f.PayloadLength))
            {
                block.PhysicalOffset = physical;
                physical += block.StoredLength;
            }

            pos += payload.Length;
            if (f.WholeBlockRaw)
                pos = RoundUp(pos, BlockSize);
        }

        long dataEndLogical = afidOrder.Count > 0
            ? afidOrder.Max(f => f.LogicalOffset + f.PayloadLength)
            : 0;
        long physicalDataBlocks = RoundUp(pos, BlockSize) / BlockSize;
        long dataBlocks = physicalDataBlocks;
        if (compressionMode != ProsperoInnerCompressionMode.Stored)
        {
            // The mount's logical address space must cover the UNCOMPRESSED payload, which can be
            // far larger than the compressed physical block count. Basing the metadata region on the
            // physical count places metaBase before the end of the logical data once compression
            // savings exceed the ~4 MiB metadata reserve (observed at ~3.5 GiB scale), producing a
            // non-monotonic fidx. Reserve after the logical data end, rounded to a 256 KiB ublock
            // boundary. The stored layout (logical == physical) is preserved byte-for-byte.
            long logicalDataBlocks = RoundUp(Math.Max(dataEndLogical, 1), 4 * BlockSize) / BlockSize;
            dataBlocks = Math.Max(physicalDataBlocks, logicalDataBlocks);
        }

        // ---- 5. Dirents. ----
        BuildDirents(uroot);

        // ---- 6. Metadata nodes + geometry. ----
        int metadataContentBlocks = 1 + 3 + dirsPreOrder.Count + 1;
        // metaBaseBlock = the block where the metadata region starts. The metadata plaintext spans
        // 2 (superblock + inode table) + metadataContentBlocks blocks. ndblock = the mount's total
        // block count = metaBaseBlock + 2 + metadataContentBlocks.
        long metaBaseBlock = dataBlocks + MetadataReserveBlocks + 2;
        long metaBase = metaBaseBlock * BlockSize;
        long ndblock = metaBaseBlock + 2 + metadataContentBlocks;

        var nodes = BuildNodes(uroot, dirsPreOrder, fileNodes, metaBase);

        // ---- 7. Build metadata plaintext. ----
        byte[] metaPlain = BuildMetadataPlaintext(nodes, dirsPreOrder, fileNodes, afidOrder, ndblock,
            inodeFltInode, aprFltInode, afidTableInode, uroot);

        // ---- 8. Block-info table + stored metadata container. ----
        long urootSize = 0;
        foreach (FileNode f in afidOrder)
            if (!f.FullPath.StartsWith("/sce_sys/", StringComparison.Ordinal))
                urootSize += f.PayloadLength;
        byte[] blockInfo = BuildBlockInfoTable(urootSize);
        pos = RoundUp(pos, BlockSize);
        long blockInfoOnDisk = pos;
        if (imageFs is not null)
        {
            imageFs.Position = pos;
            imageFs.Write(blockInfo, 0, blockInfo.Length);
        }
        else
        {
            imageChunks!.Add((pos, blockInfo));
        }
        pos += blockInfo.Length;

        // The default stored policy is byte-identical to the historical writer; Kraken/Auto wrap the
        // metadata region in the compressed PFSv3 container (per-block stored fallback is internal).
        byte[] compressedMeta;
        IReadOnlyList<ProsperoPfsv3Writer.CompressedBlock> metaBlocks;
        if (compressionMode == ProsperoInnerCompressionMode.Stored)
        {
            compressedMeta = ProsperoPfsv3Writer.WriteStored(metaPlain);
            metaBlocks = BuildStoredMetadataBlocks(metaPlain);
        }
        else
        {
            (compressedMeta, metaBlocks) = ProsperoPfsv3Writer.WriteCompressed(metaPlain);
        }
        pos = RoundUp(pos, BlockSize);
        long metadataOnDisk = pos;
        if (imageFs is not null)
        {
            imageFs.Position = pos;
            imageFs.Write(compressedMeta, 0, compressedMeta.Length);
        }
        else
        {
            imageChunks!.Add((pos, compressedMeta));
        }
        pos += compressedMeta.Length;
        long imageLength = pos;

        byte[] image;
        if (imageFs is not null)
        {
            imageFs.SetLength(imageLength);
            imageFs.Flush();
            image = [];
        }
        else
        {
            image = new byte[imageLength];
            foreach (var (offset, data) in imageChunks!)
                data.CopyTo(image.AsSpan((int)offset, data.Length));
        }

        long metaBaseLogical = ndblock * BlockSize - metaPlain.Length;
        int innerContentInodes = nodes.Count(n => n.ParentInode >= 0);
        int appFileCount = fileNodes.Count(f => !f.FullPath.StartsWith("/sce_sys/", StringComparison.Ordinal));

        // Public MetaNodeInfo snapshot (inode order) for SI/naps callers.
        var nodeInfos = nodes.OrderBy(n => n.Inode)
            .Select(n => new MetaNodeInfo
            {
                Name = n.Name,
                FullPath = n.FullPath,
                Inode = n.Inode,
                IsDirectory = n.IsDirectory,
                IsApr = !n.IsDirectory && !n.FullPath.StartsWith("/sce_sys/", StringComparison.Ordinal),
                Afid = n.Afid,
                LogicalOffset = n.LogicalOffset,
                Size = n.Size,
                Mode = n.Mode,
                Nlink = n.Nlink,
                Flags = n.Flags,
                ParentInode = n.ParentInode,
                DirentOffset = n.DirentOffset,
            }).ToList();

        // Placements in afid order for naps/meta18.
        var placements = afidOrder.Select(f => new Placement(
            OnDiskOffset: f.OnDiskOffset,
            LogicalOffset: f.LogicalOffset,
            OnDiskSize: f.EncodedLength,
            UncompressedSize: f.PayloadLength,
            StoreRaw: f.StoreRaw)).ToList();

        return new InnerImageResult
        {
            Image = image,
            ImagePath = outputPath,
            ImageLength = imageLength,
            MetadataPlaintext = metaPlain,
            CompressedMetadata = compressedMeta,
            MetadataBlocks = metaBlocks,
            EncodedBlocks = encodedBlocks,
            CompressionMetrics = new ProsperoCompressionMetrics(
                encodedBlocks.Sum(b => (long)b.UncompressedLength), encodedBlocks.Sum(b => (long)b.StoredLength),
                encodedBlocks.Count(b => !b.IsStored), encodedBlocks.Count(b => b.IsStored)),
            Nodes = nodeInfos,
            Ndblock = ndblock,
            MetaBaseLogical = metaBaseLogical,
            DataEndLogical = dataEndLogical,
            BlockInfoOnDiskOffset = blockInfoOnDisk,
            MetadataOnDiskOffset = metadataOnDisk,
            Placements = placements,
            AfidLogicalOffsets = afidOffsets,
            InodeCount = nodes.Count,
            InnerContentInodes = innerContentInodes,
            AppFileCount = appFileCount,
        };
    }

    private static bool VerifyKraken(ReadOnlySpan<byte> raw, KrakenEncoder.EncodedBlock encoded)
    {
        byte[] decoded = new byte[raw.Length];
        return KrakenDecoder.DecodeBlock(encoded.Payload, encoded.Flags, encoded.FirstChunkCompressedLength, decoded)
            == KrakenDecoder.KrakenDecodeStatus.Success && decoded.AsSpan().SequenceEqual(raw);
    }

    /// <summary>Stored metadata chunk table (one entry per 256 KiB block): compressed == uncompressed.</summary>
    private static IReadOnlyList<ProsperoPfsv3Writer.CompressedBlock> BuildStoredMetadataBlocks(byte[] metaPlain)
    {
        var blocks = new List<ProsperoPfsv3Writer.CompressedBlock>();
        for (int i = 0; i < metaPlain.Length; i += ProsperoPfsv3Writer.DefaultBlockSize)
        {
            int size = Math.Min(ProsperoPfsv3Writer.DefaultBlockSize, metaPlain.Length - i);
            blocks.Add(new ProsperoPfsv3Writer.CompressedBlock(size, size, false, 0, 0));
        }
        return blocks;
    }

    // ---- Tree model ----

    private sealed class Dir
    {
        public string Name = "";
        public string FullPath = "";
        public Dir? Parent;
        public readonly List<Dir> SubDirs = [];
        public readonly List<FileNode> Files = [];
        public uint Inode;
        public int DirentOffsetInParent = -1;
        public readonly List<Dirent> Dirents = [];
    }

    private sealed class FileNode
    {
        public string Name = "";
        public string FullPath = "";
        public byte[] Data = [];
        public string? SourcePath;
        public long PayloadLength;
        public Dir Parent = null!;
        public uint Inode;
        public uint Afid;
        public bool StoreRaw;
        public bool WholeBlockRaw;
        public byte PlayGoChunkId;
        public long LogicalOffset;
        public long OnDiskOffset;
        public long EncodedLength;
        public byte[]? OnDiskData;
        public int DirentOffsetInParent = -1;
    }

    private readonly record struct Dirent(uint Inode, int Type, string Name);

    private static Dir BuildTree(IReadOnlyList<InnerFile> files)
    {
        var uroot = new Dir { Name = "uroot", FullPath = "" };
        var dirLookup = new Dictionary<string, Dir>(StringComparer.Ordinal) { [""] = uroot };

        Dir GetDir(string fullPath)
        {
            if (dirLookup.TryGetValue(fullPath, out Dir? d)) return d;
            int slash = fullPath.LastIndexOf('/');
            string parentPath = slash <= 0 ? "" : fullPath[..slash];
            string name = fullPath[(slash + 1)..];
            Dir parent = GetDir(parentPath);
            var dir = new Dir { Name = name, FullPath = fullPath, Parent = parent };
            parent.SubDirs.Add(dir);
            dirLookup[fullPath] = dir;
            return dir;
        }

        foreach (InnerFile f in files.OrderBy(f => f.Path, StringComparer.Ordinal))
        {
            string path = f.Path.StartsWith('/') ? f.Path[1..] : f.Path;
            int slash = path.LastIndexOf('/');
            string dirPath = slash < 0 ? "" : path[..slash];
            string name = slash < 0 ? path : path[(slash + 1)..];
            Dir parent = GetDir(dirPath);
            parent.Files.Add(new FileNode
            {
                Name = name,
                FullPath = "/" + path,
                Data = f.Data,
                SourcePath = f.SourcePath,
                PayloadLength = f.PayloadLength,
                Parent = parent,
                PlayGoChunkId = f.PlayGoChunkId,
            });
        }
        return uroot;
    }

    private static void CollectDirsPreOrder(Dir dir, List<Dir> outList)
    {
        outList.Add(dir);
        foreach (Dir d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            CollectDirsPreOrder(d, outList);
    }

    private static void CollectDirsPostOrder(Dir dir, List<Dir> outList)
    {
        foreach (Dir d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            CollectDirsPostOrder(d, outList);
        outList.Add(dir);
    }

    private static void CollectDirsPostOrderImpl(Dir dir, List<Dir> outList)
    {
        foreach (Dir d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            CollectDirsPostOrderImpl(d, outList);
        outList.Add(dir);
    }

    private static void CollectFilesPreOrder(Dir dir, List<FileNode> outList)
    {
        foreach (FileNode f in dir.Files.OrderBy(f => f.Name, StringComparer.Ordinal))
            outList.Add(f);
        foreach (Dir d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            CollectFilesPreOrder(d, outList);
    }

    private static bool IsUnder(Dir dir, Dir? ancestor)
    {
        if (ancestor == null) return false;
        for (Dir? d = dir; d != null; d = d.Parent)
            if (d == ancestor) return true;
        return false;
    }

    private static bool IsKeystone(string fullPath) =>
        string.Equals(fullPath, "/sce_sys/keystone", StringComparison.Ordinal);

    private static bool IsExecutableModule(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return false;
        uint magic = (uint)(data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24));
        return magic is 0x1D3D154F or 0xEEF51454 or 0x464C457F;
    }

    /// <summary>Executable-module magic check for a node whose payload may be file-backed.</summary>
    private static bool IsExecutableModule(FileNode f)
    {
        if (f.Data.Length >= 4 || f.SourcePath is null)
            return IsExecutableModule(f.Data.AsSpan());

        Span<byte> magic = stackalloc byte[4];
        using var stream = new FileStream(f.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        int read = 0;
        while (read < magic.Length)
        {
            int n = stream.Read(magic[read..]);
            if (n <= 0) break;
            read += n;
        }
        return read == magic.Length && IsExecutableModule(magic);
    }

    // ---- Dirents ----

    private const int DirentTypeFile = 2;
    private const int DirentTypeDirectory = 3;
    private const int DirentTypeDot = 4;
    private const int DirentTypeDotDot = 5;

    private static void BuildDirents(Dir uroot)
    {
        BuildDirentsRecursive(uroot);
    }

    private static void BuildDirentsRecursive(Dir dir)
    {
        dir.Dirents.Clear();
        dir.Dirents.Add(new Dirent(dir.Inode, DirentTypeDot, "."));
        uint parentIno = dir.Parent?.Inode ?? dir.Inode;
        dir.Dirents.Add(new Dirent(parentIno, DirentTypeDotDot, ".."));
        foreach (Dir d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            dir.Dirents.Add(new Dirent(d.Inode, DirentTypeDirectory, d.Name));
        foreach (FileNode f in dir.Files.OrderBy(f => f.Name, StringComparer.Ordinal))
            dir.Dirents.Add(new Dirent(f.Inode, DirentTypeFile, f.Name));

        int off = 0;
        var byName = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (Dirent e in dir.Dirents)
        {
            byName[e.Name] = off;
            off += DirentSize(e.Name.Length);
        }
        foreach (Dir d in dir.SubDirs)
            d.DirentOffsetInParent = byName[d.Name];
        foreach (FileNode f in dir.Files)
            f.DirentOffsetInParent = byName[f.Name];

        foreach (Dir d in dir.SubDirs.OrderBy(d => d.Name, StringComparer.Ordinal))
            BuildDirentsRecursive(d);
    }

    private static int DirentSize(int nameLen)
    {
        int sz = nameLen + 17;
        if (sz % 8 != 0) sz += 8 - sz % 8;
        return sz;
    }

    // ---- Nodes ----

    private sealed class MetaNode
    {
        public string Name = "";
        public string FullPath = "";
        public uint Inode;
        public bool IsDirectory;
        public uint Afid;
        public ulong LogicalOffset;
        public long Size;
        public ushort Mode;
        public ushort Nlink = 1;
        public uint Flags;
        public int ParentInode = -1;
        public int DirentOffset = -1;
    }

    private List<MetaNode> BuildNodes(Dir uroot, List<Dir> dirsPreOrder, List<FileNode> fileNodes, long metaBase)
    {
        var nodes = new List<MetaNode>();
        // Content blocks start 2 blocks after the metadata region base (superblock + inode table).
        long b = metaBase + 2 * BlockSize;

        // inode 0: super-root directory.
        nodes.Add(new MetaNode { Name = "", Inode = 0, IsDirectory = true, Mode = 0x416D, Nlink = 1, Flags = 0x00020010, Size = BlockSize, LogicalOffset = (ulong)b });
        b += BlockSize;
        // inodes 1..3: internal metadata files.
        nodes.Add(new MetaNode { Name = "inode_flat_path_table", Inode = 1, Mode = 0x816D, Nlink = 1, Flags = 0x00020010, LogicalOffset = (ulong)b }); b += BlockSize;
        nodes.Add(new MetaNode { Name = "apr_flat_path_table", Inode = 2, Mode = 0x816D, Nlink = 1, Flags = 0x00020010, LogicalOffset = (ulong)b }); b += BlockSize;
        nodes.Add(new MetaNode { Name = "afid_to_ino_table", Inode = 3, Mode = 0x816D, Nlink = 1, Flags = 0x00020010, LogicalOffset = (ulong)b }); b += BlockSize;
        // inode 4+: uroot + sub-directories.
        foreach (Dir d in dirsPreOrder)
        {
            bool isUroot = d == uroot;
            nodes.Add(new MetaNode
            {
                Name = d.Name,
                Inode = d.Inode,
                IsDirectory = true,
                Mode = (ushort)(isUroot ? 0x416D : 0x4168),
                Nlink = (ushort)(2 + d.SubDirs.Count + (isUroot ? 1 : 0)),
                Flags = (uint)(isUroot ? 0x00000010 : 0x00020010),
                Size = BlockSize,
                LogicalOffset = (ulong)b,
                ParentInode = isUroot ? -1 : (int)d.Parent!.Inode,
                DirentOffset = isUroot ? -1 : d.DirentOffsetInParent,
            });
            b += BlockSize;
        }
        // Regular files (inode order).
        foreach (FileNode f in fileNodes)
        {
            bool sceSys = f.FullPath.StartsWith("/sce_sys/", StringComparison.Ordinal);
            bool exec = IsExecutableModule(f);
            nodes.Add(new MetaNode
            {
                Name = f.Name,
                FullPath = f.FullPath,
                Inode = f.Inode,
                IsDirectory = false,
                Mode = (ushort)(sceSys ? 0x8168 : 0x816D),
                Nlink = 1,
                Flags = 0x10u | (exec ? 0x40u : 0x20u) | (sceSys ? 0x20000u : 0u),
                Afid = f.Afid,
                Size = f.PayloadLength,
                LogicalOffset = (ulong)f.LogicalOffset,
                ParentInode = (int)f.Parent.Inode,
                DirentOffset = f.DirentOffsetInParent,
            });
        }
        return nodes.OrderBy(n => n.Inode).ToList();
    }

    // ---- Metadata plaintext ----

    private byte[] BuildMetadataPlaintext(
        List<MetaNode> nodes, List<Dir> dirsPreOrder, List<FileNode> fileNodes,
        List<FileNode> afidOrder, long ndblock,
        uint inodeFltInode, uint aprFltInode, uint afidTableInode, Dir uroot)
    {
        // Flat-path tables.
        var inodeFlt = new List<FlatPathEntry>();
        var aprFlt = new List<FlatPathEntry>();
        foreach (Dir d in dirsPreOrder)
            if (d != uroot)
                inodeFlt.Add(new FlatPathEntry(HashPath(d.FullPath),
                    PackInodeEntry(d.Inode, true, false, 0)));
        foreach (FileNode f in fileNodes)
        {
            bool apr = !f.FullPath.StartsWith("/sce_sys/", StringComparison.Ordinal);
            inodeFlt.Add(new FlatPathEntry(HashPath(f.FullPath),
                PackInodeEntry(f.Inode, false, !apr, f.Afid)));
            if (apr)
                aprFlt.Add(new FlatPathEntry(HashPath(f.FullPath),
                    PackAprEntry(f.PayloadLength, f.Afid)));
        }
        byte[] inodeFltBytes = SerializeFlatPathTable(inodeFlt);
        byte[] aprFltBytes = SerializeFlatPathTable(aprFlt);

        // afid_to_ino_table: [firstFileInode, inode per afid, -1, -1].
        var afidList = new List<int> { (int)fileNodes.Min(f => f.Inode) };
        foreach (FileNode f in afidOrder) afidList.Add((int)f.Inode);
        afidList.Add(-1); afidList.Add(-1);
        byte[] afidBytes = new byte[afidList.Count * 4];
        for (int i = 0; i < afidList.Count; i++)
            BinaryPrimitives.WriteInt32LittleEndian(afidBytes.AsSpan(i * 4), afidList[i]);

        // Fill internal-file sizes.
        foreach (MetaNode n in nodes)
        {
            if (n.Inode == inodeFltInode) n.Size = inodeFltBytes.Length;
            else if (n.Inode == aprFltInode) n.Size = aprFltBytes.Length;
            else if (n.Inode == afidTableInode) n.Size = afidBytes.Length;
        }

        // Metadata blocks: [super-root dirents][inode_flt][apr_flt][afid][dir dirents...][empty].
        var blocks = new List<byte[]>
        {
            SerializeDirents(SuperRootDirents(inodeFltInode, aprFltInode, afidTableInode, uroot.Inode)),
            inodeFltBytes, aprFltBytes, afidBytes,
        };
        foreach (Dir d in dirsPreOrder)
            blocks.Add(SerializeDirents(d.Dirents));
        blocks.Add([]);

        // Assemble: superblock (block 0) + inode table (block 1) + content blocks.
        int totalBlocks = 2 + blocks.Count;
        byte[] metaPlain = new byte[totalBlocks * BlockSize];
        BuildSuperblock(metaPlain.AsSpan(0, BlockSize), nodes.Count, ndblock, ndblock - totalBlocks + 1);
        for (int i = 0; i < nodes.Count; i++)
            WriteInode(metaPlain.AsSpan(BlockSize + i * 0xA8, 0xA8), nodes[i]);
        for (int b = 0; b < blocks.Count; b++)
            blocks[b].CopyTo(metaPlain.AsSpan((2 + b) * BlockSize));
        return metaPlain;
    }

    private static IEnumerable<Dirent> SuperRootDirents(uint inodeFlt, uint aprFlt, uint afid, uint uroot) => new[]
    {
        new Dirent(inodeFlt, DirentTypeFile, "inode_flat_path_table"),
        new Dirent(aprFlt, DirentTypeFile, "apr_flat_path_table"),
        new Dirent(afid, DirentTypeFile, "afid_to_ino_table"),
        new Dirent(uroot, DirentTypeDirectory, "uroot"),
    };

    private void BuildSuperblock(Span<byte> sb, int inodeCount, long ndblock, long inodeTableBlock)
    {
        sb.Clear();
        BinaryPrimitives.WriteInt64LittleEndian(sb, 2);                        // version
        BinaryPrimitives.WriteInt64LittleEndian(sb[8..], 20130315);           // magic
        sb[0x1A] = 1;                                                          // ReadOnly
        BinaryPrimitives.WriteUInt16LittleEndian(sb[0x1C..], 0x18);          // Mode
        BinaryPrimitives.WriteUInt32LittleEndian(sb[0x20..], BlockSize);
        BinaryPrimitives.WriteInt64LittleEndian(sb[0x28..], 1);              // NBlock
        BinaryPrimitives.WriteInt64LittleEndian(sb[0x30..], inodeCount);     // DinodeCount
        BinaryPrimitives.WriteInt64LittleEndian(sb[0x38..], ndblock);        // Ndblock
        BinaryPrimitives.WriteInt64LittleEndian(sb[0x40..], 1);              // DinodeBlockCount
        BinaryPrimitives.WriteUInt32LittleEndian(sb[0x50..], BlockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(sb[0x54..], 0x10);
        BinaryPrimitives.WriteUInt32LittleEndian(sb[0x58..], BlockSize);
        BinaryPrimitives.WriteUInt32LittleEndian(sb[0x60..], BlockSize);
        for (int t = 0; t < 4; t++) BinaryPrimitives.WriteInt64LittleEndian(sb[(0x68 + t * 8)..], _timeSec);
        for (int t = 0; t < 4; t++) BinaryPrimitives.WriteUInt32LittleEndian(sb[(0x88 + t * 4)..], _timeNsec);
        BinaryPrimitives.WriteInt64LittleEndian(sb[0xB0..], 1);
        BinaryPrimitives.WriteInt64LittleEndian(sb[0xD8..], inodeTableBlock); // InodeBlockSig.db[0].block (inode table StartBlock)
        sb[0x368] = 1;
    }

    private void WriteInode(Span<byte> dst, MetaNode n)
    {
        dst.Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(dst, n.Mode);
        BinaryPrimitives.WriteUInt16LittleEndian(dst[2..], n.Nlink);
        BinaryPrimitives.WriteUInt32LittleEndian(dst[4..], n.Flags);
        BinaryPrimitives.WriteInt64LittleEndian(dst[8..], n.Size);
        BinaryPrimitives.WriteInt64LittleEndian(dst[0x10..], n.Size);
        for (int t = 0; t < 4; t++) BinaryPrimitives.WriteInt64LittleEndian(dst[(0x18 + t * 8)..], _timeSec);
        for (int t = 0; t < 4; t++) BinaryPrimitives.WriteUInt32LittleEndian(dst[(0x38 + t * 4)..], _timeNsec);
        BinaryPrimitives.WriteUInt64LittleEndian(dst[0x60..], n.LogicalOffset);
        BinaryPrimitives.WriteInt32LittleEndian(dst[0x64..], 0);
        int db1 = n.ParentInode < 0 ? -1 : (n.IsDirectory ? -1 : (int)n.Afid);
        BinaryPrimitives.WriteInt32LittleEndian(dst[0x68..], db1);
        BinaryPrimitives.WriteInt32LittleEndian(dst[0x6C..], n.ParentInode);
        BinaryPrimitives.WriteInt32LittleEndian(dst[0x70..], n.DirentOffset);
    }

    private static byte[] SerializeDirents(IEnumerable<Dirent> dirents)
    {
        using var ms = new MemoryStream();
        var rowBuf = new byte[280]; // max dirent size
        foreach (Dirent d in dirents)
        {
            byte[] nameBytes = Encoding.ASCII.GetBytes(d.Name);
            int entSize = DirentSize(nameBytes.Length);
            Array.Clear(rowBuf, 0, entSize);
            Span<byte> row = rowBuf.AsSpan(0, entSize);
            BinaryPrimitives.WriteUInt32LittleEndian(row, d.Inode);
            BinaryPrimitives.WriteInt32LittleEndian(row[4..], d.Type);
            BinaryPrimitives.WriteInt32LittleEndian(row[8..], nameBytes.Length);
            BinaryPrimitives.WriteInt32LittleEndian(row[12..], entSize);
            nameBytes.CopyTo(row[16..]);
            ms.Write(row);
        }
        return ms.ToArray();
    }

    // ---- Flat path table ----

    private readonly record struct FlatPathEntry(ulong Hash, ulong Packed);

    private const ulong FltSeed0 = 0x92CA8AAB26A24F51UL;
    private const ulong FltSeed1 = 0x09BBB761A41BC44DUL;
    private const ulong FltRoundConst = 0x8000000080008081UL;
    private const ulong FltFlagDir = 0x40000000UL;
    private const ulong FltFlagSubtree = 0x80000000UL;
    private const ulong FltDirValue = 0xFFFFFFUL;

    private static ulong Rotl(ulong x, int n) => (x << n) | (x >> (64 - n));
    private static ulong Rotr(ulong x, int n) => (x >> n) | (x << (64 - n));

    private static ulong HashPath(string path)
    {
        if (path.Length > 0 && path[0] == '/')
            path = path[1..];
        return HashBytes(Encoding.ASCII.GetBytes(path.ToUpperInvariant()));
    }

    private static ulong HashBytes(ReadOnlySpan<byte> str)
    {
        int len = str.Length;
        ulong s0 = FltSeed0, s1 = Rotl(FltSeed0, 11), s2 = Rotl(FltSeed0, 23);
        ulong tail = 0;
        if (len != 0)
        {
            int nwords = (len - 1) >> 3;
            ulong a0 = s0, a1 = s1, a2 = s2;
            int off = 0;
            for (int i = 0; i < nwords; i++)
            {
                ulong w = BinaryPrimitives.ReadUInt64LittleEndian(str.Slice(off, 8));
                off += 8;
                a0 ^= w;
                ulong t18 = Rotr(Rotl(a2 ^ a1, 5) ^ a0, 11);
                ulong t12 = Rotl(Rotl(a2 ^ a0, 17) ^ a1, 11);
                a2 = Rotr(Rotl(a1 ^ a0, 1) ^ a2, 5);
                a0 = (~t12 & a2) ^ t18 ^ FltRoundConst;
                a1 = (~a2 & t18) ^ t12;
                a2 = (~t18 & t12) ^ a2;
            }
            s0 = a0; s1 = a1; s2 = a2;
            int tlen = ((len - 1) & 7) + 1;
            for (int j = 0; j < tlen; j++)
                tail |= (ulong)str[off + j] << (8 * j);
        }
        ulong u16 = s1, u11 = s2, u6 = tail ^ s0 ^ FltSeed1;
        ulong u17 = Rotl(u11 ^ u16, 5) ^ u6;
        ulong u18 = Rotl(u11 ^ u6, 17) ^ u16;
        u11 = Rotl(u16 ^ u6, 1) ^ u11;
        return (~Rotl(u18, 11) & Rotr(u11, 5)) ^ Rotr(u17, 11) ^ FltRoundConst;
    }

    private static ulong PackInodeEntry(uint inode, bool isDir, bool isSubtree, uint afid)
    {
        ulong packed = inode & 0xFFFFFFUL;
        if (isDir) packed |= FltFlagDir;
        if (isSubtree) packed |= FltFlagSubtree;
        packed |= (isDir ? FltDirValue : afid) << 40;
        return packed;
    }

    private static ulong PackAprEntry(long size, uint afid)
        => ((ulong)size & 0xFFFFFFFFFFUL) | ((ulong)afid << 40);

    private static byte[] SerializeFlatPathTable(List<FlatPathEntry> entries)
    {
        entries.Sort((a, b) => a.Hash.CompareTo(b.Hash));
        using var ms = new MemoryStream();
        Span<byte> hdr = stackalloc byte[0x40];
        hdr.Clear();
        BinaryPrimitives.WriteUInt32LittleEndian(hdr, 1);
        hdr[0x04] = 0x10;
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[0x08..], 0x40);
        hdr[0x20] = 0x7F; hdr[0x21] = (byte)'F'; hdr[0x22] = (byte)'L'; hdr[0x23] = (byte)'T';
        BinaryPrimitives.WriteUInt32LittleEndian(hdr[0x2C..], (uint)entries.Count);
        BinaryPrimitives.WriteUInt64LittleEndian(hdr[0x30..], FltSeed0);
        BinaryPrimitives.WriteUInt64LittleEndian(hdr[0x38..], FltSeed1);
        ms.Write(hdr);
        Span<byte> ent = stackalloc byte[16];
        foreach (FlatPathEntry e in entries)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(ent, e.Hash);
            BinaryPrimitives.WriteUInt64LittleEndian(ent[8..], e.Packed);
            ms.Write(ent);
        }
        return ms.ToArray();
    }

    // ---- Data-first image assembly ----

    private const uint BlockInfoVersion = 0x00400003;
    private const uint BlockInfoTemplate = 0x00FCFF27;
    private const uint BlockInfoBase = 0x0027373C;

    private static long RoundUp(long value, long granularity) => (value + granularity - 1) / granularity * granularity;

    private static byte[] BuildBlockInfoTable(long urootFileSizeSum)
    {
        uint sub = (uint)((4L * urootFileSizeSum) & 0xFFFFF);
        uint bigEndian = (BlockInfoBase - sub) & 0xFFFFFF;
        uint value = ((bigEndian & 0xFF) << 16) | (bigEndian & 0xFF00) | ((bigEndian >> 16) & 0xFF);
        var table = new byte[32];
        WriteBlockInfoEntry(table, 0, BlockInfoTemplate);
        WriteBlockInfoEntry(table, 8, BlockInfoTemplate);
        WriteBlockInfoEntry(table, 16, BlockInfoTemplate);
        WriteBlockInfoEntry(table, 24, value);
        return table;

        static void WriteBlockInfoEntry(byte[] buf, int off, uint val)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off), val);
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(off + 4), BlockInfoVersion);
        }
    }

    /// <summary>
    /// Renders one file's on-disk payload by reading its source in <see cref="KrakenEncoder.ChunkSize"/>
    /// chunks (from memory or <see cref="FileNode.SourcePath"/>) and appending the per-chunk encoded
    /// bytes. When <paramref name="retainEncodedBytes"/> is false (file-backed build) the block
    /// records keep only their sizes/flags and leave <see cref="ProsperoEncodedBlock.EncodedBytes"/>
    /// empty, so the returned payload is the only per-file copy.
    /// </summary>
    private static byte[] RenderFilePayload(
        FileNode f, ProsperoInnerCompressionMode compressionMode,
        List<ProsperoEncodedBlock> encodedBlocks, ref int sourceBlockIndex, bool retainEncodedBytes)
    {
        if (f.PayloadLength == 0)
        {
            // An empty file still materializes as one zero-length stored block.
            encodedBlocks.Add(new ProsperoEncodedBlock
            {
                SourceBlockIndex = sourceBlockIndex++, LogicalOffset = f.LogicalOffset,
                UncompressedLength = 0, EncodedBytes = [], EncodedLength = 0, IsStored = true,
            });
            return [];
        }

        var filePayload = new List<byte>();
        using Stream source = OpenSource(f);
        var buffer = new byte[KrakenEncoder.ChunkSize];
        long remaining = f.PayloadLength;
        long blockOffset = 0;
        while (remaining > 0)
        {
            int rawLength = (int)Math.Min(KrakenEncoder.ChunkSize, remaining);
            ReadExactly(source, buffer, rawLength);
            ReadOnlySpan<byte> raw = buffer.AsSpan(0, rawLength);
            // A terminal compressed block immediately before a NAPS RUN re-anchor has no
            // independently serialized total-length field in the current reader contract.
            // Keep that boundary stored; preceding blocks still use Kraken when beneficial.
            bool terminalFileBlock = blockOffset + rawLength >= f.PayloadLength;
            KrakenEncoder.EncodedBlock? kraken = compressionMode == ProsperoInnerCompressionMode.Stored || terminalFileBlock
                ? null : KrakenEncoder.TryEncode(raw);
            if (kraken is not null && VerifyKraken(raw, kraken))
            {
                filePayload.AddRange(kraken.Payload);
                encodedBlocks.Add(new ProsperoEncodedBlock
                {
                    SourceBlockIndex = sourceBlockIndex++, LogicalOffset = f.LogicalOffset + blockOffset,
                    UncompressedLength = rawLength,
                    EncodedBytes = retainEncodedBytes ? kraken.Payload : [],
                    EncodedLength = kraken.Payload.Length, IsStored = false,
                    KrakenMode = kraken.Mode, Flags = kraken.Flags,
                    FirstChunkCompressedLength = kraken.FirstChunkCompressedLength,
                });
            }
            else
            {
                byte[] stored = raw.ToArray();
                filePayload.AddRange(stored);
                encodedBlocks.Add(new ProsperoEncodedBlock
                {
                    SourceBlockIndex = sourceBlockIndex++, LogicalOffset = f.LogicalOffset + blockOffset,
                    UncompressedLength = rawLength,
                    EncodedBytes = retainEncodedBytes ? stored : [],
                    EncodedLength = stored.Length, IsStored = true,
                });
            }
            remaining -= rawLength;
            blockOffset += rawLength;
        }
        return filePayload.ToArray();
    }

    private static Stream OpenSource(FileNode f) => f.SourcePath is null
        ? new MemoryStream(f.Data, writable: false)
        : new FileStream(f.SourcePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);

    private static void ReadExactly(Stream stream, byte[] buffer, int length)
    {
        int read = 0;
        while (read < length)
        {
            int n = stream.Read(buffer, read, length - read);
            if (n <= 0)
                throw new EndOfStreamException("A source file ended before its declared length.");
            read += n;
        }
    }
}
