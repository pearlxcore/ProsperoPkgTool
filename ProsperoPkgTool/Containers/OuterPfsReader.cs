using System.Buffers.Binary;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room reader for the PS5 outer PFS image (FINDINGS.md §3.3, §4.3–4.5).
///
/// The outer image uses a data-first layout of fixed 0x10000-byte blocks:
/// file-data blocks first, then a single plaintext superblock, with metadata blocks after.
/// Every block except the superblock is AES-128-XTS encrypted. The per-block sector is
/// classification-driven (verified against the reference package):
///   * <c>pfs_image.dat</c> data blocks use sector = block index,
///   * every other file/metadata block uses sector = 0x800000000000 | block index,
///   * the superblock is plaintext.
/// The superblock carries the seed used to derive the XTS keys from the EKPFS.
/// </summary>
public sealed class OuterPfsReader
{
    public const long BlockSize = 0x10000;
    public const int SuperblockSeedOffset = 0x370;
    public const int SuperblockIcvOffset = 0x380;
    public const int SuperblockIcvLength = 32;
    public const int SuperblockIcvRegionLength = 0x5A0;  // ICV is computed over the first 0x5A0 bytes with the ICV field zeroed
    private const long SuperblockMagic = 20130315;       // little-endian i64 at offset 0x08
    private const ulong SignedSectorFlag = 0x800000000000UL;

    /// <summary>
    /// Seed marker written by community / plain builds that store the outer PFS unencrypted
    /// (no AES-XTS and no authentication). When the superblock seed holds this value every block
    /// is read verbatim instead of being XTS-decrypted.
    /// </summary>
    private static readonly byte[] PlainNoAuthSeed = "PPRPLAIN-NOAUTH!"u8.ToArray();

    // S32 inode layout (verified byte-exact against PPSA03530-bd-nw.pkg; FINDINGS.md §3.3).
    private const int S32InodeSize = 0x2C8;
    private const int S32DirectBlockOffset = 0x64;    // 12 x BlockSig32 (32 sig + 4 block) stride 36
    private const int S32IndirectBlockOffset = 0x214; // 5 x BlockSig32 stride 36
    private const int BlockSig32Stride = 36;          // 32-byte sig + 4-byte block index
    private const int BlockIndexOffsetInSig = 32;     // block index sits after the 32-byte sig
    private const int InodeSigSize = 0x310;           // superblock inode-sig is ALWAYS S64
    private const int InodeSigIndirectOffset = 0x244; // 5 x BlockSig64 (32 sig + 8 block) stride 40

    private readonly Stream _stream;
    private readonly long _pfsOffset;
    private readonly long _pfsSize;

    public int SuperblockIndex { get; }
    public int BlockCount { get; }
    public byte[] Seed { get; }
    public byte[] Superblock { get; }

    /// <summary>True when the outer PFS is stored unencrypted (community <c>PPRPLAIN-NOAUTH!</c> layout).</summary>
    public bool IsPlainNoAuth { get; }

    private OuterPfsReader(Stream stream, long pfsOffset, long pfsSize, int superblockIndex, byte[] superblock, byte[] seed)
    {
        _stream = stream;
        _pfsOffset = pfsOffset;
        _pfsSize = pfsSize;
        SuperblockIndex = superblockIndex;
        BlockCount = (int)(pfsSize / BlockSize);
        Superblock = superblock;
        Seed = seed;
        IsPlainNoAuth = seed.AsSpan().SequenceEqual(PlainNoAuthSeed);
    }

    /// <summary>
    /// Locate the plaintext superblock within the outer PFS image and read the seed. The
    /// superblock is identified by the little-endian i64 value 20130315 at offset 0x08.
    /// </summary>
    /// <param name="superblockIndexHint">
    /// Optional block index of the plaintext superblock, when the caller can derive it from the
    /// FIH header. Supplying it avoids the full linear scan (and read) of a multi-GB outer image.
    /// The hint is validated against the magic; when it is wrong or absent the reader falls back
    /// to the full scan, preserving correctness for foreign layouts.
    /// </param>
    public static OuterPfsReader Open(Stream stream, long pfsOffset, long pfsSize, int superblockIndexHint = -1)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (pfsOffset < 0 || pfsSize < BlockSize)
            throw new ArgumentOutOfRangeException(nameof(pfsSize), "PFS region is too small to contain a superblock.");

        int blockCount = (int)(pfsSize / BlockSize);
        byte[] block = new byte[BlockSize];
        if (superblockIndexHint >= 0 && superblockIndexHint < blockCount)
        {
            ReadBlockRaw(stream, pfsOffset, superblockIndexHint, block);
            if (BinaryPrimitives.ReadInt64LittleEndian(block.AsSpan(0x08, 8)) == SuperblockMagic)
            {
                byte[] seed = block.AsSpan(SuperblockSeedOffset, 16).ToArray();
                return new OuterPfsReader(stream, pfsOffset, pfsSize, superblockIndexHint, (byte[])block.Clone(), seed);
            }
        }
        for (int i = 0; i < blockCount; i++)
        {
            ReadBlockRaw(stream, pfsOffset, i, block);
            if (BinaryPrimitives.ReadInt64LittleEndian(block.AsSpan(0x08, 8)) == SuperblockMagic)
            {
                byte[] seed = block.AsSpan(SuperblockSeedOffset, 16).ToArray();
                return new OuterPfsReader(stream, pfsOffset, pfsSize, i, (byte[])block.Clone(), seed);
            }
        }
        throw new InvalidDataException("No plaintext PFS superblock found in the outer image.");
    }

    /// <summary>
    /// Read and decrypt a single block. The superblock is returned as-is (plaintext); all
    /// other blocks are XTS-decrypted as <em>signed</em> (sector = 0x800000000000 | index).
    /// This is the "probe" classification used to walk the inode/directory tree, which is
    /// all signed metadata. <see cref="ReadBlock(AesXts, int, bool)"/> decodes a block with
    /// an explicit data-vs-signed classification; <c>pfs_image.dat</c> data blocks must be
    /// read with <c>signed: false</c>.
    /// </summary>
    public byte[] ReadBlock(AesXts xts, int blockIndex) => ReadBlock(xts, blockIndex, signed: true);

    /// <summary>
    /// Read and decrypt a single block with an explicit classification. <paramref name="signed"/>
    /// selects the XTS sector: <c>false</c> uses the plain block index (for <c>pfs_image.dat</c>
    /// data blocks), <c>true</c> uses 0x800000000000 | block index (for all metadata and the
    /// naps file). The superblock is always returned plaintext.
    /// </summary>
    public byte[] ReadBlock(AesXts xts, int blockIndex, bool signed)
    {
        ArgumentNullException.ThrowIfNull(xts);
        if (blockIndex < 0 || blockIndex >= BlockCount)
            throw new ArgumentOutOfRangeException(nameof(blockIndex));

        byte[] raw = new byte[BlockSize];
        ReadBlockRaw(_stream, _pfsOffset, blockIndex, raw);

        if (blockIndex == SuperblockIndex)
            return raw; // superblock is plaintext

        // Community / plain builds store the whole outer PFS unencrypted; the superblock seed is
        // the literal PPRPLAIN-NOAUTH! marker, so no XTS key derivation or decryption applies.
        if (IsPlainNoAuth)
            return raw;

        ulong sector = signed ? ((ulong)(uint)blockIndex | SignedSectorFlag) : (ulong)(uint)blockIndex;
        return xts.Decrypt(raw, sector);
    }

    /// <summary>
    /// Block span of the contiguous <c>pfs_image.dat</c> data region (blocks 0 .. before the
    /// superblock). May exceed 2 GiB for multi-GB packages; callers must stream.
    /// </summary>
    public long InnerImageLength => (long)Math.Max(0, SuperblockIndex - 1) * BlockSize;

    /// <summary>
    /// Decrypt and return the contiguous <c>pfs_image.dat</c> data region (blocks 0 ..
    /// next-signed-block - 1) using the data-sector classification (sector = block index).
    /// The <c>pfs_image.dat</c> file's on-disk extent runs from block 0 up to the start of the
    /// next outer file (the naps, which is signed); its inode size is the inner mount's
    /// logical size and does NOT bound the on-disk span.
    /// </summary>
    public byte[] ReadInnerImage(AesXts xts)
    {
        int dataBlocks = Math.Max(0, SuperblockIndex - 1);
        long total = (long)dataBlocks * BlockSize;
        if (total > int.MaxValue)
            throw new InvalidDataException(
                $"pfs_image.dat ({total} bytes) exceeds the in-memory reader limit; use the file-backed reader.");
        using var ms = new MemoryStream((int)total);
        for (int i = 0; i < dataBlocks; i++)
        {
            byte[] plaintext = ReadBlock(xts, i, signed: false);
            ms.Write(plaintext, 0, plaintext.Length);
        }
        return ms.ToArray();
    }

    /// <summary>
    /// Decrypt and return an arbitrary byte range of <c>pfs_image.dat</c> in 64 KiB block-sized
    /// reads, so multi-GB images can be consumed without materializing the whole span.
    /// </summary>
    public byte[] ReadInnerImageRegion(AesXts xts, long offset, int length)
    {
        ArgumentNullException.ThrowIfNull(xts);
        if (offset < 0 || length < 0 || offset + length > InnerImageLength)
            throw new InvalidDataException($"Inner-image region 0x{offset:X}+0x{length:X} is outside pfs_image.dat.");
        if (length == 0)
            return [];

        int firstBlock = checked((int)(offset / BlockSize));
        int lastBlock = checked((int)((offset + length - 1) / BlockSize));
        var result = new byte[length];
        int destination = 0;
        for (int blockIndex = firstBlock; blockIndex <= lastBlock; blockIndex++)
        {
            byte[] plaintext = ReadBlock(xts, blockIndex, signed: false);
            int startInBlock = blockIndex == firstBlock ? (int)(offset - (long)blockIndex * BlockSize) : 0;
            int take = (int)Math.Min(BlockSize - startInBlock, length - destination);
            Array.Copy(plaintext, startInBlock, result, destination, take);
            destination += take;
        }
        return result;
    }

    /// <summary>
    /// Decrypt and return a single <c>pfs_image.dat</c> data block (64 KiB) without reading
    /// the rest of the inner image. Each data block is a fixed 0x10000-byte chunk of the
    /// compressed inner stream; a Kraken block at compressed offset <c>coff</c> lives in data
    /// block <c>coff &gt;&gt; 16</c> at byte <c>coff &amp; 0xFFFF</c>. This enables targeted
    /// extraction of individual compressed blocks from a multi-GB image.
    /// </summary>
    public byte[] ReadInnerImageBlock(AesXts xts, int blockIndex)
    {
        if (blockIndex < 0 || blockIndex >= Math.Max(0, SuperblockIndex - 1))
            throw new ArgumentOutOfRangeException(nameof(blockIndex),
                $"Block index {blockIndex} is outside the pfs_image.dat data region (0 .. {Math.Max(0, SuperblockIndex - 1) - 1}).");
        return ReadBlock(xts, blockIndex, signed: false);
    }

    /// <summary>
    /// Verify the superblock ICV: SHA3-256 of the first 0x5A0 bytes of the superblock with
    /// the 32-byte ICV field (at 0x380) zeroed. Returns true when it matches the stored ICV.
    /// </summary>
    public bool VerifySuperblockIcv()
    {
        // A plain/no-auth outer PFS carries no authentication tag, so there is nothing to verify.
        if (IsPlainNoAuth)
            return true;
        byte[] region = Superblock.AsSpan(0, SuperblockIcvRegionLength).ToArray();
        Array.Clear(region, SuperblockIcvOffset, SuperblockIcvLength);
        byte[] computed = Sha3.Sha3_256(region);
        return Superblock.AsSpan(SuperblockIcvOffset, SuperblockIcvLength).SequenceEqual(computed);
    }

    // ---- Outer PFS inode-table walker (S32 inodes) ----

    /// <summary>
    /// Walk the outer PFS inode/directory tree (all signed metadata) and return a lookup of
    /// the <c>pfs_image.dat</c> and <c>naps_pkg_layout.dat</c> files with their resolved
    /// block lists and per-block classification. <c>pfs_image.dat</c> blocks are data
    /// (plain sector), naps and all metadata blocks are signed (0x800000000000 | index).
    /// </summary>
    public IReadOnlyDictionary<string, OuterFile> EnumerateOuterFiles(AesXts xts)
    {
        var inodes = ReadInodeTable(xts);
        var uroot = ReadDirectory(xts, inodes[2]);

        var result = new Dictionary<string, OuterFile>(StringComparer.OrdinalIgnoreCase);
        foreach (var de in uroot)
        {
            if (de.Name == "." || de.Name == "..")
                continue;
            var inode = inodes[(int)de.Inode];
            bool signed = !string.Equals(de.Name, "pfs_image.dat", StringComparison.OrdinalIgnoreCase);
            result[de.Name] = new OuterFile(
                de.Name, inode.Size, inode.SizeCompressed, ResolveBlocks(xts, inode), signed);
        }
        return result;
    }

    /// <summary>Read <c>naps_pkg_layout.dat</c> from the outer PFS (signed blocks).</summary>
    public byte[] ReadNaps(AesXts xts)
    {
        IReadOnlyDictionary<string, OuterFile> files = EnumerateOuterFiles(xts);
        if (!files.TryGetValue("naps_pkg_layout.dat", out OuterFile? naps))
            throw new InvalidDataException("Outer PFS uroot is missing naps_pkg_layout.dat.");
        return ReadFileBytes(xts, naps);
    }

    /// <summary>Parse the S32 inode table (signed metadata) from the outer PFS.</summary>
    private S32Inode[] ReadInodeTable(AesXts xts)
    {
        // The superblock inode-sig is always S64; its 5 indirect blocks precede the inode
        // table, so the table starts at superblock + 1 + (nonzero indirect blocks).
        ReadOnlySpan<byte> sig = Superblock.AsSpan(0x50, InodeSigSize);
        int indirectCount = 0;
        for (int i = 0; i < 5; i++)
        {
            long block = BinaryPrimitives.ReadInt64LittleEndian(sig.Slice(InodeSigIndirectOffset + i * 40 + 8, 8));
            if (block > 0)
                indirectCount++;
        }

        int dinodeCount = checked((int)BinaryPrimitives.ReadInt64LittleEndian(Superblock.AsSpan(0x30, 8)));
        int dinodeBlockCount = checked((int)BinaryPrimitives.ReadInt64LittleEndian(Superblock.AsSpan(0x40, 8)));
        int dinodeStart = SuperblockIndex + 1 + indirectCount;

        var inodeTable = new byte[dinodeBlockCount * (int)BlockSize];
        for (int b = 0; b < dinodeBlockCount; b++)
        {
            byte[] plain = ReadBlock(xts, dinodeStart + b, signed: true);
            plain.CopyTo(inodeTable, b * (int)BlockSize);
        }

        var inodes = new S32Inode[dinodeCount];
        for (int i = 0; i < dinodeCount; i++)
        {
            ReadOnlySpan<byte> e = inodeTable.AsSpan(i * S32InodeSize, S32InodeSize);
            inodes[i] = new S32Inode
            {
                Mode = BinaryPrimitives.ReadUInt16LittleEndian(e),
                Flags = BinaryPrimitives.ReadUInt32LittleEndian(e[4..]),
                Size = BinaryPrimitives.ReadInt64LittleEndian(e[8..]),
                SizeCompressed = BinaryPrimitives.ReadInt64LittleEndian(e[16..]),
                Blocks = BinaryPrimitives.ReadUInt32LittleEndian(e[0x60..]),
                DirectBlocks = ReadBlockSigs32(e.Slice(S32DirectBlockOffset, 12 * BlockSig32Stride), 12),
                IndirectBlocks = ReadBlockSigs32(e.Slice(S32IndirectBlockOffset, 5 * BlockSig32Stride), 5),
            };
        }
        // A wrong passcode decrypts the signed inode table to garbage. Detect an implausible uroot
        // inode (index 2) here so callers get a passcode-oriented message instead of a low-level
        // block-resolution failure further down.
        if (inodes.Length <= 2)
            throw new InvalidDataException("The outer PFS inode table is missing its uroot inode.");
        S32Inode uroot = inodes[2];
        if ((uroot.Mode & 0xF000) != 0x4000 || uroot.Size <= 0 ||
            uroot.Size > (long)BlockCount * BlockSize || uroot.Blocks == 0 || uroot.Blocks > (uint)BlockCount)
        {
            throw new InvalidDataException(
                "The outer PFS inode table did not yield a valid uroot directory: the passcode is wrong, " +
                "the outer-PFS layout is unsupported, or the package is corrupt.");
        }

        return inodes;
    }

    /// <summary>Read a directory inode's dirent stream (signed blocks).</summary>
    private List<OuterDirent> ReadDirectory(AesXts xts, S32Inode inode)
    {
        byte[] data = ReadFileBytes(xts, inode, signed: true);
        int length = (int)Math.Min(inode.Size, data.Length);
        var entries = new List<OuterDirent>();
        int pos = 0;
        while (pos + 16 <= length)
        {
            ReadOnlySpan<byte> de = data.AsSpan(pos, 16);
            uint ino = BinaryPrimitives.ReadUInt32LittleEndian(de);
            uint type = BinaryPrimitives.ReadUInt32LittleEndian(de[4..]);
            uint namelen = BinaryPrimitives.ReadUInt32LittleEndian(de[8..]);
            uint entsize = BinaryPrimitives.ReadUInt32LittleEndian(de[12..]);
            if (entsize < 16 || pos + (int)entsize > length)
                break;
            string name = System.Text.Encoding.ASCII.GetString(data, pos + 16, (int)namelen);
            entries.Add(new OuterDirent(ino, type, name, entsize));
            pos += (int)entsize;
        }
        return entries;
    }

    /// <summary>
    /// Resolve a file's block index list (12 direct + the 5 inode indirect trees) without reading
    /// the payload. Each <c>ib[b]</c> is the root of a depth <c>b+1</c> tree; leaves hold
    /// {32-byte digest, int32 data-block index} entries and higher nodes hold child-block indices.
    /// The tree blocks themselves are always signed metadata, independent of the file's data
    /// classification.
    /// </summary>
    private int[] ResolveBlocks(AesXts xts, S32Inode inode)
    {
        if (inode.Blocks > (uint)Math.Max(0, BlockCount))
            throw new InvalidDataException(
                $"Outer inode declares {inode.Blocks} blocks, more than the image's {BlockCount} blocks: " +
                "the passcode is wrong, the outer-PFS layout is unsupported, or the package is corrupt.");
        int blocks = (int)inode.Blocks;
        if (blocks < 0)
            throw new InvalidDataException("Inode block count is negative.");

        var result = new List<int>(blocks);
        for (int i = 0; i < 12 && result.Count < blocks; i++)
            result.Add(inode.DirectBlocks[i]);

        for (int level = 0; level < 5 && result.Count < blocks; level++)
        {
            int root = inode.IndirectBlocks[level];
            if (root <= 0)
                continue;
            ProsperoOuterPfsBuilder.CollectIndirectTree(root, level + 1, blocks,
                blockIndex =>
                {
                    if (blockIndex < 0 || blockIndex >= BlockCount)
                        throw new InvalidDataException(
                            "An outer inode references an out-of-range metadata block: the passcode is wrong, " +
                            "the outer-PFS layout is unsupported, or the package is corrupt.");
                    return ReadBlock(xts, (int)blockIndex, signed: true);
                }, result);
        }

        if (result.Count < blocks)
            throw new InvalidDataException(
                $"Outer inode resolves {result.Count} blocks but declares {blocks}; the indirect tree is incomplete.");
        return result.ToArray();
    }

    /// <summary>Read a file's payload, bounded to its stored size (inode Size).</summary>
    private byte[] ReadFileBytes(AesXts xts, OuterFile file)
    {
        int[] blockIndexes = file.BlockIndexes;
        long total = Math.Min(file.Size, (long)blockIndexes.Length * BlockSize);
        if (total > int.MaxValue)
            throw new InvalidDataException($"File '{file.Name}' is too large to read into memory ({total} bytes).");

        var result = new byte[(int)total];
        int written = 0;
        foreach (int blockIndex in blockIndexes)
        {
            byte[] plain = ReadBlock(xts, blockIndex, file.Signed);
            int take = Math.Min(plain.Length, (int)(total - written));
            if (take <= 0)
                break;
            Array.Copy(plain, 0, result, written, take);
            written += take;
        }
        return result;
    }

    /// <summary>Read a file's payload from an inode, bounded to its stored size.</summary>
    private byte[] ReadFileBytes(AesXts xts, S32Inode inode, bool signed)
    {
        int[] blockIndexes = ResolveBlocks(xts, inode);
        return ReadFileBytes(xts, new OuterFile("", inode.Size, inode.SizeCompressed, blockIndexes, signed));
    }

    private static int[] ReadBlockSigs32(ReadOnlySpan<byte> region, int count)
    {
        var result = new int[count];
        for (int i = 0; i < count; i++)
            result[i] = BinaryPrimitives.ReadInt32LittleEndian(region.Slice(i * BlockSig32Stride + BlockIndexOffsetInSig, 4));
        return result;
    }

    private sealed class S32Inode
    {
        public ushort Mode;
        public uint Flags;
        public long Size;
        public long SizeCompressed;
        public uint Blocks;
        public int[] DirectBlocks = Array.Empty<int>();
        public int[] IndirectBlocks = Array.Empty<int>();
    }

    private readonly record struct OuterDirent(uint Inode, uint Type, string Name, uint EntSize);

    private static void ReadBlockRaw(Stream stream, long pfsOffset, int blockIndex, byte[] buffer)
    {
        stream.Position = pfsOffset + (long)blockIndex * BlockSize;
        stream.ReadExactly(buffer, 0, (int)BlockSize);
    }
}

/// <summary>An outer-PFS file entry with its resolved block list and classification.</summary>
public sealed class OuterFile
{
    public string Name { get; }
    public long Size { get; }
    public long SizeCompressed { get; }
    public int[] BlockIndexes { get; }
    public bool Signed { get; }

    public OuterFile(string name, long size, long sizeCompressed, int[] blockIndexes, bool signed)
    {
        Name = name;
        Size = size;
        SizeCompressed = sizeCompressed;
        BlockIndexes = blockIndexes;
        Signed = signed;
    }
}
