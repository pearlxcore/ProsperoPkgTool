using System.Buffers.Binary;
using System.Text;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>Classification of an outer-PFS block for AES-XTS sector numbering.</summary>
public enum OuterBlockKind : byte
{
    /// <summary>Plain file-data block: XTS sector = block index.</summary>
    Data = 0,

    /// <summary>Signed/metadata block: XTS sector = 0x800000000000 | block index.</summary>
    Signed = 1,

    /// <summary>Superblock block stored plaintext (not encrypted).</summary>
    Plaintext = 2,
}

/// <summary>One file at the outer level of the finalized image (e.g. <c>pfs_image.dat</c>).</summary>
public sealed class OuterPfsFile
{
    /// <summary>The outer file name (stored as-is in dirents; conventionally lowercase).</summary>
    public required string Name { get; init; }

    /// <summary>The raw file bytes, laid out block-by-block (zero-padded to the block size).</summary>
    public required byte[] Data { get; init; }

    /// <summary>
    /// The dinode <c>SizeCompressed</c> field. For <c>naps_pkg_layout.dat</c> this equals the file
    /// length; for <c>pfs_image.dat</c> it is the nested image's logical (uncompressed) size.
    /// Defaults to <see cref="Data"/>'s length.
    /// </summary>
    public long? SizeCompressed { get; init; }

    /// <summary>
    /// Whether this file's data blocks are AES-XTS encrypted as <em>signed</em> blocks
    /// (sector = 0x800000000000 | block index). <c>pfs_image.dat</c> is plain data;
    /// <c>naps_pkg_layout.dat</c> is signed.
    /// </summary>
    public bool Signed { get; init; }
}

/// <summary>Build parameters for the outer-PFS generator (timestamps and crypt seed).</summary>
public sealed class OuterPfsBuildParameters
{
    /// <summary>POSIX seconds stamped into every inode time field.</summary>
    public long TimestampSeconds { get; init; } = 0x6A31A5B9;

    /// <summary>Nanosecond fraction stamped into every inode time field.</summary>
    public uint TimestampNanoseconds { get; init; } = 0x14DC9380;

    /// <summary>The 16-byte crypt seed written at superblock+0x370 (and used for key derivation).</summary>
    public byte[]? Seed { get; init; }

    /// <summary>
    /// Worker threads for the per-block SHA3 and AES-XTS passes; 0 (the default) uses the processor
    /// count. The produced image bytes are independent of the thread count.
    /// </summary>
    public int BlockParallelism { get; init; }
}

/// <summary>Result of building the plaintext outer-PFS image (assembled + signed, not encrypted).</summary>
public sealed class OuterPfsBuildResult
{
    /// <summary>The assembled plaintext image (a whole number of 64 KiB blocks).</summary>
    public required byte[] Plaintext { get; init; }

    /// <summary>Per-block AES-XTS classification, one entry per block.</summary>
    public required OuterBlockKind[] BlockKinds { get; init; }

    /// <summary>Index of the plaintext superblock block.</summary>
    public required int SuperblockIndex { get; init; }

    /// <summary>First image block of each outer file, parallel to the input file list.</summary>
    public int[] FileFirstBlock { get; init; } = [];

    /// <summary>Image block count of each outer file, parallel to the input file list.</summary>
    public int[] FileBlockCount { get; init; } = [];

    /// <summary>Block index of the inode (dinode) table.</summary>
    public int InodeTableIndex { get; init; }

    /// <summary>Block index of the super-root dirents.</summary>
    public int SuperRootDirentIndex { get; init; }

    /// <summary>Block index of the inode_flat_path_table.</summary>
    public int FltIndex { get; init; }

    /// <summary>Block index of the uroot dirents.</summary>
    public int UrootDirentIndex { get; init; }

    /// <summary>Total block count of the image.</summary>
    public int BlockCount => BlockKinds.Length;
}

/// <summary>One outer file backed by a source path, for the streamed (array-limit-free) builder.</summary>
public sealed class OuterPfsFileSource
{
    /// <summary>The outer file name (stored as-is in dirents; conventionally lowercase).</summary>
    public required string Name { get; init; }

    /// <summary>Path to the source bytes; the file length supplies the block plan.</summary>
    public required string Path { get; init; }

    /// <summary>
    /// The dinode <c>SizeCompressed</c> field. For <c>naps_pkg_layout.dat</c> this equals the file
    /// length; for <c>pfs_image.dat</c> it is the nested image's logical (uncompressed) size.
    /// Defaults to the source length.
    /// </summary>
    public long? SizeCompressed { get; init; }

    /// <summary>Whether this file's data blocks are AES-XTS encrypted as <em>signed</em> blocks.</summary>
    public bool Signed { get; init; }
}

/// <summary>Result of the streamed outer-PFS build (image written to disk, metadata in memory).</summary>
public sealed class OuterPfsFileBuildResult
{
    /// <summary>The on-disk ciphertext (or plaintext) outer-PFS image path.</summary>
    public required string ImagePath { get; init; }

    /// <summary>Exact image length in bytes (a whole number of 64 KiB blocks).</summary>
    public required long ImageLength { get; init; }

    /// <summary>Per-block AES-XTS classification, one entry per block.</summary>
    public required OuterBlockKind[] BlockKinds { get; init; }

    /// <summary>Index of the plaintext superblock block.</summary>
    public required int SuperblockIndex { get; init; }

    /// <summary>First image block of each outer file, parallel to the input file list.</summary>
    public required int[] FileFirstBlock { get; init; }

    /// <summary>Image block count of each outer file, parallel to the input file list.</summary>
    public required int[] FileBlockCount { get; init; }

    /// <summary>Block index of the inode (dinode) table.</summary>
    public required int InodeTableIndex { get; init; }

    /// <summary>Block index of the super-root dirents.</summary>
    public required int SuperRootDirentIndex { get; init; }

    /// <summary>Block index of the inode_flat_path_table.</summary>
    public required int FltIndex { get; init; }

    /// <summary>Block index of the uroot dirents.</summary>
    public required int UrootDirentIndex { get; init; }

    /// <summary>One SHA3-256 per plaintext block (matches <see cref="ComputeImageDigests"/>).</summary>
    public required byte[] ImageDigests { get; init; }

    /// <summary>Superblock ICV.</summary>
    public required byte[] SuperblockIcv { get; init; }

    /// <summary>A copy of the assembled plaintext superblock block.</summary>
    public required byte[] SuperblockPlaintext { get; init; }

    /// <summary>Total block count of the image.</summary>
    public int BlockCount => BlockKinds.Length;
}

/// <summary>
/// Clean-room builder for the PS5 outer PFS image — the data-first 64 KiB-block filesystem that
/// wraps the outer files (<c>pfs_image.dat</c> = the nested inner image, and
/// <c>naps_pkg_layout.dat</c>) together with fixed metadata (superblock, inode table, super-root
/// dirents, inode_flat_path_table, uroot dirents), signing every block with SHA3-256 and encrypting
/// with AES-XTS (the superblock stays plaintext).
///
/// Layout (data-first): blocks [0..D-1] = file data in order; block D = superblock (plaintext);
/// D+1 = inode table; D+2 = super-root dirents; D+3 = FLT; D+4.. = indirect blocks (for files
/// spanning more than 12 blocks); then the uroot dirents.
///
/// Inode template: 0 = super-root dir (mode 0x416d, flags 0x2000c), 1 = inode_flat_path_table
/// (mode 0x816d, flags 0x2000c), 2 = uroot dir (mode 0x416d, nlink 3, flags 0xc),
/// 3.. = the outer files in order (mode 0x816d, flags 0xd).
///
/// S32 inode (0x2C8 bytes): mode@0 (u16), nlink@2 (u16), flags@4 (u32), size@8 (i64),
/// sizeCompressed@16 (i64), times@24..72 (4×i64 sec + 4×u32 nsec), uid@72, gid@76, unk1@80 (u64),
/// unk2@88 (u64), blocks@96 (u32), db@100 (12×36: 32-byte SHA3 + i32 block), ib@0x214 (5×36).
///
/// Superblock: version@0 (2), magic@8 (20130315), id@16, flags@0x18 (readonly), mode@0x1C (0x0D),
/// blockSize@0x20, nBlock@0x28 (1), dinodeCount@0x30, ndblock@0x38, dinodeBlockCount@0x40 (1),
/// zero@0x48, S64 inode-sig@0x50 (0x310 bytes; db[0].sig@0xB8 = SHA3(inode table),
/// db[0].block@0xD8), unknownIndex@0x36C (1), seed@0x370 (16), ICV@0x380 (32) =
/// SHA3-256(block[0:0x5A0] with the ICV field zeroed).
/// </summary>
public static class ProsperoOuterPfsBuilder
{
    /// <summary>The outer PFS block size (one block = one AES-XTS data unit).</summary>
    public const int BlockSize = 0x10000;

    private const string FlatPathTableName = "inode_flat_path_table";
    private const string UrootName = "uroot";
    private const int MetadataInodeCount = 3;

    // Inode mode / flag constants.
    private const ushort ModeDir = 0x416D;            // S_IFDIR | 0555
    private const ushort ModeFile = 0x816D;           // S_IFREG | 0555
    private const uint FlagsInternalMeta = 0x2000C;   // @internal | unk2 | unk3
    private const uint FlagsDir = 0x000C;             // unk2 | unk3
    private const uint FlagsFile = 0x000D;            // compressed | unk2 | unk3

    // Superblock constants.
    private const long SuperblockVersion = 2;
    private const long SuperblockMagic = 20130315;
    private const int SuperblockInodeSigOffset = 0x50;
    private const int SuperblockUnknownIndexOffset = 0x36C;
    private const int SuperblockSeedOffset = 0x370;
    private const int SuperblockIcvOffset = 0x380;
    private const int SuperblockIcvLength = 32;
    private const int SuperblockIcvCoverage = 0x5A0;

    // Signed-sector XTS tweak flag (bit 47).
    private const ulong SignedSectorFlag = 0x800000000000UL;

    // S32 inode table constants.
    private const int S32InodeSize = 0x2C8;
    private const int DirectBlockSlots = 12;
    private const int IndirectLevelCount = 5;        // 5-level indirect tree per inode
    private const int BlockSig32Stride = 36;         // 32-byte sig + 4-byte block index
    private const int IndirectEntriesPerBlock = BlockSize / BlockSig32Stride;

    /// <summary>Entry stride of the outer indirect tree (32-byte digest + 4-byte block index).</summary>
    public const int TreeEntrySize = BlockSig32Stride;

    /// <summary>Entries addressable by one outer indirect block.</summary>
    public const int TreeEntriesPerBlock = IndirectEntriesPerBlock;

    /// <summary>Maximum depth of the outer indirect tree.</summary>
    public const int TreeLevelCount = IndirectLevelCount;
    private const int S32DirectBlockOffset = 0x64;   // 100
    private const int S32IndirectBlockOffset = 0x214;

    // S64 inode (superblock inode-sig) constants.
    private const int S64InodeSize = 0x310;
    private const int S64DirectBlockOffset = 104;    // 12 × 40-byte entries
    private const int BlockSig64Stride = 40;         // 32-byte sig + 8-byte block index

    // FLT (inode_flat_path_table) constants.
    private const uint FltVersion = 1;
    private const uint FltHeaderSize = 0x10;
    private const uint FltDataOffset = 0x40;
    private static readonly byte[] FltMagic = [0x7F, 0x46, 0x4C, 0x54]; // "\x7fFLT"
    private const ulong FltRoundConstant = 0x8000000080008081UL;
    private const ulong FltSeed0 = 0x92CA8AAB26A24F51UL;
    private const ulong FltSeed1 = 0x09BBB761A41BC44DUL;

    // Dirent constants.
    private const int DirentHeaderSize = 16;
    private const int DirentMaxSize = 280;

    /// <summary>
    /// Build the plaintext outer-PFS image for the ordered outer <paramref name="files"/>
    /// (assembled + signed, not encrypted). Use <see cref="Encrypt"/> to encrypt in place.
    /// </summary>
    public static OuterPfsBuildResult BuildPlaintext(
        IReadOnlyList<OuterPfsFile> files, OuterPfsBuildParameters parameters,
        IProgress<ProsperoBuildProgress>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(parameters);
        if (files.Count == 0)
            throw new ArgumentException("At least one outer file is required.", nameof(files));

        // ---- 1. Plan the block layout (data-first). ----
        int dataBlockTotal = 0;
        var fileFirstBlock = new int[files.Count];
        var fileBlockCount = new int[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            OuterPfsFile f = files[i];
            ArgumentNullException.ThrowIfNull(f);
            int blocks = Math.Max(1, (f.Data.Length + BlockSize - 1) / BlockSize);
            fileFirstBlock[i] = dataBlockTotal;
            fileBlockCount[i] = blocks;
            dataBlockTotal += blocks;
        }

        int superblockIndex = dataBlockTotal;
        int inodeTableIndex = dataBlockTotal + 1;
        int superRootDirentIndex = dataBlockTotal + 2;
        int fltIndex = dataBlockTotal + 3;

        // Files spanning more than 12 blocks use a 5-level indirect tree laid out after the FLT,
        // before the uroot dirents. Each tree block holds BlockSize/36 {sig, block} entries.
        var filePlans = new List<IndirectPlan>[files.Count];
        int indirectRegionStart = fltIndex + 1;
        int nextBlock = indirectRegionStart;
        int indirectBlocksTotal = 0;
        for (int i = 0; i < files.Count; i++)
            filePlans[i] = PlanIndirectTree(files[i].Name, fileBlockCount[i], ref nextBlock, ref indirectBlocksTotal);

        int urootDirentIndex = nextBlock;
        int totalBlocks = urootDirentIndex + 1;
        if ((long)totalBlocks * BlockSize > Array.MaxLength)
            throw new NotSupportedException(
                $"The outer image ({(long)totalBlocks * BlockSize} bytes) exceeds the in-memory array limit.");

        var image = new byte[(long)totalBlocks * BlockSize];

        // ---- 2. Lay out file data blocks. ----
        for (int i = 0; i < files.Count; i++)
        {
            byte[] data = files[i].Data;
            Buffer.BlockCopy(data, 0, image, fileFirstBlock[i] * BlockSize, data.Length);
            progress?.Report(new ProsperoBuildProgress("Outer PFS", i + 1, files.Count));
        }

        // ---- 3. Build the structural metadata blocks. ----
        BuildSuperRootDirents(image.AsSpan(superRootDirentIndex * BlockSize, BlockSize));
        BuildFlatPathTable(image.AsSpan(fltIndex * BlockSize, BlockSize), files);
        BuildUrootDirents(image.AsSpan(urootDirentIndex * BlockSize, BlockSize), files);

        // ---- 4. Build the inode table with per-block SHA3 hashes. ----
        BuildInodeTable(
            image, inodeTableIndex, parameters, files,
            fileFirstBlock, fileBlockCount, filePlans,
            superRootDirentIndex, fltIndex, urootDirentIndex);

        // ---- 5. Build the superblock (root inode-sig + seed + ICV). ----
        byte[] inodeTableHash = Sha3.Sha3_256(image.AsSpan(inodeTableIndex * BlockSize, BlockSize));
        BuildSuperblock(
            image.AsSpan(superblockIndex * BlockSize, BlockSize),
            parameters, files.Count, totalBlocks, inodeTableIndex, inodeTableHash);

        // ---- 6. Classify blocks for AES-XTS. ----
        var kinds = new OuterBlockKind[totalBlocks];
        for (int i = 0; i < files.Count; i++)
        {
            OuterBlockKind kind = files[i].Signed ? OuterBlockKind.Signed : OuterBlockKind.Data;
            for (int j = 0; j < fileBlockCount[i]; j++)
                kinds[fileFirstBlock[i] + j] = kind;
        }
        kinds[superblockIndex] = OuterBlockKind.Plaintext;
        kinds[inodeTableIndex] = OuterBlockKind.Signed;
        kinds[superRootDirentIndex] = OuterBlockKind.Signed;
        kinds[fltIndex] = OuterBlockKind.Signed;
        foreach (List<IndirectPlan> plans in filePlans)
            foreach (IndirectPlan plan in plans)
                MarkTreeSigned(plan.Root, kinds);
        kinds[urootDirentIndex] = OuterBlockKind.Signed;

        return new OuterPfsBuildResult
        {
            Plaintext = image,
            BlockKinds = kinds,
            SuperblockIndex = superblockIndex,
            FileFirstBlock = fileFirstBlock,
            FileBlockCount = fileBlockCount,
            InodeTableIndex = inodeTableIndex,
            SuperRootDirentIndex = superRootDirentIndex,
            FltIndex = fltIndex,
            UrootDirentIndex = urootDirentIndex,
        };
    }

    /// <summary>Encrypt (or decrypt) the built image in place using the given XTS key pair.</summary>
    public static void Encrypt(
        OuterPfsBuildResult build, ReadOnlySpan<byte> tweakKey, ReadOnlySpan<byte> dataKey, bool encrypt = true,
        IProgress<ProsperoBuildProgress>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(build);
        using var xts = new AesXts(dataKey, tweakKey);
        for (int i = 0; i < build.BlockCount; i++)
        {
            OuterBlockKind kind = build.BlockKinds[i];
            if (kind == OuterBlockKind.Plaintext)
            {
                progress?.Report(new ProsperoBuildProgress("Encrypt", i + 1, build.BlockCount));
                continue;
            }
            int offset = i * BlockSize;
            ulong sector = kind == OuterBlockKind.Signed
                ? ((ulong)(uint)i | SignedSectorFlag)
                : (ulong)(uint)i;
            byte[] block = build.Plaintext.AsSpan(offset, BlockSize).ToArray();
            byte[] transformed = encrypt ? xts.Encrypt(block, sector) : xts.Decrypt(block, sector);
            transformed.CopyTo(build.Plaintext, offset);
            progress?.Report(new ProsperoBuildProgress("Encrypt", i + 1, build.BlockCount));
        }
    }

    /// <summary>
    /// Convenience: build the plaintext image and encrypt it with keys derived from the package
    /// <paramref name="contentId"/> + <paramref name="passcode"/> and the build seed, returning
    /// the final on-disk ciphertext image.
    /// </summary>
    public static byte[] BuildEncrypted(
        IReadOnlyList<OuterPfsFile> files, OuterPfsBuildParameters parameters,
        string contentId, string passcode)
    {
        ArgumentNullException.ThrowIfNull(parameters);
        if (parameters.Seed is not { Length: 16 })
            throw new ArgumentException("A 16-byte build seed is required to encrypt the image.", nameof(parameters));

        OuterPfsBuildResult build = BuildPlaintext(files, parameters);
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(contentId, passcode);
        var (tweak, data) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, parameters.Seed);
        Encrypt(build, tweak, data);
        return build.Plaintext;
    }

    /// <summary>
    /// Streamed outer-PFS builder for arbitrarily large outer files. Source bytes are read from
    /// <see cref="OuterPfsFileSource.Path"/> and the assembled image is written to
    /// <paramref name="outputPath"/>; peak managed memory is bounded by one 64 KiB block plus the
    /// metadata region (superblock, inode table, dirents, indirect blocks), so images above 2 GiB
    /// are supported. Per-block SHA3 digests are returned for the container imagedigs table.
    /// </summary>
    public static OuterPfsFileBuildResult BuildForPackageToFile(
        IReadOnlyList<OuterPfsFileSource> files, OuterPfsBuildParameters parameters,
        string outputPath, bool encryptOutput, ReadOnlySpan<byte> tweakKey, ReadOnlySpan<byte> dataKey,
        IProgress<ProsperoBuildProgress>? progress = null)
    {
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(parameters);
        if (files.Count == 0)
            throw new ArgumentException("At least one outer file is required.", nameof(files));

        string full = Path.GetFullPath(outputPath);
        Directory.CreateDirectory(Path.GetDirectoryName(full) ?? Directory.GetCurrentDirectory());

        // ---- 1. Plan the block layout (data-first). ----
        var fileLengths = new long[files.Count];
        int dataBlockTotal = 0;
        var fileFirstBlock = new int[files.Count];
        var fileBlockCount = new int[files.Count];
        for (int i = 0; i < files.Count; i++)
        {
            OuterPfsFileSource f = files[i];
            ArgumentNullException.ThrowIfNull(f);
            long len = new FileInfo(f.Path).Length;
            fileLengths[i] = len;
            long blocks = Math.Max(1, (len + BlockSize - 1) / BlockSize);
            if (blocks > int.MaxValue)
                throw new NotSupportedException($"Outer file '{f.Name}' spans {blocks} blocks.");
            fileFirstBlock[i] = dataBlockTotal;
            fileBlockCount[i] = (int)blocks;
            dataBlockTotal += (int)blocks;
        }

        int superblockIndex = dataBlockTotal;
        int inodeTableIndex = dataBlockTotal + 1;
        int superRootDirentIndex = dataBlockTotal + 2;
        int fltIndex = dataBlockTotal + 3;

        var filePlans = new List<IndirectPlan>[files.Count];
        int indirectRegionStart = fltIndex + 1;
        int nextBlock = indirectRegionStart;
        int indirectBlocksTotal = 0;
        for (int i = 0; i < files.Count; i++)
            filePlans[i] = PlanIndirectTree(files[i].Name, fileBlockCount[i], ref nextBlock, ref indirectBlocksTotal);

        int urootDirentIndex = nextBlock;
        int totalBlocks = urootDirentIndex + 1;
        long imageLength = (long)totalBlocks * BlockSize;
        if (totalBlocks > Array.MaxLength / 32)
            throw new NotSupportedException($"The outer image digest table for {totalBlocks} blocks is too large.");

        var imageDigests = new byte[totalBlocks * 32];

        // ---- 2. Hash every data block, parallelising the SHA3 work. ----
        int parallelism = parameters.BlockParallelism <= 0
            ? Environment.ProcessorCount
            : Math.Clamp(parameters.BlockParallelism, 1, 256);
        HashDataBlocks(files, fileFirstBlock, fileBlockCount, imageDigests, parallelism);

        // ---- 3. Structural metadata blocks (in memory). ----
        byte[] superRootBlock = new byte[BlockSize];
        BuildSuperRootDirents(superRootBlock);
        Sha3.Sha3_256(superRootBlock).CopyTo(imageDigests, superRootDirentIndex * 32);

        byte[] fltBlock = new byte[BlockSize];
        BuildFlatPathTableFromNames(fltBlock, files.Select(f => f.Name).ToArray());
        Sha3.Sha3_256(fltBlock).CopyTo(imageDigests, fltIndex * 32);

        byte[] urootBlock = new byte[BlockSize];
        BuildUrootDirentsFromNames(urootBlock, files.Select(f => f.Name).ToArray());
        Sha3.Sha3_256(urootBlock).CopyTo(imageDigests, urootDirentIndex * 32);

        // Indirect tree blocks are serialized leaf-first; each block's plaintext SHA3 is recorded
        // in the digest table (the data-block SHA3s were captured above).
        byte[]? indirectRegion = indirectBlocksTotal > 0
            ? new byte[checked(indirectBlocksTotal * BlockSize)] : null;
        if (indirectRegion is not null)
        {
            for (int i = 0; i < files.Count; i++)
            {
                int firstBlock = fileFirstBlock[i];
                foreach (IndirectPlan plan in filePlans[i])
                {
                    SerializeIndirectNode(plan.Root, firstBlock,
                        dataBlock => imageDigests.AsSpan(dataBlock * 32, 32).ToArray(),
                        (blockIndex, bytes) => bytes.CopyTo(indirectRegion.AsSpan((blockIndex - indirectRegionStart) * BlockSize)),
                        recordDigest: (blockIndex, hash) => hash.CopyTo(imageDigests, blockIndex * 32));
                }
            }
        }

        // Inode table (data + indirect signatures).
        byte[] inodeTable = new byte[BlockSize];
        BuildInodeTableFromHashes(inodeTable, parameters, files, fileLengths, imageDigests,
            fileFirstBlock, fileBlockCount, filePlans,
            superRootDirentIndex, fltIndex, urootDirentIndex);
        Sha3.Sha3_256(inodeTable).CopyTo(imageDigests, inodeTableIndex * 32);

        // Superblock (plaintext).
        byte[] superblock = new byte[BlockSize];
        BuildSuperblock(superblock, parameters, files.Count, totalBlocks, inodeTableIndex,
            imageDigests.AsSpan(inodeTableIndex * 32, 32).ToArray());
        Sha3.Sha3_256(superblock).CopyTo(imageDigests, superblockIndex * 32);
        byte[] icv = ComputeSuperblockIcv(superblock);

        // ---- 4. Classify blocks for AES-XTS. ----
        var kinds = new OuterBlockKind[totalBlocks];
        for (int i = 0; i < files.Count; i++)
        {
            OuterBlockKind kind = files[i].Signed ? OuterBlockKind.Signed : OuterBlockKind.Data;
            for (int j = 0; j < fileBlockCount[i]; j++)
                kinds[fileFirstBlock[i] + j] = kind;
        }
        kinds[superblockIndex] = OuterBlockKind.Plaintext;
        kinds[inodeTableIndex] = OuterBlockKind.Signed;
        kinds[superRootDirentIndex] = OuterBlockKind.Signed;
        kinds[fltIndex] = OuterBlockKind.Signed;
        for (int b = 0; b < indirectBlocksTotal; b++)
            kinds[indirectRegionStart + b] = OuterBlockKind.Signed;
        kinds[urootDirentIndex] = OuterBlockKind.Signed;

        // ---- 5. Write the image, encrypting data + metadata blocks. ----
        using (var outFs = new FileStream(full, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20, FileOptions.SequentialScan))
        using (var xts = encryptOutput ? new AesXts(dataKey, tweakKey) : null)
        {
            outFs.SetLength(imageLength);
            WriteDataBlocks(outFs, files, fileFirstBlock, fileBlockCount, dataBlockTotal,
                encryptOutput, tweakKey, dataKey, parallelism, progress);

            WriteBlock(outFs, superblockIndex, superblock, OuterBlockKind.Plaintext, encryptOutput, xts);
            WriteBlock(outFs, inodeTableIndex, inodeTable, OuterBlockKind.Signed, encryptOutput, xts);
            WriteBlock(outFs, superRootDirentIndex, superRootBlock, OuterBlockKind.Signed, encryptOutput, xts);
            WriteBlock(outFs, fltIndex, fltBlock, OuterBlockKind.Signed, encryptOutput, xts);
            for (int b = 0; b < indirectBlocksTotal; b++)
            {
                byte[] ib = indirectRegion!.AsSpan(b * BlockSize, BlockSize).ToArray();
                WriteBlock(outFs, indirectRegionStart + b, ib, OuterBlockKind.Signed, encryptOutput, xts);
            }
            WriteBlock(outFs, urootDirentIndex, urootBlock, OuterBlockKind.Signed, encryptOutput, xts);
            outFs.Flush();
        }

        return new OuterPfsFileBuildResult
        {
            ImagePath = full,
            ImageLength = imageLength,
            BlockKinds = kinds,
            SuperblockIndex = superblockIndex,
            FileFirstBlock = fileFirstBlock,
            FileBlockCount = fileBlockCount,
            InodeTableIndex = inodeTableIndex,
            SuperRootDirentIndex = superRootDirentIndex,
            FltIndex = fltIndex,
            UrootDirentIndex = urootDirentIndex,
            ImageDigests = imageDigests,
            SuperblockIcv = icv,
            SuperblockPlaintext = superblock,
        };
    }

    /// <summary>Encrypts one block for its kind and returns the ciphertext (Data/Signed only).</summary>
    /// <summary>
    /// Records SHA3-256 of every plaintext data block into <paramref name="imageDigests"/>. Reads each
    /// source sequentially and hashes a small window of blocks concurrently; the digest table is
    /// independent of the thread count.
    /// </summary>
    private static void HashDataBlocks(
        IReadOnlyList<OuterPfsFileSource> files, int[] fileFirstBlock, int[] fileBlockCount,
        byte[] imageDigests, int parallelism)
    {
        byte[] block = new byte[BlockSize];
        if (parallelism <= 1)
        {
            for (int i = 0; i < files.Count; i++)
            {
                using var src = new FileStream(files[i].Path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
                for (int j = 0; j < fileBlockCount[i]; j++)
                {
                    int read = ReadBlock(src, block);
                    if (read < BlockSize)
                        block.AsSpan(read).Clear();
                    Sha3.Sha3_256(block).CopyTo(imageDigests, (fileFirstBlock[i] + j) * 32);
                }
            }
            return;
        }

        int window = Math.Max(parallelism, 8);
        byte[][] buffers = new byte[window][];
        for (int k = 0; k < window; k++)
            buffers[k] = new byte[BlockSize];
        var options = new ParallelOptions { MaxDegreeOfParallelism = parallelism };
        for (int i = 0; i < files.Count; i++)
        {
            using var src = new FileStream(files[i].Path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
            for (int start = 0; start < fileBlockCount[i]; start += window)
            {
                int count = Math.Min(window, fileBlockCount[i] - start);
                for (int k = 0; k < count; k++)
                {
                    int read = ReadBlock(src, buffers[k]);
                    if (read < BlockSize)
                        buffers[k].AsSpan(read).Clear();
                }
                int baseIndex = fileFirstBlock[i] + start;
                Parallel.For(0, count, options, k =>
                    Sha3.Sha3_256(buffers[k]).CopyTo(imageDigests, (baseIndex + k) * 32));
            }
        }
    }

    /// <summary>
    /// Writes the file-data blocks at their planned offsets, encrypting signed/data blocks with
    /// AES-XTS. Reading and writing are sequential; the AES-XTS work runs concurrently over a bounded
    /// window, so peak memory stays at a few blocks and the bytes are identical to a serial write.
    /// </summary>
    private static void WriteDataBlocks(
        FileStream outFs, IReadOnlyList<OuterPfsFileSource> files,
        int[] fileFirstBlock, int[] fileBlockCount, int dataBlockTotal,
        bool encryptOutput, ReadOnlySpan<byte> tweakKey, ReadOnlySpan<byte> dataKey,
        int parallelism, IProgress<ProsperoBuildProgress>? progress)
    {
        int processedBlocks = 0;
        if (parallelism <= 1 || !encryptOutput)
        {
            byte[] block = new byte[BlockSize];
            for (int i = 0; i < files.Count; i++)
            {
                OuterBlockKind kind = files[i].Signed ? OuterBlockKind.Signed : OuterBlockKind.Data;
                outFs.Position = (long)fileFirstBlock[i] * BlockSize;
                using var src = new FileStream(files[i].Path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
                using var xts = encryptOutput ? new AesXts(dataKey, tweakKey) : null;
                for (int j = 0; j < fileBlockCount[i]; j++)
                {
                    int blockIndex = fileFirstBlock[i] + j;
                    int read = ReadBlock(src, block);
                    if (read < BlockSize)
                        block.AsSpan(read).Clear();
                    if (encryptOutput)
                        block = ApplyXts(xts!, block, kind, blockIndex);
                    outFs.Write(block, 0, BlockSize);
                    progress?.Report(new ProsperoBuildProgress("Outer PFS", ++processedBlocks, dataBlockTotal));
                }
            }
            return;
        }

        byte[] tweak = tweakKey.ToArray();
        byte[] data = dataKey.ToArray();
        int window = Math.Max(parallelism, 8);
        byte[][] buffers = new byte[window][];
        for (int k = 0; k < window; k++)
            buffers[k] = new byte[BlockSize];
        var options = new ParallelOptions { MaxDegreeOfParallelism = parallelism };
        for (int i = 0; i < files.Count; i++)
        {
            OuterBlockKind kind = files[i].Signed ? OuterBlockKind.Signed : OuterBlockKind.Data;
            using var src = new FileStream(files[i].Path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20, FileOptions.SequentialScan);
            for (int start = 0; start < fileBlockCount[i]; start += window)
            {
                int count = Math.Min(window, fileBlockCount[i] - start);
                for (int k = 0; k < count; k++)
                {
                    int read = ReadBlock(src, buffers[k]);
                    if (read < BlockSize)
                        buffers[k].AsSpan(read).Clear();
                }
                int baseIndex = fileFirstBlock[i] + start;
                Parallel.For(0, count, options,
                    () => new AesXts(data, tweak),
                    (k, _, local) =>
                    {
                        buffers[k] = ApplyXts(local, buffers[k], kind, baseIndex + k);
                        return local;
                    },
                    local => local.Dispose());
                outFs.Position = (long)baseIndex * BlockSize;
                for (int k = 0; k < count; k++)
                    outFs.Write(buffers[k], 0, BlockSize);
                processedBlocks += count;
                progress?.Report(new ProsperoBuildProgress("Outer PFS", processedBlocks, dataBlockTotal));
            }
        }
    }

    private static byte[] ApplyXts(AesXts xts, byte[] plaintext, OuterBlockKind kind, int blockIndex)
    {
        ulong sector = kind == OuterBlockKind.Signed
            ? ((ulong)(uint)blockIndex | SignedSectorFlag)
            : (ulong)(uint)blockIndex;
        return xts.Encrypt(plaintext, sector);
    }

    private static void WriteBlock(FileStream fs, int blockIndex, byte[] plaintext,
        OuterBlockKind kind, bool encryptOutput, AesXts? xts)
    {
        fs.Position = (long)blockIndex * BlockSize;
        if (encryptOutput && kind != OuterBlockKind.Plaintext)
        {
            byte[] cipher = kind == OuterBlockKind.Signed
                ? ApplyXts(xts!, plaintext, kind, blockIndex)
                : xts!.Encrypt(plaintext, (ulong)(uint)blockIndex);
            fs.Write(cipher, 0, cipher.Length);
        }
        else
        {
            fs.Write(plaintext, 0, plaintext.Length);
        }
    }

    private static int ReadBlock(Stream stream, byte[] buffer)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = stream.Read(buffer, total, buffer.Length - total);
            if (n <= 0) break;
            total += n;
        }
        return total;
    }

    private static void BuildFlatPathTableFromNames(Span<byte> block, IReadOnlyList<string> names)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x00..], FltVersion);
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x04..], FltHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x08..], FltDataOffset);
        FltMagic.CopyTo(block[0x20..]);
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x2C..], (uint)names.Count);
        BinaryPrimitives.WriteUInt64LittleEndian(block[0x30..], FltSeed0);
        BinaryPrimitives.WriteUInt64LittleEndian(block[0x38..], FltSeed1);
        int off = (int)FltDataOffset;
        for (int i = 0; i < names.Count; i++)
        {
            ulong packed = (ulong)(uint)(MetadataInodeCount + i) | ((ulong)(uint)i << 40);
            BinaryPrimitives.WriteUInt64LittleEndian(block[off..], FltPathHash(names[i]));
            BinaryPrimitives.WriteUInt64LittleEndian(block[(off + 8)..], packed);
            off += 16;
        }
    }

    private static void BuildUrootDirentsFromNames(Span<byte> block, IReadOnlyList<string> names)
    {
        int pos = 0;
        pos = WriteDirent(block, pos, inode: 2, type: DirentTypeDot, ".");
        pos = WriteDirent(block, pos, inode: 2, type: DirentTypeDotDot, "..");
        for (int i = 0; i < names.Count; i++)
            pos = WriteDirent(block, pos, inode: (uint)(MetadataInodeCount + i), type: DirentTypeFile, names[i]);
    }

    private static void BuildInodeTableFromHashes(
        byte[] inodeTable, OuterPfsBuildParameters p, IReadOnlyList<OuterPfsFileSource> files, long[] fileLengths,
        byte[] imageDigests, int[] fileFirstBlock, int[] fileBlockCount, List<IndirectPlan>[] filePlans,
        int superRootDirentIndex, int fltIndex, int urootDirentIndex)
    {
        Span<byte> inode = stackalloc byte[S32InodeSize];

        WriteHashInode(inode, inodeTable, imageDigests, p, 0, ModeDir, 1, FlagsInternalMeta, BlockSize, BlockSize, [superRootDirentIndex]);
        long fltSize = FltDataOffset + (long)files.Count * 16;
        WriteHashInode(inode, inodeTable, imageDigests, p, 1, ModeFile, 1, FlagsInternalMeta, fltSize, fltSize, [fltIndex]);
        WriteHashInode(inode, inodeTable, imageDigests, p, 2, ModeDir, 3, FlagsDir, BlockSize, BlockSize, [urootDirentIndex]);

        for (int i = 0; i < files.Count; i++)
        {
            int firstBlock = fileFirstBlock[i];
            int blockCount = fileBlockCount[i];
            inode.Clear();
            BinaryPrimitives.WriteUInt16LittleEndian(inode, ModeFile);
            BinaryPrimitives.WriteUInt16LittleEndian(inode[2..], 1);
            BinaryPrimitives.WriteUInt32LittleEndian(inode[4..], FlagsFile);
            BinaryPrimitives.WriteInt64LittleEndian(inode[8..], fileLengths[i]);
            BinaryPrimitives.WriteInt64LittleEndian(inode[16..], files[i].SizeCompressed ?? fileLengths[i]);
            StampInodeTimes(inode, p);
            BinaryPrimitives.WriteUInt32LittleEndian(inode[96..], (uint)blockCount);

            int directCount = Math.Min(blockCount, DirectBlockSlots);
            for (int j = 0; j < directCount; j++)
            {
                imageDigests.AsSpan((firstBlock + j) * 32, 32).CopyTo(inode[(S32DirectBlockOffset + j * BlockSig32Stride)..]);
                BinaryPrimitives.WriteInt32LittleEndian(inode[(S32DirectBlockOffset + j * BlockSig32Stride + 32)..], firstBlock + j);
            }

            foreach (IndirectPlan plan in filePlans[i])
            {
                imageDigests.AsSpan(plan.Root.BlockIndex * 32, 32).CopyTo(
                    inode[(S32IndirectBlockOffset + plan.InodeLevel * BlockSig32Stride)..]);
                BinaryPrimitives.WriteInt32LittleEndian(
                    inode[(S32IndirectBlockOffset + plan.InodeLevel * BlockSig32Stride + 32)..], plan.Root.BlockIndex);
            }

            inode.CopyTo(inodeTable.AsSpan((MetadataInodeCount + i) * S32InodeSize));
        }
    }

    // ------------------------------------------------------------------ indirect tree

    /// <summary>One node of a file's indirect tree; leaves point at data blocks, higher depths at children.</summary>
    private sealed class IndirectTreeNode
    {
        public int BlockIndex;
        public int Depth;
        public int FirstDataOffset;
        public int DataBlockCount;
        public readonly List<IndirectTreeNode> Children = [];
    }

    /// <summary>A planned root for one inode indirect-block level.</summary>
    private readonly record struct IndirectPlan(int InodeLevel, IndirectTreeNode Root);

    /// <summary>
    /// Plans the per-inode indirect tree for a file spanning more than <see cref="DirectBlockSlots"/>
    /// blocks, allocating block indices parent-first. Level <c>j</c> (depth <c>j+1</c>) addresses
    /// <c>IndirectEntriesPerBlock^(j+1)</c> data blocks; at most <see cref="IndirectLevelCount"/>
    /// levels are supported.
    /// </summary>
    private static List<IndirectPlan> PlanIndirectTree(
        string fileName, int fileBlockCount, ref int nextBlock, ref int indirectBlocksAllocated)
    {
        var plans = new List<IndirectPlan>();
        int excess = Math.Max(0, fileBlockCount - DirectBlockSlots);
        int firstDataOffset = DirectBlockSlots;
        for (int level = 0; level < IndirectLevelCount && excess > 0; level++)
        {
            int depth = level + 1;
            int take = (int)Math.Min(excess, Capacity(depth));
            IndirectTreeNode root = AllocateIndirectNode(depth, firstDataOffset, take, ref nextBlock, ref indirectBlocksAllocated);
            plans.Add(new IndirectPlan(level, root));
            firstDataOffset += take;
            excess -= take;
        }
        if (excess > 0)
        {
            long maxBlocks = DirectBlockSlots + TotalTreeCapacity();
            throw new NotSupportedException(
                $"Outer file '{fileName}' spans {fileBlockCount} blocks; one inode addresses at most " +
                $"{maxBlocks} blocks (~{maxBlocks * (long)BlockSize / (1024 * 1024)} MiB).");
        }
        return plans;
    }

    private static IndirectTreeNode AllocateIndirectNode(
        int depth, int firstDataOffset, int dataBlockCount, ref int nextBlock, ref int indirectBlocksAllocated)
    {
        var node = new IndirectTreeNode
        {
            BlockIndex = nextBlock++,
            Depth = depth,
            FirstDataOffset = firstDataOffset,
            DataBlockCount = dataBlockCount,
        };
        indirectBlocksAllocated++;
        if (depth > 1)
        {
            long childCapacity = Capacity(depth - 1);
            int remaining = dataBlockCount;
            int childOffset = firstDataOffset;
            while (remaining > 0)
            {
                int childTake = (int)Math.Min(remaining, childCapacity);
                node.Children.Add(AllocateIndirectNode(depth - 1, childOffset, childTake, ref nextBlock, ref indirectBlocksAllocated));
                childOffset += childTake;
                remaining -= childTake;
            }
        }
        return node;
    }

    /// <summary>Number of data-block entries addressable by a tree of the given depth, saturating at long.MaxValue.</summary>
    private static long Capacity(int depth)
    {
        long capacity = 1;
        for (int i = 0; i < depth; i++)
        {
            if (capacity > long.MaxValue / IndirectEntriesPerBlock)
                return long.MaxValue;
            capacity *= IndirectEntriesPerBlock;
        }
        return capacity;
    }

    private static long TotalTreeCapacity()
    {
        long total = 0;
        for (int depth = 1; depth <= IndirectLevelCount; depth++)
        {
            long capacity = Capacity(depth);
            if (total > long.MaxValue - capacity)
                return long.MaxValue;
            total += capacity;
        }
        return total;
    }

    /// <summary>
    /// Serializes one indirect node into its 64 KiB plaintext block, recursing children first. Leaf
    /// entries pair a data block's SHA3 (via <paramref name="dataBlockDigest"/>) with its index;
    /// higher nodes pair each child block's SHA3 with the child block index. The node's plaintext
    /// block is stored via <paramref name="store"/> and its SHA3 recorded via
    /// <paramref name="recordDigest"/>; the node's block SHA3 is returned.
    /// </summary>
    private static byte[] SerializeIndirectNode(
        IndirectTreeNode node, int fileFirstBlock,
        Func<int, byte[]> dataBlockDigest, Action<int, byte[]> store, Action<int, byte[]>? recordDigest)
    {
        var blockBytes = new byte[BlockSize];
        if (node.Depth == 1)
        {
            for (int i = 0; i < node.DataBlockCount; i++)
            {
                int dataBlock = fileFirstBlock + node.FirstDataOffset + i;
                dataBlockDigest(dataBlock).CopyTo(blockBytes.AsSpan(i * BlockSig32Stride));
                BinaryPrimitives.WriteInt32LittleEndian(blockBytes.AsSpan(i * BlockSig32Stride + 32), dataBlock);
            }
        }
        else
        {
            for (int j = 0; j < node.Children.Count; j++)
            {
                IndirectTreeNode child = node.Children[j];
                byte[] childHash = SerializeIndirectNode(child, fileFirstBlock, dataBlockDigest, store, recordDigest);
                childHash.CopyTo(blockBytes.AsSpan(j * BlockSig32Stride));
                BinaryPrimitives.WriteInt32LittleEndian(blockBytes.AsSpan(j * BlockSig32Stride + 32), child.BlockIndex);
            }
        }
        byte[] hash = Sha3.Sha3_256(blockBytes);
        recordDigest?.Invoke(node.BlockIndex, hash);
        store(node.BlockIndex, blockBytes);
        return hash;
    }

    private static void MarkTreeSigned(IndirectTreeNode node, OuterBlockKind[] kinds)
    {
        kinds[node.BlockIndex] = OuterBlockKind.Signed;
        foreach (IndirectTreeNode child in node.Children)
            MarkTreeSigned(child, kinds);
    }

    /// <summary>
    /// Walks one inode indirect tree and appends its data-block indices in order, stopping once
    /// <paramref name="maxEntries"/> entries have been collected (so partial leaves and internal
    /// nodes never contribute trailing zero entries). <paramref name="readBlock"/> must return the
    /// full 64 KiB plaintext block for a block index.
    /// </summary>
    public static void CollectIndirectTree(
        long rootBlock, int depth, int maxEntries, Func<long, byte[]> readBlock, List<int> output)
    {
        ArgumentNullException.ThrowIfNull(readBlock);
        ArgumentNullException.ThrowIfNull(output);
        if (depth < 1 || depth > TreeLevelCount)
            throw new InvalidDataException($"Outer indirect tree depth {depth} is out of range.");
        if (output.Count >= maxEntries)
            return;

        byte[] block = readBlock(rootBlock);
        if (block.Length < TreeEntriesPerBlock * TreeEntrySize)
            throw new InvalidDataException($"Outer indirect block {rootBlock} is truncated.");

        for (int i = 0; i < TreeEntriesPerBlock && output.Count < maxEntries; i++)
        {
            int child = BinaryPrimitives.ReadInt32LittleEndian(block.AsSpan(i * TreeEntrySize + 32, 4));
            if (depth == 1)
                output.Add(child);
            else if (child > 0)
                CollectIndirectTree(child, depth - 1, maxEntries, readBlock, output);
            else
                throw new InvalidDataException($"Outer indirect block {rootBlock} entry {i} has no child.");
        }
    }

    private static void WriteHashInode(
        Span<byte> inode, byte[] inodeTable, byte[] imageDigests, OuterPfsBuildParameters p,
        int inodeNumber, ushort mode, ushort nlink, uint flags, long size, long sizeCompressed, int[] ownedBlocks)
    {
        inode.Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(inode, mode);
        BinaryPrimitives.WriteUInt16LittleEndian(inode[2..], nlink);
        BinaryPrimitives.WriteUInt32LittleEndian(inode[4..], flags);
        BinaryPrimitives.WriteInt64LittleEndian(inode[8..], size);
        BinaryPrimitives.WriteInt64LittleEndian(inode[16..], sizeCompressed);
        StampInodeTimes(inode, p);
        BinaryPrimitives.WriteUInt32LittleEndian(inode[96..], (uint)ownedBlocks.Length);
        for (int j = 0; j < ownedBlocks.Length; j++)
        {
            imageDigests.AsSpan(ownedBlocks[j] * 32, 32).CopyTo(inode[(S32DirectBlockOffset + j * BlockSig32Stride)..]);
            BinaryPrimitives.WriteInt32LittleEndian(inode[(S32DirectBlockOffset + j * BlockSig32Stride + 32)..], ownedBlocks[j]);
        }
        inode.CopyTo(inodeTable.AsSpan(inodeNumber * S32InodeSize));
    }

    /// <summary>
    /// Compute the per-block digest table (one SHA3-256 per plaintext block) and the superblock
    /// ICV from a plaintext build, for the container-level imagedigs table.
    /// </summary>
    public static (byte[] ImageDigests, byte[] SuperblockIcv) ComputeImageDigests(OuterPfsBuildResult build)
    {
        ArgumentNullException.ThrowIfNull(build);
        var imageDigests = new byte[build.BlockCount * 32];
        for (int i = 0; i < build.BlockCount; i++)
            Sha3.Sha3_256(build.Plaintext.AsSpan(i * BlockSize, BlockSize))
                .CopyTo(imageDigests, i * 32);
        byte[] icv = ComputeSuperblockIcv(
            build.Plaintext.AsSpan(build.SuperblockIndex * BlockSize, BlockSize));
        return (imageDigests, icv);
    }

    // ------------------------------------------------------------------ structural blocks

    private static void BuildSuperRootDirents(Span<byte> block)
    {
        int pos = 0;
        pos = WriteDirent(block, pos, inode: 1, type: DirentTypeFile, FlatPathTableName);
        pos = WriteDirent(block, pos, inode: 2, type: DirentTypeDirectory, UrootName);
    }

    private static void BuildUrootDirents(Span<byte> block, IReadOnlyList<OuterPfsFile> files)
    {
        int pos = 0;
        pos = WriteDirent(block, pos, inode: 2, type: DirentTypeDot, ".");
        pos = WriteDirent(block, pos, inode: 2, type: DirentTypeDotDot, "..");
        for (int i = 0; i < files.Count; i++)
            pos = WriteDirent(block, pos, inode: (uint)(MetadataInodeCount + i), type: DirentTypeFile, files[i].Name);
    }

    private const int DirentTypeFile = 2;
    private const int DirentTypeDirectory = 3;
    private const int DirentTypeDot = 4;
    private const int DirentTypeDotDot = 5;

    private static int WriteDirent(Span<byte> block, int pos, uint inode, int type, string name)
    {
        byte[] nameBytes = Encoding.ASCII.GetBytes(name);
        int entSize = nameBytes.Length + 17;
        if (entSize % 8 != 0)
            entSize += 8 - entSize % 8;
        if (entSize > DirentMaxSize)
            throw new InvalidOperationException($"Dirent name '{name}' is too long.");

        BinaryPrimitives.WriteUInt32LittleEndian(block[pos..], inode);
        BinaryPrimitives.WriteInt32LittleEndian(block[(pos + 4)..], type);
        BinaryPrimitives.WriteInt32LittleEndian(block[(pos + 8)..], nameBytes.Length);
        BinaryPrimitives.WriteInt32LittleEndian(block[(pos + 12)..], entSize);
        nameBytes.CopyTo(block[(pos + 16)..]);
        return pos + entSize;
    }

    private static void BuildFlatPathTable(Span<byte> block, IReadOnlyList<OuterPfsFile> files)
    {
        // Header (16 bytes): ver, hdrSize, dataOff, reserved.
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x00..], FltVersion);
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x04..], FltHeaderSize);
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x08..], FltDataOffset);
        // Magic @0x20, count @0x2C, the two fixed seeds @0x30/@0x38.
        FltMagic.CopyTo(block[0x20..]);
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x2C..], (uint)files.Count);
        BinaryPrimitives.WriteUInt64LittleEndian(block[0x30..], FltSeed0);
        BinaryPrimitives.WriteUInt64LittleEndian(block[0x38..], FltSeed1);
        // One 16-byte entry per file: { u64 pathHash, u64 inode | fileOrdinal<<40 }.
        int off = (int)FltDataOffset;
        for (int i = 0; i < files.Count; i++)
        {
            ulong packed = (ulong)(uint)(MetadataInodeCount + i) | ((ulong)(uint)i << 40);
            BinaryPrimitives.WriteUInt64LittleEndian(block[off..], FltPathHash(files[i].Name));
            BinaryPrimitives.WriteUInt64LittleEndian(block[(off + 8)..], packed);
            off += 16;
        }
    }

    // ------------------------------------------------------------------ inode table + superblock

    private static void BuildInodeTable(
        byte[] image, int inodeTableIndex, OuterPfsBuildParameters p,
        IReadOnlyList<OuterPfsFile> files,
        int[] fileFirstBlock, int[] fileBlockCount, List<IndirectPlan>[] filePlans,
        int superRootDirentIndex, int fltIndex, int urootDirentIndex)
    {
        int inodeCount = MetadataInodeCount + files.Count;
        long tableBytes = (long)inodeCount * S32InodeSize;
        if (tableBytes > BlockSize)
            throw new NotSupportedException(
                $"{inodeCount} outer inodes ({tableBytes} bytes) exceed one {BlockSize}-byte inode block.");

        Span<byte> inode = stackalloc byte[S32InodeSize];

        // inode 0: super-root directory (owns the super-root dirent block).
        WriteS32Inode(
            image, inodeTableIndex, 0, p, ModeDir, nlink: 1, FlagsInternalMeta,
            size: BlockSize, sizeCompressed: BlockSize, blocks: 1, image, [superRootDirentIndex]);

        // inode 1: inode_flat_path_table file (owns the FLT block). Size = FLT content length.
        long fltSize = FltDataOffset + (long)files.Count * 16;
        WriteS32Inode(
            image, inodeTableIndex, 1, p, ModeFile, nlink: 1, FlagsInternalMeta,
            size: fltSize, sizeCompressed: fltSize, blocks: 1, image, [fltIndex]);

        // inode 2: uroot directory (owns the uroot dirent block).
        WriteS32Inode(
            image, inodeTableIndex, 2, p, ModeDir, nlink: 3, FlagsDir,
            size: BlockSize, sizeCompressed: BlockSize, blocks: 1, image, [urootDirentIndex]);

        // inode 3..: the outer files in order, each with per-block SHA3 signatures in db/ib.
        for (int i = 0; i < files.Count; i++)
        {
            OuterPfsFile f = files[i];
            int firstBlock = fileFirstBlock[i];
            int blockCount = fileBlockCount[i];

            inode.Clear();
            BinaryPrimitives.WriteUInt16LittleEndian(inode, ModeFile);
            BinaryPrimitives.WriteUInt16LittleEndian(inode[2..], 1);                    // nlink
            BinaryPrimitives.WriteUInt32LittleEndian(inode[4..], FlagsFile);
            BinaryPrimitives.WriteInt64LittleEndian(inode[8..], f.Data.Length);
            BinaryPrimitives.WriteInt64LittleEndian(inode[16..], f.SizeCompressed ?? f.Data.Length);
            StampInodeTimes(inode, p);
            BinaryPrimitives.WriteUInt32LittleEndian(inode[96..], (uint)blockCount);

            // Direct blocks (up to 12), each { SHA3(plaintext block), block index }.
            int directCount = Math.Min(blockCount, DirectBlockSlots);
            for (int j = 0; j < directCount; j++)
                WriteBlockSig32(inode, S32DirectBlockOffset + j * BlockSig32Stride,
                    Sha3.Sha3_256(image.AsSpan((firstBlock + j) * BlockSize, BlockSize)), firstBlock + j);

            // Spilled blocks are addressed by the per-inode indirect tree; ib[level] points at each
            // tree's root with the root block's SHA3.
            foreach (IndirectPlan plan in filePlans[i])
            {
                byte[] rootHash = SerializeIndirectNode(plan.Root, firstBlock,
                    dataBlock => Sha3.Sha3_256(image.AsSpan(dataBlock * BlockSize, BlockSize)),
                    (blockIndex, bytes) => bytes.CopyTo(image.AsSpan(blockIndex * BlockSize, BlockSize)),
                    recordDigest: null);
                WriteBlockSig32(inode, S32IndirectBlockOffset + plan.InodeLevel * BlockSig32Stride,
                    rootHash, plan.Root.BlockIndex);
            }

            inode.CopyTo(image.AsSpan((inodeTableIndex * BlockSize) + (MetadataInodeCount + i) * S32InodeSize, S32InodeSize));
        }
    }

    // Writes a metadata inode (super-root / FLT / uroot) with its owned-block signatures.
    private static void WriteS32Inode(
        byte[] image, int inodeTableIndex, int inodeNumber, OuterPfsBuildParameters p,
        ushort mode, ushort nlink, uint flags, long size, long sizeCompressed, int blocks,
        byte[] srcImage, int[] ownedBlocks)
    {
        Span<byte> inode = stackalloc byte[S32InodeSize];
        inode.Clear();
        BinaryPrimitives.WriteUInt16LittleEndian(inode, mode);
        BinaryPrimitives.WriteUInt16LittleEndian(inode[2..], nlink);
        BinaryPrimitives.WriteUInt32LittleEndian(inode[4..], flags);
        BinaryPrimitives.WriteInt64LittleEndian(inode[8..], size);
        BinaryPrimitives.WriteInt64LittleEndian(inode[16..], sizeCompressed);
        StampInodeTimes(inode, p);
        BinaryPrimitives.WriteUInt32LittleEndian(inode[96..], (uint)blocks);
        for (int j = 0; j < ownedBlocks.Length; j++)
            WriteBlockSig32(inode, S32DirectBlockOffset + j * BlockSig32Stride,
                Sha3.Sha3_256(srcImage.AsSpan(ownedBlocks[j] * BlockSize, BlockSize)), ownedBlocks[j]);
        inode.CopyTo(image.AsSpan((inodeTableIndex * BlockSize) + inodeNumber * S32InodeSize, S32InodeSize));
    }

    private static void StampInodeTimes(Span<byte> inode, OuterPfsBuildParameters p)
    {
        BinaryPrimitives.WriteInt64LittleEndian(inode[24..], p.TimestampSeconds);
        BinaryPrimitives.WriteInt64LittleEndian(inode[32..], p.TimestampSeconds);
        BinaryPrimitives.WriteInt64LittleEndian(inode[40..], p.TimestampSeconds);
        BinaryPrimitives.WriteInt64LittleEndian(inode[48..], p.TimestampSeconds);
        BinaryPrimitives.WriteUInt32LittleEndian(inode[56..], p.TimestampNanoseconds);
        BinaryPrimitives.WriteUInt32LittleEndian(inode[60..], p.TimestampNanoseconds);
        BinaryPrimitives.WriteUInt32LittleEndian(inode[64..], p.TimestampNanoseconds);
        BinaryPrimitives.WriteUInt32LittleEndian(inode[68..], p.TimestampNanoseconds);
    }

    private static void WriteBlockSig32(Span<byte> inode, int offset, byte[] sig, int block)
    {
        sig.CopyTo(inode[offset..]);
        BinaryPrimitives.WriteInt32LittleEndian(inode[(offset + 32)..], block);
    }

    private static void BuildSuperblock(
        Span<byte> block, OuterPfsBuildParameters p,
        int fileCount, int totalBlocks, int inodeTableIndex, byte[] inodeTableHash)
    {
        int ninodes = MetadataInodeCount + fileCount;
        block.Clear();

        // Header fields.
        BinaryPrimitives.WriteInt64LittleEndian(block[0x00..], SuperblockVersion);
        BinaryPrimitives.WriteInt64LittleEndian(block[0x08..], SuperblockMagic);
        // 0x10: id = 0.
        block[0x1A] = 1;                                          // ReadOnly
        BinaryPrimitives.WriteUInt16LittleEndian(block[0x1C..], 0x0D); // mode: signed|encrypted|unk
        BinaryPrimitives.WriteUInt32LittleEndian(block[0x20..], BlockSize);
        // 0x24: nbackup = 0.
        BinaryPrimitives.WriteInt64LittleEndian(block[0x28..], 1);           // NBlock = 1
        BinaryPrimitives.WriteInt64LittleEndian(block[0x30..], ninodes);     // DinodeCount
        BinaryPrimitives.WriteInt64LittleEndian(block[0x38..], totalBlocks); // Ndblock
        BinaryPrimitives.WriteInt64LittleEndian(block[0x40..], 1);           // DinodeBlockCount
        // 0x48: zero (i64).

        // Embedded S64 super-root inode-sig @0x50: db[0] = { SHA3(inode table), table block }.
        Span<byte> sig = block.Slice(SuperblockInodeSigOffset, S64InodeSize);
        BinaryPrimitives.WriteUInt16LittleEndian(sig, 0);        // mode = 0
        BinaryPrimitives.WriteUInt16LittleEndian(sig[2..], 1);   // nlink = 1
        // flags = 0
        BinaryPrimitives.WriteInt64LittleEndian(sig[8..], BlockSize);            // size
        BinaryPrimitives.WriteInt64LittleEndian(sig[16..], BlockSize);           // sizeCompressed
        StampS64Times(sig, p);
        BinaryPrimitives.WriteUInt32LittleEndian(sig[96..], 1);                  // blocks (u32 + 4 pad)
        inodeTableHash.CopyTo(sig[S64DirectBlockOffset..]);
        BinaryPrimitives.WriteInt64LittleEndian(
            sig[(S64DirectBlockOffset + 32)..], inodeTableIndex);

        // UnknownIndex @0x36C (1) and seed @0x370.
        BinaryPrimitives.WriteInt32LittleEndian(block[SuperblockUnknownIndexOffset..], 1);
        (p.Seed ?? new byte[16]).CopyTo(block[SuperblockSeedOffset..]);

        // ICV @0x380 = SHA3-256(block[0:0x5A0] with the ICV field zeroed).
        byte[] icv = ComputeSuperblockIcv(block);
        icv.CopyTo(block[SuperblockIcvOffset..]);
    }

    private static void StampS64Times(Span<byte> sig, OuterPfsBuildParameters p)
    {
        BinaryPrimitives.WriteInt64LittleEndian(sig[24..], p.TimestampSeconds);
        BinaryPrimitives.WriteInt64LittleEndian(sig[32..], p.TimestampSeconds);
        BinaryPrimitives.WriteInt64LittleEndian(sig[40..], p.TimestampSeconds);
        BinaryPrimitives.WriteInt64LittleEndian(sig[48..], p.TimestampSeconds);
        BinaryPrimitives.WriteUInt32LittleEndian(sig[56..], p.TimestampNanoseconds);
        BinaryPrimitives.WriteUInt32LittleEndian(sig[60..], p.TimestampNanoseconds);
        BinaryPrimitives.WriteUInt32LittleEndian(sig[64..], p.TimestampNanoseconds);
        BinaryPrimitives.WriteUInt32LittleEndian(sig[68..], p.TimestampNanoseconds);
    }

    // ------------------------------------------------------------------ FLT path hash

    private static ulong Rotl(ulong x, int n) => (x << n) | (x >> (64 - n));
    private static ulong Rotr(ulong x, int n) => (x >> n) | (x << (64 - n));

    /// <summary>
    /// The \x7fFLT path hash: a custom 3-lane reduced-Keccak permutation over the UPPERCASED
    /// ASCII file name with two fixed 64-bit seeds and round constant 0x8000000080008081.
    /// </summary>
    public static ulong FltPathHash(string name)
    {
        byte[] nm = new byte[name.Length];
        for (int i = 0; i < name.Length; i++)
        {
            char ch = name[i];
            if (ch is >= 'a' and <= 'z')
                ch = (char)(ch - 32);
            nm[i] = (byte)ch;
        }

        int n = nm.Length;
        ulong a = FltSeed0;
        ulong b = Rotl(FltSeed0, 11);
        ulong c = Rotl(FltSeed0, 23);
        ulong tail = 0;

        if (n != 0)
        {
            int nwords = (n - 1) >> 3;
            int pos = 0;
            for (int w = 0; w < nwords; w++)
            {
                ulong word = BinaryPrimitives.ReadUInt64LittleEndian(nm.AsSpan(pos, 8));
                a ^= word;
                ulong t18 = Rotr(Rotl(c ^ b, 5) ^ a, 11);
                ulong t12 = Rotl(Rotl(c ^ a, 17) ^ b, 11);
                ulong c2 = Rotr(Rotl(b ^ a, 1) ^ c, 5);
                a = (~t12 & c2) ^ t18 ^ FltRoundConstant;
                b = (~c2 & t18) ^ t12;
                c = (~t18 & t12) ^ c2;
                pos += 8;
            }
            int rem = ((n - 1) & 7) + 1;
            Span<byte> tb = stackalloc byte[8];
            tb.Clear();
            nm.AsSpan(pos, rem).CopyTo(tb);
            tail = BinaryPrimitives.ReadUInt64LittleEndian(tb);
        }

        ulong x16 = b, x11 = c, x6 = tail ^ a ^ FltSeed1;
        ulong u17 = Rotl(x11 ^ x16, 5) ^ x6;
        ulong u18 = Rotl(x11 ^ x6, 17) ^ x16;
        ulong x11b = Rotl(x16 ^ x6, 1) ^ x11;
        return (~Rotl(u18, 11) & Rotr(x11b, 5)) ^ Rotr(u17, 11) ^ FltRoundConstant;
    }

    /// <summary>Compute the superblock ICV: SHA3-256 over block[0:0x5A0] with the ICV field zeroed.</summary>
    public static byte[] ComputeSuperblockIcv(ReadOnlySpan<byte> superblock)
    {
        if (superblock.Length < SuperblockIcvCoverage)
            throw new ArgumentException("Superblock must be at least 0x5A0 bytes.", nameof(superblock));
        Span<byte> region = stackalloc byte[SuperblockIcvCoverage];
        superblock[..SuperblockIcvCoverage].CopyTo(region);
        region.Slice(SuperblockIcvOffset, SuperblockIcvLength).Clear();
        return Sha3.Sha3_256(region);
    }
}
