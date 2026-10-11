using System.Buffers.Binary;
using System.Text;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Clean-room reader for the inner PFSv2 metadata emitted by this project. It consumes the
/// already reconstructed mount, not an assembler snapshot, so list/extract verifies the bytes
/// that were actually packaged. The inode and dirent layout is independently documented by the
/// corresponding clean-room writer. Unsupported foreign layouts fail explicitly.
///
/// <para><see cref="Enumerate(ReadOnlySpan{byte})"/> and <see cref="Enumerate(Stream)"/> preserve
/// the on-disk directory record order (a pre-order walk: each child in dirent order, recursing
/// into a directory in place) rather than sorting by path. That is the order the reference
/// production reader (<c>SaveInnerFiles</c>/<c>GetAllFiles</c>) emits, so <c>img_file_list</c>
/// output matches it. Callers that need deterministic alphabetical order must sort themselves.</para>
/// </summary>
public static class ProsperoInnerPfsReader
{
    public const int BlockSize = 0x10000;
    private const int InodeSize = 0xA8;
    // The reference writer (and native layout) pack inodes at BlockSize/InodeSize per block, leaving
    // the remainder of each 64 KiB block unused. Inodes must NOT be read as one contiguous array.
    private const int InodesPerBlock = BlockSize / InodeSize;
    private const long SuperblockMagic = 20130315;

    public sealed record Entry(string Path, bool IsDirectory, long LogicalOffset, long Size, uint Inode);

    public static IReadOnlyList<Entry> Enumerate(ReadOnlySpan<byte> mount, bool repairTruncatedOffsets = false)
        => Enumerate(mount, repairTruncatedOffsets, out _);

    /// <summary>
    /// As <see cref="Enumerate(ReadOnlySpan{byte}, bool)"/>, also reporting whether truncated
    /// 64-bit directory offsets had to be reconstructed (<paramref name="repaired"/>).
    /// </summary>
    public static IReadOnlyList<Entry> Enumerate(ReadOnlySpan<byte> mount, bool repairTruncatedOffsets, out bool repaired)
    {
        int super = FindSuperblock(mount);
        int inodeCount = CheckedInt(BinaryPrimitives.ReadInt64LittleEndian(mount.Slice(super + 0x30, 8)), "inode count");
        if (inodeCount < 1)
            throw new InvalidDataException("Inner PFS inode count is invalid.");
        // The mount size is the only real bound: a bogus inodeCount simply cannot fit, so no arbitrary
        // ceiling is needed (any fixed cap would eventually reject a legitimate large title).
        long inodeTableEnd = super + BlockSize + InodeBlockCount(inodeCount) * BlockSize;
        if (inodeTableEnd > mount.Length)
            throw new InvalidDataException("Inner PFS inode table is outside the reconstructed mount.");

        var inodes = new Inode[inodeCount];
        for (int i = 0; i < inodes.Length; i++)
            inodes[i] = ReadInode(mount.Slice(InodeOffset(super, i), InodeSize));

        repaired = RepairOrThrowTruncated(inodes, super, (int)InodeBlockCount(inodeCount), mount.Length, repairTruncatedOffsets);

        var result = new List<Entry>();
        WalkDirectory(mount, inodes, 0, string.Empty, result, new HashSet<uint>());
        return result;
    }

    public static byte[] ReadFile(ReadOnlySpan<byte> mount, Entry entry)
    {
        if (entry.IsDirectory)
            throw new InvalidDataException($"'{entry.Path}' is a directory.");
        if (entry.LogicalOffset < 0 || entry.Size < 0 || entry.LogicalOffset > mount.Length || entry.Size > mount.Length - entry.LogicalOffset)
            throw new InvalidDataException($"Inner PFS file '{entry.Path}' lies outside the reconstructed mount.");
        return mount.Slice(checked((int)entry.LogicalOffset), checked((int)entry.Size)).ToArray();
    }

    /// <summary>
    /// File-backed counterpart of <see cref="Enumerate(ReadOnlySpan{byte})"/>: reads the inode
    /// table and directory records from a seekable mount stream with 64-bit offsets, so a
    /// multi-GB mount never has to be materialized as one <c>byte[]</c>.
    /// </summary>
    /// <param name="superblockHint">
    /// Optional logical mount offset of the inner superblock, when the caller already knows it
    /// (e.g. from the FIH metadata-base field). Supplying it avoids scanning — and therefore
    /// decoding — the whole image when <paramref name="mount"/> is a lazy
    /// <see cref="ProsperoInnerMountStream"/>. The hint is validated; when it is wrong or absent
    /// the reader falls back to a full scan, preserving correctness for foreign layouts.
    /// </param>
    public static IReadOnlyList<Entry> Enumerate(Stream mount, long superblockHint = -1, bool repairTruncatedOffsets = false)
        => Enumerate(mount, superblockHint, repairTruncatedOffsets, out _);

    /// <summary>
    /// As <see cref="Enumerate(Stream, long, bool)"/>, also reporting whether truncated 64-bit
    /// directory offsets had to be reconstructed (<paramref name="repaired"/>).
    /// </summary>
    public static IReadOnlyList<Entry> Enumerate(Stream mount, long superblockHint, bool repairTruncatedOffsets, out bool repaired)
    {
        ArgumentNullException.ThrowIfNull(mount);
        if (!mount.CanSeek)
            throw new ArgumentException("The inner mount stream must be seekable.", nameof(mount));

        long length = mount.Length;
        long super = FindSuperblock(mount, length, superblockHint);
        long inodeCountValue = ReadInt64(mount, super + 0x30);
        if (inodeCountValue is < 1 or > int.MaxValue)
            throw new InvalidDataException("Inner PFS inode count is invalid.");
        int inodeCount = (int)inodeCountValue;
        long inodeTableOffset = super + BlockSize;
        // See the span overload: the mount size is the real bound, not a fixed inode ceiling.
        if (inodeTableOffset + InodeBlockCount(inodeCount) * BlockSize > length)
            throw new InvalidDataException("Inner PFS inode table is outside the reconstructed mount.");

        var inodes = new Inode[inodeCount];
        Span<byte> inodeBytes = stackalloc byte[InodeSize];
        for (int i = 0; i < inodeCount; i++)
        {
            mount.Position = inodeTableOffset + (long)(i / InodesPerBlock) * BlockSize + (long)(i % InodesPerBlock) * InodeSize;
            mount.ReadExactly(inodeBytes);
            inodes[i] = ReadInode(inodeBytes);
        }

        repaired = RepairOrThrowTruncated(inodes, super, (int)InodeBlockCount(inodeCount), length, repairTruncatedOffsets);

        var result = new List<Entry>();
        WalkDirectory(mount, length, inodes, 0, string.Empty, result, new HashSet<uint>());
        return result;
    }

    /// <summary>Streams one inner-PFS file's bytes from a seekable mount to <paramref name="destination"/>.</summary>
    public static void ExtractFile(Stream mount, Entry entry, Stream destination)
    {
        ArgumentNullException.ThrowIfNull(mount);
        ArgumentNullException.ThrowIfNull(destination);
        if (entry.IsDirectory)
            throw new InvalidDataException($"'{entry.Path}' is a directory.");
        if (entry.LogicalOffset < 0 || entry.Size < 0 ||
            entry.LogicalOffset > mount.Length || entry.Size > mount.Length - entry.LogicalOffset)
            throw new InvalidDataException($"Inner PFS file '{entry.Path}' lies outside the reconstructed mount.");

        mount.Position = entry.LogicalOffset;
        byte[] buffer = new byte[1 << 20];
        long remaining = entry.Size;
        while (remaining > 0)
        {
            int take = (int)Math.Min(buffer.Length, remaining);
            int read = mount.Read(buffer, 0, take);
            if (read <= 0)
                throw new InvalidDataException($"Inner PFS file '{entry.Path}' ended before its declared size.");
            destination.Write(buffer, 0, read);
            remaining -= read;
        }
    }

    private static long FindSuperblock(Stream mount, long length, long hint)
    {
        Span<byte> probe = stackalloc byte[0x28];
        if (hint >= 0 && hint + BlockSize <= length && ProbeIsSuperblock(mount, hint, probe))
            return hint;
        for (long offset = 0; offset + BlockSize <= length; offset += BlockSize)
            if (ProbeIsSuperblock(mount, offset, probe))
                return offset;
        throw new InvalidDataException("No supported inner PFSv2 superblock was found in the reconstructed mount.");
    }

    private static bool ProbeIsSuperblock(Stream mount, long offset, Span<byte> probe)
    {
        mount.Position = offset;
        int read = 0;
        while (read < probe.Length)
        {
            int n = mount.Read(probe[read..]);
            if (n <= 0)
                return false;
            read += n;
        }
        return BinaryPrimitives.ReadInt64LittleEndian(probe[..8]) == 2 &&
            BinaryPrimitives.ReadInt64LittleEndian(probe.Slice(8, 8)) == SuperblockMagic &&
            BinaryPrimitives.ReadUInt32LittleEndian(probe.Slice(0x20, 4)) == BlockSize;
    }

    private static void WalkDirectory(Stream mount, long mountLength, Inode[] inodes, uint inodeIndex,
        string prefix, List<Entry> result, HashSet<uint> active)
    {
        if (inodeIndex >= inodes.Length)
            throw new InvalidDataException("Inner PFS directory references an invalid inode.");
        if (!active.Add(inodeIndex))
            throw new InvalidDataException("Inner PFS directory graph contains a cycle.");
        Inode dir = inodes[inodeIndex];
        if (!dir.IsDirectory)
            throw new InvalidDataException("Inner PFS directory entry points to a regular inode.");
        long dirOffset = dir.LogicalOffset;
        if (dirOffset < 0 || dir.Size < 0 || dirOffset > mountLength || dir.Size > mountLength - dirOffset)
            throw new InvalidDataException("Inner PFS directory bytes lie outside the reconstructed mount.");
        if (dir.Size > int.MaxValue)
            throw new InvalidDataException("Inner PFS directory is too large to enumerate.");
        byte[] data = new byte[(int)dir.Size];
        mount.Position = dirOffset;
        mount.ReadExactly(data);

        // Native order is files-first, then subdirectories, at each level (the reference reader's
        // LoadDir collects files inline and defers directories), so sibling files always precede a
        // subdirectory's contents. Mirror that here instead of a strict pre-order walk.
        var pending = new List<(uint Child, string Path)>();
        int offset = 0;
        while (offset + 16 <= data.Length)
        {
            uint child = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4));
            int type = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset + 4, 4));
            int nameLength = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset + 8, 4));
            int recordLength = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(offset + 12, 4));
            if (recordLength == 0) break; // writer zero-pads each 64-KiB directory block
            if (recordLength < 16 || recordLength > data.Length - offset || nameLength < 0 || nameLength > recordLength - 16)
                throw new InvalidDataException("Inner PFS directory record is malformed.");
            string name = Encoding.ASCII.GetString(data.AsSpan(offset + 16, nameLength));
            offset += recordLength;
            if (name is "." or "..") continue;
            if (name.Length == 0 || name.Contains('/') || child >= inodes.Length)
                throw new InvalidDataException("Inner PFS directory contains an invalid name or inode.");
            string path = prefix + "/" + name;
            Inode node = inodes[child];
            bool directory = type == 3;
            if (directory != node.IsDirectory)
                throw new InvalidDataException("Inner PFS dirent type disagrees with its inode.");
            if (directory)
                pending.Add((child, path));
            else
                result.Add(new Entry(path, false, node.LogicalOffset, node.Size, child));
        }
        foreach ((uint child, string path) in pending)
        {
            Inode node = inodes[child];
            result.Add(new Entry(path, true, node.LogicalOffset, node.Size, child));
            WalkDirectory(mount, mountLength, inodes, child, path, result, active);
        }
        active.Remove(inodeIndex);
    }

    private static long ReadInt64(Stream stream, long offset)
    {
        Span<byte> buffer = stackalloc byte[8];
        stream.Position = offset;
        stream.ReadExactly(buffer);
        return BinaryPrimitives.ReadInt64LittleEndian(buffer);
    }

    private static int FindSuperblock(ReadOnlySpan<byte> mount)
    {
        for (int offset = 0; offset + BlockSize <= mount.Length; offset += BlockSize)
        {
            if (BinaryPrimitives.ReadInt64LittleEndian(mount.Slice(offset, 8)) == 2 &&
                BinaryPrimitives.ReadInt64LittleEndian(mount.Slice(offset + 8, 8)) == SuperblockMagic &&
                BinaryPrimitives.ReadUInt32LittleEndian(mount.Slice(offset + 0x20, 4)) == BlockSize)
                return offset;
        }
        throw new InvalidDataException("No supported inner PFSv2 superblock was found in the reconstructed mount.");
    }

    private static void WalkDirectory(ReadOnlySpan<byte> mount, Inode[] inodes, uint inodeIndex,
        string prefix, List<Entry> result, HashSet<uint> active)
    {
        if (inodeIndex >= inodes.Length)
            throw new InvalidDataException("Inner PFS directory references an invalid inode.");
        if (!active.Add(inodeIndex))
            throw new InvalidDataException("Inner PFS directory graph contains a cycle.");
        Inode dir = inodes[inodeIndex];
        if (!dir.IsDirectory)
            throw new InvalidDataException("Inner PFS directory entry points to a regular inode.");
        if (dir.LogicalOffset > mount.Length || dir.Size > mount.Length - dir.LogicalOffset)
            throw new InvalidDataException("Inner PFS directory bytes lie outside the reconstructed mount.");

        ReadOnlySpan<byte> data = mount.Slice(checked((int)dir.LogicalOffset), checked((int)dir.Size));
        // Native order is files-first, then subdirectories, at each level (see the stream overload).
        var pending = new List<(uint Child, string Path)>();
        int offset = 0;
        while (offset + 16 <= data.Length)
        {
            uint child = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, 4));
            int type = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset + 4, 4));
            int nameLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset + 8, 4));
            int recordLength = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset + 12, 4));
            if (recordLength == 0) break; // writer zero-pads each 64-KiB directory block
            if (recordLength < 16 || recordLength > data.Length - offset || nameLength < 0 || nameLength > recordLength - 16)
                throw new InvalidDataException("Inner PFS directory record is malformed.");
            string name = Encoding.ASCII.GetString(data.Slice(offset + 16, nameLength));
            offset += recordLength;
            if (name is "." or "..") continue;
            if (name.Length == 0 || name.Contains('/') || child >= inodes.Length)
                throw new InvalidDataException("Inner PFS directory contains an invalid name or inode.");
            string path = prefix + "/" + name;
            Inode node = inodes[child];
            bool directory = type == 3;
            if (directory != node.IsDirectory)
                throw new InvalidDataException("Inner PFS dirent type disagrees with its inode.");
            if (directory)
                pending.Add((child, path));
            else
                result.Add(new Entry(path, false, node.LogicalOffset, node.Size, child));
        }
        foreach ((uint child, string path) in pending)
        {
            Inode node = inodes[child];
            result.Add(new Entry(path, true, node.LogicalOffset, node.Size, child));
            WalkDirectory(mount, inodes, child, path, result, active);
        }
        active.Remove(inodeIndex);
    }

    private static Inode ReadInode(ReadOnlySpan<byte> source) => new(
        BinaryPrimitives.ReadUInt16LittleEndian(source) is 0x416D or 0x4168,
        BinaryPrimitives.ReadInt64LittleEndian(source.Slice(8, 8)),
        BinaryPrimitives.ReadUInt64LittleEndian(source.Slice(0x60, 8)));

    private static long InodeBlockCount(int inodeCount) => ((long)inodeCount + InodesPerBlock - 1) / InodesPerBlock;

    private static int InodeOffset(int superblock, int index)
        => checked((int)(superblock + BlockSize + ((long)index / InodesPerBlock) * BlockSize + (long)(index % InodesPerBlock) * InodeSize));

    /// <summary>
    /// Handles packages whose 64-bit inode <c>DataOffset</c> was truncated to 32 bits. Every
    /// directory's content lives in the metadata region that follows the inode table, so once that
    /// region starts above 4 GiB a directory offset below it means the high dword was zeroed (a
    /// known generator bug). By default this throws a clear diagnostic; when <paramref name="repair"/>
    /// is set the high dword is reconstructed from the metadata region's 4 GiB window so the tree can
    /// be listed. Repair recovers directory offsets only - file <c>DataOffset</c> values in the data
    /// region may still be truncated, so it is not safe to extract from a repaired mount.
    /// </summary>
    /// <returns><see langword="true"/> when at least one directory offset was reconstructed.</returns>
    private static bool RepairOrThrowTruncated(Inode[] inodes, long superblock, int inodeBlockCount,
        long mountLength, bool repair)
    {
        long metadataStart = superblock + (long)(1 + inodeBlockCount) * BlockSize;
        if (metadataStart <= uint.MaxValue)
            return false;
        ulong high = (ulong)metadataStart & 0xFFFFFFFF00000000UL;
        bool repaired = false;
        for (int i = 0; i < inodes.Length; i++)
        {
            if (!inodes[i].IsDirectory)
                continue;
            ulong offset = inodes[i].Offset;
            if (offset >= (ulong)metadataStart)
                continue;
            if (!repair)
                throw new InvalidDataException(
                    $"Inner PFS inode {i} DataOffset 0x{offset:X} lies below the inner metadata region " +
                    $"0x{metadataStart:X}: the inode's 64-bit offset was truncated to 32 bits (offsets " +
                    ">= 4 GiB are lost). This package was produced by a generator with a 64-bit inode " +
                    "offset-write bug. Re-run img_file_list with --repair-offsets to reconstruct the " +
                    "directory offsets for listing.");
            ulong reconstructed = high | (offset & 0xFFFFFFFFUL);
            if (reconstructed < (ulong)metadataStart || reconstructed >= (ulong)mountLength)
                throw new InvalidDataException(
                    $"Inner PFS inode {i} DataOffset 0x{offset:X} cannot be repaired: the reconstructed " +
                    $"offset 0x{reconstructed:X} lies outside the inner metadata region.");
            inodes[i] = inodes[i] with { Offset = reconstructed };
            repaired = true;
        }
        return repaired;
    }

    private static int CheckedInt(long value, string label) => value is < 0 or > int.MaxValue
        ? throw new InvalidDataException($"Inner PFS {label} is invalid.") : (int)value;

    private readonly record struct Inode(bool IsDirectory, long Size, ulong Offset)
    {
        public long LogicalOffset => Offset > long.MaxValue
            ? throw new InvalidDataException("Inner PFS offset is invalid.") : (long)Offset;
    }
}
