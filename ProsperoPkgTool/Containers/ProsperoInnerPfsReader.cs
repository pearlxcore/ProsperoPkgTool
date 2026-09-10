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
    private const long SuperblockMagic = 20130315;

    public sealed record Entry(string Path, bool IsDirectory, long LogicalOffset, long Size, uint Inode);

    public static IReadOnlyList<Entry> Enumerate(ReadOnlySpan<byte> mount)
    {
        int super = FindSuperblock(mount);
        int inodeCount = CheckedInt(BinaryPrimitives.ReadInt64LittleEndian(mount.Slice(super + 0x30, 8)), "inode count");
        if (inodeCount is < 1 or > 0x10000 || super + BlockSize + inodeCount * InodeSize > mount.Length)
            throw new InvalidDataException("Inner PFS inode table is outside the reconstructed mount.");

        var inodes = new Inode[inodeCount];
        for (int i = 0; i < inodes.Length; i++)
            inodes[i] = ReadInode(mount.Slice(super + BlockSize + i * InodeSize, InodeSize));

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
    public static IReadOnlyList<Entry> Enumerate(Stream mount)
    {
        ArgumentNullException.ThrowIfNull(mount);
        if (!mount.CanSeek)
            throw new ArgumentException("The inner mount stream must be seekable.", nameof(mount));

        long length = mount.Length;
        long super = FindSuperblock(mount, length);
        long inodeCountValue = ReadInt64(mount, super + 0x30);
        if (inodeCountValue is < 1 or > 0x10000)
            throw new InvalidDataException("Inner PFS inode table is outside the reconstructed mount.");
        int inodeCount = (int)inodeCountValue;
        long inodeTableOffset = super + BlockSize;
        if (inodeTableOffset + (long)inodeCount * InodeSize > length)
            throw new InvalidDataException("Inner PFS inode table is outside the reconstructed mount.");

        var inodes = new Inode[inodeCount];
        Span<byte> inodeBytes = stackalloc byte[InodeSize];
        for (int i = 0; i < inodeCount; i++)
        {
            mount.Position = inodeTableOffset + (long)i * InodeSize;
            mount.ReadExactly(inodeBytes);
            inodes[i] = ReadInode(inodeBytes);
        }

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

    private static long FindSuperblock(Stream mount, long length)
    {
        Span<byte> probe = stackalloc byte[0x28];
        for (long offset = 0; offset + BlockSize <= length; offset += BlockSize)
        {
            mount.Position = offset;
            mount.ReadExactly(probe);
            if (BinaryPrimitives.ReadInt64LittleEndian(probe[..8]) == 2 &&
                BinaryPrimitives.ReadInt64LittleEndian(probe.Slice(8, 8)) == SuperblockMagic &&
                BinaryPrimitives.ReadUInt32LittleEndian(probe.Slice(0x20, 4)) == BlockSize)
                return offset;
        }
        throw new InvalidDataException("No supported inner PFSv2 superblock was found in the reconstructed mount.");
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

    private static int CheckedInt(long value, string label) => value is < 0 or > int.MaxValue
        ? throw new InvalidDataException($"Inner PFS {label} is invalid.") : (int)value;

    private readonly record struct Inode(bool IsDirectory, long Size, ulong Offset)
    {
        public long LogicalOffset => Offset > long.MaxValue
            ? throw new InvalidDataException("Inner PFS offset is invalid.") : (long)Offset;
    }
}
