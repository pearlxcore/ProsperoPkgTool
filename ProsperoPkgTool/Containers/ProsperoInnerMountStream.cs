namespace ProsperoPkgTool.Containers;

/// <summary>
/// Seekable, read-only view of a reconstructed PS5 inner mount that decodes only the blocks a
/// reader actually touches. The inner image is a per-block stream (raw, Kraken, dedup alias, or
/// zero hole) whose geometry lives in the NAPS <c>CblockInfo</c> table; this class maps logical
/// mount offsets onto those blocks and decodes them on demand, so enumerating or extracting from
/// a multi-GB image never materializes the whole mount.
/// </summary>
public sealed class ProsperoInnerMountStream : Stream
{
    private readonly IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> _blocks;
    private readonly long _innerImageLength;
    private readonly Func<long, int, byte[]> _readInnerImage;
    private readonly long _length;

    private long _position;
    private int _cachedIndex = -1;
    private byte[]? _cachedBlock;

    public ProsperoInnerMountStream(
        IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks,
        long innerImageLength,
        Func<long, int, byte[]> readInnerImage)
    {
        ArgumentNullException.ThrowIfNull(blocks);
        ArgumentNullException.ThrowIfNull(readInnerImage);
        if (blocks.Count == 0)
            throw new ArgumentException("The inner image has no decodable blocks.", nameof(blocks));

        _blocks = blocks;
        _innerImageLength = innerImageLength;
        _readInnerImage = readInnerImage;
        _length = ProsperoPs5InnerImageReader.MountSize(blocks);
        if (_length <= 0)
            throw new InvalidDataException("The inner mount has no addressable bytes.");
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length => _length;

    public override long Position
    {
        get => _position;
        set => _position = value >= 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    }

    public override void Flush() { }
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    public override long Seek(long offset, SeekOrigin origin)
    {
        long target = origin switch
        {
            SeekOrigin.Begin => offset,
            SeekOrigin.Current => _position + offset,
            SeekOrigin.End => _length + offset,
            _ => throw new ArgumentOutOfRangeException(nameof(origin)),
        };
        if (target < 0)
            throw new IOException("Cannot seek before the start of the inner mount.");
        _position = target;
        return _position;
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        ArgumentNullException.ThrowIfNull(buffer);
        if (offset < 0 || count < 0 || offset + count > buffer.Length)
            throw new ArgumentOutOfRangeException(nameof(offset));

        long remaining = _length - _position;
        if (remaining <= 0 || count == 0)
            return 0;

        int wanted = (int)Math.Min(count, remaining);
        int written = 0;
        while (written < wanted)
        {
            long position = _position + written;
            int index = FindBlock(position);
            ProsperoPs5InnerImageReader.InnerBlock block = _blocks[index];
            int withinBlock = checked((int)(position - block.UncompressedOffset));
            int take = Math.Min(block.UncompressedLength - withinBlock, wanted - written);
            if (take <= 0)
                throw new InvalidDataException($"Inner mount offset 0x{position:X} maps to an empty NAPS block.");
            byte[] decoded = GetBlock(index);
            Array.Copy(decoded, withinBlock, buffer, offset + written, take);
            written += take;
        }
        _position += written;
        return written;
    }

    private int FindBlock(long position)
    {
        int low = 0;
        int high = _blocks.Count - 1;
        while (low <= high)
        {
            int mid = low + ((high - low) >> 1);
            ProsperoPs5InnerImageReader.InnerBlock block = _blocks[mid];
            if (position < block.UncompressedOffset)
                high = mid - 1;
            else if (position >= block.UncompressedOffset + block.UncompressedLength)
                low = mid + 1;
            else
                return mid;
        }
        throw new InvalidDataException($"Inner mount offset 0x{position:X} is not covered by any NAPS block.");
    }

    private byte[] GetBlock(int index)
    {
        if (_cachedIndex == index && _cachedBlock is not null)
            return _cachedBlock;
        _cachedBlock = ProsperoPs5InnerImageReader.DecodeBlock(_blocks, index, _readInnerImage, _innerImageLength);
        _cachedIndex = index;
        return _cachedBlock;
    }
}
