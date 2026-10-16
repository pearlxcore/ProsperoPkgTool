namespace ProsperoPkgTool.Containers;

/// <summary>
/// Read-only view of a patch's reconstructed outer-PFS image that never materializes it. Every
/// 64 KiB virtual block is resolved through the SI relocation tables to its source block in either
/// the reference (base) package or the patch package and read from that file on demand, so a
/// multi-GB patched image costs no more memory than the relocation tables themselves.
/// </summary>
/// <remarks>
/// Destination <c>d</c> of the relocation tables is virtual block <c>d - 1</c>; destination 0
/// is the patched package's FIH and never part of the outer PFS. Each destination must name exactly
/// one source: an inherited block (<c>Origin</c>) is a 64 KiB block of the reference package file,
/// a gathered block (<c>Gathered</c>) is a 64 KiB block of the patch package file. Both are
/// addressed by file block, not by PFS block, exactly as
/// <see cref="ProsperoPatchRelocation.MaterializeEncryptedVirtualImage"/> addresses them.
/// </remarks>
public sealed class ProsperoPatchVirtualStream : Stream
{
    private const int BlockSize = 0x10000;
    private const uint Missing = uint.MaxValue;

    private readonly FileStream _patch;
    private readonly FileStream _reference;
    private readonly ProsperoPatchRelocation.Tables _tables;
    private long _position;

    private ProsperoPatchVirtualStream(FileStream patch, FileStream reference, ProsperoPatchRelocation.Tables tables)
    {
        _patch = patch;
        _reference = reference;
        _tables = tables;
        Length = (tables.Count - 1) * (long)BlockSize;
    }

    /// <summary>
    /// Open the patch's virtual image over the patch and reference package files. The relocation
    /// tables are validated up front so a malformed table fails here rather than mid-read.
    /// </summary>
    public static ProsperoPatchVirtualStream Open(string patchPath, string referencePath, ProsperoPatchRelocation.Tables tables)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(patchPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(referencePath);
        ArgumentNullException.ThrowIfNull(tables);
        if (tables.Count < 2)
            throw new InvalidDataException("Patch relocation table contains no virtual PFS blocks.");

        var patch = new FileStream(Path.GetFullPath(patchPath), FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.RandomAccess);
        try
        {
            var reference = new FileStream(Path.GetFullPath(referencePath), FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 16, FileOptions.RandomAccess);
            try
            {
                Validate(tables, patch.Length, reference.Length);
                return new ProsperoPatchVirtualStream(patch, reference, tables);
            }
            catch
            {
                reference.Dispose();
                throw;
            }
        }
        catch
        {
            patch.Dispose();
            throw;
        }
    }

    private static void Validate(ProsperoPatchRelocation.Tables tables, long patchLength, long referenceLength)
    {
        for (int destination = 1; destination < tables.Count; destination++)
        {
            uint origin = tables.Origin[destination];
            uint gathered = tables.Gathered[destination];
            bool inherited = origin != Missing;
            bool local = gathered != Missing;
            if (inherited == local)
                throw new InvalidDataException($"Patch relocation destination block {destination} must have exactly one source.");
            uint sourceBlock = inherited ? origin : gathered;
            long sourceOffset = (long)sourceBlock * BlockSize;
            long sourceLength = inherited ? referenceLength : patchLength;
            if (sourceOffset > sourceLength - BlockSize)
                throw new InvalidDataException($"Patch relocation source block {sourceBlock} is outside the {(inherited ? "reference" : "patch")} package.");
        }
    }

    public override bool CanRead => true;
    public override bool CanSeek => true;
    public override bool CanWrite => false;
    public override long Length { get; }

    public override long Position
    {
        get => _position;
        set => _position = value >= 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
    }

    public override void Flush() { }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        int total = 0;
        while (buffer.Length > 0 && _position < Length)
        {
            long virtualBlock = _position / BlockSize;
            int withinBlock = (int)(_position % BlockSize);
            int destination = checked((int)virtualBlock + 1);
            uint origin = _tables.Origin[destination];
            bool inherited = origin != Missing;
            FileStream source = inherited ? _reference : _patch;
            long sourceBlock = inherited ? origin : _tables.Gathered[destination];
            int take = (int)Math.Min(buffer.Length, BlockSize - withinBlock);
            source.Position = sourceBlock * BlockSize + withinBlock;
            source.ReadExactly(buffer[..take]);
            buffer = buffer[take..];
            _position += take;
            total += take;
        }
        return total;
    }

    public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
    {
        SeekOrigin.Begin => offset,
        SeekOrigin.Current => _position + offset,
        SeekOrigin.End => Length + offset,
        _ => throw new ArgumentOutOfRangeException(nameof(origin)),
    };

    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _patch.Dispose();
            _reference.Dispose();
        }
        base.Dispose(disposing);
    }
}
