namespace ProsperoPkgTool.Containers;

/// <summary>
/// Supplies the bytes of one inner-image file without requiring it to exist on disk. The assembler
/// peeks the first four bytes (executable-module detection) and then performs a single
/// forward-only, exact-length read, so <see cref="Open"/> may be called more than once and the
/// returned stream need not be seekable. Reads are issued from one thread at a time, so
/// implementations need not be thread-safe.
/// </summary>
public interface IProsperoFileSource
{
    /// <summary>Exact payload length in bytes; drives the file's block plan.</summary>
    long Length { get; }

    /// <summary>Opens a fresh, bounded, forward-readable stream over the payload.</summary>
    Stream Open();
}
