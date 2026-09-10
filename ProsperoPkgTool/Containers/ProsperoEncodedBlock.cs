using ProsperoPkgTool.Compression;

namespace ProsperoPkgTool.Containers;

/// <summary>Opt-in inner-image compression policy. Stored remains the compatibility default.</summary>
public enum ProsperoInnerCompressionMode
{
    Stored,
    Kraken,
    Auto,
}

/// <summary>
/// One finalized physical inner-image payload block. NAPS consumes these records directly; it
/// never repeats the encoder decision or derives a second compressed-size schedule.
/// </summary>
public sealed class ProsperoEncodedBlock
{
    public required int SourceBlockIndex { get; init; }
    public required long LogicalOffset { get; init; }
    public required int UncompressedLength { get; init; }
    public required byte[] EncodedBytes { get; init; }
    public required bool IsStored { get; init; }
    public KrakenEncoder.LiteralMode? KrakenMode { get; init; }
    public int Flags { get; init; }
    public int FirstChunkCompressedLength { get; init; }
    /// <summary>Explicit stored byte length; -1 derives it from <see cref="EncodedBytes"/>. The
    /// file-backed assembler keeps only this metadata and leaves <see cref="EncodedBytes"/> empty.</summary>
    public int EncodedLength { get; init; } = -1;
    public long PhysicalOffset { get; internal set; }
    public int StoredLength => EncodedLength >= 0 ? EncodedLength : EncodedBytes.Length;
}

/// <summary>Aggregate diagnostics for one assembled inner image.</summary>
public readonly record struct ProsperoCompressionMetrics(
    long RawBytes,
    long EncodedBytes,
    int KrakenBlocks,
    int StoredBlocks)
{
    public double Ratio => RawBytes == 0 ? 1d : (double)EncodedBytes / RawBytes;
}
