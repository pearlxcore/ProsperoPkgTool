using System.Buffers.Binary;
using System.IO.Compression;

namespace ProsperoPkgTool.Containers;

/// <summary>Clean-room reader for the complete patch relocation tables retained in SI.</summary>
public static class ProsperoPatchRelocation
{
    private const int HeaderSize = 0x1000;
    private const int BlockSize = 0x10000;
    private const uint Missing = uint.MaxValue;

    public sealed record Tables(uint[] Origin, uint[] Gathered, uint[] Target, uint[] Update)
    {
        public int Count => Origin.Length;
    }

    public static Tables Read(string patchPath, ProsperoPackageInspection inspection)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(patchPath);
        ArgumentNullException.ThrowIfNull(inspection);
        if (inspection.Kind != ProsperoPackageKind.FinalizedPatchDebug || inspection.Lih is null)
            throw new InvalidDataException("Relocation tables require a debug LIH patch package.");

        using var package = File.OpenRead(Path.GetFullPath(patchPath));
        ProsperoPackageSegment si = inspection.Segments.Single(segment => segment.Name == "SI");
        if (si.Size <= 0 || si.Size > int.MaxValue)
            throw ProsperoErrorInfo.Unsupported("Patch SI size is unsupported.");
        byte[] siBytes = new byte[checked((int)si.Size)];
        package.Position = si.Offset;
        package.ReadExactly(siBytes);
        using var stream = new MemoryStream(siBytes, writable: false);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read);
        uint[] origin = ReadTable(archive, "common/origin-relocinfo.dat");
        uint[] gathered = ReadTable(archive, "common/gathered-relocinfo.dat");
        uint[] target = ReadTable(archive, "common/target-relocinfo.dat");
        uint[] update = ReadTable(archive, "common/update-relocinfo.dat");
        if (gathered.Length != origin.Length || target.Length != origin.Length || update.Length != origin.Length)
            throw new InvalidDataException("Patch relocation tables disagree on record count.");
        return new Tables(origin, gathered, target, update);
    }

    public static byte[] MaterializeEncryptedVirtualImage(
        string patchPath, string referencePath, Tables tables)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(patchPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(referencePath);
        ArgumentNullException.ThrowIfNull(tables);
        if (tables.Count < 2)
            throw new InvalidDataException("Patch relocation table contains no virtual PFS blocks.");

        long virtualImageLength = VirtualImageLength(tables);
        if (virtualImageLength > int.MaxValue)
            throw ProsperoErrorInfo.Unsupported(
                $"Reconstructed patch mount exceeds the supported in-memory size: {tables.Count - 1} virtual blocks " +
                $"({virtualImageLength >> 30} GiB); use the file-backed patch reader.");

        using var image = ProsperoPatchVirtualStream.Open(patchPath, referencePath, tables);
        var virtualImage = new byte[(int)virtualImageLength];
        image.ReadExactly(virtualImage);
        return virtualImage;
    }

    /// <summary>Size in bytes of the patched outer-PFS image the relocation tables describe.</summary>
    public static long VirtualImageLength(Tables tables)
    {
        ArgumentNullException.ThrowIfNull(tables);
        return Math.Max(0, tables.Count - 1) * (long)BlockSize;
    }

    private static uint[] ReadTable(ZipArchive archive, string name)
    {
        ZipArchiveEntry entry = archive.GetEntry(name)
            ?? throw new InvalidDataException($"Patch SI does not contain '{name}'.");
        if (entry.Length < HeaderSize || entry.Length > int.MaxValue)
            throw new InvalidDataException($"Patch relocation file '{name}' has an invalid size.");
        byte[] bytes = new byte[checked((int)entry.Length)];
        using (Stream source = entry.Open())
            source.ReadExactly(bytes);
        if (bytes.Length < 0x28)
            throw new InvalidDataException($"Patch relocation file '{name}' has a truncated header.");
        uint count = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0x14, 4));
        uint declaredSize = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0x18, 4));
        uint tableOffset = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0x20, 4));
        uint tableLength = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(0x24, 4));
        if (declaredSize != bytes.Length || tableOffset != HeaderSize || tableLength != count * 4L ||
            tableOffset > bytes.Length || tableLength > bytes.Length - tableOffset)
            throw new InvalidDataException($"Patch relocation file '{name}' has inconsistent geometry.");
        var result = new uint[count];
        for (int index = 0; index < result.Length; index++)
            result[index] = BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(HeaderSize + index * 4, 4));
        return result;
    }
}
