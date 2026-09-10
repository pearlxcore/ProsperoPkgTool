using System.Buffers.Binary;
using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class ProsperoLihReaderTests
{
    [Fact]
    public void Read_DebugPatchEnvelope_UsesVerifiedLihGeometry()
    {
        const int fihOffset = 0x10000;
        const int pfsOffset = 0x20000;
        const int cntOffset = 0xC0000;
        const int cntSize = 0x50000;
        const int siOffset = 0x110000;
        const int siSize = 4;
        byte[] package = new byte[siOffset + siSize];

        package[0] = 0x7F; package[1] = (byte)'L'; package[2] = (byte)'I'; package[3] = (byte)'H';
        BinaryPrimitives.WriteUInt16LittleEndian(package.AsSpan(0x06), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(package.AsSpan(0x10), fihOffset);
        BinaryPrimitives.WriteUInt32LittleEndian(package.AsSpan(0x14), 0x0C);
        BinaryPrimitives.WriteUInt64LittleEndian(package.AsSpan(0x18), (ulong)package.Length);
        BinaryPrimitives.WriteUInt64LittleEndian(package.AsSpan(0x20), 0x10000);
        BinaryPrimitives.WriteUInt64LittleEndian(package.AsSpan(0x28), 0x10000);
        BinaryPrimitives.WriteUInt64LittleEndian(package.AsSpan(0x30), cntOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(package.AsSpan(0x38), cntSize);
        BinaryPrimitives.WriteUInt64LittleEndian(package.AsSpan(0x40), siOffset);
        BinaryPrimitives.WriteUInt64LittleEndian(package.AsSpan(0x48), siSize);

        package[fihOffset] = 0x7F; package[fihOffset + 1] = (byte)'F'; package[fihOffset + 2] = (byte)'I'; package[fihOffset + 3] = (byte)'H';
        BinaryPrimitives.WriteUInt16LittleEndian(package.AsSpan(fihOffset + 6), 3);
        package[cntOffset] = 0x7F; package[cntOffset + 1] = (byte)'C'; package[cntOffset + 2] = (byte)'N'; package[cntOffset + 3] = (byte)'T';
        BinaryPrimitives.WriteUInt16BigEndian(package.AsSpan(cntOffset + 4), 2);
        BinaryPrimitives.WriteUInt32BigEndian(package.AsSpan(cntOffset + 0x18), 0x5A0);
        package[siOffset] = (byte)'P'; package[siOffset + 1] = (byte)'K'; package[siOffset + 2] = 0x03; package[siOffset + 3] = 0x04;

        string path = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(path, package);
            ProsperoPackageInspection result = ProsperoPackageReader.Read(path);

            Assert.Equal(ProsperoPackageKind.FinalizedPatchDebug, result.Kind);
            Assert.Equal((ulong)fihOffset, result.Lih!.FihOffset);
            Assert.Equal((ulong)cntOffset, result.Lih.CntOffset);
            Assert.Equal((ulong)siOffset, result.Lih.SiOffset);
            Assert.Equal((ulong)pfsOffset, result.Fih!.PfsOffset);
            Assert.Equal((ulong)(cntOffset - pfsOffset), result.Fih.PfsSize);
            Assert.Equal(["LIH", "FIH", "PFS", "SC", "SI"], result.Segments.Select(segment => segment.Name));
            Assert.True(result.Structure.IsValid);
            Assert.Throws<InvalidDataException>(() => ProsperoPackageContent.Read(path));
        }
        finally
        {
            File.Delete(path);
        }
    }
}
