using System.Buffers.Binary;
using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class ProsperoPlayGoBuildersTests
{
    [Fact]
    public void SharedPopulation_NormalizesLeavesAndSortsUnsignedHash()
    {
        ProsperoInnerImageAssembler.InnerImageResult inner = Build(
            ("/eboot.bin", new byte[] { 0x7f, (byte)'E', (byte)'L', (byte)'F' }),
            ("/assets/test.bin", new byte[] { 1 }),
            ("/empty.bin", Array.Empty<byte>()),
            ("/sce_sys/keystone", new byte[96]),
            ("/sce_sys/about/right.sprx", new byte[] { 2 }));

        IReadOnlyList<ProsperoPlayGoFileRecord> records = ProsperoPlayGoRecordBuilder.Build(inner,
            new Dictionary<string, byte> { ["/assets/test.bin"] = 2, ["eboot.bin"] = 1 });

        Assert.Equal(5, records.Count);
        Assert.Contains(records, r => r.Path == "EBOOT.BIN" && r.ChunkId == 1);
        Assert.Contains(records, r => r.Path == "ASSETS/TEST.BIN" && r.ChunkId == 2);
        Assert.Contains(records, r => r.Path == "EMPTY.BIN" && r.ChunkId == 0);
        Assert.Contains(records, r => r.Path == "SCE_SYS/KEYSTONE");
        Assert.Contains(records, r => r.Path == "SCE_SYS/ABOUT/RIGHT.SPRX");
        Assert.Equal(records.Select(r => r.PathHash).Order(), records.Select(r => r.PathHash));
    }

    [Fact]
    public void Builders_WriteObservedDebugNwonlyHeadersAndSharedOrder()
    {
        ProsperoInnerImageAssembler.InnerImageResult inner = Build(
            ("/z.bin", new byte[] { 1 }), ("/nested/a.bin", Array.Empty<byte>()));
        IReadOnlyList<ProsperoPlayGoFileRecord> records = ProsperoPlayGoRecordBuilder.Build(inner,
            new Dictionary<string, byte> { ["z.bin"] = 2, ["nested/a.bin"] = 1 });

        byte[] hash = ProsperoPlayGoHashTableBuilder.Build(records);
        byte[] ficm = ProsperoPlayGoFicmBuilder.Build(records);

        Assert.Equal(0x38 + 8 * records.Count, hash.Length);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(hash));
        Assert.Equal(0x08000000u, BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(4)));
        Assert.Equal(0x544c467fu, BinaryPrimitives.ReadUInt32LittleEndian(hash.AsSpan(0x18)));
        Assert.Equal(ProsperoPlayGoHashTableBuilder.Seed0, BinaryPrimitives.ReadUInt64LittleEndian(hash.AsSpan(0x28)));
        Assert.Equal(ProsperoPlayGoHashTableBuilder.Seed1, BinaryPrimitives.ReadUInt64LittleEndian(hash.AsSpan(0x30)));
        Assert.Equal(0x10 + 2 * records.Count, ficm.Length);
        Assert.Equal((uint)(2 * records.Count), BinaryPrimitives.ReadUInt32LittleEndian(ficm.AsSpan(0x0c)));
        for (int i = 0; i < records.Count; i++)
        {
            Assert.Equal(records[i].PathHash, BinaryPrimitives.ReadUInt64LittleEndian(hash.AsSpan(0x38 + 8 * i)));
            Assert.Equal(records[i].ChunkId, ficm[0x10 + 2 * i]);
            Assert.Equal(0, ficm[0x11 + 2 * i]);
        }
    }

    [Fact]
    public void SharedPopulation_RejectsAssignmentOutsideFinalLeaves()
    {
        ProsperoInnerImageAssembler.InnerImageResult inner = Build(("/a.bin", new byte[] { 1 }));
        Assert.Throws<InvalidDataException>(() => ProsperoPlayGoRecordBuilder.Build(inner,
            new Dictionary<string, byte> { ["not-a-file"] = 1 }));
    }

    private static ProsperoInnerImageAssembler.InnerImageResult Build(params (string Path, byte[] Data)[] files) =>
        new ProsperoInnerImageAssembler(1, 2).Build(files.Select(f => new ProsperoInnerImageAssembler.InnerFile
        {
            Path = f.Path,
            Data = f.Data,
        }).ToList());
}
