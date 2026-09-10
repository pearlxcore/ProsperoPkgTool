using System.Buffers.Binary;
using ProsperoPkgTool.Content;
using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Coverage for the <c>sce_sys</c> media/system entry mapping: ids, protected-entry flags, naming,
/// DDS generation and inner-PFS exclusion.
/// </summary>
public sealed class ProsperoSceSysMediaTests
{
    private const string TinyPngBase64 =
        "iVBORw0KGgoAAAANSUhEUgAAAAQAAAAECAYAAACp8Z5+AAAAGklEQVR4XmNk+M/wX+AD+w8YZnE4IPOANAEAMSwf9B7uakAAAAAASUVORK5CYII=";

    private static Dictionary<string, byte[]> Files(params (string Name, byte[] Data)[] files) =>
        files.ToDictionary(f => f.Name, f => f.Data, StringComparer.OrdinalIgnoreCase);

    [Fact]
    public void Collect_MapsMediaAndSystemFilesToExpectedIdsFlagsAndNames()
    {
        Dictionary<string, byte[]> files = Files(
            ("icon0.png", [1, 2, 3]),
            ("pic2.png", [4]),
            ("nptitle.dat", [5]),
            ("license.dat", [6]),
            ("param.sfo", [7]),
            ("uds/npbind.dat", [8]));

        IReadOnlyList<ProsperoSceSysMedia.Entry> entries = ProsperoSceSysMedia.Collect(files, generateDds: false);

        ProsperoSceSysMedia.Entry icon = Assert.Single(entries, e => e.Id == CntEntryId.Icon0Png);
        Assert.Equal("icon0.png", icon.Name);
        Assert.Equal(0x08000000u, icon.Flags1);
        Assert.Equal([1, 2, 3], icon.Data);

        ProsperoSceSysMedia.Entry pic2 = Assert.Single(entries, e => e.Id == CntEntryId.Pic2Png);
        Assert.Equal(0x08000000u, pic2.Flags1);

        ProsperoSceSysMedia.Entry nptitle = Assert.Single(entries, e => e.Id == CntEntryId.NptitleDat);
        Assert.Null(nptitle.Name);
        Assert.Equal(0x80000000u, nptitle.Flags1);
        Assert.Equal(3u << 12, nptitle.Flags2);

        ProsperoSceSysMedia.Entry license = Assert.Single(entries, e => e.Id == CntEntryId.LicenseDat);
        Assert.Null(license.Name);
        Assert.Equal(0x80000000u, license.Flags1);
        Assert.Equal(3u << 12, license.Flags2);

        ProsperoSceSysMedia.Entry nestedNpbind = Assert.Single(entries, e => e.Id == CntEntryId.UdsNpbind);
        Assert.Equal("uds/npbind.dat", nestedNpbind.Name);
        Assert.Equal(0x80000000u, nestedNpbind.Flags1);
        Assert.Equal(3u << 12, nestedNpbind.Flags2);

        Assert.DoesNotContain(entries, e => e.Id == CntEntryId.ParamSfo);
    }

    [Theory]
    [InlineData(null, 2u)]
    [InlineData("standard", 2u)]
    [InlineData("upgradable", 4u)]
    public void Collect_LicenseInfoUsesTheApplicationKeyIndex(string? drmType, uint expectedKey)
    {
        Dictionary<string, byte[]> files = Files(("license.info", [1]));
        IReadOnlyList<ProsperoSceSysMedia.Entry> entries = ProsperoSceSysMedia.Collect(files, drmType, generateDds: false);

        ProsperoSceSysMedia.Entry license = Assert.Single(entries);
        Assert.Equal(CntEntryId.LicenseInfo, license.Id);
        Assert.Equal(0x80000000u, license.Flags1);
        Assert.Equal(expectedKey << 12, license.Flags2);
    }

    [Fact]
    public void Collect_GeneratesDdsCompanionFromPng()
    {
        Dictionary<string, byte[]> files = Files(("icon0.png", Convert.FromBase64String(TinyPngBase64)));
        IReadOnlyList<ProsperoSceSysMedia.Entry> entries = ProsperoSceSysMedia.Collect(files);

        Assert.Contains(entries, e => e.Id == CntEntryId.Icon0Png);
        ProsperoSceSysMedia.Entry dds = Assert.Single(entries, e => e.Id == CntEntryId.Icon0Dds);
        Assert.Equal("icon0.dds", dds.Name);
        Assert.Equal("DDS ", System.Text.Encoding.ASCII.GetString(dds.Data, 0, 4));
        Assert.Equal(98u, BinaryPrimitives.ReadUInt32LittleEndian(dds.Data.AsSpan(128)));
    }

    [Fact]
    public void Collect_PrefersSuppliedDdsOverPngGeneration()
    {
        byte[] supplied = [0x44, 0x44, 0x53, 0x20, 9, 9, 9];
        Dictionary<string, byte[]> files = Files(
            ("icon0.png", Convert.FromBase64String(TinyPngBase64)),
            ("icon0.dds", supplied));

        IReadOnlyList<ProsperoSceSysMedia.Entry> entries = ProsperoSceSysMedia.Collect(files);
        ProsperoSceSysMedia.Entry dds = Assert.Single(entries, e => e.Id == CntEntryId.Icon0Dds);
        Assert.Equal(supplied, dds.Data);
    }

    [Fact]
    public void Collect_KeepsPngWhenDdsGenerationFails()
    {
        Dictionary<string, byte[]> files = Files(("icon0.png", [0x89, (byte)'P', (byte)'N', (byte)'G']));
        IReadOnlyList<ProsperoSceSysMedia.Entry> entries = ProsperoSceSysMedia.Collect(files);

        Assert.Contains(entries, e => e.Id == CntEntryId.Icon0Png);
        Assert.DoesNotContain(entries, e => e.Id == CntEntryId.Icon0Dds);
    }

    [Theory]
    [InlineData("param.json", true)]
    [InlineData("pic2.png", true)]
    [InlineData("icon0.png", true)]
    [InlineData("playgo-chunk.dat", true)]
    [InlineData("trophy2/trophy00.ucp", true)]
    [InlineData("about/right.sprx", false)]
    [InlineData("keystone", false)]
    [InlineData("pfs-version.dat", false)]
    public void IsOuterCntFile_RecognizesOnlyMappedSceSysFiles(string relative, bool expected)
    {
        Assert.Equal(expected, ProsperoSceSysMedia.IsOuterCntFile(relative));
    }

    [Fact]
    public void IsOuterCntFile_DoesNotTreatNestedTrophyFilesAsFlat()
    {
        Assert.True(ProsperoSceSysMedia.TryGetId("trophy/trophy99.trp", out CntEntryId id));
        Assert.Equal((CntEntryId)(5120 + 99), id);
    }
}
