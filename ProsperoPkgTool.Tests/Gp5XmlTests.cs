using System.Text;
using System.Xml;
using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Tests;

public sealed class Gp5XmlTests
{
    [Fact]
    public void FlatProjectRoundTripsDeterministicallyAndEscapesAttributes()
    {
        var project = BuildProject();
        project.Files.Add(new Gp5FileEntry
        {
            DestinationPath = "\\data\\A&B\".bin",
            SourcePath = "\\data\\A&B\".bin",
            Chunk = 0,
            ContentConfigLabel = "primary",
        });

        byte[] first = Write(project);
        Gp5Project parsed = Gp5Xml.Read(new MemoryStream(first));
        byte[] second = Write(parsed);

        Assert.Equal(first, second);
        Assert.Contains("A&amp;B&quot;.bin", Encoding.UTF8.GetString(first), StringComparison.Ordinal);
        Assert.Equal("\\data\\A&B\".bin", parsed.Files[0].DestinationPath);
    }

    [Fact]
    public void ReadsNestedRootDirectoryForm()
    {
        const string xml = """
            <?xml version="1.0" encoding="utf-8" standalone="yes"?>
            <psproject fmt="gp5">
              <volume>
                <volume_type>prospero_ac</volume_type>
                <package passcode="00000000000000000000000000000000"/>
              </volume>
              <rootdir virtual="true">
                <dir dst_path="sce_sys" src_path="\sce_sys">
                  <file dst_path="sce_sys\param.json" src_path="\sce_sys\param.json"/>
                </dir>
              </rootdir>
            </psproject>
            """;

        Gp5Project project = Gp5Xml.Read(new MemoryStream(Encoding.UTF8.GetBytes(xml)));
        Assert.Equal(Gp5ContentLayout.RootDirectory, project.Layout);
        Gp5DirectoryEntry directory = Assert.IsType<Gp5DirectoryEntry>(Assert.Single(project.RootDirectory.Children));
        Assert.Equal("sce_sys", directory.DestinationPath);
        Assert.IsType<Gp5FileEntry>(Assert.Single(directory.Children));
    }

    [Fact]
    public void RejectsDtdAndUnsupportedElements()
    {
        const string dtd = "<!DOCTYPE psproject [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><psproject fmt=\"gp5\"><volume/></psproject>";
        Assert.Throws<XmlException>(() => Gp5Xml.Read(new MemoryStream(Encoding.UTF8.GetBytes(dtd))));

        const string unsupported = "<psproject fmt=\"gp5\"><volume><volume_type>prospero_app</volume_type><package/></volume><unknown/></psproject>";
        Assert.Throws<InvalidDataException>(() => Gp5Xml.Read(new MemoryStream(Encoding.UTF8.GetBytes(unsupported))));
    }

    internal static Gp5Project BuildProject()
    {
        var project = new Gp5Project
        {
            Volume = new Gp5Volume
            {
                VolumeType = Gp5Constants.ApplicationVolume,
                Package = new Gp5Package
                {
                    ContentId = "UP0000-PPSA12345_00-TESTPACKAGE00000",
                    Passcode = Gp5Constants.DefaultPasscode,
                },
                ChunkInfo = new Gp5ChunkInfo
                {
                    ChunkCount = 1,
                    ScenarioCount = 1,
                    DefaultScenarioId = 0,
                },
            },
        };
        project.Volume.ChunkInfo.Chunks.Add(new Gp5Chunk { Id = 0, Label = "Chunk #0" });
        project.Volume.ChunkInfo.Scenarios.Add(new Gp5Scenario
        {
            Id = 0,
            InitialChunkCount = 1,
            Label = "Scenario #0",
            Sequence = "0",
        });
        return project;
    }

    private static byte[] Write(Gp5Project project)
    {
        using var stream = new MemoryStream();
        Gp5Xml.Write(project, stream);
        return stream.ToArray();
    }
}
