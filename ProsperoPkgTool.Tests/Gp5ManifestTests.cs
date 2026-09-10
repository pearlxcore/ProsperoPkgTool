using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Tests;

public sealed class Gp5ManifestTests
{
    [Fact]
    public void ResolvesFlatFilesInManifestOrder()
    {
        using var fixture = new ManifestFixture();
        var project = new Gp5Project { Layout = Gp5ContentLayout.FlatFiles };
        project.Files.Add(new Gp5FileEntry { DestinationPath = "\\eboot.bin", SourcePath = "\\eboot.bin" });
        project.Files.Add(new Gp5FileEntry { DestinationPath = "\\sce_sys\\param.json", SourcePath = "\\sce_sys\\param.json", Chunk = 1 });

        IReadOnlyList<Gp5ManifestFile> files = Gp5Manifest.Resolve(project, fixture.ProjectPath);

        Assert.Equal(["eboot.bin", "sce_sys/param.json"], files.Select(file => file.DestinationPath));
        Assert.Equal(Path.Combine(fixture.Root, "eboot.bin"), files[0].SourceFullPath);
        Assert.Null(files[0].Chunk);
        Assert.Equal(1, files[1].Chunk);
    }

    [Fact]
    public void ResolvesRootDirectoryTreeWithNestedPrefixes()
    {
        using var fixture = new ManifestFixture();
        var root = new Gp5DirectoryEntry { IsRoot = true };
        var sceSys = new Gp5DirectoryEntry { DestinationPath = "sce_sys" };
        sceSys.Children.Add(new Gp5FileEntry { DestinationPath = "param.json", SourcePath = "\\sce_sys\\param.json" });
        root.Children.Add(sceSys);
        root.Children.Add(new Gp5FileEntry { DestinationPath = "eboot.bin", SourcePath = "\\eboot.bin" });
        var project = new Gp5Project { Layout = Gp5ContentLayout.RootDirectory, RootDirectory = root };

        IReadOnlyList<Gp5ManifestFile> files = Gp5Manifest.Resolve(project, fixture.ProjectPath);

        Assert.Equal(["sce_sys/param.json", "eboot.bin"], files.Select(file => file.DestinationPath));
    }

    [Fact]
    public void ThrowsWhenSourceIsMissing()
    {
        using var fixture = new ManifestFixture();
        var project = new Gp5Project { Layout = Gp5ContentLayout.FlatFiles };
        project.Files.Add(new Gp5FileEntry { DestinationPath = "missing.bin" });

        Assert.Throws<InvalidDataException>(() => Gp5Manifest.Resolve(project, fixture.ProjectPath));
    }

    [Fact]
    public void ThrowsOnDuplicateDestination()
    {
        using var fixture = new ManifestFixture();
        var project = new Gp5Project { Layout = Gp5ContentLayout.FlatFiles };
        project.Files.Add(new Gp5FileEntry { DestinationPath = "eboot.bin" });
        project.Files.Add(new Gp5FileEntry { DestinationPath = "\\eboot.bin" });

        Assert.Throws<InvalidDataException>(() => Gp5Manifest.Resolve(project, fixture.ProjectPath));
    }

    private sealed class ManifestFixture : IDisposable
    {
        public ManifestFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "ProsperoPkgTool-Manifest-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path.Combine(Root, "sce_sys"));
            File.WriteAllBytes(Path.Combine(Root, "eboot.bin"), [0x7F, (byte)'E', (byte)'L', (byte)'F']);
            File.WriteAllBytes(Path.Combine(Root, "sce_sys", "param.json"), "{}"u8.ToArray());
            ProjectPath = Path.Combine(Root, "test.gp5");
        }

        public string Root { get; }
        public string ProjectPath { get; }

        public void Dispose()
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }
}
