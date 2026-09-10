using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Tests;

public sealed class Gp5GeneratorTests
{
    [Fact]
    public void GeneratesSortedContainedFilesAndExcludesPublishingArtifacts()
    {
        using var fixture = new SourceFixture();
        File.WriteAllText(Path.Combine(fixture.Root, "z-last.bin"), "z");
        Directory.CreateDirectory(Path.Combine(fixture.Root, "data"));
        File.WriteAllText(Path.Combine(fixture.Root, "data", "a-first.bin"), "a");
        File.WriteAllText(Path.Combine(fixture.Root, "old.pkg"), "excluded");
        File.WriteAllText(Path.Combine(fixture.Root, "sce_sys", "keystone"), "excluded");

        string output = Path.Combine(fixture.Root, "PPSA12345.gp5");
        Gp5GenerationResult result = Gp5Generator.Generate(fixture.Root, intendedProjectPath: output);
        Assert.True(result.Validation.IsValid);
        Assert.Contains(result.Validation.Issues, issue => issue.Code == "PLAYGO_DEFAULT");
        Assert.Equal(result.Project.Files.OrderBy(file => file.DestinationPath, StringComparer.Ordinal)
            .Select(file => file.DestinationPath), result.Project.Files.Select(file => file.DestinationPath));
        Assert.DoesNotContain(result.Project.Files, file => file.DestinationPath.EndsWith(".pkg", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(result.Project.Files, file => file.DestinationPath.EndsWith("keystone", StringComparison.OrdinalIgnoreCase));
        Assert.All(result.Project.Files, file => Assert.StartsWith("\\", file.SourcePath!, StringComparison.Ordinal));

        Gp5Xml.Write(result.Project, output);
        Gp5Project parsed = Gp5Xml.Read(output);
        Assert.Equal(result.Project.Files.Count, parsed.Files.Count);
        Assert.True(Gp5Validator.Validate(parsed, output).IsValid);
    }

    [Fact]
    public async Task CliGeneratesAndValidatesProjectEndToEnd()
    {
        using var fixture = new SourceFixture();
        int generated = await CliApplication.RunAsync(["gp5gen", fixture.Root]);
        string output = Path.Combine(fixture.Root, "PPSA12345.gp5");
        Assert.Equal(0, generated);
        Assert.True(File.Exists(output));

        int validated = await CliApplication.RunAsync(["gp5validate", output]);
        Assert.Equal(0, validated);
    }

    [Fact]
    public void RejectsSonyConfirmedFreeDrmApplicationCombination()
    {
        using var fixture = new SourceFixture();
        string paramPath = Path.Combine(fixture.Root, "sce_sys", "param.json");
        string json = File.ReadAllText(paramPath).Replace(
            "\"applicationCategoryType\": 0,",
            "\"applicationCategoryType\": 0,\n  \"applicationDrmType\": \"free\",");
        File.WriteAllText(paramPath, json);

        SourceFolderInspection result = SourceFolderValidator.Inspect(fixture.Root);

        Assert.False(result.Validation.IsValid);
        Assert.Contains(result.Validation.Issues, issue => issue.Code == "PARAM_DRM_COMBINATION");
    }

    [Theory]
    [InlineData("eboot.bin.esbak")]
    [InlineData("sce_module/libc.prx.esbak")]
    [InlineData("sce_sys/about/right.sprx")]
    [InlineData("sce_sys/ext_info.dat")]
    [InlineData("disc_info.dat")]
    public void ExcludesPublishingAndDumpArtifacts(string relativePath)
    {
        Assert.True(SourceFolderValidator.IsPublishingArtifact(relativePath));
    }

    [Fact]
    public void ValidatesSonyImplicitSourcePathAgainstDestination()
    {
        using var fixture = new SourceFixture();
        string projectPath = Path.Combine(fixture.Root, "implicit.gp5");
        var project = Gp5Generator.Generate(fixture.Root, intendedProjectPath: projectPath).Project;
        foreach (Gp5FileEntry file in project.Files)
            file.SourcePath = null;

        ValidationReport validation = Gp5Validator.Validate(project, projectPath);

        Assert.DoesNotContain(validation.Issues, issue => issue.Code is "SOURCE_PATH" or "SOURCE_MISSING");
    }

    [Fact]
    public void IncludesRequiredNpTitleSystemEntry()
    {
        Assert.False(SourceFolderValidator.IsPublishingArtifact("sce_sys/nptitle.dat"));
    }

    internal sealed class SourceFixture : IDisposable
    {
        public SourceFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "ProsperoPkgTool-Gp5-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path.Combine(Root, "sce_sys"));
            File.WriteAllBytes(Path.Combine(Root, "eboot.bin"), [0x7F, (byte)'E', (byte)'L', (byte)'F']);
            File.WriteAllBytes(Path.Combine(Root, "sce_sys", "icon0.png"), [0x89, (byte)'P', (byte)'N', (byte)'G']);
            File.WriteAllText(Path.Combine(Root, "sce_sys", "param.json"), """
                {
                  "titleId": "PPSA12345",
                  "contentId": "UP0000-PPSA12345_00-TESTPACKAGE00000",
                  "contentVersion": "01.000.000",
                  "applicationCategoryType": 0,
                  "pubtools": { "creationDate": "2026-08-25 12:00:00" }
                }
                """);
        }

        public string Root { get; }

        public void Dispose()
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }
}
