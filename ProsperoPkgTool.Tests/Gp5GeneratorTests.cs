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
