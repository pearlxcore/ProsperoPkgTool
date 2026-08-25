using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Tests;

public sealed class Gp5ValidatorTests
{
    [Fact]
    public void ValidProjectPassesStructuralValidation()
    {
        Gp5Project project = Gp5XmlTests.BuildProject();
        project.Files.Add(new Gp5FileEntry { DestinationPath = "\\eboot.bin", SourcePath = "\\eboot.bin" });
        ValidationReport report = Gp5Validator.Validate(project);
        Assert.True(report.IsValid);
    }

    [Fact]
    public void DetectsDuplicateDestinationsAndInvalidChunkSequence()
    {
        Gp5Project project = Gp5XmlTests.BuildProject();
        project.Files.Add(new Gp5FileEntry { DestinationPath = "\\DATA\\same.bin", SourcePath = "\\one.bin" });
        project.Files.Add(new Gp5FileEntry { DestinationPath = "data\\same.bin", SourcePath = "\\two.bin" });
        project.Volume.ChunkInfo!.Scenarios[0].Sequence = "0 0";

        ValidationReport report = Gp5Validator.Validate(project);
        Assert.False(report.IsValid);
        Assert.Contains(report.Issues, issue => issue.Code == "DUPLICATE_DESTINATION");
        Assert.Contains(report.Issues, issue => issue.Code == "SCENARIO_SEQUENCE");
    }

    [Theory]
    [InlineData("0 3 1-2", 4, true)]
    [InlineData("0-3", 4, true)]
    [InlineData("0 4", 4, false)]
    [InlineData("0-2 2", 4, false)]
    [InlineData("", 4, false)]
    public void ScenarioSequenceParserIsStrict(string sequence, int count, bool expected)
    {
        bool result = Gp5Validator.TryExpandSequence(sequence, count, out _, out _);
        Assert.Equal(expected, result);
    }
}

