using ProsperoPkgTool.Sony;
using ProsperoPkgTool.Gp5;

namespace ProsperoPkgTool.Tests;

public sealed class SonyLiveRegistryTests
{
    [Fact]
    public async Task InstalledSonyToolMatchesRegistryWhenConfigured()
    {
        string? path = Environment.GetEnvironmentVariable("PROSPERO_PUB_CMD_TEST");
        if (string.IsNullOrWhiteSpace(path))
            return;

        var backend = new SonyPublishingBackend(path);
        SonyProcessResult list = await backend.RunAsync([]);
        SonyProcessResult details = await backend.RunAsync(["helpall"]);

        Assert.True(list.Success);
        Assert.True(details.Success);
        SonyRegistryMismatch mismatch = SonyRegistryVerifier.Compare(
            list.StandardOutput + list.StandardError,
            details.StandardOutput + details.StandardError);
        Assert.True(mismatch.IsComplete,
            $"Missing commands: {string.Join(", ", mismatch.MissingCommands)}; " +
            $"unknown commands: {string.Join(", ", mismatch.UnknownCommands)}; " +
            $"missing-option commands: {string.Join(", ", mismatch.MissingOptions.Keys)}; " +
            $"unknown-option commands: {string.Join(", ", mismatch.UnknownOptions.Keys)}");
    }

    [Fact]
    public async Task GeneratedGp5IsAcceptedAndUpdatedBySonyToolWhenConfigured()
    {
        string? path = Environment.GetEnvironmentVariable("PROSPERO_PUB_CMD_TEST");
        if (string.IsNullOrWhiteSpace(path))
            return;

        using var fixture = new Gp5GeneratorTests.SourceFixture();
        string gp5Path = Path.Combine(fixture.Root, "PPSA12345.gp5");
        Gp5GenerationResult generated = Gp5Generator.Generate(fixture.Root, intendedProjectPath: gp5Path);
        Assert.True(generated.Validation.IsValid);
        Gp5Xml.Write(generated.Project, gp5Path);

        var backend = new SonyPublishingBackend(path);
        SonyProcessResult result = await backend.RunAsync([
            "gp5_proj_update",
            "--passcode", Gp5Constants.DefaultPasscode,
            gp5Path,
        ]);

        Assert.True(result.Success, result.StandardOutput + result.StandardError);
        Gp5Project updated = Gp5Xml.Read(gp5Path);
        Assert.Equal(Gp5Constants.ApplicationVolume, updated.Volume.VolumeType);
        Assert.NotEmpty(updated.Files);
    }
}
