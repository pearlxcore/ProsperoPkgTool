using ProsperoPkgTool.Sony;

namespace ProsperoPkgTool.Tests;

public sealed class SonyCommandRegistryTests
{
    private static readonly string[] ExpectedCommands =
    [
        "gp5_proj_create", "gp5_proj_update",
        "gp5_playgo_add", "gp5_playgo_update", "gp5_playgo_delete",
        "gp5_chunk_add", "gp5_chunk_update", "gp5_chunk_delete",
        "gp5_scenario_add", "gp5_scenario_update", "gp5_scenario_delete",
        "gp5_file_add", "gp5_file_update", "gp5_file_delete",
        "gp5_dir_add", "gp5_dir_update", "gp5_dir_delete",
        "img_create", "img_extract", "img_file_list", "img_info", "img_verify",
        "pkg_switch", "iso_write", "iso_copy", "iso_convert", "drive_list",
        "file_calc_loudness", "ks_create", "pc_fingerprint", "set_conf", "get_conf",
        "version", "help", "helpall",
    ];

    [Fact]
    public void RegistryContainsAllThirtyFiveSony121Commands()
    {
        Assert.Equal(35, SonyCommandRegistry.All.Count);
        Assert.Equal(
            ExpectedCommands.Order(StringComparer.Ordinal),
            SonyCommandRegistry.All.Select(command => command.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void CommandAndOptionNamesAreUnique()
    {
        Assert.Equal(SonyCommandRegistry.All.Count,
            SonyCommandRegistry.All.Select(command => command.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count());

        foreach (SonyCommandDefinition command in SonyCommandRegistry.All)
        {
            Assert.Equal(command.Options.Count,
                command.Options.Select(option => option.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count());
            Assert.All(command.Options, option => Assert.StartsWith("--", option.Name, StringComparison.Ordinal));
        }
    }

    [Fact]
    public void StateChangingCommandsHaveExplicitRiskClassification()
    {
        Assert.Equal(SonyCommandRisk.WritesOpticalMedia, SonyCommandRegistry.ByName["iso_write"].Risk);
        Assert.Equal(SonyCommandRisk.ChangesConfiguration, SonyCommandRegistry.ByName["set_conf"].Risk);
        Assert.Equal(SonyCommandRisk.MutatesInput, SonyCommandRegistry.ByName["pkg_switch"].Risk);
        Assert.Equal(SonyCommandRisk.ReadOnly, SonyCommandRegistry.ByName["img_info"].Risk);
    }
}

