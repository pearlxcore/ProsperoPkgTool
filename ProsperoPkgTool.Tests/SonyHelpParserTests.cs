using ProsperoPkgTool.Sony;

namespace ProsperoPkgTool.Tests;

public sealed class SonyHelpParserTests
{
    private const string CommandList = """
        Usage:
          Available command_name list:
            img_info
            img_verify
            version | -v
            help | -h
            helpall
          For further information, type help.
        """;

    private const string DetailedHelp = """
        Usage of img_info command:
          Description:
            Display information.

        Usage of img_verify command:
          Options:
            --passcode passcode
              Package passcode.
            --tmp_path tmp_path
              Temporary path.
            --no_progress_bar
              Hide progress.
        """;

    [Fact]
    public void ParsesAliasesOutOfAvailableCommandList()
    {
        IReadOnlySet<string> commands = SonyHelpParser.ParseAvailableCommands(CommandList);
        Assert.Equal(5, commands.Count);
        Assert.Contains("version", commands);
        Assert.DoesNotContain("-v", commands);
    }

    [Fact]
    public void ParsesDetailedOptionsByCommand()
    {
        IReadOnlyDictionary<string, SonyHelpCommand> commands = SonyHelpParser.ParseDetailedHelp(DetailedHelp);
        Assert.Empty(commands["img_info"].Options);
        Assert.Equal(["--no_progress_bar", "--passcode", "--tmp_path"],
            commands["img_verify"].Options.Order(StringComparer.Ordinal).ToArray());
    }
}

