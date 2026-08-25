namespace ProsperoPkgTool.Sony;

public sealed record SonyOutputLine(bool IsError, string Text);

public sealed record SonyProcessResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    TimeSpan Elapsed)
{
    public bool Success => ExitCode == 0;
}

