using System.Diagnostics;

namespace ProsperoPkgTool;

/// <summary>
/// Reference-style console log. Every line is prefixed with the wall-clock time and the elapsed
/// build time, e.g. <c>[05:23:09] [+00:00:01.234] [stage 1/5] Inner image complete: ... in 00:02:39.761.</c>
/// The elapsed timer runs from the first line for the whole operation.
/// </summary>
internal sealed class ProsperoConsoleLog
{
    private readonly Stopwatch _clock = Stopwatch.StartNew();

    /// <summary>Elapsed time since the log was created, formatted <c>hh:mm:ss.fff</c>.</summary>
    public string Elapsed => _clock.Elapsed.ToString(@"hh\:mm\:ss\.fff");

    /// <summary>Writes a fully formatted log line.</summary>
    public void Write(string? message) =>
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [+{Elapsed}] {message}");

    /// <summary>Alias for <see cref="Write"/> so it can be used as a logging sink.</summary>
    public void Log(string? message) => Write(message);
}
