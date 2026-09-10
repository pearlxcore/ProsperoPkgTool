namespace ProsperoPkgTool;

/// <summary>
/// Minimal console progress writer for long-running commands. Disabled unless the caller opted
/// in (for example with <c>--verbose</c>), so normal runs stay quiet. When the console is
/// redirected the live single-line <c>\r</c> update would corrupt logs, so reports are emitted
/// as ordinary lines and throttled to stage or whole-percent changes.
/// </summary>
internal sealed class ConsoleProgress : IProgress<ProsperoBuildProgress>
{
    private readonly bool _enabled;
    private readonly bool _redirected;
    private string? _lastStage;
    private int _lastPercent = -1;
    private bool _wroteLine;

    public ConsoleProgress(bool enabled)
    {
        _enabled = enabled;
        try
        {
            _redirected = Console.IsOutputRedirected;
        }
        catch
        {
            _redirected = true;
        }
    }

    public void Report(ProsperoBuildProgress value)
    {
        if (!_enabled || value.Total <= 0)
            return;
        int percent = (int)(100.0 * value.Done / value.Total);
        Write($"  [{percent,3}%] {value.Stage} ({value.Done:N0}/{value.Total:N0})", value.Stage, percent);
    }

    /// <summary>Reports extract progress as files completed out of a total.</summary>
    public void Report(int done, int total, string file)
    {
        if (!_enabled || total <= 0)
            return;
        int percent = (int)(100.0 * done / total);
        Write($"  [{percent,3}%] {done}/{total}  {file}", "Extract", percent);
    }

    private void Write(string line, string stage, int percent)
    {
        if (_redirected)
        {
            if (stage != _lastStage || percent != _lastPercent)
            {
                Console.WriteLine(line);
                _lastStage = stage;
                _lastPercent = percent;
            }
            return;
        }

        int width = SafeWidth();
        if (line.Length < width)
            line += new string(' ', width - line.Length);
        Console.Write('\r');
        Console.Write(line);
        _lastStage = stage;
        _lastPercent = percent;
        _wroteLine = true;
    }

    /// <summary>Ends the live line so following output starts on a clean row.</summary>
    public void Finish()
    {
        if (_enabled && !_redirected && _wroteLine)
            Console.WriteLine();
        _lastStage = null;
        _lastPercent = -1;
        _wroteLine = false;
    }

    private static int SafeWidth()
    {
        try
        {
            int width = Console.WindowWidth;
            return width > 0 ? width : 100;
        }
        catch
        {
            return 100;
        }
    }
}
