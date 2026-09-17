namespace ProsperoPkgTool;

/// <summary>
/// Minimal console progress writer for long-running commands. When a <see cref="ProsperoConsoleLog"/>
/// is supplied every milestone is a timestamped line (reference-style); otherwise output is disabled
/// unless the caller opted in, and an interactive console gets a live single-line update.
/// </summary>
internal sealed class ConsoleProgress : IProgress<ProsperoBuildProgress>
{
    private readonly bool _enabled;
    private readonly bool _redirected;
    private readonly ProsperoConsoleLog? _log;
    private string? _lastStage;
    private int _lastPercent = -1;
    private int _lastMilestone = -1;
    private DateTime _lastEmitUtc = DateTime.UtcNow;
    private bool _wroteLine;

    public ConsoleProgress(bool enabled, ProsperoConsoleLog? log = null)
    {
        _enabled = enabled;
        _log = log;
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
        if (!_enabled)
            return;
        // Coarse stage boundaries (NAPS/CNT/Finalize report 1/1) are covered by the stage summary.
        if (value.Total <= 1 && value.BytesTotal <= 0)
            return;

        // Prefer a byte-accurate ratio when the stage supplies one (staging, inner image, outer PFS):
        // a few multi-GB files would otherwise leave a file-count-only bar stuck for minutes.
        bool byBytes = value.BytesTotal > 0;
        double fraction = byBytes ? value.ByteFraction : value.Fraction;
        int percent = (int)(100.0 * fraction);

        if (!string.Equals(value.Stage, _lastStage, StringComparison.Ordinal))
            _lastMilestone = -1;

        // Emit every 5% and at least every 30 seconds, so a long silent stretch is impossible.
        int milestone = percent / 5;
        bool due = milestone != _lastMilestone
            || (DateTime.UtcNow - _lastEmitUtc).TotalSeconds >= 30;
        if (!due)
            return;
        _lastMilestone = milestone;

        string amount = byBytes
            ? $"{value.BytesDone / 1048576.0:N0}/{value.BytesTotal / 1048576.0:N0} MiB"
            : $"{value.Done:N0}/{value.Total:N0}";
        string where = string.IsNullOrEmpty(value.CurrentPath) ? "" : $"  {value.CurrentPath}";
        Emit($"    {percent,3}%  {value.Stage} ({amount}){where}", value.Stage, percent);
    }

    /// <summary>Reports extract progress as files completed out of a total.</summary>
    public void Report(int done, int total, string file)
    {
        if (!_enabled || total <= 0)
            return;
        int percent = (int)(100.0 * done / total);
        Emit($"    {percent,3}%  {done}/{total}  {file}", "Extract", percent);
    }

    private void Emit(string line, string stage, int percent)
    {
        _lastEmitUtc = DateTime.UtcNow;
        if (_log is not null)
        {
            _log.Write(line);
            _lastStage = stage;
            _lastPercent = percent;
            return;
        }

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
        if (_log is null && _enabled && !_redirected && _wroteLine)
            Console.WriteLine();
        _lastStage = null;
        _lastPercent = -1;
        _lastMilestone = -1;
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
