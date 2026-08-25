using System.Diagnostics;
using System.Text;

namespace ProsperoPkgTool.Sony;

public sealed class SonyPublishingBackend
{
    public SonyPublishingBackend(string executablePath)
    {
        ExecutablePath = Path.GetFullPath(executablePath);
        if (!File.Exists(ExecutablePath))
            throw new FileNotFoundException("Sony Publishing Tools executable was not found.", ExecutablePath);
    }

    public string ExecutablePath { get; }

    public async Task<SonyProcessResult> RunAsync(
        IEnumerable<string> arguments,
        Action<SonyOutputLine>? output = null,
        CancellationToken cancellationToken = default)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = ExecutablePath,
            WorkingDirectory = Path.GetDirectoryName(ExecutablePath) ?? Environment.CurrentDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        foreach (string argument in arguments)
            startInfo.ArgumentList.Add(argument);

        using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        var stopwatch = Stopwatch.StartNew();

        process.OutputDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is null)
                return;
            lock (stdout)
                stdout.AppendLine(eventArgs.Data);
            output?.Invoke(new SonyOutputLine(false, eventArgs.Data));
        };
        process.ErrorDataReceived += (_, eventArgs) =>
        {
            if (eventArgs.Data is null)
                return;
            lock (stderr)
                stderr.AppendLine(eventArgs.Data);
            output?.Invoke(new SonyOutputLine(true, eventArgs.Data));
        };

        if (!process.Start())
            throw new InvalidOperationException("Sony Publishing Tools process could not be started.");

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        try
        {
            await process.WaitForExitAsync(cancellationToken).ConfigureAwait(false);
            // WaitForExit flushes the asynchronous output event queues.
            process.WaitForExit();
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
        finally
        {
            stopwatch.Stop();
        }

        string outText;
        string errorText;
        lock (stdout)
            outText = stdout.ToString();
        lock (stderr)
            errorText = stderr.ToString();

        return new SonyProcessResult(process.ExitCode, outText, errorText, stopwatch.Elapsed);
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
                process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }
}

