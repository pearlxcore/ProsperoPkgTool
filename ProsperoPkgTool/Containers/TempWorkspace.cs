using System.Collections.Concurrent;
using System.Diagnostics;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Manages the file-backed build workspace (<c>&lt;temp&gt;\libprospero-&lt;guid&gt;</c>) used by the
/// multi-GiB pipeline, including a crash-safe sweep of orphaned workspaces. A build normally removes
/// its own workspace in a <c>finally</c>, but a killed process leaves one behind; the sweep reclaims
/// those without touching a live build, and a process-exit hook deletes the active workspace on a
/// graceful or unhandled-exception exit.
/// </summary>
public static class TempWorkspace
{
    /// <summary>Directory-name prefix of a build workspace.</summary>
    public const string Prefix = "libprospero-";

    private const string OwnerFile = "build.lock";

    // Workspaces owned by this process, cleaned on exit as a last resort.
    private static readonly ConcurrentDictionary<string, byte> Active = new(StringComparer.OrdinalIgnoreCase);
    private static int _exitHookRegistered;

    /// <summary>Creates a fresh workspace under <paramref name="root"/> and writes its owner marker.</summary>
    public static string Create(string root)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(root);
        Directory.CreateDirectory(root);
        string workspace = Path.Combine(root, Prefix + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workspace);
        try
        {
            File.WriteAllText(Path.Combine(workspace, OwnerFile),
                $"{Environment.ProcessId}\n{DateTime.UtcNow:O}\n{Environment.MachineName}\n");
        }
        catch (IOException) { /* the marker is advisory; a missing one just falls back to age */ }
        catch (UnauthorizedAccessException) { }

        Active[workspace] = 1;
        RegisterExitHook();
        return workspace;
    }

    /// <summary>Removes a workspace (best-effort; never throws).</summary>
    public static void Delete(string workspace)
    {
        Active.TryRemove(workspace, out _);
        try
        {
            if (Directory.Exists(workspace))
                Directory.Delete(workspace, recursive: true);
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    /// <summary>
    /// Deletes orphaned <c>libprospero-*</c> workspaces directly under <paramref name="root"/> that
    /// are older than <paramref name="maxAge"/> and whose recorded owner process is no longer running.
    /// Live workspaces (owner alive, or a marker from another machine) are always left alone.
    /// </summary>
    /// <returns>The workspace names that were removed.</returns>
    public static IReadOnlyList<string> SweepOrphans(string root, TimeSpan maxAge, Action<string>? log = null)
    {
        var removed = new List<string>();
        if (string.IsNullOrWhiteSpace(root) || !Directory.Exists(root))
            return removed;

        foreach (string dir in Directory.EnumerateDirectories(root, Prefix + "*"))
        {
            string name = Path.GetFileName(dir);
            if (name.Length != Prefix.Length + 32 ||
                !Guid.TryParseExact(name.AsSpan(Prefix.Length), "N", out _))
                continue;
            if (!IsOrphan(dir, maxAge))
                continue;

            Delete(dir);
            if (!Directory.Exists(dir))
            {
                removed.Add(name);
                log?.Invoke($"Removed stale build workspace: {name}");
            }
        }
        return removed;
    }

    private static bool IsOrphan(string workspace, TimeSpan maxAge)
    {
        if (TryReadOwner(workspace, out int pid, out string machine))
        {
            // A marker from another machine cannot be verified locally; leave it alone.
            if (!string.Equals(machine, Environment.MachineName, StringComparison.OrdinalIgnoreCase))
                return false;
            // A live owner is an active build; a dead owner is a crashed/abandoned run and is
            // reclaimed immediately — no age wait.
            return !IsProcessAlive(pid);
        }

        // No readable marker: fall back to the age threshold.
        return AgeExceeds(workspace, maxAge);
    }

    private static bool AgeExceeds(string workspace, TimeSpan maxAge)
    {
        try
        {
            return DateTime.UtcNow - Directory.GetLastWriteTimeUtc(workspace) > maxAge;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static void RegisterExitHook()
    {
        if (Interlocked.Exchange(ref _exitHookRegistered, 1) != 0)
            return;
        // Best-effort last resort: a graceful exit or unhandled exception still deletes the workspace
        // even if the build's finally did not run. A hard kill/power loss cannot be caught (the sweep
        // reclaims that leftover on the next run).
        AppDomain.CurrentDomain.ProcessExit += (_, _) => DeleteActiveWorkspaces();
        AppDomain.CurrentDomain.UnhandledException += (_, _) => DeleteActiveWorkspaces();
    }

    private static void DeleteActiveWorkspaces()
    {
        foreach (string workspace in Active.Keys)
            Delete(workspace);
    }

    private static bool TryReadOwner(string workspace, out int pid, out string machine)
    {
        pid = 0;
        machine = string.Empty;
        try
        {
            string[] lines = File.ReadAllLines(Path.Combine(workspace, OwnerFile));
            return lines.Length >= 3 &&
                int.TryParse(lines[0], out pid) &&
                (machine = lines[2]).Length > 0;
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    private static bool IsProcessAlive(int pid)
    {
        try
        {
            using Process process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (ArgumentException) { return false; } // no such process
        catch (InvalidOperationException) { return false; }
    }
}
