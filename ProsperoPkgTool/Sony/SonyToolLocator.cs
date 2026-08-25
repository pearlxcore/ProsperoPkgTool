namespace ProsperoPkgTool.Sony;

public static class SonyToolLocator
{
    public const string EnvironmentVariable = "PROSPERO_PUB_CMD";
    public const string ExecutableName = "prospero-pub-cmd.exe";

    public static string Resolve(string? explicitPath = null)
    {
        var candidates = new List<string>();

        if (!string.IsNullOrWhiteSpace(explicitPath))
            candidates.Add(explicitPath);

        string? configured = Environment.GetEnvironmentVariable(EnvironmentVariable);
        if (!string.IsNullOrWhiteSpace(configured))
            candidates.Add(configured);

        candidates.Add(Path.Combine(AppContext.BaseDirectory, ExecutableName));
        candidates.Add(Path.Combine(Environment.CurrentDirectory, ExecutableName));

        string? programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!string.IsNullOrWhiteSpace(programFilesX86))
        {
            candidates.Add(Path.Combine(programFilesX86, "SCE", "Prospero", "Tools",
                "Publishing Tools", "bin", ExecutableName));
        }

        string? fromPath = FindOnPath(ExecutableName);
        if (fromPath is not null)
            candidates.Add(fromPath);

        foreach (string candidate in candidates)
        {
            string expanded = Environment.ExpandEnvironmentVariables(candidate.Trim().Trim('"'));
            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(expanded);
            }
            catch (Exception) when (expanded.Length > 0)
            {
                continue;
            }

            if (File.Exists(fullPath))
                return fullPath;
        }

        throw new FileNotFoundException(
            $"{ExecutableName} was not found. Use --tool <path> or set {EnvironmentVariable}.");
    }

    private static string? FindOnPath(string fileName)
    {
        string? path = Environment.GetEnvironmentVariable("PATH");
        if (string.IsNullOrWhiteSpace(path))
            return null;

        foreach (string directory in path.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            string clean = directory.Trim().Trim('"');
            if (clean.Length == 0)
                continue;

            try
            {
                string candidate = Path.Combine(clean, fileName);
                if (File.Exists(candidate))
                    return candidate;
            }
            catch (Exception)
            {
                // Ignore malformed PATH entries and continue discovery.
            }
        }

        return null;
    }
}

