namespace ProsperoPkgTool.Gp5;

public static class Gp5Path
{
    public static string ToProjectRelative(string relativePath)
    {
        string normalized = NormalizeRelative(relativePath);
        return "\\" + normalized.Replace('/', '\\');
    }

    public static string NormalizeDestination(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string normalized = path.Replace('\\', '/').TrimStart('/');
        if (normalized.Length == 0 || normalized.Contains(':', StringComparison.Ordinal))
            throw new ArgumentException("Destination path is empty or rooted.", nameof(path));

        string[] segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Any(segment => segment is "." or ".."))
            throw new ArgumentException("Destination path contains a traversal segment.", nameof(path));
        return string.Join('/', segments);
    }

    public static string ResolveSource(string projectPath, string sourcePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(sourcePath);
        string projectDirectory = Path.GetDirectoryName(Path.GetFullPath(projectPath))
            ?? Environment.CurrentDirectory;

        string normalized = sourcePath.Replace('/', Path.DirectorySeparatorChar)
            .Replace('\\', Path.DirectorySeparatorChar);

        // A single leading slash is the GP5 convention for a project-relative path.
        // UNC paths and drive-qualified paths remain genuinely absolute.
        bool driveQualified = normalized.Length >= 3 && char.IsAsciiLetter(normalized[0]) &&
                              normalized[1] == ':' && Path.IsPathFullyQualified(normalized);
        bool unc = normalized.StartsWith(new string(Path.DirectorySeparatorChar, 2), StringComparison.Ordinal);
        if (!driveQualified && !unc)
            normalized = normalized.TrimStart(Path.DirectorySeparatorChar);

        return driveQualified || unc
            ? Path.GetFullPath(normalized)
            : Path.GetFullPath(Path.Combine(projectDirectory, normalized));
    }

    public static bool IsWithin(string root, string candidate)
    {
        string fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        string fullCandidate = Path.GetFullPath(candidate);
        return fullCandidate.Equals(fullRoot, StringComparison.OrdinalIgnoreCase) ||
               fullCandidate.StartsWith(fullRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    private static string NormalizeRelative(string path)
    {
        string normalized = path.Replace('\\', '/').TrimStart('/');
        string[] segments = normalized.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0 || segments.Any(segment => segment is "." or ".."))
            throw new ArgumentException("Path must be a contained relative path.", nameof(path));
        return string.Join('/', segments);
    }
}

