namespace ProsperoPkgTool.Gp5;

/// <summary>One concrete file selected by a GP5 project manifest, resolved to a source on disk.</summary>
public sealed record Gp5ManifestFile(
    string DestinationPath,
    string SourceFullPath,
    int? Chunk,
    string? PfsCompression);

/// <summary>
/// Resolves a GP5 project's content tree into an ordered, concrete set of source files. The GP5
/// manifest is authoritative for package creation: unlike folder enumeration it fixes the exact
/// destination paths, the per-entry PlayGo chunk ownership, and the explicit source locations.
/// Paths are resolved with <see cref="Gp5Path.ResolveSource"/> (project-relative unless the
/// <c>src_path</c> is drive-qualified or a UNC path).
/// </summary>
public static class Gp5Manifest
{
    public static IReadOnlyList<Gp5ManifestFile> Resolve(Gp5Project project, string projectPath)
    {
        ArgumentNullException.ThrowIfNull(project);
        ArgumentException.ThrowIfNullOrWhiteSpace(projectPath);
        string fullProjectPath = Path.GetFullPath(projectPath);
        var results = new List<Gp5ManifestFile>();
        var destinations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (project.Layout == Gp5ContentLayout.FlatFiles)
        {
            foreach (Gp5FileEntry file in project.Files)
                AddFile(file, string.Empty, fullProjectPath, results, destinations);
        }
        else
        {
            WalkDirectory(project.RootDirectory, string.Empty, fullProjectPath, results, destinations);
        }
        return results;
    }

    private static void WalkDirectory(
        Gp5DirectoryEntry directory,
        string prefix,
        string projectPath,
        ICollection<Gp5ManifestFile> results,
        ISet<string> destinations)
    {
        string current = Combine(prefix, directory.DestinationPath);
        foreach (Gp5ContentEntry child in directory.Children)
        {
            if (child is Gp5DirectoryEntry nested)
                WalkDirectory(nested, current, projectPath, results, destinations);
            else if (child is Gp5FileEntry file)
                AddFile(file, current, projectPath, results, destinations);
        }
    }

    private static void AddFile(
        Gp5FileEntry file,
        string prefix,
        string projectPath,
        ICollection<Gp5ManifestFile> results,
        ISet<string> destinations)
    {
        string destination = Combine(prefix, file.DestinationPath, required: true);
        if (!destinations.Add(destination))
            throw new InvalidDataException($"GP5 assigns the destination path '{destination}' more than once.");

        string sourceRaw = string.IsNullOrWhiteSpace(file.SourcePath) ? file.DestinationPath : file.SourcePath;
        string source = Gp5Path.ResolveSource(projectPath, sourceRaw);
        if (!File.Exists(source))
            throw new InvalidDataException($"GP5 source file does not exist: {sourceRaw}.");

        results.Add(new Gp5ManifestFile(destination, source, file.Chunk, file.PfsCompression));
    }

    private static string Combine(string prefix, string? path, bool required = false)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            if (required)
                throw new InvalidDataException("GP5 file entry is missing its dst_path.");
            return prefix;
        }

        string normalized;
        try
        {
            normalized = Gp5Path.NormalizeDestination(path);
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(exception.Message, exception);
        }
        return string.IsNullOrEmpty(prefix) ? normalized : prefix + "/" + normalized;
    }
}
