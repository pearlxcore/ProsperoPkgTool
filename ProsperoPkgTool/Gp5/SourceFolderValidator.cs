using System.Text.Json;

namespace ProsperoPkgTool.Gp5;

public sealed record SourceFolderInspection(
    string RootPath,
    ProsperoParam? Param,
    PlayGoProject? PlayGo,
    IReadOnlyList<string> IncludedFiles,
    IReadOnlyList<string> ExcludedFiles,
    ValidationReport Validation);

public static class SourceFolderValidator
{
    public static SourceFolderInspection Inspect(string sourceDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceDirectory);
        string root = Path.GetFullPath(sourceDirectory);
        var report = new ValidationReport();
        if (!Directory.Exists(root))
        {
            report.Error("SOURCE_DIRECTORY", "Source directory does not exist.", root);
            return new SourceFolderInspection(root, null, null, [], [], report);
        }

        string paramPath = Path.Combine(root, "sce_sys", "param.json");
        ProsperoParam? param = null;
        if (!File.Exists(paramPath))
        {
            report.Error("PARAM_MISSING", "sce_sys/param.json is required.", paramPath);
        }
        else
        {
            try
            {
                param = ProsperoParamReader.Read(paramPath);
            }
            catch (Exception exception) when (exception is IOException or JsonException or InvalidDataException)
            {
                report.Error("PARAM_INVALID", exception.Message, paramPath);
            }
        }

        if (param?.ApplicationCategoryType == 0)
        {
            if (!File.Exists(Path.Combine(root, "eboot.bin")))
                report.Error("EBOOT_MISSING", "Application source requires eboot.bin.", Path.Combine(root, "eboot.bin"));
            if (param.ApplicationDrmType == "free")
                report.Error("PARAM_DRM_COMBINATION",
                    "Sony Publishing Tools 1.21 rejects applicationCategoryType 0 with applicationDrmType 'free'.",
                    paramPath);
            WarnIfMissing(report, root, "sce_sys/pic0.png", "Sony verification requires pic0.png for an original application package.");
            WarnIfMissing(report, root, "sce_sys/pic1.png", "Sony verification requires pic1.png for an original application package.");
            WarnIfMissing(report, root, "sce_sys/pic2.png", "Sony verification requires pic2.png for an original application package.");
            if (!Directory.Exists(Path.Combine(root, "sce_module")))
                report.Warning("SCE_MODULE_MISSING",
                    "Sony verification requires sce_module for an original application package.",
                    Path.Combine(root, "sce_module"));
        }
        if (!File.Exists(Path.Combine(root, "sce_sys", "icon0.png")))
            report.Warning("ICON_MISSING", "sce_sys/icon0.png is not present.", Path.Combine(root, "sce_sys", "icon0.png"));

        PlayGoProject? playGo = null;
        string playGoPath = Path.Combine(root, "sce_sys", "playgo-chunk.dat");
        if (File.Exists(playGoPath))
        {
            try
            {
                playGo = PlayGoChunkReader.Read(playGoPath);
                if (param is not null && playGo.ContentId.Length > 0 &&
                    !playGo.ContentId.Equals(param.ContentId, StringComparison.Ordinal))
                    report.Error("PLAYGO_CONTENT_ID", "PlayGo content ID does not match param.json.", playGoPath);
            }
            catch (Exception exception) when (exception is IOException or InvalidDataException)
            {
                report.Error("PLAYGO_INVALID", exception.Message, playGoPath);
            }
        }
        else if (param?.ApplicationCategoryType == 0)
        {
            report.Warning("PLAYGO_DEFAULT", "playgo-chunk.dat is absent; a one-chunk default will be generated.", playGoPath);
        }

        var included = new List<string>();
        var excluded = new List<string>();
        Enumerate(root, root, included, excluded, report);
        included.Sort(StringComparer.Ordinal);
        excluded.Sort(StringComparer.Ordinal);
        return new SourceFolderInspection(root, param, playGo, included, excluded, report);
    }

    private static void WarnIfMissing(ValidationReport report, string root, string relativePath, string message)
    {
        string fullPath = Path.Combine(root, relativePath.Replace('/', Path.DirectorySeparatorChar));
        if (!File.Exists(fullPath))
            report.Warning("MEDIA_MISSING", message, fullPath);
    }

    public static bool IsPublishingArtifact(string relativePath)
    {
        string path = relativePath.Replace('\\', '/').TrimStart('/');
        if (path.StartsWith("sce_suppl/", StringComparison.OrdinalIgnoreCase))
            return true;

        string lower = path.ToLowerInvariant();
        if (lower.StartsWith("sce_sys/about/", StringComparison.Ordinal) ||
            lower.EndsWith(".esbak", StringComparison.Ordinal))
            return true;
        if (lower is "sce_sys/playgo-chunk.dat" or "sce_sys/playgo-ficm.dat" or
            "sce_sys/playgo-hash-table.dat" or "sce_sys/imagedigs.dat" or
            "sce_sys/pfs-version.dat" or "sce_sys/keystone" or
            "sce_sys/npbind.dat" or
            "sce_sys/ext_info.dat" or "disc_info.dat")
            return true;

        string fileName = Path.GetFileName(path);
        string directory = Path.GetDirectoryName(path)?.Replace('\\', '/') ?? string.Empty;
        if (directory.Equals("sce_sys", StringComparison.OrdinalIgnoreCase) &&
            (fileName.StartsWith("icon", StringComparison.OrdinalIgnoreCase) ||
             fileName.StartsWith("pic", StringComparison.OrdinalIgnoreCase)) &&
            Path.GetExtension(fileName).Equals(".dds", StringComparison.OrdinalIgnoreCase))
            return true;

        string extension = Path.GetExtension(fileName);
        return extension.Equals(".gp5", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".pkg", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".naps_metric.json", StringComparison.OrdinalIgnoreCase);
    }

    private static void Enumerate(
        string root,
        string directory,
        ICollection<string> included,
        ICollection<string> excluded,
        ValidationReport report)
    {
        IEnumerable<string> files;
        IEnumerable<string> directories;
        try
        {
            files = Directory.EnumerateFiles(directory).Order(StringComparer.Ordinal).ToArray();
            directories = Directory.EnumerateDirectories(directory).Order(StringComparer.Ordinal).ToArray();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            report.Error("SOURCE_ENUMERATION", exception.Message, directory);
            return;
        }

        foreach (string file in files)
        {
            string relative = Path.GetRelativePath(root, file).Replace('\\', '/');
            if (IsPublishingArtifact(relative))
                excluded.Add(relative);
            else
                included.Add(relative);
        }

        foreach (string child in directories)
        {
            FileAttributes attributes;
            try
            {
                attributes = File.GetAttributes(child);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                report.Error("SOURCE_ATTRIBUTES", exception.Message, child);
                continue;
            }

            if (attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                report.Warning("REPARSE_POINT", "Reparse-point directory was skipped.", child);
                continue;
            }
            string relative = Path.GetRelativePath(root, child).Replace('\\', '/');
            if (relative.Equals("sce_suppl", StringComparison.OrdinalIgnoreCase))
            {
                excluded.Add(relative + "/");
                continue;
            }
            Enumerate(root, child, included, excluded, report);
        }
    }
}
