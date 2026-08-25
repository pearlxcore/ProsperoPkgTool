using System.Globalization;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace ProsperoPkgTool.Gp5;

public static class Gp5Xml
{
    public static Gp5Project Read(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using FileStream stream = File.OpenRead(path);
        return Read(stream);
    }

    public static Gp5Project Read(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreWhitespace = true,
            CloseInput = false,
        };
        using XmlReader reader = XmlReader.Create(stream, settings);
        XDocument document = XDocument.Load(reader, LoadOptions.SetLineInfo);
        XElement root = document.Root ?? throw new InvalidDataException("GP5 XML has no document element.");
        if (root.Name != "psproject")
            throw Error(root, "GP5 root element must be <psproject>.");

        var project = new Gp5Project
        {
            Format = Attribute(root, "fmt") ?? string.Empty,
            Version = Attribute(root, "version"),
        };
        CaptureExtraAttributes(root, project.ExtraAttributes, "fmt", "version");

        XElement volumeElement = SingleRequired(root, "volume");
        project.Volume = ParseVolume(volumeElement);

        XElement? files = SingleOptional(root, "files");
        XElement? rootDirectory = SingleOptional(root, "rootdir");
        if (files is not null && rootDirectory is not null)
            throw Error(root, "GP5 cannot contain both <files> and <rootdir>.");
        if (files is null && rootDirectory is null)
            throw Error(root, "GP5 must contain either <files> or <rootdir>.");

        if (files is not null)
        {
            EnsureOnlyChildren(files, "file");
            project.Layout = Gp5ContentLayout.FlatFiles;
            foreach (XElement file in files.Elements("file"))
                project.Files.Add(ParseFile(file));
        }
        else
        {
            project.Layout = Gp5ContentLayout.RootDirectory;
            project.RootDirectory = ParseDirectory(rootDirectory!, isRoot: true);
        }

        EnsureOnlyChildren(root, "volume", "files", "rootdir");
        return project;
    }

    public static void Write(Gp5Project project, string path)
    {
        ArgumentNullException.ThrowIfNull(project);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string fullPath = Path.GetFullPath(path);
        string? directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
            Directory.CreateDirectory(directory);
        using FileStream stream = new(fullPath, FileMode.Create, FileAccess.Write, FileShare.None);
        Write(project, stream);
    }

    public static void Write(Gp5Project project, Stream stream)
    {
        ArgumentNullException.ThrowIfNull(project);
        ArgumentNullException.ThrowIfNull(stream);

        var root = new XElement("psproject", new XAttribute("fmt", project.Format));
        if (!string.IsNullOrWhiteSpace(project.Version))
            root.Add(new XAttribute("version", project.Version));
        AddExtraAttributes(root, project.ExtraAttributes, "fmt", "version");
        root.Add(WriteVolume(project.Volume));

        if (project.Layout == Gp5ContentLayout.FlatFiles)
        {
            var files = new XElement("files");
            foreach (Gp5FileEntry file in project.Files)
                files.Add(WriteFile(file));
            root.Add(files);
        }
        else
        {
            root.Add(WriteDirectory(project.RootDirectory, isRoot: true));
        }

        var document = new XDocument(new XDeclaration("1.0", "utf-8", "no"), root);
        var settings = new XmlWriterSettings
        {
            Encoding = new UTF8Encoding(false),
            Indent = true,
            IndentChars = "\t",
            NewLineChars = "\r\n",
            NewLineHandling = NewLineHandling.Replace,
            OmitXmlDeclaration = false,
            CloseOutput = false,
        };
        using XmlWriter writer = XmlWriter.Create(stream, settings);
        document.Save(writer);
    }

    private static Gp5Volume ParseVolume(XElement element)
    {
        EnsureOnlyChildren(element, "volume_type", "package", "chunk_info");
        return new Gp5Volume
        {
            VolumeType = SingleRequired(element, "volume_type").Value.Trim(),
            Package = ParsePackage(SingleRequired(element, "package")),
            ChunkInfo = SingleOptional(element, "chunk_info") is { } chunkInfo ? ParseChunkInfo(chunkInfo) : null,
        };
    }

    private static Gp5Package ParsePackage(XElement element)
    {
        EnsureNoElements(element);
        var package = new Gp5Package
        {
            ContentId = Attribute(element, "content_id"),
            Passcode = Attribute(element, "passcode") ?? string.Empty,
            CreationDate = Attribute(element, "c_date"),
            EntitlementKey = Attribute(element, "entitlement_key"),
            StorageType = Attribute(element, "storage_type"),
            AppType = Attribute(element, "app_type"),
        };
        CaptureExtraAttributes(element, package.ExtraAttributes,
            "content_id", "passcode", "c_date", "entitlement_key", "storage_type", "app_type");
        return package;
    }

    private static Gp5ChunkInfo ParseChunkInfo(XElement element)
    {
        EnsureOnlyChildren(element, "chunks", "scenarios");
        XElement chunks = SingleRequired(element, "chunks");
        XElement scenarios = SingleRequired(element, "scenarios");
        EnsureOnlyChildren(chunks, "chunk");
        EnsureOnlyChildren(scenarios, "scenario");

        var info = new Gp5ChunkInfo
        {
            ChunkCount = IntAttribute(element, "chunk_count"),
            ScenarioCount = IntAttribute(element, "scenario_count"),
            SupportedLanguages = Attribute(chunks, "supported_languages"),
            DefaultLanguage = Attribute(chunks, "default_language"),
            DefaultScenarioId = IntAttribute(scenarios, "default_id"),
        };

        foreach (XElement chunkElement in chunks.Elements("chunk"))
        {
            EnsureNoElements(chunkElement);
            var chunk = new Gp5Chunk
            {
                Id = IntAttribute(chunkElement, "id"),
                Label = Attribute(chunkElement, "label") ?? string.Empty,
                Languages = Attribute(chunkElement, "languages"),
            };
            CaptureExtraAttributes(chunkElement, chunk.ExtraAttributes, "id", "label", "languages");
            info.Chunks.Add(chunk);
        }

        foreach (XElement scenarioElement in scenarios.Elements("scenario"))
        {
            EnsureNoElements(scenarioElement);
            var scenario = new Gp5Scenario
            {
                Id = IntAttribute(scenarioElement, "id"),
                Type = Attribute(scenarioElement, "type") ?? string.Empty,
                InitialChunkCount = IntAttribute(scenarioElement, "initial_chunk_count"),
                Label = Attribute(scenarioElement, "label") ?? string.Empty,
                Sequence = scenarioElement.Value.Trim(),
            };
            CaptureExtraAttributes(scenarioElement, scenario.ExtraAttributes,
                "id", "type", "initial_chunk_count", "label");
            info.Scenarios.Add(scenario);
        }
        return info;
    }

    private static Gp5FileEntry ParseFile(XElement element)
    {
        EnsureNoElements(element);
        var file = new Gp5FileEntry();
        ParseContentAttributes(element, file);
        return file;
    }

    private static Gp5DirectoryEntry ParseDirectory(XElement element, bool isRoot)
    {
        EnsureOnlyChildren(element, "file", "dir");
        var directory = new Gp5DirectoryEntry
        {
            IsRoot = isRoot,
            Virtual = OptionalBoolAttribute(element, "virtual"),
            DirectoryExclude = Attribute(element, "dir_exclude"),
            FileExclude = Attribute(element, "file_exclude"),
        };
        ParseContentAttributes(element, directory, "virtual", "dir_exclude", "file_exclude");
        foreach (XElement child in element.Elements())
        {
            directory.Children.Add(child.Name == "file"
                ? ParseFile(child)
                : ParseDirectory(child, isRoot: false));
        }
        return directory;
    }

    private static void ParseContentAttributes(XElement element, Gp5ContentEntry entry, params string[] additionalKnown)
    {
        entry.DestinationPath = Attribute(element, "dst_path") ?? string.Empty;
        entry.SourcePath = Attribute(element, "src_path");
        entry.Chunk = OptionalIntAttribute(element, "chunk");
        entry.ContentConfigLabel = Attribute(element, "content_config_label");
        entry.PfsCompression = Attribute(element, "pfs_compression");
        string[] known = ["dst_path", "src_path", "chunk", "content_config_label", "pfs_compression", .. additionalKnown];
        CaptureExtraAttributes(element, entry.ExtraAttributes, known);
    }

    private static XElement WriteVolume(Gp5Volume volume)
    {
        var element = new XElement("volume",
            new XElement("volume_type", volume.VolumeType),
            WritePackage(volume.Package));
        if (volume.ChunkInfo is not null)
            element.Add(WriteChunkInfo(volume.ChunkInfo));
        return element;
    }

    private static XElement WritePackage(Gp5Package package)
    {
        var element = new XElement("package");
        AddOptionalAttribute(element, "content_id", package.ContentId);
        AddOptionalAttribute(element, "passcode", package.Passcode);
        AddOptionalAttribute(element, "c_date", package.CreationDate);
        AddOptionalAttribute(element, "entitlement_key", package.EntitlementKey);
        AddOptionalAttribute(element, "storage_type", package.StorageType);
        AddOptionalAttribute(element, "app_type", package.AppType);
        AddExtraAttributes(element, package.ExtraAttributes,
            "content_id", "passcode", "c_date", "entitlement_key", "storage_type", "app_type");
        return element;
    }

    private static XElement WriteChunkInfo(Gp5ChunkInfo info)
    {
        var chunks = new XElement("chunks");
        AddOptionalAttribute(chunks, "supported_languages", info.SupportedLanguages);
        AddOptionalAttribute(chunks, "default_language", info.DefaultLanguage);
        foreach (Gp5Chunk chunk in info.Chunks)
        {
            var element = new XElement("chunk", new XAttribute("id", chunk.Id));
            AddOptionalAttribute(element, "languages", chunk.Languages);
            AddOptionalAttribute(element, "label", chunk.Label);
            AddExtraAttributes(element, chunk.ExtraAttributes, "id", "languages", "label");
            chunks.Add(element);
        }

        var scenarios = new XElement("scenarios", new XAttribute("default_id", info.DefaultScenarioId));
        foreach (Gp5Scenario scenario in info.Scenarios)
        {
            var element = new XElement("scenario",
                new XAttribute("id", scenario.Id),
                new XAttribute("initial_chunk_count", scenario.InitialChunkCount),
                new XAttribute("label", scenario.Label),
                new XAttribute("type", scenario.Type),
                scenario.Sequence);
            AddExtraAttributes(element, scenario.ExtraAttributes,
                "id", "initial_chunk_count", "label", "type");
            scenarios.Add(element);
        }

        return new XElement("chunk_info",
            new XAttribute("chunk_count", info.ChunkCount),
            new XAttribute("scenario_count", info.ScenarioCount),
            chunks,
            scenarios);
    }

    private static XElement WriteFile(Gp5FileEntry file)
    {
        var element = new XElement("file");
        WriteContentAttributes(element, file);
        return element;
    }

    private static XElement WriteDirectory(Gp5DirectoryEntry directory, bool isRoot)
    {
        var element = new XElement(isRoot ? "rootdir" : "dir");
        if (directory.Virtual.HasValue)
            element.Add(new XAttribute("virtual", directory.Virtual.Value ? "true" : "false"));
        AddOptionalAttribute(element, "dir_exclude", directory.DirectoryExclude);
        AddOptionalAttribute(element, "file_exclude", directory.FileExclude);
        WriteContentAttributes(element, directory, "virtual", "dir_exclude", "file_exclude");
        foreach (Gp5ContentEntry child in directory.Children)
            element.Add(child is Gp5FileEntry file ? WriteFile(file) : WriteDirectory((Gp5DirectoryEntry)child, false));
        return element;
    }

    private static void WriteContentAttributes(XElement element, Gp5ContentEntry entry, params string[] additionalKnown)
    {
        AddOptionalAttribute(element, "dst_path", entry.DestinationPath);
        AddOptionalAttribute(element, "src_path", entry.SourcePath);
        if (entry.Chunk.HasValue)
            element.Add(new XAttribute("chunk", entry.Chunk.Value));
        AddOptionalAttribute(element, "content_config_label", entry.ContentConfigLabel);
        AddOptionalAttribute(element, "pfs_compression", entry.PfsCompression);
        string[] known = ["dst_path", "src_path", "chunk", "content_config_label", "pfs_compression", .. additionalKnown];
        AddExtraAttributes(element, entry.ExtraAttributes, known);
    }

    private static XElement SingleRequired(XElement parent, string name) =>
        SingleOptional(parent, name) ?? throw Error(parent, $"Missing required <{name}> element.");

    private static XElement? SingleOptional(XElement parent, string name)
    {
        XElement[] matches = parent.Elements(name).ToArray();
        if (matches.Length > 1)
            throw Error(matches[1], $"Duplicate <{name}> element.");
        return matches.SingleOrDefault();
    }

    private static string? Attribute(XElement element, string name) => element.Attribute(name)?.Value;

    private static int IntAttribute(XElement element, string name) =>
        OptionalIntAttribute(element, name) ?? throw Error(element, $"Missing required '{name}' attribute.");

    private static int? OptionalIntAttribute(XElement element, string name)
    {
        string? value = Attribute(element, name);
        if (value is null)
            return null;
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out int result) || result < 0)
            throw Error(element, $"Attribute '{name}' must be a non-negative integer.");
        return result;
    }

    private static bool? OptionalBoolAttribute(XElement element, string name)
    {
        string? value = Attribute(element, name);
        if (value is null)
            return null;
        if (!bool.TryParse(value, out bool result))
            throw Error(element, $"Attribute '{name}' must be true or false.");
        return result;
    }

    private static void EnsureOnlyChildren(XElement parent, params string[] allowed)
    {
        var set = allowed.ToHashSet(StringComparer.Ordinal);
        XElement? unexpected = parent.Elements().FirstOrDefault(child => !set.Contains(child.Name.LocalName));
        if (unexpected is not null)
            throw Error(unexpected, $"Unsupported <{unexpected.Name.LocalName}> element inside <{parent.Name.LocalName}>.");
    }

    private static void EnsureNoElements(XElement element)
    {
        if (element.HasElements)
            throw Error(element.Elements().First(), $"<{element.Name.LocalName}> cannot contain child elements.");
    }

    private static void CaptureExtraAttributes(
        XElement element,
        IDictionary<string, string> target,
        params string[] known)
    {
        var set = known.ToHashSet(StringComparer.Ordinal);
        foreach (XAttribute attribute in element.Attributes().Where(attribute => !attribute.IsNamespaceDeclaration))
        {
            if (!set.Contains(attribute.Name.LocalName))
                target[attribute.Name.LocalName] = attribute.Value;
        }
    }

    private static void AddExtraAttributes(XElement element, IReadOnlyDictionary<string, string> attributes, params string[] known)
    {
        var set = known.ToHashSet(StringComparer.Ordinal);
        foreach ((string name, string value) in attributes.OrderBy(item => item.Key, StringComparer.Ordinal))
        {
            if (!set.Contains(name) && element.Attribute(name) is null)
                element.Add(new XAttribute(name, value));
        }
    }

    private static void AddOptionalAttribute(XElement element, string name, string? value)
    {
        if (!string.IsNullOrEmpty(value))
            element.Add(new XAttribute(name, value));
    }

    private static InvalidDataException Error(XElement element, string message)
    {
        if (element is IXmlLineInfo lineInfo && lineInfo.HasLineInfo())
            return new InvalidDataException($"{message} Line {lineInfo.LineNumber}, position {lineInfo.LinePosition}.");
        return new InvalidDataException(message);
    }
}

