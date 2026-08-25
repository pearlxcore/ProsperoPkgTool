using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Gp5;
using ProsperoPkgTool.Sony;

namespace ProsperoPkgTool;

public static class CliApplication
{
    private static readonly IReadOnlyDictionary<string, string> FriendlyAliases =
        new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["info"] = "img_info",
            ["list"] = "img_file_list",
            ["extract"] = "img_extract",
            ["verify"] = "img_verify",
            ["build"] = "img_create",
            ["keystone"] = "ks_create",
            ["fingerprint"] = "pc_fingerprint",
            ["loudness"] = "file_calc_loudness",
        };

    public static async Task<int> RunAsync(string[] inputArgs, CancellationToken cancellationToken = default)
    {
        (string? toolPath, string[] args) = ExtractGlobalToolOption(inputArgs);

        if (args.Length == 0 || args is ["-h"] or ["--help"])
        {
            PrintUsage();
            return 0;
        }

        string command = args[0];
        string[] commandArgs = args[1..];

        try
        {
            switch (command.ToLowerInvariant())
            {
                case "commands":
                    PrintCommands();
                    return 0;
                case "formats":
                    PrintFormats();
                    return 0;
                case "tool-path":
                    Console.WriteLine(SonyToolLocator.Resolve(toolPath));
                    return 0;
                case "tool-version":
                    return await InvokeSonyAsync(toolPath, ["version"], cancellationToken).ConfigureAwait(false);
                case "registry-check":
                    return await VerifyRegistryAsync(toolPath, cancellationToken).ConfigureAwait(false);
                case "sony":
                    return await RunSonyNamespaceAsync(toolPath, commandArgs, cancellationToken).ConfigureAwait(false);
                case "command-help":
                    PrintCommandHelp(commandArgs);
                    return 0;
                case "gp5gen":
                    return RunGp5Generate(commandArgs);
                case "gp5info":
                    return RunGp5Info(commandArgs);
                case "gp5validate":
                case "gp5-validate":
                    return RunGp5Validate(commandArgs);
                case "gp5format":
                case "gp5-format":
                    return RunGp5Format(commandArgs);
                case "source-validate":
                    return RunSourceValidate(commandArgs);
                case "playgo-info":
                    return RunPlayGoInfo(commandArgs);
            }

            if (FriendlyAliases.TryGetValue(command, out string? sonyAlias))
                return await InvokeSonyAsync(toolPath, [sonyAlias, .. commandArgs], cancellationToken).ConfigureAwait(false);

            if (SonyCommandRegistry.TryGet(command, out _))
                return await InvokeSonyAsync(toolPath, [command, .. commandArgs], cancellationToken).ConfigureAwait(false);

            Console.Error.WriteLine($"Unknown command '{command}'. Run 'ProsperoPkgTool commands' for the complete list.");
            return 2;
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Operation cancelled.");
            return 130;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            Console.Error.WriteLine($"Error: {exception.Message}");
            return 2;
        }
    }

    private static async Task<int> RunSonyNamespaceAsync(
        string? toolPath,
        string[] args,
        CancellationToken cancellationToken)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool sony <command> [arguments]");
            Console.Error.WriteLine("       ProsperoPkgTool sony raw <arguments>");
            return 2;
        }

        if (args[0].Equals("raw", StringComparison.OrdinalIgnoreCase))
            return await InvokeSonyAsync(toolPath, args[1..], cancellationToken).ConfigureAwait(false);

        if (!SonyCommandRegistry.TryGet(args[0], out _))
        {
            Console.Error.WriteLine($"Sony command '{args[0]}' is not registered. Use 'sony raw' to pass it through explicitly.");
            return 2;
        }

        return await InvokeSonyAsync(toolPath, args, cancellationToken).ConfigureAwait(false);
    }

    private static async Task<int> InvokeSonyAsync(
        string? toolPath,
        IReadOnlyList<string> args,
        CancellationToken cancellationToken)
    {
        string executable = SonyToolLocator.Resolve(toolPath);
        var backend = new SonyPublishingBackend(executable);
        SonyProcessResult result = await backend.RunAsync(args, line =>
        {
            TextWriter writer = line.IsError ? Console.Error : Console.Out;
            writer.WriteLine(line.Text);
        }, cancellationToken).ConfigureAwait(false);
        return result.ExitCode;
    }

    private static async Task<int> VerifyRegistryAsync(string? toolPath, CancellationToken cancellationToken)
    {
        string executable = SonyToolLocator.Resolve(toolPath);
        var backend = new SonyPublishingBackend(executable);
        SonyProcessResult list = await backend.RunAsync([], cancellationToken: cancellationToken).ConfigureAwait(false);
        SonyProcessResult details = await backend.RunAsync(["helpall"], cancellationToken: cancellationToken).ConfigureAwait(false);
        string listText = list.StandardOutput + list.StandardError;
        string detailText = details.StandardOutput + details.StandardError;
        SonyRegistryMismatch mismatch = SonyRegistryVerifier.Compare(listText, detailText);
        int discovered = SonyHelpParser.ParseAvailableCommands(listText).Count;

        Console.WriteLine($"Sony tool: {executable}");
        Console.WriteLine($"Discovered commands: {discovered}");
        Console.WriteLine($"Registered commands: {SonyCommandRegistry.All.Count}");
        PrintItems("Missing commands", mismatch.MissingCommands);
        PrintItems("Unknown commands", mismatch.UnknownCommands);
        PrintOptionItems("Missing options", mismatch.MissingOptions);
        PrintOptionItems("Unknown options", mismatch.UnknownOptions);
        Console.WriteLine(mismatch.IsComplete ? "Registry is complete." : "Registry mismatch detected.");
        return mismatch.IsComplete ? 0 : 3;
    }

    private static int RunGp5Generate(string[] args)
    {
        if (args.Length == 0)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool gp5gen <source-folder> [--out <file>] [--passcode <32 chars>] [--force]");
            return 2;
        }

        string source = args[0];
        string? output = null;
        string passcode = Gp5Constants.DefaultPasscode;
        bool force = false;
        for (int index = 1; index < args.Length; index++)
        {
            switch (args[index])
            {
                case "--out" when index + 1 < args.Length:
                    output = args[++index];
                    break;
                case "--passcode" when index + 1 < args.Length:
                    passcode = args[++index];
                    break;
                case "--force":
                    force = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown or incomplete gp5gen option '{args[index]}'.");
            }
        }

        string root = Path.GetFullPath(source);
        SourceFolderInspection initial = SourceFolderValidator.Inspect(root);
        if (initial.Param is null)
        {
            PrintValidation(initial.Validation);
            return 4;
        }
        output = Path.GetFullPath(output ?? Path.Combine(root, initial.Param.TitleId + ".gp5"));
        string outputDirectory = Path.GetDirectoryName(output)!;
        if (!outputDirectory.Equals(Path.TrimEndingDirectorySeparator(root), StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Generated GP5 must be written directly inside the source folder so relative source paths remain valid.");
        if (File.Exists(output) && !force)
            throw new IOException($"Output already exists: {output}. Use --force to replace it.");

        Gp5GenerationResult result = Gp5Generator.Generate(root,
            new Gp5GeneratorOptions { Passcode = passcode }, output);
        PrintValidation(result.Validation);
        if (!result.Validation.IsValid)
            return 4;

        Gp5Xml.Write(result.Project, output);
        Console.WriteLine($"Generated: {output}");
        Console.WriteLine($"Included files: {result.Source.IncludedFiles.Count}");
        Console.WriteLine($"Excluded artifacts: {result.Source.ExcludedFiles.Count}");
        return 0;
    }

    private static int RunGp5Info(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool gp5info <project.gp5>");
            return 2;
        }
        Gp5Project project = Gp5Xml.Read(args[0]);
        Console.WriteLine($"Format: {project.Format}");
        Console.WriteLine($"Version: {project.Version ?? "(unspecified)"}");
        Console.WriteLine($"Volume type: {project.Volume.VolumeType}");
        Console.WriteLine($"Content ID: {project.Volume.Package.ContentId ?? "(from param.json)"}");
        Console.WriteLine($"Layout: {project.Layout}");
        Console.WriteLine($"Files: {(project.Layout == Gp5ContentLayout.FlatFiles ? project.Files.Count : CountEntries(project.RootDirectory))}");
        if (project.Volume.ChunkInfo is { } chunkInfo)
        {
            Console.WriteLine($"Chunks: {chunkInfo.Chunks.Count}");
            Console.WriteLine($"Scenarios: {chunkInfo.Scenarios.Count} (default {chunkInfo.DefaultScenarioId})");
        }
        return 0;
    }

    private static int RunGp5Validate(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool gp5validate <project.gp5>");
            return 2;
        }
        string path = Path.GetFullPath(args[0]);
        Gp5Project project = Gp5Xml.Read(path);
        ValidationReport report = Gp5Validator.Validate(project, path);
        PrintValidation(report);
        return report.IsValid ? 0 : 4;
    }

    private static int RunGp5Format(string[] args)
    {
        if (args.Length < 3 || !args[1].Equals("--out", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool gp5format <input.gp5> --out <output.gp5> [--force]");
            return 2;
        }
        string input = Path.GetFullPath(args[0]);
        string output = Path.GetFullPath(args[2]);
        bool force = args.Skip(3).Any(argument => argument.Equals("--force", StringComparison.OrdinalIgnoreCase));
        if (args.Skip(3).Any(argument => !argument.Equals("--force", StringComparison.OrdinalIgnoreCase)))
            throw new ArgumentException("Unknown gp5format option.");
        if (input.Equals(output, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("gp5format requires a separate output path.");
        if (File.Exists(output) && !force)
            throw new IOException($"Output already exists: {output}. Use --force to replace it.");
        Gp5Project project = Gp5Xml.Read(input);
        ValidationReport report = Gp5Validator.Validate(project, input);
        PrintValidation(report);
        if (!report.IsValid)
            return 4;
        Gp5Xml.Write(project, output);
        Console.WriteLine($"Formatted: {output}");
        return 0;
    }

    private static int RunSourceValidate(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool source-validate <source-folder>");
            return 2;
        }
        SourceFolderInspection source = SourceFolderValidator.Inspect(args[0]);
        if (source.Param is { } param)
        {
            Console.WriteLine($"Title ID: {param.TitleId}");
            Console.WriteLine($"Content ID: {param.ContentId}");
            Console.WriteLine($"Content version: {param.ContentVersion ?? "(unspecified)"}");
            Console.WriteLine($"Volume type: {param.VolumeType}");
        }
        Console.WriteLine($"Included files: {source.IncludedFiles.Count}");
        Console.WriteLine($"Excluded artifacts: {source.ExcludedFiles.Count}");
        PrintValidation(source.Validation);
        return source.Validation.IsValid ? 0 : 4;
    }

    private static int RunPlayGoInfo(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool playgo-info <playgo-chunk.dat>");
            return 2;
        }
        PlayGoProject playGo = PlayGoChunkReader.Read(args[0]);
        Console.WriteLine($"Version: {playGo.VersionMajor:X4}.{playGo.VersionMinor:X4}");
        Console.WriteLine($"Content ID: {playGo.ContentId}");
        Console.WriteLine($"Chunks: {playGo.Chunks.Count}");
        foreach (PlayGoChunk chunk in playGo.Chunks)
            Console.WriteLine($"  {chunk.Id}: {chunk.Label} language-mask=0x{chunk.LanguageMask:X16}");
        Console.WriteLine($"Scenarios: {playGo.Scenarios.Count} (default {playGo.DefaultScenarioId})");
        foreach (PlayGoScenario scenario in playGo.Scenarios)
            Console.WriteLine($"  {scenario.Id}: {scenario.Label} initial={scenario.InitialChunkCount} sequence={Gp5Generator.FormatSequence(scenario.Chunks)}");
        return 0;
    }

    private static void PrintValidation(ValidationReport report)
    {
        foreach (ValidationIssue issue in report.Issues)
        {
            TextWriter writer = issue.Severity == ValidationSeverity.Error ? Console.Error : Console.Out;
            writer.WriteLine($"{issue.Severity}: {issue.Code}: {issue.Message}{(issue.Path is null ? string.Empty : $" [{issue.Path}]")}");
        }
        Console.WriteLine($"Validation: {report.ErrorCount} error(s), {report.WarningCount} warning(s).");
    }

    private static int CountEntries(Gp5DirectoryEntry directory) =>
        directory.Children.Sum(child => 1 + (child is Gp5DirectoryEntry nested ? CountEntries(nested) : 0));

    private static void PrintCommandHelp(string[] args)
    {
        if (args.Length != 1 || !SonyCommandRegistry.TryGet(args[0], out SonyCommandDefinition? command))
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool command-help <sony-command>");
            return;
        }

        Console.WriteLine(command.Name);
        Console.WriteLine(command.Description);
        Console.WriteLine($"Group: {command.Group}");
        Console.WriteLine($"Risk: {command.Risk}");
        if (command.Options.Count == 0)
        {
            Console.WriteLine("Options: none");
            return;
        }

        Console.WriteLine("Options:");
        foreach (SonyCommandOption option in command.Options)
            Console.WriteLine($"  {option.Name}{(option.TakesValue ? " <value>" : string.Empty)}{(option.ValueHint is null ? string.Empty : $"  [{option.ValueHint}]")}");
    }

    private static void PrintCommands()
    {
        foreach (IGrouping<string, SonyCommandDefinition> group in SonyCommandRegistry.All.GroupBy(command => command.Group))
        {
            Console.WriteLine(group.Key);
            foreach (SonyCommandDefinition command in group)
                Console.WriteLine($"  {command.Name,-24} {command.Description}");
            Console.WriteLine();
        }
        Console.WriteLine($"Total Sony commands: {SonyCommandRegistry.All.Count}");
    }

    private static void PrintFormats()
    {
        foreach (ContainerBackendDescriptor backend in ContainerBackendCatalog.All)
            Console.WriteLine($"{backend.FormatId,-10} {backend.Status,-12} {backend.DisplayName} [{backend.Capabilities}]");
    }

    private static void PrintUsage()
    {
        Console.WriteLine("ProsperoPkgTool 0.1 - PS5 publishing and container toolkit");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  ProsperoPkgTool [--tool <prospero-pub-cmd.exe>] <command> [arguments]");
        Console.WriteLine();
        Console.WriteLine("Foundation commands:");
        Console.WriteLine("  commands, formats, tool-path, tool-version, registry-check, command-help");
        Console.WriteLine("GP5 and source commands:");
        Console.WriteLine("  gp5gen, gp5info, gp5validate, gp5format, source-validate, playgo-info");
        Console.WriteLine("Friendly aliases:");
        Console.WriteLine("  info, list, extract, verify, build, keystone, fingerprint, loudness");
        Console.WriteLine("Sony commands:");
        Console.WriteLine("  sony <registered-command> [arguments]");
        Console.WriteLine("  sony raw <arguments>");
        Console.WriteLine("  <original-sony-command> [arguments]");
        Console.WriteLine();
        Console.WriteLine("Run 'ProsperoPkgTool commands' to list all 35 Sony 1.21 commands.");
    }

    private static (string? ToolPath, string[] Args) ExtractGlobalToolOption(string[] args)
    {
        var remaining = new List<string>(args.Length);
        string? toolPath = null;
        for (int index = 0; index < args.Length; index++)
        {
            if (!args[index].Equals("--tool", StringComparison.OrdinalIgnoreCase))
            {
                remaining.Add(args[index]);
                continue;
            }

            if (index + 1 >= args.Length)
                throw new ArgumentException("--tool requires the path to prospero-pub-cmd.exe.");
            toolPath = args[++index];
        }
        return (toolPath, remaining.ToArray());
    }

    private static void PrintItems(string label, IReadOnlyList<string> items) =>
        Console.WriteLine($"{label}: {(items.Count == 0 ? "0" : string.Join(", ", items))}");

    private static void PrintOptionItems(string label, IReadOnlyDictionary<string, IReadOnlyList<string>> items)
    {
        Console.WriteLine($"{label}: {(items.Count == 0 ? "0" : items.Count)}");
        foreach ((string command, IReadOnlyList<string> options) in items)
            Console.WriteLine($"  {command}: {string.Join(", ", options)}");
    }
}
