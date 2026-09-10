using System.Buffers.Binary;
using System.Text.Json;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Content;
using ProsperoPkgTool.Crypto;
using ProsperoPkgTool.Gp5;
using ProsperoPkgTool.Native;

namespace ProsperoPkgTool;

/// <summary>
/// ProsperoPkgTool command-line application. This is a fully native, clean-room PS5
/// package toolkit: it has no dependency on Sony's prospero-pub-cmd and no third-party
/// GPL code. Package reading, key derivation, and outer-PFS decryption are implemented
/// from scratch (see FINDINGS.md); package creation targets debug packages for
/// jailbroken consoles.
/// </summary>
public static class CliApplication
{
    public static Task<int> RunAsync(string[] args, CancellationToken cancellationToken = default)
    {
        if (args.Length == 0 || args is ["-h"] or ["--help"])
        {
            PrintUsage();
            return Task.FromResult(0);
        }

        string command = args[0];
        string[] commandArgs = args[1..];

        try
        {
            int result = command.ToLowerInvariant() switch
            {
                "formats" => PrintFormats(),
                "gp5gen" => RunGp5Generate(commandArgs),
                "gp5info" => RunGp5Info(commandArgs),
                "gp5validate" or "gp5-validate" => RunGp5Validate(commandArgs),
                "gp5format" or "gp5-format" => RunGp5Format(commandArgs),
                "source-validate" => RunSourceValidate(commandArgs),
                "playgo-info" => RunPlayGoInfo(commandArgs),
                "pkg-detect" => RunNativePackageInfo(commandArgs, validateOnly: false, kindOnly: true),
                "native-info" or "fih-info" => RunNativePackageInfo(commandArgs, validateOnly: false, kindOnly: false),
                "native-validate" or "fih-validate" => RunNativePackageInfo(commandArgs, validateOnly: true, kindOnly: false),
                "native-entries" or "cnt-entries" => RunNativePackageEntries(commandArgs),
                "native-decrypt" => RunNativeDecrypt(commandArgs),
                "img-info" or "img-blocks" or "img_info" => RunInnerImageInfo(commandArgs),
                "img-file-list" or "img_file_list" => RunInnerImageFileList(commandArgs),
                "img-extract" or "img_extract" => RunInnerImageExtract(commandArgs),
                "img-verify" or "img_verify" => RunInnerImageVerify(commandArgs),
                "img-create" or "img_create" => RunInnerImageCreate(commandArgs),
                "convert" or "backup-convert" or "backup_convert" => RunBackupConvert(commandArgs),
                "compare" => RunCompare(commandArgs),
                "fself" or "fake-sign" => RunFakeSign(commandArgs),
                _ => UnknownCommand(command),
            };
            return Task.FromResult(result);
        }
        catch (OperationCanceledException)
        {
            Console.Error.WriteLine("Operation cancelled.");
            return Task.FromResult(130);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or InvalidDataException)
        {
            Console.Error.WriteLine($"Error: {exception.Message}");
            return Task.FromResult(2);
        }
    }

    private static int UnknownCommand(string command)
    {
        Console.Error.WriteLine($"Unknown command '{command}'. Run 'ProsperoPkgTool --help' for the complete list.");
        return 2;
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

    private static int RunFakeSign(string[] args)
    {
        string? input = null;
        string? output = null;
        string? authorityHex = null;
        string? appVersionHex = null;
        string? firmwareVersionHex = null;
        string? sceVersionName = null;
        string? sceVersionFrom = null;
        bool force = false;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--out" when i + 1 < args.Length:
                    output = args[++i];
                    break;
                case "--authority" when i + 1 < args.Length:
                    authorityHex = args[++i];
                    break;
                case "--app-version" when i + 1 < args.Length:
                    appVersionHex = args[++i];
                    break;
                case "--fw-version" when i + 1 < args.Length:
                    firmwareVersionHex = args[++i];
                    break;
                case "--sceversion-name" when i + 1 < args.Length:
                    sceVersionName = args[++i];
                    break;
                case "--sceversion-from" when i + 1 < args.Length:
                    sceVersionFrom = args[++i];
                    break;
                case "--force":
                    force = true;
                    break;
                default:
                    if (args[i].StartsWith("--", StringComparison.Ordinal))
                        return UnknownOption(args[i]);
                    input ??= args[i];
                    break;
            }
        }
        if (input is null || output is null)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool fself <module.elf> --out <module.bin> [--authority <hex64>] [--app-version <hex64>] [--fw-version <hex64>] [--sceversion-name <name> --sceversion-from <reference.elf>] [--force]");
            return 2;
        }
        string inputPath = Path.GetFullPath(input);
        string outputPath = Path.GetFullPath(output);
        if (inputPath.Equals(outputPath, StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("fself requires a separate output path.");
        if (File.Exists(outputPath) && !force)
            throw new IOException($"Output already exists: {outputPath}. Use --force to replace it.");

        byte[]? sceVersionRecord = null;
        if (sceVersionFrom is not null &&
            !ProsperoSelfBuilder.TryGetSceVersionRecord(File.ReadAllBytes(sceVersionFrom), out sceVersionRecord))
        {
            throw new InvalidDataException("No .sceversion record was found in the reference module.");
        }

        var options = new FselfOptions
        {
            AuthorityId = authorityHex is null ? null : Convert.ToUInt64(authorityHex, 16),
            AppVersion = appVersionHex is null ? 0 : Convert.ToUInt64(appVersionHex, 16),
            FirmwareVersion = firmwareVersionHex is null ? 0 : Convert.ToUInt64(firmwareVersionHex, 16),
            SceVersionName = sceVersionName,
            SceVersionRecord = sceVersionRecord,
        };
        byte[] fself = ProsperoSelfBuilder.MakeFself(File.ReadAllBytes(inputPath), options);
        File.WriteAllBytes(outputPath, fself);
        Console.WriteLine($"Fake-signed: {inputPath} -> {outputPath} ({fself.Length} bytes)");
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

    private static int RunNativePackageInfo(string[] args, bool validateOnly, bool kindOnly)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool pkg-detect|native-info|native-validate <package>");
            return 2;
        }

        ProsperoPackageInspection package = ProsperoPackageReader.Read(args[0]);
        Console.WriteLine($"Kind: {package.Kind}");
        if (kindOnly)
            return 0;

        if (!validateOnly)
        {
            Console.WriteLine($"File size: {package.FileSize} (0x{package.FileSize:X})");
            if (package.Fih is { } fih)
            {
                Console.WriteLine($"FIH version: {fih.FormatVersion}");
                Console.WriteLine($"Signed byte: 0x{fih.SignedByte:X2}");
            }
            Console.WriteLine($"Content ID: {(package.Cnt.ContentId.Length == 0 ? "(empty)" : package.Cnt.ContentId)}");
            Console.WriteLine($"CNT entries: {package.Cnt.EntryCount}");
            Console.WriteLine($"DRM type: 0x{package.Cnt.DrmType:X8}");
            Console.WriteLine($"Content type: 0x{package.Cnt.ContentType:X8}");
            Console.WriteLine("Segments:");
            foreach (ProsperoPackageSegment segment in package.Segments)
                Console.WriteLine($"  {segment.Name,-3} offset=0x{segment.Offset:X12} size=0x{segment.Size:X12} ({segment.Size} bytes)");
        }

        foreach (VerificationIssue issue in package.Structure.Issues)
        {
            TextWriter writer = issue.IsError ? Console.Error : Console.Out;
            writer.WriteLine($"{(issue.IsError ? "Error" : "Warning")}: {issue.Code}: {issue.Message}");
        }
        Console.WriteLine(package.Structure.IsValid
            ? "Native structural validation passed."
            : "Native structural validation failed.");
        return package.Structure.IsValid ? 0 : 4;
    }

    private static int RunNativePackageEntries(string[] args)
    {
        if (args.Length != 1)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool native-entries <package>");
            return 2;
        }
        ProsperoPackageInspection package = ProsperoPackageReader.Read(args[0]);
        foreach (ProsperoCntEntry entry in package.Entries)
        {
            Console.WriteLine(
                $"0x{entry.Id:X8} offset=0x{entry.DataOffset:X8} size=0x{entry.DataSize:X8} " +
                $"{(entry.IsEncrypted ? "encrypted" : "plain"),-9} {entry.DisplayName}");
        }
        Console.WriteLine($"CNT entries: {package.Entries.Count}");
        return package.Structure.IsValid ? 0 : 4;
    }

    private static int RunNativeDecrypt(string[] args)
    {
        string? package = null;
        string? passcode = null;
        string? output = null;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--passcode" when i + 1 < args.Length:
                    passcode = args[++i];
                    break;
                case "--out" when i + 1 < args.Length:
                    output = args[++i];
                    break;
                default:
                    if (args[i].StartsWith("--", StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine($"Unknown option: {args[i]}");
                        return 2;
                    }
                    package ??= args[i];
                    break;
            }
        }
        if (package is null || passcode is null)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool native-decrypt <package> --passcode <32 chars> [--out <inner-image.bin>]");
            return 2;
        }

        CleanRoomDecrypt.Result result = CleanRoomDecrypt.DecryptOuter(package, passcode, output);
        Console.WriteLine($"Content ID: {result.ContentId}");
        Console.WriteLine($"Package kind: {result.PackageKind}");
        Console.WriteLine($"Outer PFS: {result.BlockCount} blocks, superblock at block {result.SuperblockIndex}");
        Console.WriteLine($"Seed: {result.SeedHex}");
        Console.WriteLine($"Superblock ICV: {(result.SuperblockIcvValid ? "valid" : "INVALID")}");
        Console.WriteLine($"Inner image: {result.InnerImageLength} bytes (0x{result.InnerImageLength:X})");
        Console.WriteLine($"Keystone present: {(result.KeystoneFound ? "yes" : "no")}");
        if (result.InnerImagePath is not null)
            Console.WriteLine($"Wrote inner image: {result.InnerImagePath}");
        return result.SuperblockIcvValid && result.KeystoneFound ? 0 : 5;
    }

    private static int RunInnerImageInfo(string[] args)
    {
        string? package = null;
        string? passcode = null;
        bool noPasscode = false;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--passcode" when i + 1 < args.Length:
                    passcode = args[++i];
                    break;
                case "--no_passcode":
                    noPasscode = true;
                    break;
                case "--tmp_path" when i + 1 < args.Length:
                    i++; // accepted for parity; temporary directory is unused
                    break;
                default:
                    if (args[i].StartsWith("--", StringComparison.Ordinal))
                        return UnknownOption(args[i]);
                    package ??= args[i];
                    break;
            }
        }
        if (package is null)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool img_info [--passcode <passcode>|--no_passcode] <package>");
            return 2;
        }

        ProsperoPackageInspection structural = ProsperoPackageReader.Read(package);
        ProsperoPackageCategoryInfo category = structural.Category();
        Console.WriteLine($"Package category: {category.Category} (raw CNT type 0x{category.RawContentType:X8}; {category.Evidence})");
        Console.WriteLine($"Envelope: {structural.Kind}");
        Console.WriteLine($"Package size: {structural.FileSize} bytes (0x{structural.FileSize:X})");
        Console.WriteLine($"Content ID: {(structural.Cnt.ContentId.Length == 0 ? "(unavailable)" : structural.Cnt.ContentId)}");
        Console.WriteLine($"CNT entries: {structural.Entries.Count}");
        if (structural.Fih is { } fih)
        {
            Console.WriteLine($"FIH: version {fih.FormatVersion}, signed byte 0x{fih.SignedByte:X2}");
            Console.WriteLine($"PFS: offset 0x{fih.PfsOffset:X}, size 0x{fih.PfsSize:X}");
        }
        foreach (ProsperoPackageSegment segment in structural.Segments.Where(s => s.Name is "SC" or "SI"))
            Console.WriteLine($"{segment.Name}: offset 0x{segment.Offset:X}, size 0x{segment.Size:X}");
        PrintParamSummary(package, structural);

        // Multi-GB finalized-debug PFS images cannot be materialized as one byte[]; use the
        // file-backed reader.
        bool large = structural.Kind == ProsperoPackageKind.FinalizedDebug &&
            structural.Fih is { } fihLarge && fihLarge.PfsSize > (1L << 31);
        if (large)
        {
            try
            {
                using ProsperoFileBackedPackage fileBacked =
                    ProsperoPackageContent.ReadFileBacked(package, noPasscode ? null : passcode);
                PrintDecodedSummary(fileBacked.Naps, fileBacked.Blocks, fileBacked.Entries);
                PrintPlayGoSummary(package, structural);
                return structural.Structure.IsValid ? 0 : 4;
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or System.Security.Cryptography.CryptographicException)
            {
                Console.WriteLine("Encrypted payload: key required");
                Console.WriteLine("Inner PFS/PFSC: unavailable");
                Console.WriteLine("PlayGo: unavailable");
                return structural.Structure.IsValid ? 0 : 4;
            }
        }

        ProsperoDecodedPackage decoded;
        try { decoded = ProsperoPackageContent.Read(package, noPasscode ? null : passcode); }
        catch (Exception ex) when (ex is IOException or InvalidDataException or System.Security.Cryptography.CryptographicException)
        {
            Console.WriteLine("Encrypted payload: key required");
            Console.WriteLine("Inner PFS/PFSC: unavailable");
            Console.WriteLine("PlayGo: unavailable");
            return structural.Structure.IsValid ? 0 : 4;
        }
        PrintDecodedSummary(decoded.Naps, decoded.Blocks, ProsperoInnerPfsReader.Enumerate(decoded.Mount));
        PrintPlayGoSummary(package, structural);
        return 0;
    }

    private static void PrintDecodedSummary(
        byte[] naps, IReadOnlyList<ProsperoPs5InnerImageReader.InnerBlock> blocks,
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries)
    {
        NapsLayoutDocument doc = ProsperoNapsLayout.Parse(naps);
        long totalCompressed = 0, totalUncompressed = 0;
        int rawBlocks = 0, krakenBlocks = 0, dedupBlocks = 0;
        foreach (ProsperoPs5InnerImageReader.InnerBlock b in blocks)
        {
            totalCompressed += b.CompressedLength;
            totalUncompressed += b.UncompressedLength;
            if (b.CompressedLength == 0) dedupBlocks++;
            else if (b.IsKraken) krakenBlocks++;
            else rawBlocks++;
        }

        Console.WriteLine($"Compression type: {doc.Counts.CompressionType} ({(doc.Counts.CompressionType == 2 ? "Kraken" : "other")})");
        Console.WriteLine($"ublocks: {doc.Counts.NumUBlocks}");
        Console.WriteLine($"CblockInfo entries: {doc.Counts.NumCblockInfo}");
        Console.WriteLine($"Blocks walked: {blocks.Count} (raw {rawBlocks}, Kraken {krakenBlocks}, dedup {dedupBlocks})");
        Console.WriteLine($"Uncompressed total: {totalUncompressed} (0x{totalUncompressed:X})");
        Console.WriteLine($"Compressed total: {totalCompressed} (0x{totalCompressed:X})");
        Console.WriteLine($"Inner PFS: supported v2, {entries.Count} logical entries");
    }

    private static void PrintPlayGoSummary(string package, ProsperoPackageInspection structural)
    {
        ProsperoCntEntry? chunk = structural.Entries.FirstOrDefault(e => e.Id == (uint)CntEntryId.PlaygoChunkDat);
        if (chunk is null)
        {
            Console.WriteLine("PlayGo: not present");
            return;
        }
        try
        {
            PlayGoProject project = PlayGoChunkReader.Read(ProsperoPackageContent.ReadCntEntry(package, structural, chunk));
            Console.WriteLine($"PlayGo: {project.Chunks.Count} chunk(s), {project.Scenarios.Count} scenario(s)");
        }
        catch (InvalidDataException) { Console.WriteLine("PlayGo: present, unreadable"); }
    }

    private static int RunBackupConvert(string[] args)
    {
        string? backup = null;
        string? output = null;
        string? decrypted = null;
        string? contentId = null;
        string? passcode = null;
        string? version = null;
        string? staging = null;
        bool keepStaging = false;
        bool useEmbeddedRightSprx = false;
        bool noPasscode = false;
        ProsperoInnerCompressionMode compressionMode = ProsperoInnerCompressionMode.Stored;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--out" when i + 1 < args.Length:
                    output = args[++i];
                    break;
                case "--decrypted" when i + 1 < args.Length:
                    decrypted = args[++i];
                    break;
                case "--content-id" when i + 1 < args.Length:
                    contentId = args[++i];
                    break;
                case "--passcode" when i + 1 < args.Length:
                    passcode = args[++i];
                    break;
                case "--version" when i + 1 < args.Length:
                    version = args[++i];
                    break;
                case "--staging" when i + 1 < args.Length:
                    staging = args[++i];
                    break;
                case "--compression" when i + 1 < args.Length:
                    compressionMode = args[++i].ToLowerInvariant() switch
                    {
                        "stored" => ProsperoInnerCompressionMode.Stored,
                        "kraken" or "auto" => ProsperoInnerCompressionMode.Auto,
                        _ => throw new ArgumentException("--compression must be 'stored' or 'kraken'."),
                    };
                    break;
                case "--keep-staging":
                    keepStaging = true;
                    break;
                case "--use-embedded-right-sprx":
                    useEmbeddedRightSprx = true;
                    break;
                case "--no_passcode":
                    noPasscode = true;
                    break;
                default:
                    if (args[i].StartsWith("--", StringComparison.Ordinal))
                        return UnknownOption(args[i]);
                    backup ??= args[i];
                    break;
            }
        }
        if (backup is null || output is null)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool convert <backup-folder> --out <package.pkg> [--decrypted <subfolder>] [--content-id <id>] [--passcode <32 chars>|--no_passcode] [--version NN.NN] [--compression stored|kraken] [--staging <folder>] [--keep-staging] [--use-embedded-right-sprx]");
            return 2;
        }

        string resolvedPasscode = noPasscode || string.IsNullOrEmpty(passcode)
            ? ProsperoDebugLicense.DefaultPasscode
            : passcode;
        string outputPath = Path.GetFullPath(output);

        var options = new ProsperoBackupConversionOptions
        {
            BackupFolder = backup,
            OutputFolder = Path.GetDirectoryName(outputPath) ?? ".",
            DecryptedSubfolder = decrypted ?? "decrypted",
            ContentId = contentId ?? "",
            Passcode = resolvedPasscode,
            Version = version ?? "",
            StagingFolder = staging ?? "",
            KeepStaging = keepStaging,
            UseEmbeddedRightSprx = useEmbeddedRightSprx,
        };

        ProsperoBackupConversionResult result = ProsperoBackupConverter.Convert(options, staged =>
        {
            var buildArgs = new List<string> { staged.StagingFolder, "--out", outputPath };
            if (noPasscode) buildArgs.Add("--no_passcode");
            else { buildArgs.Add("--passcode"); buildArgs.Add(resolvedPasscode); }
            if (!string.IsNullOrWhiteSpace(contentId)) { buildArgs.Add("--content-id"); buildArgs.Add(contentId!); }
            buildArgs.Add("--compression");
            buildArgs.Add(compressionMode == ProsperoInnerCompressionMode.Stored ? "stored" : "kraken");

            int code = RunInnerImageCreate(buildArgs.ToArray());
            if (code != 0)
                throw new InvalidDataException($"The package build failed (exit code {code}).");
            return outputPath;
        }, Console.WriteLine);

        PrintConversionReport(result);
        return result.LaunchReadiness.IsLaunchReady ? 0 : 5;
    }

    private static void PrintConversionReport(ProsperoBackupConversionResult result)
    {
        Console.WriteLine($"Output: {result.OutputPath}");
        Console.WriteLine($"Content ID: {result.DebugLicense.ContentId}");
        Console.WriteLine($"Passcode: {result.DebugLicense.Passcode}");
        Console.WriteLine($"Debug license requires rif: {result.DebugLicense.RequiresRif}");
        Console.WriteLine($"Substituted modules: {result.SubstitutedModules.Count}");
        foreach (string module in result.SubstitutedModules)
            Console.WriteLine($"  {module}");
        Console.WriteLine($"Plaintext modules: {result.PlaintextModules.Count}");
        foreach (string module in result.PlaintextModules)
            Console.WriteLine($"  {module}");
        Console.WriteLine($"Unresolved modules: {result.UnresolvedModules.Count}");
        foreach (string module in result.UnresolvedModules)
            Console.WriteLine($"  {module}");
        foreach (string warning in result.Warnings)
            Console.WriteLine($"Warning: {warning}");
        Console.WriteLine($"Launch readiness: {(result.LaunchReadiness.IsLaunchReady ? "READY" : "NOT READY")} (requires debug console: {result.LaunchReadiness.RequiresDebugConsole})");
        foreach (string issue in result.LaunchReadiness.Issues)
            Console.WriteLine($"  Issue: {issue}");
        foreach (ModuleLaunchReadiness module in result.LaunchReadiness.Modules)
            Console.WriteLine($"  Module {module.Path}: {module.Kind} authority=0x{module.AuthorityId:X16} willRun={module.WillRunOnDebugConsole}");
        if (result.StagingFolder.Length > 0)
            Console.WriteLine($"Staging folder: {result.StagingFolder}");
    }

    private static int RunInnerImageCreate(string[] args)
    {
        string? source = null;
        string? output = null;
        string? contentId = null;
        string? gp5Path = null;
        string? requestedType = null;
        ProsperoInnerCompressionMode compressionMode = ProsperoInnerCompressionMode.Stored;
        string passcode = Gp5Constants.DefaultPasscode;
        bool passcodeProvided = false;
        bool noPasscode = false;
        bool fakeSignModules = true;
        bool injectRightSprx = true;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--out" when i + 1 < args.Length:
                    output = args[++i];
                    break;
                case "--passcode" when i + 1 < args.Length:
                    passcode = args[++i];
                    passcodeProvided = true;
                    break;
                case "--content-id" when i + 1 < args.Length:
                    contentId = args[++i];
                    break;
                case "--gp5" when i + 1 < args.Length:
                    gp5Path = args[++i];
                    break;
                case "--type" when i + 1 < args.Length:
                    requestedType = args[++i].ToLowerInvariant();
                    break;
                case "--compression" when i + 1 < args.Length:
                    compressionMode = args[++i].ToLowerInvariant() switch
                    {
                        "stored" => ProsperoInnerCompressionMode.Stored,
                        "kraken" or "auto" => ProsperoInnerCompressionMode.Auto,
                        _ => throw new ArgumentException("--compression must be 'stored' or 'kraken'."),
                    };
                    break;
                case "--no_passcode":
                    noPasscode = true;
                    break;
                case "--no_fself" or "--no-fake-sign" or "--no-fake-sign-modules":
                    fakeSignModules = false;
                    break;
                case "--no_right_sprx" or "--no-right-sprx":
                    injectRightSprx = false;
                    break;
                default:
                    if (args[i].StartsWith("--", StringComparison.Ordinal))
                        return UnknownOption(args[i]);
                    source ??= args[i];
                    break;
            }
        }
        if (source is null || output is null)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool img_create <source-folder | project.gp5> --out <package.pkg> [--type base] [--compression stored|kraken] [--content-id <id>] [--passcode <32 chars>|--no_passcode] [--no_fself] [--no_right_sprx]");
            return 2;
        }

        if (noPasscode)
        {
            passcode = Gp5Constants.DefaultPasscode;
            passcodeProvided = false;
        }

        // A .gp5 positional source selects GP5-manifest mode: the project's file list is
        // authoritative for destination paths, source locations, and PlayGo chunk ownership.
        string fullSource = Path.GetFullPath(source);
        bool manifestMode = File.Exists(fullSource) &&
            fullSource.EndsWith(".gp5", StringComparison.OrdinalIgnoreCase);
        if (!manifestMode && !Directory.Exists(fullSource))
            throw new DirectoryNotFoundException($"Source folder or GP5 manifest not found: {fullSource}");

        ProsperoParam param;
        byte[] paramJson;
        Gp5Project? manifestProject = null;
        IReadOnlyList<Gp5ManifestFile>? manifestFiles = null;
        string? sourceRoot = null;
        if (manifestMode)
        {
            if (gp5Path is not null &&
                !Path.GetFullPath(gp5Path).Equals(fullSource, StringComparison.OrdinalIgnoreCase))
                throw new ArgumentException("In GP5-manifest mode the manifest is the PlayGo source; --gp5 must not name a different file.");
            gp5Path = fullSource;

            manifestProject = Gp5Xml.Read(fullSource);
            ValidateGp5OrThrow(manifestProject, fullSource);
            manifestFiles = Gp5Manifest.Resolve(manifestProject, fullSource);
            Gp5ManifestFile paramEntry = manifestFiles.FirstOrDefault(file =>
                file.DestinationPath.Equals("sce_sys/param.json", StringComparison.OrdinalIgnoreCase))
                ?? throw new InvalidDataException("The GP5 manifest does not list sce_sys/param.json.");
            paramJson = File.ReadAllBytes(paramEntry.SourceFullPath);
            param = ProsperoParamReader.Read(paramJson);

            if (!passcodeProvided && IsValidPasscode(manifestProject.Volume.Package.Passcode))
                passcode = manifestProject.Volume.Package.Passcode!;
        }
        else
        {
            SourceFolderInspection inspection = SourceFolderValidator.Inspect(fullSource);
            if (inspection.Param is null)
            {
                PrintValidation(inspection.Validation);
                return 4;
            }
            param = inspection.Param;
            paramJson = File.ReadAllBytes(Path.Combine(fullSource, "sce_sys", "param.json"));
            sourceRoot = fullSource;
        }

        string inferredType = param.ApplicationCategoryType == 0 ? "base" : "dlc";
        string packageType = requestedType ?? inferredType;
        if (packageType != "base")
        {
            if (packageType == "dlc")
                throw new InvalidDataException("DLC-data creation is not enabled: no clean-room CNT/GP5 oracle proves its category and required metadata.");
            if (packageType is "dlc-nodata" or "dlc_nodata")
                throw new InvalidDataException("No-data DLC creation is not enabled: its PFS/CNT absence and entitlement semantics are unverified.");
            throw new ArgumentException("--type must be 'base'. DLC categories are intentionally not guessed.");
        }
        contentId ??= param.ContentId;
        if (contentId is null || contentId.Length != 36)
            throw new ArgumentException("A 36-character content id is required (supply --content-id or set it in sce_sys/param.json).");
        if (passcode.Length != 32)
            throw new ArgumentException("Passcode must be exactly 32 characters.");

        PlayGoProject? gp5PlayGo = null;
        if (manifestProject is not null)
        {
            ValidateGp5ContentId(manifestProject, contentId);
            gp5PlayGo = PlayGoProjectFactory.FromGp5(manifestProject, contentId);
        }
        else if (gp5Path is not null)
        {
            Gp5Project gp5 = Gp5Xml.Read(gp5Path);
            ValidateGp5OrThrow(gp5, gp5Path);
            ValidateGp5ContentId(gp5, contentId);
            gp5PlayGo = PlayGoProjectFactory.FromGp5(gp5, contentId);
        }

        Console.WriteLine($"Building debug base/application package: {contentId}");

        // ---- 1. Collect inner files (exclude sce_sys outer-CNT entries). ----
        var innerFiles = new List<ProsperoInnerImageAssembler.InnerFile>();
        if (manifestFiles is not null)
        {
            foreach (Gp5ManifestFile file in manifestFiles)
            {
                if (IsExcludedFromInner(file.DestinationPath) ||
                    SourceFolderValidator.IsPublishingArtifact(file.DestinationPath))
                    continue;
                innerFiles.Add(CreateInnerFile(
                    file.DestinationPath, file.SourceFullPath, AssignmentForInnerPath(gp5PlayGo, file.DestinationPath)));
            }
        }
        else
        {
            foreach (string file in Directory.EnumerateFiles(fullSource, "*", SearchOption.AllDirectories)
                                            .OrderBy(p => p, StringComparer.Ordinal))
            {
                string name = Path.GetFileName(file);
                if (name.EndsWith(".gp4", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".gp5", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".pkg", StringComparison.OrdinalIgnoreCase))
                    continue; // publishing artifacts (SourceFolderValidator.IsPublishingArtifact)
                string rel = Path.GetRelativePath(fullSource, file).Replace('\\', '/');
                if (IsExcludedFromInner(rel))
                    continue;
                innerFiles.Add(CreateInnerFile(rel, file, AssignmentForInnerPath(gp5PlayGo, rel)));
            }
        }

        // Convert raw ELF application modules to debug fake-SELF containers (scene method).
        if (fakeSignModules)
            FakeSignInnerModules(innerFiles);

        // Inject the debug pfs-version marker if the source doesn't ship one (scene method): ASCII
        // content-version string, e.g. "01.000.000".
        if (!innerFiles.Any(f => f.Path == "/sce_sys/pfs-version.dat"))
        {
            innerFiles.Add(new ProsperoInnerImageAssembler.InnerFile
            {
                Path = "/sce_sys/pfs-version.dat",
                Data = System.Text.Encoding.ASCII.GetBytes(param.ContentVersion ?? "01.000.000"),
                PlayGoChunkId = 0,
            });
        }

        // Inject the debug keystone if the source doesn't ship one.
        if (!innerFiles.Any(f => f.Path == "/sce_sys/keystone"))
        {
            byte[] keystone = Keystone.Create(passcode);
            innerFiles.Add(new ProsperoInnerImageAssembler.InnerFile
            {
                Path = "/sce_sys/keystone",
                Data = keystone,
                PlayGoChunkId = 0,
            });
        }

        // Inject the fixed debug rights module when the source doesn't ship one (LibProsperoPkg behavior).
        if (injectRightSprx && !innerFiles.Any(f => f.Path == "/sce_sys/about/right.sprx"))
        {
            byte[]? rightSprx = ProsperoRightSprx.Get();
            if (rightSprx is { Length: > 0 })
            {
                innerFiles.Add(new ProsperoInnerImageAssembler.InnerFile
                {
                    Path = "/sce_sys/about/right.sprx",
                    Data = rightSprx,
                    PlayGoChunkId = 0,
                });
                Console.WriteLine($"  Injected sce_sys/about/right.sprx ({rightSprx.Length} bytes)");
            }
            else
            {
                Console.Error.WriteLine("  warning: sce_sys/about/right.sprx is absent and the embedded module is unavailable.");
            }
        }

        if (innerFiles.Count == 0)
            throw new ArgumentException("No inner files found in the source folder.");

        // ---- 2. Assemble the inner image. ----
        long tsSec = 0x6A31A5B9;
        uint tsNsec = 0x14DC9380;

        // Canonicalise the publisher param.json entry: normalise the source document, stamp the build
        // timestamp, and fill the application defaults the console expects (scene publisher method).
        byte[]? ebootSource = ResolveEbootBytes(sourceRoot, manifestFiles);
        ulong sdkVersion = ebootSource is null ? 0 : ProsperoPublisherParamJson.ResolveSdkVersion(ebootSource);
        paramJson = ProsperoPublisherParamJson.Build(paramJson, DateTimeOffset.FromUnixTimeSeconds(tsSec).UtcDateTime, sdkVersion);

        // Large inputs use a file-backed pipeline (temp workspace) so the assembled inner/outer
        // images never materialize as a single byte[]; small inputs keep the in-memory path.
        long totalInnerBytes = 0;
        foreach (ProsperoInnerImageAssembler.InnerFile file in innerFiles)
            totalInnerBytes += file.PayloadLength;
        if (totalInnerBytes > FileBackedInnerImageThreshold)
            return RunInnerImageCreateFileBacked(
                innerFiles, output, contentId, passcode, param, paramJson, compressionMode,
                gp5PlayGo, sourceRoot, fullSource, manifestFiles, tsSec, tsNsec);

        var assembler = new ProsperoInnerImageAssembler(tsSec, tsNsec);
        ProsperoInnerImageAssembler.InnerImageResult innerResult = assembler.Build(innerFiles, compressionMode);
        Console.WriteLine($"  Inner image: {innerResult.Image.Length} bytes, {innerResult.Ndblock} mount blocks, {innerResult.InodeCount} inodes");
        ProsperoCompressionMetrics compression = innerResult.CompressionMetrics;
        Console.WriteLine($"  Inner payload: {compression.RawBytes} raw -> {compression.EncodedBytes} encoded; " +
            $"Kraken {compression.KrakenBlocks}, stored {compression.StoredBlocks}, ratio {compression.Ratio:P2}");

        // ---- 3. Generate NAPS from the assembled source geometry. ----
        ProsperoNapsPlanGenerator.PlanResult napsPlan = ProsperoNapsPlanGenerator.Generate(innerResult);
        byte[] naps = ProsperoNapsLayoutBuilder.Build(napsPlan.ToRequest(
            compressionMode == ProsperoInnerCompressionMode.Stored ? (byte)0 : (byte)2));
        Console.WriteLine($"  NAPS layout: {naps.Length} bytes");

        // ---- 4. Build the outer PFS. ----
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(contentId, passcode);
        byte[] outerSeed = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
        long innerImageSize = innerResult.Image.Length;
        long innerImageBlocks = (innerImageSize + ProsperoOuterPfsBuilder.BlockSize - 1) / ProsperoOuterPfsBuilder.BlockSize;
        var outerFiles = new List<OuterPfsFile>
        {
            new()
            {
                Name = "pfs_image.dat",
                Data = innerResult.Image,
                SizeCompressed = innerResult.Ndblock * ProsperoOuterPfsBuilder.BlockSize,
                Signed = false,
            },
            new()
            {
                Name = "naps_pkg_layout.dat",
                Data = naps,
                Signed = true,
            },
        };
        var outerParams = new OuterPfsBuildParameters { TimestampSeconds = tsSec, TimestampNanoseconds = tsNsec, Seed = outerSeed };
        OuterPfsBuildResult outerBuild = ProsperoOuterPfsBuilder.BuildPlaintext(outerFiles, outerParams);
        (byte[] imageDigests, byte[] superblockIcv) = ProsperoOuterPfsBuilder.ComputeImageDigests(outerBuild);
        ProsperoOuterPfsBuilder.Encrypt(outerBuild, ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, outerSeed).TweakKey,
            ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, outerSeed).DataKey);
        byte[] outerImage = outerBuild.Plaintext;
        byte[] pfsImageDigest = Sha3.Sha3_256(outerBuild.Plaintext.AsSpan(outerBuild.SuperblockIndex * ProsperoOuterPfsBuilder.BlockSize, ProsperoOuterPfsBuilder.BlockSize));
        Console.WriteLine($"  Outer PFS: {outerImage.Length} bytes, {outerBuild.BlockCount} blocks, superblock at block {outerBuild.SuperblockIndex}");

        // ---- 5. Build the CNT container. ----
        var cntParams = new CntBuildParameters { ContentId = contentId, Passcode = passcode, ContentType = 0x20, ContentFlags = 0x02020000 };
        List<ProsperoCntBuilder.Entry> entries = ProsperoCntBuilder.BuildStandardEntries(contentId, passcode, ekpfs);

        // param.json entry.
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.ParamJson, Name = "param.json", Data = paramJson,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.ParamJson),
        });

        // imagedigs entry (placeholder sized to the outer block count).
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.Imagedigs, Name = null, Data = new byte[outerBuild.BlockCount * 32],
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.Imagedigs),
        });

        // PlayGo: build the complete observed debug/nwonly family from semantic final-image data.
        // A GP5 supplies the supported explicit assignment model. Without one, a source PLGX is
        // optional compatibility input for chunk/scenario vocabulary; it is parsed, never copied.
        string playGoChunkPath = sourceRoot is null
            ? string.Empty
            : Path.Combine(sourceRoot, "sce_sys", "playgo-chunk.dat");
        PlayGoProject playGoProject = gp5PlayGo ?? (File.Exists(playGoChunkPath)
            ? PlayGoChunkReader.Read(playGoChunkPath)
            : ProsperoPlayGoChunkBuilder.CreateDefaultProject(contentId));
        ulong fihPfsOffset = ProsperoFihBuilder.HeaderRegionSize;
        ulong fihCntOffset = checked(fihPfsOffset + (ulong)outerImage.Length);
        ProsperoPlayGoChunkBuildResult playGoChunk = ProsperoPlayGoChunkBuilder.Build(
            contentId, playGoProject, innerResult, fihPfsOffset, fihCntOffset);
        IReadOnlyList<ProsperoPlayGoFileRecord> playGoRecords = ProsperoPlayGoRecordBuilder.Build(
            innerResult, playGoProject.FileChunkAssignments);
        byte[] playGoHashTable = ProsperoPlayGoHashTableBuilder.Build(playGoRecords);
        byte[] playGoFicm = ProsperoPlayGoFicmBuilder.Build(playGoRecords);

        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.PlaygoChunkDat, Name = "playgo-chunk.dat", Data = playGoChunk.Data,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoChunkDat),
        });
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.PlaygoHashTable, Name = "playgo-hash-table.dat", Data = playGoHashTable,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoHashTable),
        });
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.PlaygoFicm, Name = "playgo-ficm.dat", Data = playGoFicm,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoFicm),
        });

        // sce_sys media/system files are outer CNT entries (never inner-PFS files). PNG icons and
        // pictures also get a generated BC7 DDS companion when the source does not ship one.
        // Generated entries (PlayGo family, param.json) win over a source-supplied duplicate id.
        IReadOnlyDictionary<string, byte[]> sceSysFiles = CollectSceSysFiles(fullSource, manifestFiles);
        foreach (ProsperoSceSysMedia.Entry media in ProsperoSceSysMedia.Collect(sceSysFiles, param.ApplicationDrmType))
        {
            if (entries.Any(e => (uint)e.Id == (uint)media.Id))
                continue;
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = media.Id, Name = media.Name, Data = media.Data,
                Flags1 = media.Flags1, Flags2 = media.Flags2,
            });
        }

        // FIH geometry + accounting are needed before the CNT so the embedded CNT can carry
        // pfs_signed_digest = SHA3-256(FIH header) at 0x460. The reference stamps 0x460 before it
        // computes the GeneralDigests header slot (whose preimage spans 0x400..0x480) and the
        // package self-seal at 0xFE0. The FIH header is independent of the CNT, so a preview of the
        // exact final header can be hashed first.
        byte[] nestedDigest = Sha3.Sha3_256(naps);
        long nestedMetaBaseBlocks = innerResult.MetaBaseLogical / ProsperoOuterPfsBuilder.BlockSize;
        // FIH 0x94 is the NAPS FIDX file count (NumFiles - 1); 0x98 = 0x94 + zero-length files.
        int emptyFileCount = innerFiles.Count(f => f.PayloadLength == 0);
        int fihMetaBlockCount = napsPlan.FileLogicalOffsets.Count - 1;
        int fihMetaBlockCountMirror = fihMetaBlockCount + emptyFileCount;
        byte[] fihHeaderPreview = ProsperoFihBuilder.BuildHeaderBlock(
            FihVariant.Debug,
            (ulong)outerImage.Length,
            (ulong)(ProsperoFihBuilder.HeaderRegionSize + outerImage.Length),
            outerImage,
            nestedImageDigest: nestedDigest,
            nestedImageSize: naps.Length,
            nestedMetaBaseBlocks: nestedMetaBaseBlocks,
            contentVersionHi: 0x01000000,
            innerContentInodes: innerResult.InnerContentInodes,
            appFileCount: innerResult.AppFileCount,
            metaBlockCount: fihMetaBlockCount,
            metaBlockCountMirror: fihMetaBlockCountMirror,
            emptyFileCount: emptyFileCount);
        byte[] pfsSignedDigest = Sha3.Sha3_256(fihHeaderPreview);

        byte[] cnt = ProsperoCntBuilder.Build(entries, cntParams, outerImage, outerSeed, pfsImageDigest,
            nestedImageDigest: nestedDigest, nestedImageSize: naps.Length,
            pfsSignedDigest: pfsSignedDigest);
        Console.WriteLine($"  CNT container: {cnt.Length} bytes");

        // ---- 6. Build the FIH image with the SI (install-metadata) segment. ----
        // Three-phase build: the SI segment carries the fixed-info-digest = SHA3-256 of the FIH
        // header block, so the FIH is first built WITHOUT the SI; the SI is then assembled from
        // the (header-only) mount image and the already-produced CNT/outer geometry; finally the
        // FIH is rebuilt with the SI appended. The header bytes are identical between the two
        // phases (the SI trails the CNT and never feeds back into the 0x10000-byte header region),
        // so the fixed-info-digest stays self-consistent.
        byte[] fihNoSi = ProsperoFihBuilder.BuildFromCnt(
            cnt, FihVariant.Debug,
            nestedImageDigest: nestedDigest, nestedImageSize: naps.Length,
            nestedMetaBaseBlocks: nestedMetaBaseBlocks,
            contentVersionHi: 0x01000000,
            innerContentInodes: innerResult.InnerContentInodes,
            appFileCount: innerResult.AppFileCount,
            metaBlockCount: fihMetaBlockCount,
            metaBlockCountMirror: fihMetaBlockCountMirror,
            emptyFileCount: emptyFileCount);

        byte[]? playGoChunkDat = entries.FirstOrDefault(e => e.Id == CntEntryId.PlaygoChunkDat)?.Data;
        byte[] siSegment = BuildSiSegment(
            contentId, param, cnt, entries, outerFiles, outerBuild, outerSeed, superblockIcv,
            innerResult, fihNoSi, paramJson, playGoChunkDat);

        byte[] fih = ProsperoFihBuilder.BuildFromCnt(
            cnt, FihVariant.Debug,
            nestedImageDigest: nestedDigest, nestedImageSize: naps.Length,
            nestedMetaBaseBlocks: nestedMetaBaseBlocks,
            contentVersionHi: 0x01000000,
            innerContentInodes: innerResult.InnerContentInodes,
            appFileCount: innerResult.AppFileCount,
            metaBlockCount: fihMetaBlockCount,
            metaBlockCountMirror: fihMetaBlockCountMirror,
            emptyFileCount: emptyFileCount,
            siSegment: siSegment);

        // ---- 7. Write the output. ----
        string outDir = Path.GetDirectoryName(Path.GetFullPath(output))!;
        Directory.CreateDirectory(outDir);
        File.WriteAllBytes(output, fih);
        Console.WriteLine($"Wrote: {output} ({fih.Length} bytes)");
        return 0;
    }

    /// <summary>Assembled inner-image size above which the file-backed build path is used.</summary>
    private const long FileBackedInnerImageThreshold = 1L << 30;

    /// <summary>Locates the source <c>eboot.bin</c> bytes for SDK-version resolution, or null when absent.</summary>
    private static byte[]? ResolveEbootBytes(string? sourceRoot, IReadOnlyList<Gp5ManifestFile>? manifestFiles)
    {
        if (manifestFiles is not null)
        {
            Gp5ManifestFile? entry = manifestFiles.FirstOrDefault(file =>
                file.DestinationPath.Equals("eboot.bin", StringComparison.OrdinalIgnoreCase));
            return entry is null || !File.Exists(entry.SourceFullPath) ? null : File.ReadAllBytes(entry.SourceFullPath);
        }
        if (sourceRoot is null)
            return null;
        string path = Path.Combine(sourceRoot, "eboot.bin");
        return File.Exists(path) ? File.ReadAllBytes(path) : null;
    }

    /// <summary>
    /// File-backed companion to the tail of <see cref="RunInnerImageCreate"/>: assembles the inner
    /// image, outer PFS, CNT and finalized FIH as temporary files (with the SI computed by streaming
    /// the mount image), so a multi-GiB package never materializes as one <c>byte[]</c>. Every temp
    /// artifact is removed in a <c>finally</c>.
    /// </summary>
    private static int RunInnerImageCreateFileBacked(
        List<ProsperoInnerImageAssembler.InnerFile> innerFiles,
        string output, string contentId, string passcode,
        ProsperoParam param, byte[] paramJson,
        ProsperoInnerCompressionMode compressionMode,
        PlayGoProject? gp5PlayGo, string? sourceRoot, string fullSource,
        IReadOnlyList<Gp5ManifestFile>? manifestFiles,
        long tsSec, uint tsNsec)
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "libprospero-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        try
        {
            string innerImagePath = Path.Combine(tempRoot, "pfs_image.dat");
            string napsPath = Path.Combine(tempRoot, "naps_pkg_layout.dat");
            string outerPath = Path.Combine(tempRoot, "outer_pfs.dat");
            string cntPath = Path.Combine(tempRoot, "outer.cnt");

            var assembler = new ProsperoInnerImageAssembler(tsSec, tsNsec);
            ProsperoInnerImageAssembler.InnerImageResult innerResult =
                assembler.BuildToFile(innerFiles, innerImagePath, compressionMode);
            Console.WriteLine($"  Inner image (file-backed): {innerResult.ImageSize} bytes, {innerResult.Ndblock} mount blocks, {innerResult.InodeCount} inodes");
            ProsperoCompressionMetrics compression = innerResult.CompressionMetrics;
            Console.WriteLine($"  Inner payload: {compression.RawBytes} raw -> {compression.EncodedBytes} encoded; " +
                $"Kraken {compression.KrakenBlocks}, stored {compression.StoredBlocks}, ratio {compression.Ratio:P2}");

            ProsperoNapsPlanGenerator.PlanResult napsPlan = ProsperoNapsPlanGenerator.Generate(innerResult);
            byte[] naps = ProsperoNapsLayoutBuilder.Build(napsPlan.ToRequest(
                compressionMode == ProsperoInnerCompressionMode.Stored ? (byte)0 : (byte)2));
            File.WriteAllBytes(napsPath, naps);
            Console.WriteLine($"  NAPS layout: {naps.Length} bytes");

            byte[] ekpfs = ProsperoKeys.ComputeEkpfs(contentId, passcode);
            byte[] outerSeed = System.Security.Cryptography.RandomNumberGenerator.GetBytes(16);
            var outerSources = new List<OuterPfsFileSource>
            {
                new()
                {
                    Name = "pfs_image.dat",
                    Path = innerImagePath,
                    SizeCompressed = innerResult.Ndblock * ProsperoOuterPfsBuilder.BlockSize,
                    Signed = false,
                },
                new()
                {
                    Name = "naps_pkg_layout.dat",
                    Path = napsPath,
                    Signed = true,
                },
            };
            var outerParams = new OuterPfsBuildParameters { TimestampSeconds = tsSec, TimestampNanoseconds = tsNsec, Seed = outerSeed };
            (byte[] outerTweakKey, byte[] outerDataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, outerSeed);
            OuterPfsFileBuildResult outerBuild = ProsperoOuterPfsBuilder.BuildForPackageToFile(
                outerSources, outerParams, outerPath, encryptOutput: true, outerTweakKey, outerDataKey);
            byte[] pfsImageDigest = Sha3.Sha3_256(outerBuild.SuperblockPlaintext);
            long outerLength = outerBuild.ImageLength;
            Console.WriteLine($"  Outer PFS (file-backed): {outerLength} bytes, {outerBuild.BlockCount} blocks, superblock at block {outerBuild.SuperblockIndex}");

            var cntParams = new CntBuildParameters { ContentId = contentId, Passcode = passcode, ContentType = 0x20, ContentFlags = 0x02020000 };
            List<ProsperoCntBuilder.Entry> entries = ProsperoCntBuilder.BuildStandardEntries(contentId, passcode, ekpfs);
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.ParamJson, Name = "param.json", Data = paramJson,
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.ParamJson),
            });
            // The streamed outer build already produced the per-block digest table.
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.Imagedigs, Name = null, Data = outerBuild.ImageDigests,
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.Imagedigs),
            });

            string playGoChunkPath = sourceRoot is null
                ? string.Empty
                : Path.Combine(sourceRoot, "sce_sys", "playgo-chunk.dat");
            PlayGoProject playGoProject = gp5PlayGo ?? (File.Exists(playGoChunkPath)
                ? PlayGoChunkReader.Read(playGoChunkPath)
                : ProsperoPlayGoChunkBuilder.CreateDefaultProject(contentId));
            ulong fihPfsOffset = ProsperoFihBuilder.HeaderRegionSize;
            ulong fihCntOffset = checked(fihPfsOffset + (ulong)outerLength);
            ProsperoPlayGoChunkBuildResult playGoChunk = ProsperoPlayGoChunkBuilder.Build(
                contentId, playGoProject, innerResult, fihPfsOffset, fihCntOffset);
            IReadOnlyList<ProsperoPlayGoFileRecord> playGoRecords = ProsperoPlayGoRecordBuilder.Build(
                innerResult, playGoProject.FileChunkAssignments);
            byte[] playGoHashTable = ProsperoPlayGoHashTableBuilder.Build(playGoRecords);
            byte[] playGoFicm = ProsperoPlayGoFicmBuilder.Build(playGoRecords);

            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.PlaygoChunkDat, Name = "playgo-chunk.dat", Data = playGoChunk.Data,
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoChunkDat),
            });
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.PlaygoHashTable, Name = "playgo-hash-table.dat", Data = playGoHashTable,
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoHashTable),
            });
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = CntEntryId.PlaygoFicm, Name = "playgo-ficm.dat", Data = playGoFicm,
                Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.PlaygoFicm),
            });

            IReadOnlyDictionary<string, byte[]> sceSysFiles = CollectSceSysFiles(fullSource, manifestFiles);
            foreach (ProsperoSceSysMedia.Entry media in ProsperoSceSysMedia.Collect(sceSysFiles, param.ApplicationDrmType))
            {
                if (entries.Any(e => (uint)e.Id == (uint)media.Id))
                    continue;
                entries.Add(new ProsperoCntBuilder.Entry
                {
                    Id = media.Id, Name = media.Name, Data = media.Data,
                    Flags1 = media.Flags1, Flags2 = media.Flags2,
                });
            }

            byte[] nestedDigest = Sha3.Sha3_256(naps);
            long nestedMetaBaseBlocks = innerResult.MetaBaseLogical / ProsperoOuterPfsBuilder.BlockSize;
            int emptyFileCount = innerFiles.Count(f => f.PayloadLength == 0);
            int fihMetaBlockCount = napsPlan.FileLogicalOffsets.Count - 1;
            int fihMetaBlockCountMirror = fihMetaBlockCount + emptyFileCount;
            byte[] fihHeaderPreview = ProsperoFihBuilder.BuildHeaderBlockFromSuperblock(
                FihVariant.Debug,
                (ulong)outerLength,
                (ulong)(ProsperoFihBuilder.HeaderRegionSize + outerLength),
                outerBuild.SuperblockPlaintext,
                (long)outerBuild.SuperblockIndex * ProsperoOuterPfsBuilder.BlockSize,
                nestedImageDigest: nestedDigest,
                nestedImageSize: naps.Length,
                nestedMetaBaseBlocks: nestedMetaBaseBlocks,
                contentVersionHi: 0x01000000,
                innerContentInodes: innerResult.InnerContentInodes,
                appFileCount: innerResult.AppFileCount,
                metaBlockCount: fihMetaBlockCount,
                metaBlockCountMirror: fihMetaBlockCountMirror,
                emptyFileCount: emptyFileCount);
            byte[] pfsSignedDigest = Sha3.Sha3_256(fihHeaderPreview);

            ProsperoCntBuilder.BuildToFile(entries, cntParams, outerPath, outerLength, cntPath,
                outerSeed, pfsImageDigest, pfsSignedDigest);
            Console.WriteLine($"  CNT container (file-backed): {new FileInfo(cntPath).Length} bytes");

            byte[]? playGoChunkDat = entries.First(e => e.Id == CntEntryId.PlaygoChunkDat).Data;
            Func<Stream, long, byte[]> siFactory = (stream, mountLength) =>
            {
                long pfsImageSize = outerLength;
                long cntOffset = ProsperoFihBuilder.HeaderRegionSize + pfsImageSize;
                long containerSize = mountLength - cntOffset;

                byte[] cntHead = ReadStreamRange(stream, cntOffset, 0x5A0);
                long bodyOffset = (long)BinaryPrimitives.ReadUInt64BigEndian(cntHead.AsSpan(0x20));
                long bodySize = (long)BinaryPrimitives.ReadUInt64BigEndian(cntHead.AsSpan(0x28));
                long mandatorySize = (long)BinaryPrimitives.ReadUInt64BigEndian(cntHead.AsSpan(0x30));
                long packageSize = ProsperoFihBuilder.HeaderRegionSize + pfsImageSize + containerSize;

                byte[] headerBlock = ReadStreamRange(stream, 0, ProsperoFihBuilder.HeaderRegionSize);
                ulong innerImageSize = BinaryPrimitives.ReadUInt64LittleEndian(headerBlock.AsSpan(0xA0));

                long mountTotalToCnt = ProsperoFihBuilder.HeaderRegionSize + pfsImageSize;
                long chunkInfoOuter0 = (long)outerBuild.FileBlockCount[0] * ProsperoOuterPfsBuilder.BlockSize;

                byte[] packageDigest = ReadStreamRange(stream, cntOffset + ProsperoCntBuilder.PackageDigestStoredOffset, 32);
                byte[] bodyBytes = ReadStreamRange(stream, cntOffset + bodyOffset, checked((int)bodySize));
                byte[] bodyDigest = Sha3.Sha3_256(bodyBytes);
                byte[] fixedInfoDigest = Sha3.Sha3_256(headerBlock);

                byte[]? generalDigests = entries.FirstOrDefault(e => e.Id == CntEntryId.GeneralDigests)?.Data;
                byte[]? Dig(int slotOff) => generalDigests is { Length: >= 0x1E0 }
                    ? generalDigests.AsSpan(slotOff, 32).ToArray() : null;
                byte[]? contentDigest = Dig(0x20);
                byte[]? headerDigest = Dig(0x60);
                byte[]? systemDigest = Dig(0x80);
                byte[] gameDigest = Sha3.Sha3_256(outerBuild.SuperblockPlaintext);
                byte[] paramDigest = Sha3.Sha3_256(paramJson);
                byte[] pfsImageSeed = outerBuild.SuperblockPlaintext.AsSpan(0x370, 16).ToArray();

                List<ProsperoPfsImageEntry> xmlEntries = entries
                    .Where(e => (uint)e.Id >= 0x400)
                    .Select(e => new ProsperoPfsImageEntry(
                        (uint)e.Id == (uint)CntEntryId.Imagedigs ? "imagedigs.dat" : (e.Name ?? $"0x{(uint)e.Id:x4}.bin"),
                        e.DataOffset, e.DataSize))
                    .OrderBy(e => e.Offset)
                    .ToList();

                List<(string Path, long Size)> contentFiles = innerResult.Nodes
                    .Where(n => !n.IsDirectory && n.ParentInode >= 0)
                    .OrderBy(n => n.Afid)
                    .Select(n => (n.FullPath.TrimStart('/'), n.Size))
                    .ToList();

                string applicationDrmType = param.ApplicationDrmType ?? "free";
                var options = new ProsperoPfsImageXmlOptions
                {
                    ContentId = contentId,
                    TitleName = param.TitleName ?? "",
                    ContentVersion = param.ContentVersion ?? "01.000.000",
                    DrmType = "none",
                    ApplicationDrmType = applicationDrmType,
                    ContentType = "PS5GD",
                    ApplicationType = applicationDrmType,
                    MasterVersion = "01.00",
                    PackageSize = packageSize,
                    PfsImageOffset = ProsperoFihBuilder.HeaderRegionSize,
                    PfsImageSize = pfsImageSize,
                    PfsImageSeed = pfsImageSeed,
                    ContainerSize = containerSize,
                    MandatorySize = mandatorySize,
                    BodyOffset = bodyOffset,
                    SupplementalOffset = containerSize,
                    Entries = xmlEntries,
                    ContentDigest = contentDigest,
                    GameDigest = gameDigest,
                    HeaderDigest = headerDigest,
                    SystemDigest = systemDigest,
                    ParamDigest = paramDigest,
                    PackageDigest = packageDigest,
                    BodyDigest = bodyDigest,
                    SblockDigest = gameDigest,
                    FixedInfoDigest = fixedInfoDigest,
                    NestedInner = innerResult,
                    OuterPfsTree = new OuterPfsTreeInfo
                    {
                        BlockSize = ProsperoOuterPfsBuilder.BlockSize,
                        ImageBlocks = outerBuild.BlockCount,
                        InodeCount = 3 + outerSources.Count,
                        DinodeBlockCount = 1,
                        DinodeBlock = outerBuild.InodeTableIndex,
                        DinodeSize = ProsperoOuterPfsBuilder.BlockSize,
                        DinodeFlags = 0,
                        RootInode = 0,
                        Seed = outerSeed,
                        SuperblockIcv = outerBuild.SuperblockIcv,
                        Signed = true,
                        Encrypted = true,
                        Root = BuildOuterPfsTreeRoot(
                            outerBuild.SuperRootDirentIndex, outerBuild.FltIndex, outerBuild.UrootDirentIndex,
                            outerBuild.FileFirstBlock,
                            new List<(string, long, long)>
                            {
                                ("pfs_image.dat", innerResult.ImageLength, innerResult.Ndblock * ProsperoOuterPfsBuilder.BlockSize),
                                ("naps_pkg_layout.dat", naps.Length, naps.Length),
                            }),
                    },
                    ChunkInfo = new ProsperoChunkInfoModel
                    {
                        PlayGoChunkDatSize = playGoChunkDat?.Length ?? 0,
                        TotalSize = mountTotalToCnt,
                        Outer0Size = chunkInfoOuter0,
                        Outer1Size = mountTotalToCnt - chunkInfoOuter0,
                    },
                };

                return ProsperoSiArchive.BuildDebugSiSegmentFromStream(
                    options, playGoChunkDat, stream, mountLength, innerImageSize, contentFiles,
                    outerBuild.SuperblockPlaintext, includePfsImageXml: false);
            };

            ProsperoFihBuilder.BuildFromCntToFile(
                cntPath, output, FihVariant.Debug, outerBuild.SuperblockIndex,
                nestedDigest, naps.Length, nestedMetaBaseBlocks, 0x01000000,
                innerResult.InnerContentInodes, innerResult.AppFileCount,
                fihMetaBlockCount, fihMetaBlockCountMirror, emptyFileCount, 0,
                siFactory);

            Console.WriteLine($"Wrote: {output} ({new FileInfo(output).Length} bytes)");
            return 0;
        }
        finally
        {
            try
            {
                if (Directory.Exists(tempRoot))
                    Directory.Delete(tempRoot, recursive: true);
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static byte[] ReadStreamRange(Stream stream, long offset, int length)
    {
        var buffer = new byte[length];
        stream.Position = offset;
        int read = 0;
        while (read < length)
        {
            int n = stream.Read(buffer, read, length - read);
            if (n <= 0)
                throw new EndOfStreamException("Unexpected end of the mount stream.");
            read += n;
        }
        return buffer;
    }

    /// <summary>
    /// Build the debug SI (install-metadata) segment from values the package build has already
    /// produced. The SI is a STORED ZIP whose members are: <c>naps_meta_18.dat</c>,
    /// <c>naps_meta_300/301/302/308.dat</c>, <c>common/etc/pfsimage.xml</c>, the copied
    /// <c>playgo-chunk.dat</c> (when present), and the per-content-id <c>playgo-chunk.crc</c>
    /// computed by CRC-32C over the finalized mount image. Every reproducible digest and geometry
    /// field of <c>pfsimage.xml</c> is sourced from the produced CNT/outer image — keyed digests
    /// that the builder has already written are read back; nothing is fabricated.
    /// </summary>
    private static byte[] BuildSiSegment(
        string contentId, ProsperoParam param,
        byte[] cnt, IReadOnlyList<ProsperoCntBuilder.Entry> entries,
        IReadOnlyList<OuterPfsFile> outerFiles, OuterPfsBuildResult outerBuild, byte[] outerSeed,
        byte[] superblockIcv,
        ProsperoInnerImageAssembler.InnerImageResult innerResult,
        byte[] fihNoSi, byte[] paramJson, byte[]? playGoChunkDat)
    {
        long pfsImageSize = (long)BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x418));
        // CNT+0x410 stores the FIH-relative pfs_image_offset (0x10000); the CNT-internal container
        // size = body end = total CNT length − embedded PFS image size.
        long containerSize = cnt.Length - pfsImageSize;
        long bodyOffset = (long)BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x20));
        ulong bodySizeU = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x28));
        long mandatorySize = (long)BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x30));
        long packageSize = (long)ProsperoFihBuilder.HeaderRegionSize + pfsImageSize + containerSize;

        // The inner-image size the SI records describe MUST be the FIH 0xA0 value the produced
        // package carries (phdr/meta300/pgpl all state it), so read it back from the finalized
        // header rather than recomputing it.
        ulong innerImageSize = BinaryPrimitives.ReadUInt64LittleEndian(fihNoSi.AsSpan(0xA0));
        // chunkinfo tiles the mount image [0, cnt_offset): outer 0 = the block-aligned stored
        // pfs_image.dat, outer 1 = the remainder of the PFS region up to the CNT.
        long mountTotalToCnt = (long)ProsperoFihBuilder.HeaderRegionSize + pfsImageSize;
        long chunkInfoOuter0 = (long)outerBuild.FileBlockCount[0] * ProsperoOuterPfsBuilder.BlockSize;

        // Reproducible digests already stamped into the CNT/outer image.
        byte[] packageDigest = cnt.AsSpan(ProsperoCntBuilder.PackageDigestStoredOffset, 32).ToArray();
        byte[] bodyDigest = Sha3.Sha3_256(cnt.AsSpan((int)bodyOffset, (int)bodySizeU));
        byte[] fixedInfoDigest = Sha3.Sha3_256(fihNoSi.AsSpan(0, ProsperoFihBuilder.HeaderRegionSize));

        // General-digests payload slots (CntBuilder order): +0x20 content, +0x40 game,
        // +0x60 header, +0x80 system, +0xC0 param.
        byte[]? generalDigests = entries.FirstOrDefault(e => e.Id == CntEntryId.GeneralDigests)?.Data;
        byte[]? Dig(int slotOff) => generalDigests is { Length: >= 0x1E0 }
            ? generalDigests.AsSpan(slotOff, 32).ToArray() : null;
        byte[]? contentDigest = Dig(0x20);
        byte[]? headerDigest = Dig(0x60);
        byte[]? systemDigest = Dig(0x80);

        // Game/sblock digest = SHA3-256 of the plaintext outer superblock block (= the value the
        // FIH stamps at 0x30/0x70/0xD0); param-digest = SHA3-256(param.json).
        int sbOff = outerBuild.SuperblockIndex * ProsperoOuterPfsBuilder.BlockSize;
        byte[] gameDigest = Sha3.Sha3_256(outerBuild.Plaintext.AsSpan(sbOff, ProsperoOuterPfsBuilder.BlockSize));
        byte[] paramDigest = Sha3.Sha3_256(paramJson);

        // pfs-image seed: 16 bytes at superblock+0x370.
        byte[] pfsImageSeed = outerBuild.Plaintext.AsSpan(sbOff + 0x370, 16).ToArray();

        // The <entries> table = the file-class CNT entries (id >= 0x400), ordered by container offset.
        // imagedigs (0x040A) is stored UNNAMED in the CNT, so special-case its display name.
        List<ProsperoPfsImageEntry> xmlEntries = entries
            .Where(e => (uint)e.Id >= 0x400)
            .Select(e => new ProsperoPfsImageEntry(
                (uint)e.Id == (uint)CntEntryId.Imagedigs ? "imagedigs.dat" : (e.Name ?? $"0x{(uint)e.Id:x4}.bin"),
                e.DataOffset, e.DataSize))
            .OrderBy(e => e.Offset)
            .ToList();

        // Content files for naps_meta_18's file/fstr table: real inner content files in afid order
        // (non-directory nodes with ParentInode >= 0), each FullPath made root-relative.
        List<(string Path, long Size)> contentFiles = innerResult.Nodes
            .Where(n => !n.IsDirectory && n.ParentInode >= 0)
            .OrderBy(n => n.Afid)
            .Select(n => (n.FullPath.TrimStart('/'), n.Size))
            .ToList();

        string contentVersion = param.ContentVersion ?? "01.000.000";
        string titleName = param.TitleName ?? "";
        string applicationDrmType = param.ApplicationDrmType ?? "free";
        string masterVersion = "01.00";

        var options = new ProsperoPfsImageXmlOptions
        {
            ContentId = contentId,
            TitleName = titleName,
            ContentVersion = contentVersion,
            DrmType = "none",
            ApplicationDrmType = applicationDrmType,
            ContentType = "PS5GD",
            ApplicationType = applicationDrmType,
            MasterVersion = masterVersion,
            PackageSize = packageSize,
            PfsImageOffset = ProsperoFihBuilder.HeaderRegionSize,
            PfsImageSize = pfsImageSize,
            PfsImageSeed = pfsImageSeed,
            ContainerSize = containerSize,
            MandatorySize = mandatorySize,
            BodyOffset = bodyOffset,
            SupplementalOffset = containerSize,
            Entries = xmlEntries,
            ContentDigest = contentDigest,
            GameDigest = gameDigest,
            HeaderDigest = headerDigest,
            SystemDigest = systemDigest,
            ParamDigest = paramDigest,
            PackageDigest = packageDigest,
            BodyDigest = bodyDigest,
            SblockDigest = gameDigest,
            FixedInfoDigest = fixedInfoDigest,
            NestedInner = innerResult,
            OuterPfsTree = new OuterPfsTreeInfo
            {
                BlockSize = ProsperoOuterPfsBuilder.BlockSize,
                ImageBlocks = outerBuild.BlockCount,
                InodeCount = 3 + outerFiles.Count,
                DinodeBlockCount = 1,
                DinodeBlock = outerBuild.InodeTableIndex,
                DinodeSize = ProsperoOuterPfsBuilder.BlockSize,
                DinodeFlags = 0,
                RootInode = 0,
                Seed = outerSeed,
                SuperblockIcv = superblockIcv,
                Signed = true,
                Encrypted = true,
                Root = BuildOuterPfsTreeRoot(outerBuild, outerFiles),
            },
            ChunkInfo = new ProsperoChunkInfoModel
            {
                PlayGoChunkDatSize = playGoChunkDat?.Length ?? 0,
                TotalSize = mountTotalToCnt,
                Outer0Size = chunkInfoOuter0,
                Outer1Size = mountTotalToCnt - chunkInfoOuter0,
            },
        };

        // The mount image passed for the playgo-chunk.crc must cover [0, mountImageSize) WITHOUT
        // the trailing SI — i.e. the header-only finalized bytes fihNoSi (FIH + PFS + CNT). The
        // fixture CRC file = 16 blocks × u32 over [0, 0x100000).
        // innerImageSize here is the FIH 0xA0 value read back from the header above.
        return ProsperoSiArchive.BuildDebugSiSegment(
            options, playGoChunkDat, fihNoSi, innerImageSize, contentFiles,
            includePfsImageXml: false);
    }

    /// <summary>
    /// Builds the outer-PFS inode tree snapshot for the <c>pfs-image</c> XML section, mirroring the
    /// fixed data-first inode template the outer builder writes: super-root →
    /// inode_flat_path_table + uroot → the outer files in order.
    /// </summary>
    private static OuterPfsTreeNode BuildOuterPfsTreeRoot(OuterPfsBuildResult outerBuild, IReadOnlyList<OuterPfsFile> outerFiles)
    {
        var files = new List<(string Name, long StoredSize, long PlainSize)>(outerFiles.Count);
        foreach (OuterPfsFile f in outerFiles)
            files.Add((f.Name, f.Data.Length, f.SizeCompressed ?? (long)f.Data.Length));
        return BuildOuterPfsTreeRoot(
            outerBuild.SuperRootDirentIndex, outerBuild.FltIndex, outerBuild.UrootDirentIndex,
            outerBuild.FileFirstBlock, files);
    }

    private static OuterPfsTreeNode BuildOuterPfsTreeRoot(
        int superRootDirentIndex, int fltIndex, int urootDirentIndex, int[] fileFirstBlock,
        IReadOnlyList<(string Name, long StoredSize, long PlainSize)> files)
    {
        const ushort ModeDir = 0x416D;
        const ushort ModeFile = 0x816D;
        const uint FlagsInternalMeta = 0x0002000C;
        const uint FlagsDir = 0x0000000C;
        const uint FlagsFile = 0x0000000D;
        const string FlatPathTableName = "inode_flat_path_table";
        const string UrootName = "uroot";
        const long FltDataOffset = 0x40;

        long fltSize = FltDataOffset + (long)files.Count * 16;
        var root = new OuterPfsTreeNode
        {
            Name = "",
            IsDirectory = true,
            Inode = 0,
            StartBlock = superRootDirentIndex,
            StoredSize = ProsperoOuterPfsBuilder.BlockSize,
            PlainSize = ProsperoOuterPfsBuilder.BlockSize,
            Flags = FlagsInternalMeta,
            Mode = ModeDir,
            Nlink = 1,
        };
        root.Children.Add(new OuterPfsTreeNode
        {
            Name = FlatPathTableName,
            IsDirectory = false,
            Inode = 1,
            StartBlock = fltIndex,
            StoredSize = fltSize,
            PlainSize = fltSize,
            Flags = FlagsInternalMeta,
            Mode = ModeFile,
            Nlink = 1,
            Internal = true,
        });
        var uroot = new OuterPfsTreeNode
        {
            Name = UrootName,
            IsDirectory = true,
            Inode = 2,
            StartBlock = urootDirentIndex,
            StoredSize = ProsperoOuterPfsBuilder.BlockSize,
            PlainSize = ProsperoOuterPfsBuilder.BlockSize,
            Flags = FlagsDir,
            Mode = ModeDir,
            Nlink = 3,
        };
        for (int i = 0; i < files.Count; i++)
        {
            (string name, long storedSize, long plainSize) = files[i];
            uroot.Children.Add(new OuterPfsTreeNode
            {
                Name = name,
                IsDirectory = false,
                Inode = (uint)(3 + i),
                StartBlock = fileFirstBlock[i],
                StoredSize = storedSize,
                PlainSize = plainSize,
                Flags = FlagsFile,
                Mode = ModeFile,
                Nlink = 1,
            });
        }
        root.Children.Add(uroot);
        return root;
    }

    private static bool IsExcludedFromInner(string relativePath)
    {
        const string prefix = "sce_sys/";
        if (!relativePath.StartsWith(prefix, StringComparison.Ordinal))
            return false;
        // Recognised sce_sys files (param.json, pic2.png, media and signed system files) are outer
        // CNT entries, never inner-PFS files, so the inner tree matches the outer entry set.
        return ProsperoSceSysMedia.IsOuterCntFile(relativePath[prefix.Length..]);
    }

    /// <summary>
    /// Repairs the SHA-1 digest of a trophy2/uds <c>.ucp</c> archive before it enters the package,
    /// matching the reference's best-effort digest fix-up. Other paths are returned unchanged.
    /// </summary>
    private static byte[] RepairSceSysUcp(string relativePath, byte[] data)
    {
        const string prefix = "sce_sys/";
        return relativePath.StartsWith(prefix, StringComparison.Ordinal) &&
               ProsperoUcpArchive.IsRepairableSceSysPath(relativePath[prefix.Length..])
            ? ProsperoUcpArchive.RepairIfNeeded(data)
            : data;
    }

    /// <summary>
    /// Reads the source <c>sce_sys</c> files (path relative to <c>sce_sys</c>, forward slashes) from
    /// either the GP5 manifest's resolved set or the on-disk folder.
    /// </summary>
    private static IReadOnlyDictionary<string, byte[]> CollectSceSysFiles(
        string sourceFolder, IReadOnlyList<Gp5ManifestFile>? manifestFiles)
    {
        const string prefix = "sce_sys/";
        var files = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        if (manifestFiles is not null)
        {
            foreach (Gp5ManifestFile file in manifestFiles)
            {
                if (file.DestinationPath.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    files[file.DestinationPath[prefix.Length..]] = RepairSceSysUcp(file.DestinationPath, File.ReadAllBytes(file.SourceFullPath));
            }
            return files;
        }

        string sceSys = Path.Combine(sourceFolder, "sce_sys");
        if (Directory.Exists(sceSys))
        {
            foreach (string path in Directory.EnumerateFiles(sceSys, "*", SearchOption.AllDirectories))
            {
                string rel = Path.GetRelativePath(sceSys, path).Replace('\\', '/');
                files[rel] = ProsperoUcpArchive.IsRepairableSceSysPath(rel)
                    ? ProsperoUcpArchive.RepairIfNeeded(File.ReadAllBytes(path))
                    : File.ReadAllBytes(path);
            }
        }
        return files;
    }

    private static byte AssignmentForInnerPath(PlayGoProject? playGo, string relativePath)
    {
        if (playGo is null)
            return 0;
        string normalized = ProsperoPlayGoRecordBuilder.NormalizePath(relativePath);
        return playGo.FileChunkAssignments.TryGetValue(normalized, out byte chunk) ? chunk : (byte)0;
    }

    /// <summary>
    /// Converts raw ELF application modules (<c>eboot.bin</c>, <c>sce_module/*</c>,
    /// <c>sce_sys/about/*</c>) into debug fake-SELF containers, matching the scene method. Modules
    /// that are already SELF images are left untouched. A stripped library module inherits the
    /// application's <c>.sceversion</c> record so the console can validate the SDK version.
    /// </summary>
    private static void FakeSignInnerModules(List<ProsperoInnerImageAssembler.InnerFile> innerFiles)
    {
        byte[]? applicationSceVersion = null;
        int ebootIndex = innerFiles.FindIndex(file =>
            string.Equals(file.Path, "/eboot.bin", StringComparison.Ordinal));
        if (ebootIndex >= 0 &&
            ProsperoSelfBuilder.TryGetSceVersionRecord(ReadInnerFileBytes(innerFiles[ebootIndex]), out byte[] ebootRecord))
        {
            applicationSceVersion = ebootRecord;
        }

        for (int i = 0; i < innerFiles.Count; i++)
        {
            ProsperoInnerImageAssembler.InnerFile file = innerFiles[i];
            // Fake-signing is the one transformation that may target file-backed sources, so read
            // the payload here and replace the entry with an in-memory transformed result.
            if (!IsFakeSignTarget(file.Path))
                continue;
            byte[] source = ReadInnerFileBytes(file);
            if (!ProsperoSelfBuilder.IsElf(source))
                continue;

            FselfOptions? options = null;
            if (!string.Equals(file.Path, "/eboot.bin", StringComparison.Ordinal) &&
                applicationSceVersion is not null &&
                !ProsperoSelfBuilder.TryGetSceVersionRecord(source, out _))
            {
                options = new FselfOptions
                {
                    SceVersionName = Path.GetFileNameWithoutExtension(file.Path),
                    SceVersionRecord = applicationSceVersion,
                };
            }

            byte[] signed = ProsperoSelfBuilder.MakeFself(source, options);
            innerFiles[i] = new ProsperoInnerImageAssembler.InnerFile
            {
                Path = file.Path,
                Data = signed,
                PlayGoChunkId = file.PlayGoChunkId,
            };
            Console.WriteLine($"  Fake-signed module: {file.Path} ({source.Length} -> {signed.Length} bytes)");
        }
    }

    private static byte[] ReadInnerFileBytes(ProsperoInnerImageAssembler.InnerFile file) =>
        file.SourcePath is not null ? File.ReadAllBytes(file.SourcePath) : file.Data;

    /// <summary>
    /// Creates an inner-file entry, deferring the payload to <see cref="ProsperoInnerImageAssembler.InnerFile.SourcePath"/>
    /// unless the file needs an in-memory UCP digest repair.
    /// </summary>
    private static ProsperoInnerImageAssembler.InnerFile CreateInnerFile(
        string relativePath, string sourceFullPath, byte playGoChunkId)
    {
        const string prefix = "sce_sys/";
        bool repair = relativePath.StartsWith(prefix, StringComparison.Ordinal) &&
            ProsperoUcpArchive.IsRepairableSceSysPath(relativePath[prefix.Length..]);
        if (repair)
        {
            return new ProsperoInnerImageAssembler.InnerFile
            {
                Path = "/" + relativePath,
                Data = ProsperoUcpArchive.RepairIfNeeded(File.ReadAllBytes(sourceFullPath)),
                PlayGoChunkId = playGoChunkId,
            };
        }
        return new ProsperoInnerImageAssembler.InnerFile
        {
            Path = "/" + relativePath,
            SourcePath = sourceFullPath,
            Length = new FileInfo(sourceFullPath).Length,
            PlayGoChunkId = playGoChunkId,
        };
    }

    private static bool IsFakeSignTarget(string path)
    {
        string fileName = Path.GetFileName(path);
        return fileName.Equals("eboot.bin", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".elf", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".prx", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".sprx", StringComparison.OrdinalIgnoreCase);
    }

    private static void ValidateGp5OrThrow(Gp5Project gp5, string path)
    {
        ValidationReport validation = Gp5Validator.Validate(gp5, path);
        if (validation.IsValid)
            return;
        ValidationIssue issue = validation.Issues.First(i => i.Severity == ValidationSeverity.Error);
        throw new InvalidDataException($"GP5 validation failed: {issue.Code}: {issue.Message}");
    }

    private static void ValidateGp5ContentId(Gp5Project gp5, string contentId)
    {
        if (!string.IsNullOrWhiteSpace(gp5.Volume.Package.ContentId) &&
            !string.Equals(gp5.Volume.Package.ContentId, contentId, StringComparison.Ordinal))
            throw new ArgumentException("GP5 content_id does not match the package content ID.");
    }

    private static bool IsValidPasscode(string? passcode) =>
        passcode is { Length: 32 } && passcode.All(character => character is >= ' ' and <= '~');

    private static int RunInnerImageExtract(string[] args)
    {
        string? package = null;
        string? selection = null;
        string? output = null;
        string? passcode = null;
        string? referencePackage = null;
        bool noPasscode = false;
        bool mountMode = false;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--passcode" when i + 1 < args.Length:
                    passcode = args[++i];
                    break;
                case "--no_passcode":
                    noPasscode = true;
                    break;
                case "--mount":
                    mountMode = true;
                    break;
                case "--tmp_path" when i + 1 < args.Length:
                    i++; // accepted for parity; temporary directory is unused
                    break;
                case "--ref_pkg_path" when i + 1 < args.Length:
                    referencePackage = args[++i];
                    break;
                default:
                    if (args[i].StartsWith("--", StringComparison.Ordinal))
                        return UnknownOption(args[i]);
                    if (package is null)
                        (package, selection) = SplitPackageSelection(args[i]);
                    else
                        output ??= args[i];
                    break;
            }
        }
        if (package is null || output is null)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool img_extract [--mount] [--ref_pkg_path <reference.pkg>] [--passcode <passcode>|--no_passcode] <package[:inner-path]> <out_path>");
            return 2;
        }

        if (ProsperoPackageReader.Read(package) is
            { Kind: ProsperoPackageKind.FinalizedDebug, Fih: { } fihLarge } && fihLarge.PfsSize > (1L << 31))
            return RunInnerImageExtractFileBacked(package, selection, output, noPasscode ? null : passcode, mountMode);

        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, noPasscode ? null : passcode, referencePackage);
        if (mountMode)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            File.WriteAllBytes(output, decoded.Mount);
            Console.WriteLine($"Wrote uncompressed inner mount: {output}");
            return 0;
        }

        IReadOnlyList<ProsperoInnerPfsReader.Entry> all = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        string normalized = NormalizeInnerSelection(selection);
        ProsperoInnerPfsReader.Entry? exact = all.FirstOrDefault(e => string.Equals(e.Path, normalized, StringComparison.Ordinal));
        // The default extraction is the game tree (uroot), matching the reference ExtractInnerFiles;
        // the PFS super-root's internal metadata files (flat path/afid tables) are never extracted.
        bool hasUroot = all.Any(e => e.Path == "/uroot");
        IReadOnlyList<ProsperoInnerPfsReader.Entry> selected = selection is null
            ? all.Where(e => !e.IsDirectory && (!hasUroot || e.Path.StartsWith("/uroot/", StringComparison.Ordinal))).ToArray()
            : exact is { IsDirectory: false } ? [exact]
            : all.Where(e => !e.IsDirectory && (e.Path == normalized || e.Path.StartsWith(normalized + "/", StringComparison.Ordinal))).ToArray();
        if (selection is not null && selected.Count == 0)
            throw new InvalidDataException($"Inner path '{selection}' does not exist.");

        if (exact is { IsDirectory: false })
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            File.WriteAllBytes(output, ProsperoInnerPfsReader.ReadFile(decoded.Mount, exact));
            Console.WriteLine($"Extracted {exact.Path} -> {output}");
            return 0;
        }
        Directory.CreateDirectory(output);
        string rootPrefix = selection is null ? "/uroot/" : normalized.TrimEnd('/') + "/";
        int written = 0;
        foreach (ProsperoInnerPfsReader.Entry entry in selected)
        {
            string relative = entry.Path.StartsWith(rootPrefix, StringComparison.Ordinal) ? entry.Path[rootPrefix.Length..] : entry.Path.TrimStart('/');
            if (relative.Length == 0) continue;
            string destination = Path.GetFullPath(Path.Combine(output, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!destination.StartsWith(Path.GetFullPath(output).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Inner extraction path escapes the output directory.");
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            File.WriteAllBytes(destination, ProsperoInnerPfsReader.ReadFile(decoded.Mount, entry));
            written++;
        }
        Console.WriteLine($"Extracted {written} file(s) to {output}");
        return 0;
    }

    private static int RunInnerImageExtractFileBacked(
        string package, string? selection, string output, string? passcode, bool mountMode)
    {
        using ProsperoFileBackedPackage fileBacked = ProsperoPackageContent.ReadFileBacked(package, passcode);
        if (mountMode)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            using var source = fileBacked.OpenMount();
            using var target = File.Create(output);
            source.CopyTo(target, 1 << 20);
            Console.WriteLine($"Wrote uncompressed inner mount: {output}");
            return 0;
        }

        IReadOnlyList<ProsperoInnerPfsReader.Entry> all = fileBacked.Entries;
        string normalized = NormalizeInnerSelection(selection);
        ProsperoInnerPfsReader.Entry? exact = all.FirstOrDefault(e => string.Equals(e.Path, normalized, StringComparison.Ordinal));
        // The default extraction is the game tree (uroot), matching the reference ExtractInnerFiles;
        // the PFS super-root's internal metadata files (flat path/afid tables) are never extracted.
        bool hasUroot = all.Any(e => e.Path == "/uroot");
        IReadOnlyList<ProsperoInnerPfsReader.Entry> selected = selection is null
            ? all.Where(e => !e.IsDirectory && (!hasUroot || e.Path.StartsWith("/uroot/", StringComparison.Ordinal))).ToArray()
            : exact is { IsDirectory: false } ? [exact]
            : all.Where(e => !e.IsDirectory && (e.Path == normalized || e.Path.StartsWith(normalized + "/", StringComparison.Ordinal))).ToArray();
        if (selection is not null && selected.Count == 0)
            throw new InvalidDataException($"Inner path '{selection}' does not exist.");

        using Stream mount = fileBacked.OpenMount();
        if (exact is { IsDirectory: false })
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            using var destination = File.Create(output);
            ProsperoInnerPfsReader.ExtractFile(mount, exact, destination);
            Console.WriteLine($"Extracted {exact.Path} -> {output}");
            return 0;
        }

        Directory.CreateDirectory(output);
        string rootPrefix = selection is null ? "/uroot/" : normalized.TrimEnd('/') + "/";
        int written = 0;
        foreach (ProsperoInnerPfsReader.Entry entry in selected)
        {
            string relative = entry.Path.StartsWith(rootPrefix, StringComparison.Ordinal) ? entry.Path[rootPrefix.Length..] : entry.Path.TrimStart('/');
            if (relative.Length == 0) continue;
            string destination = Path.GetFullPath(Path.Combine(output, relative.Replace('/', Path.DirectorySeparatorChar)));
            if (!destination.StartsWith(Path.GetFullPath(output).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Inner extraction path escapes the output directory.");
            Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
            using var fileDestination = File.Create(destination);
            ProsperoInnerPfsReader.ExtractFile(mount, entry, fileDestination);
            written++;
        }
        Console.WriteLine($"Extracted {written} file(s) to {output}");
        return 0;
    }

    private static int RunInnerImageFileList(string[] args)
    {
        string? package = null, passcode = null, subtree = null, referencePackage = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--passcode" && i + 1 < args.Length) passcode = args[++i];
            else if (args[i] == "--path" && i + 1 < args.Length) subtree = args[++i];
            else if (args[i] == "--ref_pkg_path" && i + 1 < args.Length) referencePackage = args[++i];
            else if (args[i] == "--no_passcode") { }
            else if (args[i].StartsWith("--", StringComparison.Ordinal)) return UnknownOption(args[i]);
            else package ??= args[i];
        }
        if (package is null) { Console.Error.WriteLine("Usage: ProsperoPkgTool img_file_list [--ref_pkg_path <reference.pkg>] [--passcode <passcode>|--no_passcode] [--path <inner-path>] <package>"); return 2; }
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(package);
        try
        {
            bool large = inspection.Kind == ProsperoPackageKind.FinalizedDebug &&
                inspection.Fih is { } fihLarge && fihLarge.PfsSize > (1L << 31);
            string prefix = NormalizeInnerSelection(subtree);
            IReadOnlyList<ProsperoInnerPfsReader.Entry> all;
            if (large)
            {
                using ProsperoFileBackedPackage fileBacked = ProsperoPackageContent.ReadFileBacked(package, passcode);
                all = fileBacked.Entries;
                foreach (ProsperoInnerPfsReader.Entry entry in all
                    .Where(e => e.Path == prefix || e.Path.StartsWith(prefix + "/", StringComparison.Ordinal)))
                    Console.WriteLine($"{(entry.IsDirectory ? "dir " : "file"),-4} {entry.Size,10} {entry.Path}");
                return 0;
            }

            ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, passcode, referencePackage);
            all = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
            foreach (ProsperoInnerPfsReader.Entry entry in all
                .Where(e => e.Path == prefix || e.Path.StartsWith(prefix + "/", StringComparison.Ordinal)))
                Console.WriteLine($"{(entry.IsDirectory ? "dir " : "file"),-4} {entry.Size,10} {entry.Path}");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or System.Security.Cryptography.CryptographicException)
        {
            if (inspection.Kind == ProsperoPackageKind.FinalizedPatchDebug)
            {
                Console.Error.WriteLine(ex.Message);
                return 4;
            }
            Console.WriteLine("Encrypted payload: key required");
            Console.WriteLine("Structural CNT entries:");
            foreach (ProsperoCntEntry entry in inspection.Entries)
                Console.WriteLine($"  0x{entry.Id:X8} {entry.DisplayName} ({entry.DataSize} bytes)");
            return inspection.Structure.IsValid ? 0 : 4;
        }
    }

    private static int RunInnerImageVerify(string[] args)
    {
        string? package = null, passcode = null, referencePackage = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--passcode" && i + 1 < args.Length) passcode = args[++i];
            else if (args[i] == "--ref_pkg_path" && i + 1 < args.Length) referencePackage = args[++i];
            else if (args[i] == "--no_passcode") { }
            else if (args[i].StartsWith("--", StringComparison.Ordinal)) return UnknownOption(args[i]);
            else package ??= args[i];
        }
        if (package is null) { Console.Error.WriteLine("Usage: ProsperoPkgTool img_verify [--ref_pkg_path <reference.pkg>] [--passcode <passcode>|--no_passcode] <package>"); return 2; }
        ProsperoPackageVerificationReport report = ProsperoPackageVerifier.Verify(package, passcode, referencePackage);
        foreach (VerificationCheck check in report.Checks)
            Console.WriteLine($"{check.State.ToString().ToUpperInvariant(),-11} {check.Name}: {check.Detail}");
        return report.HasFailure ? 4 : 0;
    }

    private static void PrintParamSummary(string packagePath, ProsperoPackageInspection package)
    {
        ProsperoCntEntry? param = package.Entries.FirstOrDefault(e => e.Id == (uint)CntEntryId.ParamJson);
        if (param is null) { Console.WriteLine("Title ID/name/version: unavailable (param.json absent)"); return; }
        try
        {
            using JsonDocument doc = JsonDocument.Parse(ProsperoPackageContent.ReadCntEntry(packagePath, package, param));
            JsonElement root = doc.RootElement;
            string Value(string property) => root.TryGetProperty(property, out JsonElement item) && item.ValueKind == JsonValueKind.String ? item.GetString() ?? "(unavailable)" : "(unavailable)";
            Console.WriteLine($"Title ID: {Value("titleId")}");
            Console.WriteLine($"Title name: {Value("titleName")}");
            Console.WriteLine($"Application/package version: {Value("contentVersion")}");
            Console.WriteLine("Master version / SDK version / required system software: unavailable");
        }
        catch (Exception) { Console.WriteLine("Title ID/name/version: unavailable (param.json unreadable)"); }
    }

    /// <summary>
    /// Strip the native <c>in_path[:dst_path]</c> suffix, if present. The drive-letter colon
    /// (position 1, e.g. <c>C:\...</c>) is not a dst-path separator, so only a <c>:</c> at
    /// index &gt; 1 is treated as the separator.
    /// </summary>
    private static (string Package, string? Selection) SplitPackageSelection(string argument)
    {
        int colon = argument.IndexOf(':', 2);
        return colon < 0 ? (argument, null) : (argument[..colon], argument[(colon + 1)..]);
    }

    private static string NormalizeInnerSelection(string? selection)
    {
        if (string.IsNullOrWhiteSpace(selection)) return "/uroot";
        string value = selection.Replace('\\', '/').Trim();
        if (!value.StartsWith('/')) value = "/" + value;
        if (!value.StartsWith("/uroot", StringComparison.Ordinal)) value = "/uroot" + value;
        if (value.Split('/', StringSplitOptions.RemoveEmptyEntries).Any(s => s is "." or ".."))
            throw new InvalidDataException("Inner path must not contain '.' or '..'.");
        return value.TrimEnd('/');
    }

    private static int UnknownOption(string option)
    {
        Console.Error.WriteLine($"Unknown option: {option}");
        return 2;
    }

    private static (byte[] InnerImage, byte[] Naps) ReadInnerImageAndNaps(
        string package, string? passcode, bool noPasscode)
    {
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(package);
        if (inspection.Fih is not { } fih)
            throw new InvalidDataException("Package has no FIH header; expected a finalized image.");
        string contentId = inspection.Cnt.ContentId;
        if (contentId.Length == 0)
            throw new InvalidDataException("Package CNT has an empty content id.");

        using var stream = File.OpenRead(Path.GetFullPath(package));
        OuterPfsReader pfs = OuterPfsReader.Open(stream, checked((long)fih.PfsOffset), checked((long)fih.PfsSize));

        byte[] ekpfs = ResolvePasscode(contentId, passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);

        byte[] naps = pfs.ReadNaps(xts);
        byte[] innerImage = pfs.ReadInnerImage(xts);
        return (innerImage, naps);
    }

    /// <summary>
    /// Resolve the outer-PFS passcode. Mirrors the native tool: an explicit
    /// <c>--passcode</c> wins; otherwise (including <c>--no_passcode</c>) the all-zero
    /// passcode (32 <c>'0'</c>) is used as the default.
    /// </summary>
    private static byte[] ResolvePasscode(string contentId, string? passcode)
    {
        if (passcode is not null)
            return ProsperoKeys.ComputeEkpfs(contentId, passcode);
        return ProsperoKeys.ComputeEkpfs(contentId, Gp5Constants.DefaultPasscode);
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

    private static int PrintFormats()
    {
        foreach (ContainerBackendDescriptor backend in ContainerBackendCatalog.All)
            Console.WriteLine($"{backend.FormatId,-10} {backend.Status,-12} {backend.DisplayName} [{backend.Capabilities}]");
        return 0;
    }

    /// <summary>
    /// PC-side parity check: field-by-field diff of a reference and candidate package. Prints
    /// MATCH (exit 0) when identical, one line per difference (exit 1), or a usage/read error (2).
    /// </summary>
    private static int RunCompare(string[] args)
    {
        if (args.Length != 2 || args.Any(a => a.StartsWith("--", StringComparison.Ordinal)))
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool compare <reference.pkg> <candidate.pkg>");
            return 2;
        }
        try
        {
            IReadOnlyList<string> differences = ProsperoContainerComparer.Compare(args[0], args[1]);
            if (differences.Count == 0)
            {
                Console.WriteLine("MATCH");
                return 0;
            }
            foreach (string difference in differences)
                Console.WriteLine(difference);
            return 1;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or ArgumentException)
        {
            Console.Error.WriteLine($"Error: {ex.Message}");
            return 2;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("ProsperoPkgTool 0.3 - clean-room PS5 package toolkit (no Sony tools required)");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  ProsperoPkgTool <command> [arguments]");
        Console.WriteLine();
        Console.WriteLine("General:");
        Console.WriteLine("  formats                 List supported/planned container backends");
        Console.WriteLine("GP5 and source:");
        Console.WriteLine("  gp5gen                  Generate a GP5 project from an unpacked title folder");
        Console.WriteLine("  gp5info                 Show GP5 project information");
        Console.WriteLine("  gp5validate             Validate a GP5 project");
        Console.WriteLine("  gp5format               Rewrite a GP5 to a separate file");
        Console.WriteLine("  source-validate         Validate a source folder (param.json, files)");
        Console.WriteLine("  playgo-info             Inspect a playgo-chunk.dat");
        Console.WriteLine("  fself <module.elf> --out <module.bin>");
        Console.WriteLine("                          Fake-sign a raw 64-bit ELF into a debug SELF container");
        Console.WriteLine("                          [--authority <hex64>] [--app-version <hex64>] [--fw-version <hex64>]");
        Console.WriteLine("                          [--sceversion-name <name> --sceversion-from <reference.elf>] [--force]");
        Console.WriteLine("Native package commands (clean-room, no Sony tool required):");
        Console.WriteLine("  pkg-detect              Identify finalized-debug, finalized-retail, or bare CNT");
        Console.WriteLine("  native-info             Read FIH/CNT metadata and segment geometry");
        Console.WriteLine("  native-validate         Validate unkeyed package structure and segment bounds");
        Console.WriteLine("  native-entries          List CNT metadata records");
        Console.WriteLine("  native-decrypt <pkg> --passcode <32 chars> [--out <inner-image.bin>]");
        Console.WriteLine("                          Derive keys, verify the superblock, decrypt the outer PFS");
        Console.WriteLine("  img_info <pkg>          Summarize package, container, and decoded inner-image state");
        Console.WriteLine("                          [--passcode <passcode>|--no_passcode] [--tmp_path <dir>]");
        Console.WriteLine("  img_file_list <pkg>     List logical inner-PFS paths; patches use --ref_pkg_path <base.pkg>");
        Console.WriteLine("  img_extract <pkg> <out> Extract logical files; patches use --ref_pkg_path <base.pkg>");
        Console.WriteLine("                          --mount writes the reconstructed mount image for diagnostics");
        Console.WriteLine("                          [--passcode <passcode>|--no_passcode] [--tmp_path <dir>]");
        Console.WriteLine("  img_verify <pkg>        Run available structural, CNT, PFS, NAPS, and inner-PFS checks");
        Console.WriteLine("  img_create <src> --out <pkg>  Build a debug base/application package");
        Console.WriteLine("                          <src> is a source folder or a project.gp5 manifest (manifest mode)");
        Console.WriteLine("                          [--gp5 <project.gp5>] [--compression stored|kraken]");
        Console.WriteLine("                          [--content-id <id>] [--passcode <32 chars>|--no_passcode] [--no_fself]");
        Console.WriteLine("  convert <backup> --out <pkg>  Convert a decrypted backup into a debug base package");
        Console.WriteLine("                          Substitutes raw ELF modules from the decrypted subtree, fake-signs");
        Console.WriteLine("                          them, then reports module classification and launch-readiness");
        Console.WriteLine("                          [--decrypted <subfolder>] [--content-id <id>] [--passcode <32 chars>|--no_passcode]");
        Console.WriteLine("                          [--version NN.NN] [--compression stored|kraken] [--staging <folder>]");
        Console.WriteLine("                          [--keep-staging] [--use-embedded-right-sprx]");
        Console.WriteLine("Parity:");
        Console.WriteLine("  compare <reference.pkg> <candidate.pkg>  Field-by-field container diff (exit 1 on differences)");
    }
}
