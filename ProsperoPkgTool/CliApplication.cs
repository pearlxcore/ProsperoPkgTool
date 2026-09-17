using System.Buffers.Binary;
using System.Text.Json;
using ProsperoPkgTool.Compression;
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
                "img-create" or "img_create" => RunInnerImageCreate(commandArgs, sharedLog: null, cancellationToken),
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
        catch (ProsperoInsufficientSpaceException space)
        {
            Console.Error.WriteLine($"Error: {space.Message}");
            return Task.FromResult(5);
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
            ProsperoPackageContent.RequiresFileBacked(package, noPasscode ? null : passcode);
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
                if (!IsEncryptionRequired(ex))
                {
                    Console.Error.WriteLine($"Error: {ex.Message}");
                    return 4;
                }
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
            if (!IsEncryptionRequired(ex))
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 4;
            }
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
        if (blocks is NapsBlockPlan plan)
        {
            Console.WriteLine($"NAPS dialect: {plan.Dialect}");
            foreach (string diagnostic in plan.Diagnostics)
                Console.WriteLine($"NAPS probe: {diagnostic}");
        }
        Console.WriteLine($"Block kinds: stored {blocks.Count(b => !b.IsKraken && !b.IsZeroHole && !b.IsAlias)}, " +
            $"Kraken {blocks.Count(b => b.IsKraken)}, zero-fill {blocks.Count(b => b.IsZeroHole)}, alias {blocks.Count(b => b.IsAlias)}");
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
        string? staging = null;
        bool keepStaging = false;
        bool useEmbeddedRightSprx = false;
        bool noPasscode = false;
        bool verbose = false;
        ProsperoInnerCompressionMode compressionMode = ProsperoInnerCompressionMode.Stored;
        int krakenLevel = KrakenTuning.DefaultLevel;
        int krakenThreads = 0;
        ulong? sdkVersionOverride = null;
        string? drmTypeOverride = null;
        string? titleOverride = null;
        string? titleIdOverride = null;
        bool sweepTemp = true;
        int staleHours = 12;
        string? tempDir = null;
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
                case "--staging" when i + 1 < args.Length:
                    staging = args[++i];
                    break;
                case "--verbose" or "-v":
                    verbose = true;
                    break;
                case "--compression" when i + 1 < args.Length:
                    compressionMode = args[++i].ToLowerInvariant() switch
                    {
                        "stored" => ProsperoInnerCompressionMode.Stored,
                        "kraken" or "auto" => ProsperoInnerCompressionMode.Auto,
                        _ => throw new ArgumentException("--compression must be 'stored' or 'kraken'."),
                    };
                    break;
                case "--kraken-level" when i + 1 < args.Length:
                    krakenLevel = ParseIntOption("--kraken-level", args[++i]);
                    break;
                case "--kraken-threads" when i + 1 < args.Length:
                    krakenThreads = ParseIntOption("--kraken-threads", args[++i]);
                    break;
                case "--sdk" when i + 1 < args.Length:
                    sdkVersionOverride = ParseSdkOption(args[++i]);
                    break;
                case "--drm-type" when i + 1 < args.Length:
                    drmTypeOverride = ParseDrmTypeOption(args[++i]);
                    break;
                case "--no-temp-sweep":
                    sweepTemp = false;
                    break;
                case "--stale-hours" when i + 1 < args.Length:
                    staleHours = ParseIntOption("--stale-hours", args[++i]);
                    break;
                case "--temp" when i + 1 < args.Length:
                    tempDir = args[++i];
                    break;
                case "--keep-staging":
                    keepStaging = true;
                    break;
                case "--use-embedded-right-sprx":
                    useEmbeddedRightSprx = true;
                    break;
                case "--title" when i + 1 < args.Length:
                    titleOverride = args[++i];
                    break;
                case "--title-id" when i + 1 < args.Length:
                    titleIdOverride = args[++i];
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
            Console.Error.WriteLine("Usage: ProsperoPkgTool convert <backup-folder> --out <package.pkg> [--decrypted <subfolder>] [--content-id <id>] [--passcode <32 chars>|--no_passcode] [--compression stored|kraken] [--kraken-level -4..9] [--kraken-threads <n|0=auto>] [--sdk <major|0x-id>] [--drm-type <token>] [--title <name>] [--title-id <id>] [--no-temp-sweep] [--stale-hours <n>] [--temp <dir>] [--staging <folder>] [--keep-staging] [--use-embedded-right-sprx] [--verbose]");
            return 2;
        }

        string resolvedPasscode = noPasscode || string.IsNullOrEmpty(passcode)
            ? ProsperoDebugLicense.DefaultPasscode
            : passcode;
        string outputPath = Path.GetFullPath(output);

        var options = new ProsperoBackupConversionOptions
        {
            BackupFolder = backup,
            OutputFolder = Path.GetDirectoryName(outputPath) is { Length: > 0 } outputDir ? outputDir : ".",
            DecryptedSubfolder = decrypted ?? "decrypted",
            ContentId = contentId ?? "",
            Passcode = resolvedPasscode,
            StagingFolder = staging ?? "",
            KeepStaging = keepStaging,
            UseEmbeddedRightSprx = useEmbeddedRightSprx,
            Verbose = verbose,
        };

        var log = new ProsperoConsoleLog();
        log.Write("Build started");
        log.Write($"Source folder: {backup}");
        log.Write($"Output: {outputPath}");
        log.Write($"Compression: {(compressionMode == ProsperoInnerCompressionMode.Stored ? "stored" : "kraken")}, " +
            $"level {krakenLevel}, threads {(krakenThreads == 0 ? "auto" : krakenThreads.ToString(System.Globalization.CultureInfo.InvariantCulture))}");
        if (compressionMode != ProsperoInnerCompressionMode.Stored)
            log.Write("Note: the clean-room Kraken encoder uses a single fixed strategy; the level is stored in the " +
                "image header but does not change the compressed size (only native Oodle acts on it).");

        var console = new ConsoleProgress(verbose, log);

        ProsperoBackupConversionResult result = ProsperoBackupConverter.Convert(options, staged =>
        {
            console.Finish();
            var buildArgs = new List<string> { staged.StagingFolder, "--out", outputPath };
            if (noPasscode) buildArgs.Add("--no_passcode");
            else { buildArgs.Add("--passcode"); buildArgs.Add(resolvedPasscode); }
            if (!string.IsNullOrWhiteSpace(contentId)) { buildArgs.Add("--content-id"); buildArgs.Add(contentId!); }
            buildArgs.Add("--compression");
            buildArgs.Add(compressionMode == ProsperoInnerCompressionMode.Stored ? "stored" : "kraken");
            buildArgs.Add("--kraken-level");
            buildArgs.Add(krakenLevel.ToString(System.Globalization.CultureInfo.InvariantCulture));
            buildArgs.Add("--kraken-threads");
            buildArgs.Add(krakenThreads.ToString(System.Globalization.CultureInfo.InvariantCulture));
            if (sdkVersionOverride is { } sdkValue)
            {
                buildArgs.Add("--sdk");
                buildArgs.Add("0x" + sdkValue.ToString("X16", System.Globalization.CultureInfo.InvariantCulture));
            }
            if (!string.IsNullOrWhiteSpace(drmTypeOverride))
            {
                buildArgs.Add("--drm-type");
                buildArgs.Add(drmTypeOverride);
            }
            if (!string.IsNullOrWhiteSpace(titleOverride))
            {
                buildArgs.Add("--title");
                buildArgs.Add(titleOverride!);
            }
            if (!string.IsNullOrWhiteSpace(titleIdOverride))
            {
                buildArgs.Add("--title-id");
                buildArgs.Add(titleIdOverride!);
            }
            if (!sweepTemp) buildArgs.Add("--no-temp-sweep");
            if (staleHours != 12)
            {
                buildArgs.Add("--stale-hours");
                buildArgs.Add(staleHours.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }
            if (!string.IsNullOrWhiteSpace(tempDir))
            {
                buildArgs.Add("--temp");
                buildArgs.Add(tempDir!);
            }
            if (verbose) buildArgs.Add("--verbose");

            int code = RunInnerImageCreate(buildArgs.ToArray(), log);
            if (code != 0)
                throw new InvalidDataException($"The package build failed (exit code {code}).");
            return outputPath;
        }, log.Write, console);

        console.Finish();
        if (File.Exists(outputPath))
            log.Write($"Build finished in {log.Elapsed}; output {new FileInfo(outputPath).Length:N0} bytes.");
        PrintConversionReport(result, log);
        return 0;
    }

    private static void PrintConversionReport(ProsperoBackupConversionResult result, ProsperoConsoleLog log)
    {
        log.Write($"Output: {result.OutputPath}");
        log.Write($"Content ID: {result.DebugLicense.ContentId}");
        log.Write($"Passcode: {result.DebugLicense.Passcode}");
        log.Write($"Debug license requires rif: {result.DebugLicense.RequiresRif}");
        if (result.StagingFolder.Length > 0)
            log.Write($"Staging folder: {result.StagingFolder}");
    }

    private static int RunInnerImageCreate(string[] args, ProsperoConsoleLog? sharedLog = null, CancellationToken cancellationToken = default)
    {
        string? source = null;
        string? output = null;
        string? contentId = null;
        string? gp5Path = null;
        string? requestedType = null;
        string? tempDir = null;
        ProsperoInnerCompressionMode compressionMode = ProsperoInnerCompressionMode.Auto;
        string passcode = Gp5Constants.DefaultPasscode;
        bool passcodeProvided = false;
        bool noPasscode = false;
        bool fakeSignModules = true;
        bool injectRightSprx = true;
        bool verbose = false;
        int krakenLevel = KrakenTuning.DefaultLevel;
        int krakenThreads = 0;
        byte[]? outerSeed = null;
        ulong? sdkVersionOverride = null;
        string? drmTypeOverride = null;
        string? titleOverride = null;
        string? titleIdOverride = null;
        bool sweepTemp = true;
        int staleHours = 12;
        int playGoChunks = 1;
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
                case "--verbose" or "-v":
                    verbose = true;
                    break;
                case "--compression" when i + 1 < args.Length:
                    compressionMode = args[++i].ToLowerInvariant() switch
                    {
                        "stored" => ProsperoInnerCompressionMode.Stored,
                        "kraken" or "auto" => ProsperoInnerCompressionMode.Auto,
                        _ => throw new ArgumentException("--compression must be 'stored' or 'kraken'."),
                    };
                    break;
                case "--kraken-level" when i + 1 < args.Length:
                    krakenLevel = ParseIntOption("--kraken-level", args[++i]);
                    break;
                case "--kraken-threads" when i + 1 < args.Length:
                    krakenThreads = ParseIntOption("--kraken-threads", args[++i]);
                    break;
                case "--seed" when i + 1 < args.Length:
                    outerSeed = ParseSeedOption(args[++i]);
                    break;
                case "--sdk" when i + 1 < args.Length:
                    sdkVersionOverride = ParseSdkOption(args[++i]);
                    break;
                case "--drm-type" when i + 1 < args.Length:
                    drmTypeOverride = ParseDrmTypeOption(args[++i]);
                    break;
                case "--no-temp-sweep":
                    sweepTemp = false;
                    break;
                case "--stale-hours" when i + 1 < args.Length:
                    staleHours = ParseIntOption("--stale-hours", args[++i]);
                    break;
                case "--temp" when i + 1 < args.Length:
                    tempDir = args[++i];
                    break;
                case "--playgo-chunks" when i + 1 < args.Length:
                    playGoChunks = ParseIntOption("--playgo-chunks", args[++i]);
                    break;
                case "--title" when i + 1 < args.Length:
                    titleOverride = args[++i];
                    break;
                case "--title-id" when i + 1 < args.Length:
                    titleIdOverride = args[++i];
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
            Console.Error.WriteLine("Usage: ProsperoPkgTool img_create <source-folder | project.gp5> --out <package.pkg> [--type base] [--compression stored|kraken] [--kraken-level -4..9] [--kraken-threads <n|0=auto>] [--seed <32-hex>] [--sdk <major|0x-id>] [--drm-type <token>] [--no-temp-sweep] [--stale-hours <n>] [--temp <dir>] [--playgo-chunks <n>] [--title <name>] [--title-id <id>] [--content-id <id>] [--passcode <32 chars>|--no_passcode] [--no_fself] [--no_right_sprx] [--verbose]");
            return 2;
        }

        var log = sharedLog ?? new ProsperoConsoleLog();
        var console = new ConsoleProgress(verbose, log);

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

        if (sharedLog is null)
        {
            log.Write("Build started");
            log.Write($"Source: {fullSource}");
            log.Write($"Output: {output}");
        }
        log.Write($"Building debug base/application package: {contentId}");

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

        var sceSysFiles = CollectSceSysFiles(fullSource, manifestFiles);
        var buildLog = new DebugPackageBuildLog
        {
            Progress = console,
            Log = log.Write,
            Finish = console.Finish,
        };
        DebugPackageBuildResult buildResult = ProsperoDebugPackageBuilder.Build(innerFiles, new DebugPackageBuildOptions
        {
            OutputPath = output,
            ContentId = contentId,
            Passcode = passcode,
            ParamJson = paramJson,
            Compression = compressionMode,
            KrakenLevel = krakenLevel,
            KrakenThreads = krakenThreads,
            OuterSeed = outerSeed,
            DeterministicEntryKeys = outerSeed is not null,
            SdkVersionOverride = sdkVersionOverride,
            DrmTypeOverride = drmTypeOverride,
            TitleOverride = titleOverride,
            TitleIdOverride = titleIdOverride,
            SweepStaleTempWorkspaces = sweepTemp,
            StaleWorkspaceHours = staleHours,
            TempDirectory = tempDir,
            PlayGo = gp5PlayGo,
            PlayGoChunkCount = playGoChunks,
            SceSysFiles = sceSysFiles,
            FakeSignModules = fakeSignModules,
            InjectRightSprx = injectRightSprx,
            Log = buildLog,
            CancellationToken = cancellationToken,
        });
        if (sharedLog is null)
            log.Write($"Build finished in {log.Elapsed}; output {buildResult.PackageLength:N0} bytes.");
        return 0;
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
        bool verbose = false;
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
                case "--verbose" or "-v":
                    verbose = true;
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

        var console = new ConsoleProgress(verbose);

        if (ProsperoPackageReader.Read(package).Kind == ProsperoPackageKind.FinalizedDebug &&
            ProsperoPackageContent.RequiresFileBacked(package, noPasscode ? null : passcode))
            return RunInnerImageExtractFileBacked(package, selection, output, noPasscode ? null : passcode, mountMode, console);

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
            console.Report(written, selected.Count, entry.Path);
        }
        console.Finish();
        Console.WriteLine($"Extracted {written} file(s) to {output}");
        return 0;
    }

    private static int RunInnerImageExtractFileBacked(
        string package, string? selection, string output, string? passcode, bool mountMode, ConsoleProgress console)
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
            console.Report(written, selected.Count, entry.Path);
        }
        console.Finish();
        Console.WriteLine($"Extracted {written} file(s) to {output}");
        return 0;
    }

    private static int RunInnerImageFileList(string[] args)
    {
        string? package = null, passcode = null, subtree = null, referencePackage = null;
        bool repairOffsets = false;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--passcode" && i + 1 < args.Length) passcode = args[++i];
            else if (args[i] == "--path" && i + 1 < args.Length) subtree = args[++i];
            else if (args[i] == "--ref_pkg_path" && i + 1 < args.Length) referencePackage = args[++i];
            else if (args[i] == "--repair-offsets") repairOffsets = true;
            else if (args[i] == "--no_passcode") { }
            else if (args[i].StartsWith("--", StringComparison.Ordinal)) return UnknownOption(args[i]);
            else package ??= args[i];
        }
        if (package is null) { Console.Error.WriteLine("Usage: ProsperoPkgTool img_file_list [--ref_pkg_path <reference.pkg>] [--passcode <passcode>|--no_passcode] [--path <inner-path>] [--repair-offsets] <package>"); return 2; }
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(package);
        try
        {
            bool large = inspection.Kind == ProsperoPackageKind.FinalizedDebug &&
                ProsperoPackageContent.RequiresFileBacked(package, passcode);
            string prefix = NormalizeInnerSelection(subtree);
            if (repairOffsets)
                Console.Error.WriteLine("Note: reconstructing truncated 64-bit directory offsets for listing; file data offsets may remain truncated.");
            IReadOnlyList<ProsperoInnerPfsReader.Entry> all;
            if (large)
            {
                using ProsperoFileBackedPackage fileBacked = ProsperoPackageContent.ReadFileBacked(package, passcode, repairOffsets);
                all = fileBacked.Entries;
                foreach (ProsperoInnerPfsReader.Entry entry in all
                    .Where(e => e.Path == prefix || e.Path.StartsWith(prefix + "/", StringComparison.Ordinal)))
                    Console.WriteLine($"{(entry.IsDirectory ? "dir " : "file"),-4} {entry.Size,10} {entry.Path}");
                return 0;
            }

            ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(package, passcode, referencePackage);
            all = ProsperoInnerPfsReader.Enumerate(decoded.Mount, repairOffsets);
            foreach (ProsperoInnerPfsReader.Entry entry in all
                .Where(e => e.Path == prefix || e.Path.StartsWith(prefix + "/", StringComparison.Ordinal)))
                Console.WriteLine($"{(entry.IsDirectory ? "dir " : "file"),-4} {entry.Size,10} {entry.Path}");
            return 0;
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or System.Security.Cryptography.CryptographicException)
        {
            bool encrypted = IsEncryptionRequired(ex);
            if (inspection.Kind == ProsperoPackageKind.FinalizedPatchDebug || !encrypted)
            {
                Console.Error.WriteLine($"Error: {ex.Message}");
                return 4;
            }
            Console.WriteLine("Encrypted payload: key required");
            Console.WriteLine("Structural CNT entries:");
            foreach (ProsperoCntEntry entry in inspection.Entries)
                Console.WriteLine($"  0x{entry.Id:X8} {entry.DisplayName} ({entry.DataSize} bytes)");
            return inspection.Structure.IsValid ? 0 : 4;
        }
    }

    private static bool IsEncryptionRequired(Exception ex) =>
        ex is System.Security.Cryptography.CryptographicException
        || ex.Message.Contains("Encrypted payload", StringComparison.OrdinalIgnoreCase);

    private static int RunInnerImageVerify(string[] args)
    {
        string? package = null, passcode = null, referencePackage = null;
        bool strict = false;
        VerificationPolicy policy = VerificationPolicy.DebugPackage;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--passcode" && i + 1 < args.Length) passcode = args[++i];
            else if (args[i] == "--ref_pkg_path" && i + 1 < args.Length) referencePackage = args[++i];
            else if (args[i] == "--policy" && i + 1 < args.Length)
            {
                if (!Enum.TryParse(args[++i], ignoreCase: true, out policy))
                {
                    Console.Error.WriteLine("Unknown --policy. Use Structural, DebugPackage, BuildAcceptance or FullAvailableChecks.");
                    return 2;
                }
            }
            else if (args[i] == "--no_passcode") { }
            else if (args[i] == "--strict") strict = true;
            else if (args[i].StartsWith("--", StringComparison.Ordinal)) return UnknownOption(args[i]);
            else package ??= args[i];
        }
        if (package is null)
        {
            Console.Error.WriteLine("Usage: ProsperoPkgTool img_verify [--ref_pkg_path <reference.pkg>] [--passcode <passcode>|--no_passcode] [--policy <Structural|DebugPackage|BuildAcceptance|FullAvailableChecks>] [--strict] <package>");
            return 2;
        }
        ProsperoPackageVerificationReport report = ProsperoPackageVerifier.Verify(package, passcode, referencePackage, policy);
        foreach (VerificationCheck check in report.Checks)
            Console.WriteLine($"{(check.Required ? "*" : " ")}{check.State.ToString().ToUpperInvariant(),-11} {check.Name}: {check.Detail}");
        int pass = report.Checks.Count(c => c.State == VerificationState.Pass);
        int fail = report.Checks.Count(c => c.State == VerificationState.Fail);
        int unavailable = report.Checks.Count(c => c.State == VerificationState.Unavailable);
        int unsupported = report.Checks.Count(c => c.State == VerificationState.Unsupported);
        int error = report.Checks.Count(c => c.State == VerificationState.Error);
        int notPresent = report.Checks.Count(c => c.State == VerificationState.NotPresent);
        Console.WriteLine($"Summary ({policy}): {pass} pass, {fail} fail, {error} error, {unavailable} unavailable, {unsupported} unsupported, {notPresent} not present.");
        Console.WriteLine($"Outcome: {report.Outcome.ToString().ToUpperInvariant()}.");
        if (report.Outcome == VerificationOutcome.Incomplete)
            Console.WriteLine("Verification is incomplete: not all required checks were performed (use --strict to fail on this).");
        if (report.HasFailure)
            return 4;
        return strict && report.Outcome == VerificationOutcome.Incomplete ? 6 : 0;
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
            // The display title usually lives under localizedParameters, not at the top level.
            string TitleName()
            {
                string top = Value("titleName");
                if (top != "(unavailable)")
                    return top;
                if (root.TryGetProperty("localizedParameters", out JsonElement locals) && locals.ValueKind == JsonValueKind.Object)
                {
                    foreach (string key in new[] { "default", "en-US" })
                        if (locals.TryGetProperty(key, out JsonElement entry) &&
                            entry.TryGetProperty("titleName", out JsonElement name) && name.ValueKind == JsonValueKind.String)
                            return name.GetString() ?? "(unavailable)";
                }
                return "(unavailable)";
            }
            Console.WriteLine($"Title ID: {Value("titleId")}");
            Console.WriteLine($"Title name: {TitleName()}");
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

    private static int ParseIntOption(string option, string value) =>
        int.TryParse(value, System.Globalization.NumberStyles.Integer,
            System.Globalization.CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : throw new ArgumentException($"{option} expects an integer but got '{value}'.");

    /// <summary>Parses a 32-hex-character outer-PFS seed for reproducible builds.</summary>
    private static byte[] ParseSeedOption(string value)
    {
        byte[] seed;
        try
        {
            seed = Convert.FromHexString(value);
        }
        catch (FormatException)
        {
            throw new ArgumentException("--seed must be 32 hexadecimal characters (16 bytes).");
        }
        return seed.Length == 16
            ? seed
            : throw new ArgumentException("--seed must be 32 hexadecimal characters (16 bytes).");
    }

    /// <summary>
    /// Parses an SDK override value: a major (<c>9</c>), a dotted version (<c>9.00.00.40</c>) or a raw
    /// 64-bit hex identifier (<c>0x0900004000000411</c>).
    /// </summary>
    private static ulong ParseSdkOption(string value) =>
        ProsperoSdkVersions.TryParse(value, out ulong sdkVersion)
            ? sdkVersion
            : throw new ArgumentException("--sdk expects a major (9), a dotted version (9.00.00.40) or a 0x 64-bit identifier.");

    /// <summary>
    /// Parses a DRM override token (<c>--drm-type</c>); any non-blank token is accepted and preserved
    /// verbatim, matching the lenient treatment of source <c>applicationDrmType</c> values.
    /// </summary>
    private static string ParseDrmTypeOption(string value) =>
        string.IsNullOrWhiteSpace(value)
            ? throw new ArgumentException("--drm-type expects a DRM token such as 'standard'.")
            : value.Trim();

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
        Console.WriteLine("                          [--passcode <passcode>|--no_passcode] [--path <inner-path>] [--repair-offsets]");
        Console.WriteLine("  img_extract <pkg> <out> Extract logical files; patches use --ref_pkg_path <base.pkg>");
        Console.WriteLine("                          --mount writes the reconstructed mount image for diagnostics");
        Console.WriteLine("                          [--passcode <passcode>|--no_passcode] [--tmp_path <dir>] [--verbose]");
        Console.WriteLine("  img_verify <pkg>        Run available structural, CNT, PFS, NAPS, and inner-PFS checks");
        Console.WriteLine("  img_create <src> --out <pkg>  Build a debug base/application package");
        Console.WriteLine("                          <src> is a source folder or a project.gp5 manifest (manifest mode)");
        Console.WriteLine("                          [--gp5 <project.gp5>] [--compression stored|kraken]");
        Console.WriteLine("                          [--content-id <id>] [--passcode <32 chars>|--no_passcode] [--no_fself] [--verbose]");
        Console.WriteLine("  convert <backup> --out <pkg>  Convert a decrypted backup into a debug base package");
        Console.WriteLine("                          Substitutes raw ELF modules from the decrypted subtree, fake-signs");
        Console.WriteLine("                          them, then reports module classification and launch-readiness");
        Console.WriteLine("                          [--decrypted <subfolder>] [--content-id <id>] [--passcode <32 chars>|--no_passcode]");
        Console.WriteLine("                          [--compression stored|kraken] [--drm-type <token>] [--title <name>]");
        Console.WriteLine("                          [--title-id <id>] [--sdk <major|0x-id>] [--staging <folder>]");
        Console.WriteLine("                          [--keep-staging] [--use-embedded-right-sprx]");
        Console.WriteLine("Parity:");
        Console.WriteLine("  compare <reference.pkg> <candidate.pkg>  Field-by-field container diff (exit 1 on differences)");
    }
}
