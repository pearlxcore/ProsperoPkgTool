namespace ProsperoPkgTool.Gui;

/// <summary>
/// Complete registry of every ProsperoPkgTool CLI command, grouped for the GUI workflow.
///
/// Split into two panes:
///   - <see cref="PackageOperations"/>: package-centric operations. The selected package and
///     passcode (from the package bar) are injected at run time, so those two values are never
///     listed as fields.
///   - <see cref="ToolOperations"/>: self-contained operations that name every input themselves
///     (GP5, source, creation, signing, parity).
/// </summary>
public static class CommandRegistry
{
    // Known Prospero SDK releases (newest first), sourced from the engine's release table so the GUI
    // combo stays in sync with what --sdk accepts. Declared before the command lists because their
    // static initializers read it.
    private static readonly string[] SdkVersions = ProsperoPkgTool.Content.ProsperoSdkVersions.Releases
        .OrderByDescending(release => release.Major)
        .Select(release => release.Version)
        .ToArray();

    // The convert command is shared: it appears in the "Build & Tools" list and is the sole command
    // of the dedicated Easy/Advanced Convert tabs, so the one instance is reused rather than cloned.
    private static readonly CommandDef ConvertCommand = BuildConvertCommand();

    public static IReadOnlyList<CommandDef> PackageOperations { get; } = BuildPackageOperations();
    public static IReadOnlyList<CommandDef> ToolOperations { get; } = BuildToolOperations();
    public static IReadOnlyList<CommandDef> ConvertOperations { get; } = [ConvertCommand];

    // Aggregate kept for callers that iterate everything.
    public static IReadOnlyList<CommandDef> All => [.. PackageOperations, .. ToolOperations];

    // ==================================================================
    // Package pane: pkg + passcode are injected by the package bar.
    // ==================================================================
    private static IReadOnlyList<CommandDef> BuildPackageOperations() =>
    [
        // ---------------------------------------------------------- Inspect
        Package("Detect package (pkg-detect)", "Inspect",
            "Identify finalized-debug, finalized-retail, or a bare CNT container.",
            "pkg-detect"),
        Package("Native info (native-info)", "Inspect",
            "Read FIH/CNT metadata and segment geometry without any external tool.",
            "native-info"),
        Package("Native validate (native-validate)", "Inspect",
            "Validate unkeyed FIH/CNT structure, segment bounds, and contiguity.",
            "native-validate"),
        Package("CNT entries (native-entries)", "Inspect",
            "List native CNT metadata entry IDs, names, offsets, sizes, and flags.",
            "native-entries"),
        new CommandDef
        {
            Name = "Image summary (img_info)",
            Group = "Inspect",
            Title = "Summarize package category, container, and decoded inner-image state",
            Description = "Print the package category and raw content type, envelope, segment geometry, and the decoded inner-PFS summary.",
            CliWord = "img_info",
            UsesSelectedPackage = true,
            Fields =
            [
                Check("usePasscode", "Use the passcode field above", "Off = the all-zero default passcode (--no_passcode)", on: true),
                Folder("tmpPath", "Temp folder (parity)", "Accepted for CLI parity; unused (--tmp_path)"),
            ],
            BuildArgs = values =>
            {
                var args = new List<string>();
                if (Value(values, "tmpPath") is { Length: > 0 } tmpPath)
                {
                    args.Add("--tmp_path");
                    args.Add(tmpPath);
                }
                if (values.GetValueOrDefault("usePasscode") == "1")
                    AddPasscode(args, values);
                else
                    args.Add("--no_passcode");
                args.Add(values["pkg"]);
                return args.ToArray();
            },
        },
        new CommandDef
        {
            Name = "Image verify (img_verify)",
            Group = "Inspect",
            Title = "Run structural, CNT, PFS, NAPS, and inner-PFS checks",
            Description = "Report every available check as PASS/FAIL/UNAVAILABLE/UNSUPPORTED/ERROR and an overall " +
                          "PASSED/FAILED/INCOMPLETE outcome. A decode/crypto/IO failure after the payload opens is a " +
                          "failure, never 'unavailable'. Supply a reference package for patch overlays.",
            CliWord = "img_verify",
            UsesSelectedPackage = true,
            Fields =
            [
                Combo("policy", "Verification policy",
                    ["DebugPackage", "Structural", "BuildAcceptance", "FullAvailableChecks"], "DebugPackage",
                    ["Default: structural checks plus the full inner-payload decode",
                     "Envelope only: structural bounds, FIH digest, CNT digests",
                     "Build-acceptance depth (same checks as DebugPackage)",
                     "Also require not-yet-implemented checks, so the result is INCOMPLETE rather than PASSED"]),
                Check("strict", "Strict", "Fail (exit 6) when required checks are unavailable/unsupported (--strict)"),
                Check("usePasscode", "Use the passcode field above", "Off = the all-zero default passcode (--no_passcode)", on: true),
                File("ref", "Reference package", "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*",
                    "Optional: base package for a patch/delta image"),
            ],
            BuildArgs = values =>
            {
                var args = new List<string>();
                if (Value(values, "policy") is { Length: > 0 } policy && policy != "DebugPackage")
                {
                    args.Add("--policy");
                    args.Add(policy);
                }
                if (values.GetValueOrDefault("strict") == "1")
                    args.Add("--strict");
                if (Value(values, "ref") is { Length: > 0 } reference)
                {
                    args.Add("--ref_pkg_path");
                    args.Add(reference);
                }
                if (values.GetValueOrDefault("usePasscode") == "1")
                    AddPasscode(args, values);
                else
                    args.Add("--no_passcode");
                args.Add(values["pkg"]);
                return args.ToArray();
            },
        },

        // ---------------------------------------------------------- Extract
        new CommandDef
        {
            Name = "Outer-PFS decrypt (native-decrypt)",
            Group = "Extract",
            Title = "Decrypt the outer PFS image",
            Description = "Derive keys from the passcode, verify the superblock, and decrypt the outer PFS inner image.",
            CliWord = "native-decrypt",
            UsesSelectedPackage = true,
            Fields =
            [
                Save("out", "Inner image output", "Binary output (*.bin)|*.bin|All files (*.*)|*.*",
                    "Optional: write the decrypted inner image"),
            ],
            BuildArgs = values =>
            {
                var args = new List<string> { values["pkg"], "--passcode", values["passcode"] };
                if (Value(values, "out") is { Length: > 0 } output)
                {
                    args.Add("--out");
                    args.Add(output);
                }
                return args.ToArray();
            },
        },
        new CommandDef
        {
            Name = "Image file list (img_file_list)",
            Group = "Extract",
            Title = "List logical inner-PFS paths",
            Description = "List inner-PFS files and directories. Supply a reference package for patches.",
            CliWord = "img_file_list",
            UsesSelectedPackage = true,
            Fields =
            [
                Text("path", "Subtree", string.Empty, "Optional: limit to an inner path, e.g. /uroot"),
                File("ref", "Reference package", "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*",
                    "Optional: base package for a patch/delta image"),
                Check("repairOffsets", "Repair truncated 64-bit offsets",
                    "Reconstruct directory offsets from the metadata region (--repair-offsets); listing only"),
                Check("usePasscode", "Use the passcode field above", "Off = the all-zero default passcode (--no_passcode)", on: true),
            ],
            BuildArgs = values =>
            {
                var args = new List<string>();
                if (Value(values, "ref") is { Length: > 0 } reference)
                {
                    args.Add("--ref_pkg_path");
                    args.Add(reference);
                }
                if (Value(values, "path") is { Length: > 0 } subtree)
                {
                    args.Add("--path");
                    args.Add(subtree);
                }
                if (values.GetValueOrDefault("repairOffsets") == "1")
                    args.Add("--repair-offsets");
                if (values.GetValueOrDefault("usePasscode") == "1")
                    AddPasscode(args, values);
                else
                    args.Add("--no_passcode");
                args.Add(values["pkg"]);
                return args.ToArray();
            },
        },
        new CommandDef
        {
            Name = "Image extract (img_extract)",
            Group = "Extract",
            Title = "Extract logical files or the reconstructed mount",
            Description = "Extract the inner game tree (default), a subtree, or the raw mount image for diagnostics.",
            CliWord = "img_extract",
            UsesSelectedPackage = true,
            Fields =
            [
                Text("selection", "Inner selection", string.Empty, "Optional: inner path to extract, e.g. /uroot/sce_sys"),
                Folder("out", "Output folder / file", "Where to write extracted files (or the mount image)"),
                Check("mount", "Write reconstructed mount image instead of files", "Mount image mode (--mount)"),
                File("ref", "Reference package", "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*",
                    "Optional: base package for a patch/delta image"),
                Check("verbose", "Verbose progress", "Show per-file extraction progress (--verbose)"),
                Check("usePasscode", "Use the passcode field above", "Off = the all-zero default passcode (--no_passcode)", on: true),
                Folder("tmpPath", "Temp folder (parity)", "Accepted for CLI parity; unused (--tmp_path)"),
            ],
            BuildArgs = values =>
            {
                var args = new List<string>();
                if (values.GetValueOrDefault("mount") == "1")
                    args.Add("--mount");
                if (Value(values, "tmpPath") is { Length: > 0 } tmpPath)
                {
                    args.Add("--tmp_path");
                    args.Add(tmpPath);
                }
                if (values.GetValueOrDefault("verbose") == "1")
                    args.Add("--verbose");
                if (Value(values, "ref") is { Length: > 0 } reference)
                {
                    args.Add("--ref_pkg_path");
                    args.Add(reference);
                }
                if (values.GetValueOrDefault("usePasscode") == "1")
                    AddPasscode(args, values);
                else
                    args.Add("--no_passcode");
                string target = Value(values, "selection") is { Length: > 0 } selection
                    ? $"{values["pkg"]}:{selection}"
                    : values["pkg"];
                args.Add(target);
                args.Add(Require(values, "out", "Output folder / file"));
                return args.ToArray();
            },
        },
    ];

    // ==================================================================
    // Tools pane: self-contained operations (every input is a field).
    // ==================================================================
    private static IReadOnlyList<CommandDef> BuildToolOperations() =>
    [
        // ----------------------------------------------------------- Create
        new CommandDef
        {
            Name = "Build package (img_create)",
            Group = "Create",
            Title = "Build a debug base/application package",
            Description = "Build a debug FIH package from a prepared title folder or a project.gp5 manifest.",
            CliWord = "img_create",
            Fields =
            [
                Folder("source", "Source folder", "Unpacked PS5 title folder (contains sce_sys)"),
                File("gp5", "Project.gp5 (manifest mode)", "GP5 projects (*.gp5)|*.gp5|All files (*.*)|*.*",
                    "Optional: use this GP5 as the source instead of the folder"),
                Save("out", "Output package", "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*", "Required"),
                Combo("type", "Package type", ["base"], "base", ["debug base application"]),
                Combo("compression", "Inner compression", ["stored", "kraken"], "kraken",
                    ["no compression", "Oodle Kraken / auto"]),
                Slider("krakenLevel", "Kraken level (-4..9)", -4, 9, 7, "Recorded in the compressed image header (default 7)"),
                Numeric("krakenThreads", "Kraken threads (0=auto)", 0, 256, 0, "0 = auto (processor count)"),
                Check("sdkOverride", "Override the SDK version", "Apply the chosen SDK version to param.json (--sdk)"),
                Combo("sdk", "SDK version", SdkVersions, SdkVersions[0]),
                Combo("drmType", "DRM type override", ["keep source", "free", "standard", "upgradable"], "keep source",
                    ["keep the source applicationDrmType", "free - no license required", "standard", "upgradable"]),
                Numeric("playgoChunks", "PlayGo chunks", 1, 8192, 1, "Generated chunk count when no source playgo-chunk.dat (default 1)"),
                Text("seed", "Outer seed (32 hex)", string.Empty, "Optional: deterministic seed, e.g. 000102030405060708090A0B0C0D0E0F"),
                Folder("temp", "Temp folder", "Optional: workspace for large builds (blank = system temp)"),
                Numeric("staleHours", "Reclaim stale temp after (hours)", 1, 720, 12, "Age before orphaned build workspaces are reclaimed"),
                Check("sweepTemp", "Sweep stale temp workspaces", "Reclaim orphaned build workspaces (off = --no-temp-sweep)", on: true),
                Text("contentId", "Content ID", string.Empty, "Auto-filled from the source sce_sys/param.json; optional override"),
                Text("titleId", "Title ID", string.Empty, "Auto-filled from param.json; overrides titleId and the content id's title segment"),
                Text("title", "Title", string.Empty, "Auto-filled from param.json; overrides the display title"),
                Text("passcode", "Passcode (32 chars)", CommandDef.DefaultPasscode, "Default: all-zero fake passcode"),
                Check("fakeSign", "Fake-sign modules", "Fake-sign raw ELF modules into debug SELF (off = --no_fself)", on: true),
                Check("injectRightSprx", "Inject debug right.sprx", "Inject the built-in debug module (off = --no_right_sprx)", on: true),
                Check("verbose", "Verbose progress", "Show stage progress (--verbose)", on: true),
            ],
            BuildArgs = values =>
            {
                var args = new List<string>();
                if (values.GetValueOrDefault("verbose") == "1")
                    args.Add("--verbose");
                if (Value(values, "type") is { Length: > 0 } type)
                {
                    args.Add("--type");
                    args.Add(type);
                }
                if (Value(values, "compression") is { Length: > 0 } compression)
                {
                    args.Add("--compression");
                    args.Add(compression);
                }
                if (Value(values, "krakenLevel") is { Length: > 0 } krakenLevel)
                {
                    args.Add("--kraken-level");
                    args.Add(krakenLevel);
                }
                if (Value(values, "krakenThreads") is { Length: > 0 } krakenThreads)
                {
                    args.Add("--kraken-threads");
                    args.Add(krakenThreads);
                }
                if (values.GetValueOrDefault("sdkOverride") == "1" && Value(values, "sdk") is { Length: > 0 } sdk)
                {
                    args.Add("--sdk");
                    args.Add(sdk);
                }
                if (Value(values, "drmType") is { Length: > 0 } drmType && drmType != "keep source")
                {
                    args.Add("--drm-type");
                    args.Add(drmType);
                }
                if (Value(values, "playgoChunks") is { Length: > 0 } playgoChunks)
                {
                    args.Add("--playgo-chunks");
                    args.Add(playgoChunks);
                }
                if (Value(values, "seed") is { Length: > 0 } seed)
                {
                    args.Add("--seed");
                    args.Add(seed);
                }
                if (Value(values, "temp") is { Length: > 0 } temp)
                {
                    args.Add("--temp");
                    args.Add(temp);
                }
                if (values.GetValueOrDefault("sweepTemp") != "1")
                    args.Add("--no-temp-sweep");
                if (Value(values, "staleHours") is { Length: > 0 } staleHours)
                {
                    args.Add("--stale-hours");
                    args.Add(staleHours);
                }
                if (Value(values, "contentId") is { Length: > 0 } contentId)
                {
                    args.Add("--content-id");
                    args.Add(contentId);
                }
                if (Value(values, "titleId") is { Length: > 0 } titleId)
                {
                    args.Add("--title-id");
                    args.Add(titleId);
                }
                if (Value(values, "title") is { Length: > 0 } title)
                {
                    args.Add("--title");
                    args.Add(title);
                }
                if (Value(values, "passcode") is { Length: > 0 } passcode)
                {
                    args.Add("--passcode");
                    args.Add(passcode);
                }
                if (values.GetValueOrDefault("fakeSign") != "1")
                    args.Add("--no_fself");
                if (values.GetValueOrDefault("injectRightSprx") != "1")
                    args.Add("--no_right_sprx");
                args.Add("--out");
                args.Add(Require(values, "out", "Output package"));
                string source = Value(values, "gp5") is { Length: > 0 } gp5
                    ? gp5
                    : Require(values, "source", "Source folder or project.gp5");
                args.Add(source);
                return args.ToArray();
            },
        },
        ConvertCommand,

        // -------------------------------------------------------------- GP5
        new CommandDef
        {
            Name = "Generate GP5 (gp5gen)",
            Group = "GP5",
            Title = "Generate a GP5 project from a title folder",
            Description = "Scan an unpacked title folder and write a GP5 publishing project.",
            CliWord = "gp5gen",
            Fields =
            [
                Folder("folder", "Source folder", "Unpacked PS5 title containing sce_sys/param.json"),
                Save("out", "Output (.gp5)", "GP5 projects (*.gp5)|*.gp5|All files (*.*)|*.*",
                    "Optional: defaults to <titleId>.gp5 inside the source folder"),
                Text("passcode", "Passcode (32 chars)", CommandDef.DefaultPasscode, "Default: all-zero fake passcode"),
                Check("force", "Overwrite existing output", "Replace the output file if it exists (--force)"),
            ],
            // gp5gen requires the positional folder first, then options.
            BuildArgs = values =>
            {
                var args = new List<string> { Require(values, "folder", "Source folder") };
                if (Value(values, "out") is { Length: > 0 } output)
                {
                    args.Add("--out");
                    args.Add(output);
                }
                if (Value(values, "passcode") is { Length: > 0 } passcode)
                {
                    args.Add("--passcode");
                    args.Add(passcode);
                }
                if (values.GetValueOrDefault("force") == "1")
                    args.Add("--force");
                return args.ToArray();
            },
        },
        new CommandDef
        {
            Name = "GP5 info (gp5info)",
            Group = "GP5",
            Title = "Show GP5 project information",
            Description = "Read and summarize a GP5 publishing project.",
            CliWord = "gp5info",
            Fields = [File("file", "GP5 project", "GP5 projects (*.gp5)|*.gp5|All files (*.*)|*.*")],
            BuildArgs = values => [Require(values, "file", "GP5 project")],
        },
        new CommandDef
        {
            Name = "GP5 validate (gp5validate)",
            Group = "GP5",
            Title = "Validate a GP5 project",
            Description = "Validate GP5 structure, metadata, chunks, paths, and sources.",
            CliWord = "gp5validate",
            Fields = [File("file", "GP5 project", "GP5 projects (*.gp5)|*.gp5|All files (*.*)|*.*")],
            BuildArgs = values => [Require(values, "file", "GP5 project")],
        },
        new CommandDef
        {
            Name = "GP5 format (gp5format)",
            Group = "GP5",
            Title = "Rewrite a GP5 to a separate file",
            Description = "Validate and re-serialize a GP5 project to a canonical output file.",
            CliWord = "gp5format",
            Fields =
            [
                File("file", "Input GP5", "GP5 projects (*.gp5)|*.gp5|All files (*.*)|*.*"),
                Save("out", "Output GP5", "GP5 projects (*.gp5)|*.gp5|All files (*.*)|*.*", "Required, must differ from the input"),
                Check("force", "Overwrite existing output", "Replace the output file if it exists (--force)"),
            ],
            // gp5format requires <input> --out <output> positionally.
            BuildArgs = values =>
            {
                var args = new List<string>
                {
                    Require(values, "file", "Input GP5"),
                    "--out",
                    Require(values, "out", "Output GP5"),
                };
                if (values.GetValueOrDefault("force") == "1")
                    args.Add("--force");
                return args.ToArray();
            },
        },

        // ----------------------------------------------------------- Source
        new CommandDef
        {
            Name = "Source validate (source-validate)",
            Group = "Source",
            Title = "Validate a source folder",
            Description = "Validate param.json, PlayGo, required files, and the source tree.",
            CliWord = "source-validate",
            Fields = [Folder("folder", "Source folder", "Unpacked PS5 title")],
            BuildArgs = values => [Require(values, "folder", "Source folder")],
        },
        new CommandDef
        {
            Name = "PlayGo info (playgo-info)",
            Group = "Source",
            Title = "Inspect playgo-chunk.dat",
            Description = "Strictly inspect a PS5 playgo-chunk.dat (chunks, scenarios, language masks).",
            CliWord = "playgo-info",
            Fields = [File("file", "playgo-chunk.dat", "PlayGo chunk (playgo-chunk.dat)|playgo-chunk.dat|All files (*.*)|*.*")],
            BuildArgs = values => [Require(values, "file", "playgo-chunk.dat")],
        },

        // ------------------------------------------------------------ Sign
        new CommandDef
        {
            Name = "Fake-sign module (fself)",
            Group = "Sign",
            Title = "Fake-sign a raw 64-bit ELF into a debug SELF",
            Description = "Wrap a raw ELF module in a debug SELF container. Advanced metadata is optional.",
            CliWord = "fself",
            Fields =
            [
                File("input", "Module (.elf)", "ELF modules (*.elf)|*.elf|All files (*.*)|*.*"),
                Save("out", "Output (.bin)", "Binary output (*.bin)|*.bin|All files (*.*)|*.*", "Required"),
                Text("authority", "Authority id (hex)", string.Empty, "Optional: 64-bit hex authority id"),
                Text("appVersion", "App version (hex)", string.Empty, "Optional: 64-bit hex app version"),
                Text("fwVersion", "Firmware version (hex)", string.Empty, "Optional: 64-bit hex firmware version"),
                Text("sceVersionName", "SceVersion name", string.Empty, "Optional: .sceversion section name"),
                File("sceVersionFrom", "SceVersion reference", "ELF modules (*.elf)|*.elf|All files (*.*)|*.*",
                    "Optional: copy the .sceversion record from this reference ELF"),
                Check("force", "Overwrite existing output", "Replace the output file if it exists (--force)"),
            ],
            BuildArgs = values =>
            {
                var args = new List<string>();
                args.Add("--out");
                args.Add(Require(values, "out", "Output (.bin)"));
                if (Value(values, "authority") is { Length: > 0 } authority)
                {
                    args.Add("--authority");
                    args.Add(authority);
                }
                if (Value(values, "appVersion") is { Length: > 0 } appVersion)
                {
                    args.Add("--app-version");
                    args.Add(appVersion);
                }
                if (Value(values, "fwVersion") is { Length: > 0 } fwVersion)
                {
                    args.Add("--fw-version");
                    args.Add(fwVersion);
                }
                if (Value(values, "sceVersionName") is { Length: > 0 } sceVersionName)
                {
                    args.Add("--sceversion-name");
                    args.Add(sceVersionName);
                }
                if (Value(values, "sceVersionFrom") is { Length: > 0 } sceVersionFrom)
                {
                    args.Add("--sceversion-from");
                    args.Add(sceVersionFrom);
                }
                if (values.GetValueOrDefault("force") == "1")
                    args.Add("--force");
                args.Add(Require(values, "input", "Module (.elf)"));
                return args.ToArray();
            },
        },

        // ---------------------------------------------------------- Parity
        new CommandDef
        {
            Name = "Compare packages (compare)",
            Group = "Parity",
            Title = "Field-by-field container diff",
            Description = "Compare a reference and a candidate package; exit 1 when fields differ.",
            CliWord = "compare",
            Fields =
            [
                File("reference", "Reference package", "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*"),
                File("candidate", "Candidate package", "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*"),
            ],
            BuildArgs = values =>
            [
                Require(values, "reference", "Reference package"),
                Require(values, "candidate", "Candidate package"),
            ],
        },

        // ------------------------------------------------------------ Info
        new CommandDef
        {
            Name = "Supported formats (formats)",
            Group = "Info",
            Title = "List supported/planned container backends",
            Description = "Print the container backend catalog and capability status.",
            CliWord = "formats",
            Fields = [],
            BuildArgs = _ => [],
        },
    ];

    // ==================================================================
    // Convert: shared by the "Build & Tools" list and the Easy/Advanced tabs.
    // Fields marked advanced-only are hidden in Easy; hidden fields still contribute their
    // DefaultFor value on a run, so Easy == Advanced with the advanced knobs left at defaults.
    // ==================================================================
    private static CommandDef BuildConvertCommand() => new()
    {
        Name = "Convert backup (convert)",
        Group = "Create",
        Title = "Convert a decrypted backup into a debug base package",
        Description = "Substitute and fake-sign raw ELF modules from a decrypted backup, then build and report launch readiness.",
        CliWord = "convert",
        Fields =
        [
            // --- Easy + advanced ---
            Folder("backup", "Backup folder", "Decrypted backup root (contains sce_sys)"),
            Save("out", "Output package", "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*", "Required"),
            Text("title", "Title", string.Empty, "Auto-filled from param.json; overrides the display title"),
            Text("contentId", "Content ID", string.Empty, "Auto-filled from the source sce_sys/param.json; optional override"),
            Text("passcode", "Passcode (32 chars)", CommandDef.DefaultPasscode, "Default: all-zero fake passcode"),
            Combo("drmType", "DRM type", ["keep source", "free", "standard", "upgradable"], "keep source",
                ["keep the source applicationDrmType", "free - no license required", "standard", "upgradable"],
                easyDefault: "free"),
            Check("sdkOverride", "Override the SDK version", "Apply the chosen SDK version to param.json (--sdk)",
                easyDefault: "1"),
            Combo("sdk", "SDK version", SdkVersions, SdkVersions[0], easyDefault: SdkVersions[^1]),
            Check("verbose", "Verbose progress", "Show per-file and stage progress (--verbose)", on: true),

            // --- Advanced only ---
            Text("titleId", "Title ID", string.Empty,
                "Auto-filled from param.json; overrides titleId and the content id's title segment", advancedOnly: true),
            Check("noPasscode", "Use the all-zero default passcode",
                "Emit --no_passcode instead of the passcode field", advancedOnly: true),
            Text("decrypted", "Decrypted subfolder", "decrypted",
                "Subfolder holding the raw ELF copies (--decrypted; default decrypted)", advancedOnly: true),
            Combo("compression", "Inner compression", ["stored", "kraken"], "kraken",
                ["no compression", "Oodle Kraken / auto"], advancedOnly: true),
            Slider("krakenLevel", "Kraken level (-4..9)", -4, 9, 7,
                "Recorded in the compressed image header (default 7)", advancedOnly: true),
            Numeric("krakenThreads", "Kraken threads (0=auto)", 0, 256, 0,
                "0 = auto (processor count)", advancedOnly: true),
            Folder("temp", "Temp folder", "Optional: workspace for large builds (blank = system temp)", advancedOnly: true),
            Numeric("staleHours", "Reclaim stale temp after (hours)", 1, 720, 12,
                "Age before orphaned build workspaces are reclaimed", advancedOnly: true),
            Check("sweepTemp", "Sweep stale temp workspaces",
                "Reclaim orphaned build workspaces (off = --no-temp-sweep)", on: true, advancedOnly: true),
            Folder("staging", "Staging folder", "Optional: keep intermediate files here", advancedOnly: true),
            Check("removeStaging", "Remove staging files (delete intermediate)",
                "Delete the intermediate tree after the build (off = --keep-staging)", on: true, advancedOnly: true),
            Check("useEmbedded", "Use embedded right.sprx",
                "Drop the backup's module and inject the built-in debug one (--use-embedded-right-sprx)",
                on: true, advancedOnly: true),
        ],
        BuildArgs = values =>
        {
            var args = new List<string>();
            args.Add("--out");
            args.Add(Require(values, "out", "Output package"));
            if (Value(values, "contentId") is { Length: > 0 } contentId)
            {
                args.Add("--content-id");
                args.Add(contentId);
            }
            if (Value(values, "titleId") is { Length: > 0 } titleId)
            {
                args.Add("--title-id");
                args.Add(titleId);
            }
            if (Value(values, "title") is { Length: > 0 } title)
            {
                args.Add("--title");
                args.Add(title);
            }
            if (values.GetValueOrDefault("noPasscode") == "1")
                args.Add("--no_passcode");
            else if (Value(values, "passcode") is { Length: > 0 } passcode)
            {
                args.Add("--passcode");
                args.Add(passcode);
            }
            if (Value(values, "decrypted") is { Length: > 0 } decrypted)
            {
                args.Add("--decrypted");
                args.Add(decrypted);
            }
            if (Value(values, "compression") is { Length: > 0 } compression)
            {
                args.Add("--compression");
                args.Add(compression);
            }
            if (Value(values, "krakenLevel") is { Length: > 0 } krakenLevel)
            {
                args.Add("--kraken-level");
                args.Add(krakenLevel);
            }
            if (Value(values, "krakenThreads") is { Length: > 0 } krakenThreads)
            {
                args.Add("--kraken-threads");
                args.Add(krakenThreads);
            }
            if (values.GetValueOrDefault("sdkOverride") == "1" && Value(values, "sdk") is { Length: > 0 } sdk)
            {
                args.Add("--sdk");
                args.Add(sdk);
            }
            if (Value(values, "drmType") is { Length: > 0 } drmType && drmType != "keep source")
            {
                args.Add("--drm-type");
                args.Add(drmType);
            }
            if (Value(values, "temp") is { Length: > 0 } temp)
            {
                args.Add("--temp");
                args.Add(temp);
            }
            if (values.GetValueOrDefault("sweepTemp") != "1")
                args.Add("--no-temp-sweep");
            if (Value(values, "staleHours") is { Length: > 0 } staleHours)
            {
                args.Add("--stale-hours");
                args.Add(staleHours);
            }
            if (Value(values, "staging") is { Length: > 0 } staging)
            {
                args.Add("--staging");
                args.Add(staging);
            }
            if (values.GetValueOrDefault("removeStaging") != "1")
                args.Add("--keep-staging");
            if (values.GetValueOrDefault("useEmbedded") == "1")
                args.Add("--use-embedded-right-sprx");
            if (values.GetValueOrDefault("verbose") == "1")
                args.Add("--verbose");
            args.Add(Require(values, "backup", "Backup folder"));
            return args.ToArray();
        },
    };

    // ==================================================================
    // Helpers
    // ==================================================================
    private static CommandDef Package(string name, string group, string description, string cliWord, bool usePasscode = false) => new()
    {
        Name = name,
        Group = group,
        Title = name,
        Description = description,
        CliWord = cliWord,
        Fields = [],
        BuildArgs = values =>
        {
            var args = new List<string>();
            if (usePasscode)
                AddPasscode(args, values);
            args.Add(values["pkg"]);
            return args.ToArray();
        },
        UsesSelectedPackage = true,
    };

    /// <summary>
    /// Appends the package bar's passcode for commands that accept one. The string is passed
    /// explicitly so the CLI does not fall back to its own default when the user typed a custom
    /// debug passcode; an empty field falls back to the CLI default (all-zero fake passcode).
    /// </summary>
    private static void AddPasscode(List<string> args, IReadOnlyDictionary<string, string> values)
    {
        if (Value(values, "passcode") is { Length: > 0 } passcode)
        {
            args.Add("--passcode");
            args.Add(passcode);
        }
    }

    private static string Value(IReadOnlyDictionary<string, string> values, string id) =>
        values.TryGetValue(id, out string? value) ? value : string.Empty;

    private static string Require(IReadOnlyDictionary<string, string> values, string id, string label) =>
        Value(values, id) is { Length: > 0 } value
            ? value
            : throw new ArgumentException($"{label} is required.");

    private static CommandField File(string id, string label, string filter, string hint = "") =>
        new() { Id = id, Label = label, Kind = FieldKind.File, Filter = filter, Hint = hint };
    private static CommandField Save(string id, string label, string filter, string hint = "") =>
        new() { Id = id, Label = label, Kind = FieldKind.SaveFile, Filter = filter, Hint = hint };
    private static CommandField Folder(string id, string label, string hint = "", bool advancedOnly = false) =>
        new() { Id = id, Label = label, Kind = FieldKind.Folder, Hint = hint, AdvancedOnly = advancedOnly };
    private static CommandField Text(string id, string label, string @default = "", string hint = "",
        bool advancedOnly = false, string? easyDefault = null) =>
        new()
        {
            Id = id, Label = label, Kind = FieldKind.Text, Default = @default, Hint = hint,
            AdvancedOnly = advancedOnly, EasyDefault = easyDefault,
        };
    private static CommandField Numeric(string id, string label, int minimum, int maximum, int @default, string hint = "",
        bool advancedOnly = false) =>
        new()
        {
            Id = id,
            Label = label,
            Kind = FieldKind.Numeric,
            Minimum = minimum,
            Maximum = maximum,
            Default = @default.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Hint = hint,
            AdvancedOnly = advancedOnly,
        };
    private static CommandField Slider(string id, string label, int minimum, int maximum, int @default, string hint = "",
        bool advancedOnly = false) =>
        new()
        {
            Id = id,
            Label = label,
            Kind = FieldKind.Slider,
            Minimum = minimum,
            Maximum = maximum,
            Default = @default.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Hint = hint,
            AdvancedOnly = advancedOnly,
        };
    private static CommandField Combo(string id, string label, string[] choices, string @default, string[]? remarks = null,
        bool advancedOnly = false, string? easyDefault = null) =>
        new()
        {
            Id = id, Label = label, Kind = FieldKind.Combo, Choices = choices, Default = @default, ChoiceRemarks = remarks,
            AdvancedOnly = advancedOnly, EasyDefault = easyDefault,
        };
    private static CommandField Check(string id, string label, string hint = "", bool on = false,
        bool advancedOnly = false, string? easyDefault = null) =>
        new()
        {
            Id = id, Label = label, Kind = FieldKind.Check, Hint = hint, Default = on ? "1" : "0",
            AdvancedOnly = advancedOnly, EasyDefault = easyDefault,
        };
}
