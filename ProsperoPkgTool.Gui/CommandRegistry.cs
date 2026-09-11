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
    public static IReadOnlyList<CommandDef> PackageOperations { get; } = BuildPackageOperations();
    public static IReadOnlyList<CommandDef> ToolOperations { get; } = BuildToolOperations();

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
        Package("Image summary (img_info)", "Inspect",
            "Summarize package category, container, and decoded inner-image state.",
            "img_info", usePasscode: true),
        new CommandDef
        {
            Name = "Image verify (img_verify)",
            Group = "Inspect",
            Title = "Run structural, CNT, PFS, NAPS, and inner-PFS checks",
            Description = "Report every available verification check. Supply a reference package for patch overlays.",
            CliWord = "img_verify",
            UsesSelectedPackage = true,
            Fields =
            [
                File("ref", "Reference package", "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*",
                    "Optional: base package for a patch/delta image"),
            ],
            BuildArgs = values =>
            {
                var args = new List<string>();
                if (Value(values, "ref") is { Length: > 0 } reference)
                {
                    args.Add("--ref_pkg_path");
                    args.Add(reference);
                }
                AddPasscode(args, values);
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
                AddPasscode(args, values);
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
            ],
            BuildArgs = values =>
            {
                var args = new List<string>();
                if (values.GetValueOrDefault("mount") == "1")
                    args.Add("--mount");
                if (values.GetValueOrDefault("verbose") == "1")
                    args.Add("--verbose");
                if (Value(values, "ref") is { Length: > 0 } reference)
                {
                    args.Add("--ref_pkg_path");
                    args.Add(reference);
                }
                AddPasscode(args, values);
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
                Combo("compression", "Inner compression", ["stored", "kraken"], "stored",
                    ["no compression", "Oodle Kraken / auto"]),
                Slider("krakenLevel", "Kraken level (-4..9)", -4, 9, 7, "Recorded in the compressed image header (default 7)"),
                Numeric("krakenThreads", "Kraken threads (0=auto)", 0, 256, 0, "0 = auto (processor count)"),
                Text("contentId", "Content ID", string.Empty, "Optional: overrides sce_sys/param.json"),
                Text("passcode", "Passcode (32 chars)", CommandDef.DefaultPasscode, "Default: all-zero fake passcode"),
                Check("noPasscode", "Use the default all-zero passcode", "Ignore the passcode field (--no_passcode)"),
                Check("noFself", "Skip module fake-signing", "Do not fake-sign ELF modules (--no_fself)"),
                Check("noRightSprx", "Skip debug right.sprx injection", "Do not inject the debug module (--no_right_sprx)"),
                Check("verbose", "Verbose progress", "Show stage progress (--verbose)"),
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
                if (Value(values, "contentId") is { Length: > 0 } contentId)
                {
                    args.Add("--content-id");
                    args.Add(contentId);
                }
                if (values.GetValueOrDefault("noPasscode") == "1")
                    args.Add("--no_passcode");
                else if (Value(values, "passcode") is { Length: > 0 } passcode)
                {
                    args.Add("--passcode");
                    args.Add(passcode);
                }
                if (values.GetValueOrDefault("noFself") == "1")
                    args.Add("--no_fself");
                if (values.GetValueOrDefault("noRightSprx") == "1")
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
        new CommandDef
        {
            Name = "Convert backup (convert)",
            Group = "Create",
            Title = "Convert a decrypted backup into a debug base package",
            Description = "Substitute and fake-sign raw ELF modules from a decrypted backup, then build and report launch readiness.",
            CliWord = "convert",
            Fields =
            [
                Folder("backup", "Backup folder", "Decrypted backup root (contains sce_sys)"),
                Save("out", "Output package", "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*", "Required"),
                Text("decrypted", "Decrypted subfolder", "decrypted", "Subfolder holding the decrypted title tree"),
                Text("contentId", "Content ID", string.Empty, "Optional: overrides sce_sys/param.json"),
                Text("passcode", "Passcode (32 chars)", CommandDef.DefaultPasscode, "Default: all-zero fake passcode"),
                Check("noPasscode", "Use the default all-zero passcode", "Ignore the passcode field (--no_passcode)"),
                Combo("compression", "Inner compression", ["stored", "kraken"], "stored",
                    ["no compression", "Oodle Kraken / auto"]),
                Slider("krakenLevel", "Kraken level (-4..9)", -4, 9, 7, "Recorded in the compressed image header (default 7)"),
                Numeric("krakenThreads", "Kraken threads (0=auto)", 0, 256, 0, "0 = auto (processor count)"),
                Folder("staging", "Staging folder", "Optional: keep intermediate files here"),
                Check("keepStaging", "Keep staging files", "Do not delete intermediates (--keep-staging)"),
                Check("useEmbedded", "Use embedded right.sprx", "Use the built-in debug module (--use-embedded-right-sprx)"),
                Check("verbose", "Verbose progress", "Show per-file and stage progress (--verbose)"),
            ],
            BuildArgs = values =>
            {
                var args = new List<string>();
                args.Add("--out");
                args.Add(Require(values, "out", "Output package"));
                if (Value(values, "decrypted") is { Length: > 0 } decrypted)
                {
                    args.Add("--decrypted");
                    args.Add(decrypted);
                }
                if (Value(values, "contentId") is { Length: > 0 } contentId)
                {
                    args.Add("--content-id");
                    args.Add(contentId);
                }
                if (values.GetValueOrDefault("noPasscode") == "1")
                    args.Add("--no_passcode");
                else if (Value(values, "passcode") is { Length: > 0 } passcode)
                {
                    args.Add("--passcode");
                    args.Add(passcode);
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
                if (Value(values, "staging") is { Length: > 0 } staging)
                {
                    args.Add("--staging");
                    args.Add(staging);
                }
                if (values.GetValueOrDefault("keepStaging") == "1")
                    args.Add("--keep-staging");
                if (values.GetValueOrDefault("useEmbedded") == "1")
                    args.Add("--use-embedded-right-sprx");
                if (values.GetValueOrDefault("verbose") == "1")
                    args.Add("--verbose");
                args.Add(Require(values, "backup", "Backup folder"));
                return args.ToArray();
            },
        },

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
    private static CommandField Folder(string id, string label, string hint = "") =>
        new() { Id = id, Label = label, Kind = FieldKind.Folder, Hint = hint };
    private static CommandField Text(string id, string label, string @default = "", string hint = "") =>
        new() { Id = id, Label = label, Kind = FieldKind.Text, Default = @default, Hint = hint };
    private static CommandField Numeric(string id, string label, int minimum, int maximum, int @default, string hint = "") =>
        new()
        {
            Id = id,
            Label = label,
            Kind = FieldKind.Numeric,
            Minimum = minimum,
            Maximum = maximum,
            Default = @default.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Hint = hint,
        };
    private static CommandField Slider(string id, string label, int minimum, int maximum, int @default, string hint = "") =>
        new()
        {
            Id = id,
            Label = label,
            Kind = FieldKind.Slider,
            Minimum = minimum,
            Maximum = maximum,
            Default = @default.ToString(System.Globalization.CultureInfo.InvariantCulture),
            Hint = hint,
        };
    private static CommandField Combo(string id, string label, string[] choices, string @default, string[]? remarks = null) =>
        new() { Id = id, Label = label, Kind = FieldKind.Combo, Choices = choices, Default = @default, ChoiceRemarks = remarks };
    private static CommandField Check(string id, string label, string hint = "") =>
        new() { Id = id, Label = label, Kind = FieldKind.Check, Hint = hint };
}
