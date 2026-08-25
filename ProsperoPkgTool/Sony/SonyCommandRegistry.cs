namespace ProsperoPkgTool.Sony;

public static class SonyCommandRegistry
{
    private static SonyCommandOption V(string name, string? hint = null) => new(name, true, hint);
    private static SonyCommandOption F(string name) => new(name, false);

    public static IReadOnlyList<SonyCommandDefinition> All { get; } = Build();

    public static IReadOnlyDictionary<string, SonyCommandDefinition> ByName { get; } =
        All.ToDictionary(command => command.Name, StringComparer.OrdinalIgnoreCase);

    public static bool TryGet(string name, out SonyCommandDefinition definition) =>
        ByName.TryGetValue(name, out definition!);

    private static IReadOnlyList<SonyCommandDefinition> Build() =>
    [
        C("gp5_proj_create", "GP5 Project", "Create a blank GP5 project.", SonyCommandRisk.WritesOutput,
            V("--volume_type", "prospero_app|prospero_ac"), V("--passcode"), V("--c_date"), V("--entitlement_key")),
        C("gp5_proj_update", "GP5 Project", "Update GP5 project attributes.", SonyCommandRisk.MutatesInput,
            V("--volume_type", "prospero_app|prospero_ac"), V("--passcode"), V("--c_date"), V("--entitlement_key")),

        C("gp5_playgo_add", "GP5 PlayGo", "Add GP5 PlayGo common settings.", SonyCommandRisk.MutatesInput,
            V("--supported_languages"), V("--default_language"), V("--scenario_default_id")),
        C("gp5_playgo_update", "GP5 PlayGo", "Update GP5 PlayGo common settings.", SonyCommandRisk.MutatesInput,
            V("--supported_languages"), V("--default_language"), V("--scenario_default_id")),
        C("gp5_playgo_delete", "GP5 PlayGo", "Delete GP5 PlayGo common settings.", SonyCommandRisk.MutatesInput),

        C("gp5_chunk_add", "GP5 Chunk", "Add PlayGo chunks.", SonyCommandRisk.MutatesInput,
            V("--id"), V("--label"), V("--languages"), V("--use", "true|false")),
        C("gp5_chunk_update", "GP5 Chunk", "Update PlayGo chunks.", SonyCommandRisk.MutatesInput,
            V("--id"), V("--label"), V("--languages"), V("--use", "true|false")),
        C("gp5_chunk_delete", "GP5 Chunk", "Delete PlayGo chunks.", SonyCommandRisk.MutatesInput, V("--id")),

        C("gp5_scenario_add", "GP5 Scenario", "Add a PlayGo scenario.", SonyCommandRisk.MutatesInput,
            V("--id"), V("--scenario"), V("--label"), V("--type", "playmode"), V("--initial_chunk_count")),
        C("gp5_scenario_update", "GP5 Scenario", "Update a PlayGo scenario.", SonyCommandRisk.MutatesInput,
            V("--id"), V("--scenario"), V("--label"), V("--type", "playmode"), V("--initial_chunk_count")),
        C("gp5_scenario_delete", "GP5 Scenario", "Delete a PlayGo scenario.", SonyCommandRisk.MutatesInput, V("--id")),

        C("gp5_file_add", "GP5 File", "Add a file to a GP5 project.", SonyCommandRisk.MutatesInput,
            V("--src_path"), V("--dst_path"), F("--force"), V("--chunk"), V("--content_config_label")),
        C("gp5_file_update", "GP5 File", "Update a GP5 file entry.", SonyCommandRisk.MutatesInput,
            V("--src_path"), V("--dst_path"), V("--chunk")),
        C("gp5_file_delete", "GP5 File", "Delete a GP5 file entry.", SonyCommandRisk.MutatesInput,
            V("--dst_path"), V("--content_config_label")),

        C("gp5_dir_add", "GP5 Directory", "Add a directory to a GP5 project.", SonyCommandRisk.MutatesInput,
            V("--virtual", "true|false"), V("--src_path"), V("--dst_path"), F("--force"), V("--chunk"), V("--content_config_label")),
        C("gp5_dir_update", "GP5 Directory", "Update a GP5 directory entry.", SonyCommandRisk.MutatesInput,
            V("--dst_path"), V("--virtual", "true|false"), V("--src_path"), V("--chunk")),
        C("gp5_dir_delete", "GP5 Directory", "Delete a GP5 directory entry.", SonyCommandRisk.MutatesInput,
            V("--dst_path"), V("--content_config_label")),

        C("img_create", "Image", "Create a package or disc image from GP5.", SonyCommandRisk.WritesOutput,
            V("--oformat", "bd66+nw|bd100+nw|bd+nw|nwonly"), V("--ref_pkg_path"), F("--for_submission"), V("--tmp_path"), F("--no_progress_bar")),
        C("img_extract", "Image", "Extract files or directories from an image.", SonyCommandRisk.WritesOutput,
            V("--passcode"), F("--no_passcode"), V("--tmp_path")),
        C("img_file_list", "Image", "List files or directories in an image.", SonyCommandRisk.ReadOnly,
            V("--passcode"), F("--no_passcode"), V("--tmp_path")),
        C("img_info", "Image", "Display package image information.", SonyCommandRisk.ReadOnly),
        C("img_verify", "Image", "Verify a package image.", SonyCommandRisk.ReadOnly,
            V("--passcode"), V("--tmp_path"), F("--no_progress_bar")),
        C("pkg_switch", "Image", "Switch shared-binary package content configuration.", SonyCommandRisk.MutatesInput,
            V("--content_id"), V("--content_config_label")),

        C("iso_write", "Optical", "Write an ISO image to optical media.", SonyCommandRisk.WritesOpticalMedia,
            F("--no_progress_bar")),
        C("iso_copy", "Optical", "Copy optical media to an ISO image.", SonyCommandRisk.WritesOutput,
            F("--no_progress_bar"), V("--compress", "on|off")),
        C("iso_convert", "Optical", "Convert ISO/CISO/package image formats.", SonyCommandRisk.WritesOutput,
            V("--compress", "on|off")),
        C("drive_list", "Optical", "List optical drives.", SonyCommandRisk.ReadOnly,
            V("--oformat", "long")),

        C("file_calc_loudness", "Utility", "Calculate WAV or ATRAC9 loudness.", SonyCommandRisk.ReadOnly),
        C("ks_create", "Utility", "Create a keystone file.", SonyCommandRisk.WritesOutput, V("--passcode")),
        C("pc_fingerprint", "Utility", "Display a passcode fingerprint.", SonyCommandRisk.ReadOnly, V("--passcode")),
        C("set_conf", "Configuration", "Set a Publishing Tools configuration value.", SonyCommandRisk.ChangesConfiguration),
        C("get_conf", "Configuration", "Read a Publishing Tools configuration value.", SonyCommandRisk.ReadOnly),
        C("version", "Meta", "Print Sony Publishing Tools version information.", SonyCommandRisk.ReadOnly),
        C("help", "Meta", "Print help for a Sony command.", SonyCommandRisk.ReadOnly),
        C("helpall", "Meta", "Print help for all Sony commands.", SonyCommandRisk.ReadOnly),
    ];

    private static SonyCommandDefinition C(
        string name,
        string group,
        string description,
        SonyCommandRisk risk,
        params SonyCommandOption[] options) =>
        new(name, group, description, risk, options);
}

