using System.Text.Json;

namespace ProsperoPkgTool.Gui;

public sealed class OperationsPane : UserControl
{
    private readonly TreeView _tree = new() { Dock = DockStyle.Fill, HideSelection = false };
    private readonly Label _description = new();
    private readonly Panel _fields = new();
    private readonly Button _run = new() { Text = "Run", Width = 90 };
    private readonly Button _cancel = new() { Text = "Cancel", Width = 90, Enabled = false };
    private readonly SplitContainer _split = new() { Dock = DockStyle.Fill };
    private readonly Dictionary<string, Control> _fieldControls = new(StringComparer.Ordinal);
    private readonly ToolTip _tips = new();
    private CommandDef? _current;
    private string? _autoOutput;

    public OperationsPane()
    {
        Dock = DockStyle.Fill;
        BuildLayout();
    }

    public event Action<CommandDef, IReadOnlyDictionary<string, string>>? RunRequested;
    public event Action? CancelRequested;
    public event Action<CommandDef?>? SelectionChanged;
    public SplitContainer Split => _split;
    public bool CanRun => _current is not null;

    /// <summary>
    /// When false this pane is a simplified (Easy) view: fields marked <see cref="CommandField.AdvancedOnly"/>
    /// are hidden, and hidden fields use their Easy default when a run is submitted. Set before
    /// <see cref="SetCommands"/> so the first render honors the mode. Defaults to true (full view).
    /// </summary>
    [System.ComponentModel.DesignerSerializationVisibility(System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    [System.ComponentModel.Browsable(false)]
    public bool ShowAdvanced { get; set; } = true;

    /// <summary>Last file/folder picked through a browse dialog, shared by every pane.</summary>
    public static string LastBrowsedPath { get; set; } = string.Empty;

    public void SetCommands(IReadOnlyList<CommandDef> commands)
    {
        _tree.BeginUpdate();
        _tree.Nodes.Clear();
        foreach (IGrouping<string, CommandDef> group in commands.GroupBy(command => command.Group))
        {
            var groupNode = new TreeNode(group.Key);
            foreach (CommandDef command in group.OrderBy(command => command.Name))
                groupNode.Nodes.Add(new TreeNode(command.Name) { Tag = command });
            groupNode.Expand();
            _tree.Nodes.Add(groupNode);
        }
        _tree.EndUpdate();
        if (_tree.Nodes.Count > 0 && _tree.Nodes[0].Nodes.Count > 0)
            _tree.SelectedNode = _tree.Nodes[0].Nodes[0];
    }

    public void SetRunning(bool running)
    {
        _run.Enabled = !running && _current is not null;
        _cancel.Enabled = running;
        _tree.Enabled = !running;
        _fields.Enabled = !running;
    }

    public void RunCurrent() => RaiseRun();

    private void BuildLayout()
    {
        var buttons = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 38,
            Padding = new Padding(6, 3, 6, 3),
            FlowDirection = FlowDirection.LeftToRight,
        };
        _run.Click += (_, _) => RaiseRun();
        _cancel.Click += (_, _) => CancelRequested?.Invoke();
        buttons.Controls.Add(_run);
        buttons.Controls.Add(_cancel);

        _description.Dock = DockStyle.Top;
        _description.Height = 48;
        _description.Padding = new Padding(8, 6, 8, 4);
        _description.BackColor = Color.FromArgb(240, 242, 247);
        _description.AutoEllipsis = true;
        _description.Text = "Select an operation.";

        _fields.Dock = DockStyle.Fill;
        _fields.AutoScroll = true;
        _fields.Padding = new Padding(6);
        var right = new Panel { Dock = DockStyle.Fill, Padding = new Padding(6) };
        right.Controls.Add(_fields);
        right.Controls.Add(_description);

        _tree.AfterSelect += (_, eventArgs) => SelectCommand(eventArgs.Node?.Tag as CommandDef);
        _tree.DoubleClick += (_, _) => RaiseRun();
        _split.Panel1.Controls.Add(_tree);
        _split.Panel2.Controls.Add(right);
        Controls.Add(_split);
        Controls.Add(buttons);
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        ApplySplitLayout();
        _split.SizeChanged += (_, _) => ApplySplitLayout();
    }

    /// <summary>
    /// Applies the pane minimums only once the split is wide enough to satisfy them. Setting a
    /// minimum larger than the available span (or leaving a stale <c>SplitterDistance</c> outside
    /// the new range) makes <see cref="SplitContainer"/> throw; deferring until there is room keeps
    /// startup safe on small/short windows and re-applies the layout as the window grows.
    /// </summary>
    private void ApplySplitLayout()
    {
        int span = _split.Orientation == Orientation.Horizontal ? _split.ClientSize.Height : _split.ClientSize.Width;
        const int panel1Min = 175;
        const int panel2Min = 380;
        if (span < panel1Min + panel2Min + _split.SplitterWidth)
            return;
        _split.Panel1MinSize = panel1Min;
        _split.Panel2MinSize = panel2Min;
        int maximum = span - panel2Min - _split.SplitterWidth;
        if (maximum >= panel1Min)
            _split.SplitterDistance = Math.Clamp(235, panel1Min, maximum);
    }

    private void SelectCommand(CommandDef? command)
    {
        if (command is null)
            return;
        _current = command;
        _description.Text = $"{command.Title} - {command.Description}";
        BuildFields(command);
        _run.Enabled = true;
        SelectionChanged?.Invoke(command);
    }

    private void BuildFields(CommandDef command)
    {
        _fields.SuspendLayout();
        _fields.Controls.Clear();
        _fieldControls.Clear();
        _autoOutput = null;
        var rows = new List<Control>();
        if (command.Fields.Length == 0)
        {
            rows.Add(new Label
            {
                Text = command.UsesSelectedPackage
                    ? "This operation uses the package and passcode selected above."
                    : "This operation has no additional options.",
                AutoSize = true,
                ForeColor = Color.DimGray,
                Padding = new Padding(4, 10, 4, 4),
            });
        }

        foreach (CommandField field in command.Fields)
        {
            if (field.AdvancedOnly && !ShowAdvanced)
                continue;
            bool hasHint = !string.IsNullOrWhiteSpace(field.Hint);
            int inputHeight = field.Kind == FieldKind.MultiText ? 92 : 30;

            var row = new TableLayoutPanel
            {
                Dock = DockStyle.Top,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 2,
                RowCount = 1,
                Margin = new Padding(0, 0, 0, 2),
            };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            row.Controls.Add(new Label
            {
                Text = field.Label,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(0, 0, 8, 0),
            }, 0, 0);

            // The guidance is a visible hint line under the input, not placeholder text, so an empty
            // optional box is never confused with "showing a default that will actually be sent".
            var cell = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                ColumnCount = 1,
                RowCount = hasHint ? 2 : 1,
                Margin = new Padding(0),
            };
            cell.RowStyles.Add(new RowStyle(SizeType.Absolute, inputHeight));
            Control input = MakeInput(field);
            input.Dock = DockStyle.Fill;
            _fieldControls[field.Id] = input;
            cell.Controls.Add(input, 0, 0);
            if (hasHint)
            {
                cell.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                var hint = new Label
                {
                    Text = field.Hint,
                    AutoSize = false,
                    Dock = DockStyle.Fill,
                    Height = 16,
                    ForeColor = Color.DimGray,
                    AutoEllipsis = true,
                    TextAlign = ContentAlignment.MiddleLeft,
                    Padding = new Padding(0, 0, 4, 0),
                };
                _tips.SetToolTip(hint, field.Hint);
                cell.Controls.Add(hint, 0, 1);
            }

            row.Controls.Add(cell, 1, 0);
            rows.Add(row);
        }
        for (int index = rows.Count - 1; index >= 0; index--)
            _fields.Controls.Add(rows[index]);
        _fields.ResumeLayout(true);
    }

    private Control MakeInput(CommandField field)
    {
        string @default = field.DefaultFor(ShowAdvanced);
        return field.Kind switch
        {
            FieldKind.File => MakePathInput(field, PathInputMode.OpenFile),
            FieldKind.SaveFile => MakePathInput(field, PathInputMode.SaveFile),
            FieldKind.Folder => MakePathInput(field, PathInputMode.Folder),
            FieldKind.Combo => MakeCombo(field, @default),
            FieldKind.Check => new CheckBox
            {
                Text = field.Hint,
                Checked = @default == "1",
                AutoSize = true,
                Padding = new Padding(0, 5, 0, 0),
            },
            FieldKind.MultiText => new TextBox
            {
                Multiline = true,
                ScrollBars = ScrollBars.Vertical,
                AcceptsReturn = true,
                Text = @default,
                Font = new Font("Cascadia Mono", 9f),
            },
            FieldKind.Numeric => MakeNumeric(field, @default),
            FieldKind.Slider => MakeSlider(field, @default),
            _ => MakeTextInput(field, @default),
        };
    }

    /// <summary>
    /// A plain text input. The title id is special: editing it keeps the content id's embedded
    /// 9-character title segment consistent, because the console derives the title id from it.
    /// </summary>
    private Control MakeTextInput(CommandField field, string @default)
    {
        var box = new TextBox { Text = @default };
        if (field.Id == "titleId")
        {
            box.TextChanged += (_, _) =>
            {
                string titleId = box.Text.Trim();
                if (titleId.Length != 9)
                    return;
                if (_fieldControls.TryGetValue("contentId", out Control? control) &&
                    TextBoxOf(control) is { } content && content.Text.Trim() is { Length: 36 } text)
                    content.Text = string.Concat(text.AsSpan(0, 7), titleId, text.AsSpan(16));
            };
        }
        return box;
    }

    private static Control MakeNumeric(CommandField field, string @default)
    {
        var numeric = new NumericUpDown
        {
            Minimum = field.Minimum,
            Maximum = field.Maximum,
            Increment = field.Increment,
            TextAlign = HorizontalAlignment.Left,
        };
        numeric.Value = int.TryParse(@default, out int value)
            ? Math.Clamp(value, field.Minimum, field.Maximum)
            : Math.Clamp(0, field.Minimum, field.Maximum);
        return numeric;
    }

    private static Control MakeSlider(CommandField field, string @default)
    {
        int initial = int.TryParse(@default, out int value)
            ? Math.Clamp(value, field.Minimum, field.Maximum)
            : field.Minimum;
        var panel = new TableLayoutPanel { ColumnCount = 2, RowCount = 1, Margin = new Padding(0) };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 44));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var track = new TrackBar
        {
            Minimum = field.Minimum,
            Maximum = field.Maximum,
            TickStyle = TickStyle.None,
            SmallChange = 1,
            LargeChange = 1,
            Value = initial,
            Dock = DockStyle.Fill,
        };
        var readout = new Label
        {
            Text = initial.ToString(System.Globalization.CultureInfo.InvariantCulture),
            TextAlign = ContentAlignment.MiddleLeft,
            Dock = DockStyle.Fill,
            AutoSize = false,
        };
        track.ValueChanged += (_, _) =>
            readout.Text = track.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
        panel.Controls.Add(track, 0, 0);
        panel.Controls.Add(readout, 1, 0);
        return panel;
    }

    private static Control MakeCombo(CommandField field, string @default)
    {
        var combo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        for (int index = 0; index < field.Choices.Length; index++)
        {
            string remark = field.ChoiceRemarks is { } remarks && index < remarks.Length ? remarks[index] : string.Empty;
            combo.Items.Add(remark.Length == 0 ? field.Choices[index] : $"{field.Choices[index]} - {remark}");
        }
        if (combo.Items.Count > 0)
        {
            int selected = Array.IndexOf(field.Choices, @default);
            combo.SelectedIndex = selected >= 0 ? selected : 0;
        }
        return combo;
    }

    private Control MakePathInput(CommandField field, PathInputMode mode)
    {
        var panel = new TableLayoutPanel { ColumnCount = 2, RowCount = 1, Margin = new Padding(0) };
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 32));
        panel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        var box = new TextBox { Dock = DockStyle.Fill, Text = field.DefaultFor(ShowAdvanced) };
        var browse = new Button { Dock = DockStyle.Fill, Text = "..." };
        browse.Click += (_, _) => BrowsePath(box, field, mode);
        panel.Controls.Add(box, 0, 0);
        panel.Controls.Add(browse, 1, 0);
        return panel;
    }

    private void BrowsePath(TextBox box, CommandField field, PathInputMode mode)
    {
        string current = box.Text.Trim();
        if (mode == PathInputMode.Folder)
        {
            using var dialog = new FolderBrowserDialog { Description = field.Label, UseDescriptionForTitle = true };
            string start = Directory.Exists(current)
                ? current
                : Directory.Exists(LastBrowsedPath) ? LastBrowsedPath : string.Empty;
            if (start.Length > 0)
            {
                dialog.SelectedPath = start;
                dialog.InitialDirectory = start;
            }
            if (dialog.ShowDialog(FindForm()) == DialogResult.OK)
            {
                box.Text = dialog.SelectedPath;
                LastBrowsedPath = dialog.SelectedPath;
                AutoFillFromInput(field, dialog.SelectedPath);
            }
            return;
        }
        FileDialog fileDialog = mode == PathInputMode.OpenFile ? new OpenFileDialog() : new SaveFileDialog();
        using (fileDialog)
        {
            fileDialog.Title = field.Label;
            fileDialog.Filter = field.Filter.Length > 0 ? field.Filter : "All files (*.*)|*.*";
            string startDirectory = ResolveStartDirectory(current);
            if (startDirectory.Length > 0)
                fileDialog.InitialDirectory = startDirectory;
            if (current.Length > 0)
            {
                // Pre-fill the file name so a Save dialog opens with the derived name (e.g. <folder>.pkg).
                fileDialog.FileName = File.Exists(current) ? current : Path.GetFileName(current);
            }
            if (fileDialog.ShowDialog(FindForm()) == DialogResult.OK)
            {
                box.Text = fileDialog.FileName;
                LastBrowsedPath = fileDialog.FileName;
                _autoOutput = null; // a hand-picked output is authoritative
                AutoFillFromInput(field, fileDialog.FileName);
            }
        }
    }

    /// <summary>
    /// After an input path is picked, derives the output path and auto-fills the identity fields
    /// (content id, title id, title) from the source tree's <c>sce_sys/param.json</c>. Only the
    /// output is conditional (empty box); the identity fields are always refreshed from the pick.
    /// </summary>
    private void AutoFillFromInput(CommandField field, string path)
    {
        if (_current is null || field.Kind is not (FieldKind.Folder or FieldKind.File))
            return;

        string? directory = Directory.Exists(path) ? path
            : File.Exists(path) ? Path.GetDirectoryName(path) : null;
        if (string.IsNullOrEmpty(directory))
            return;

        // 1. Output "<parent>\<name>.pkg" from the selected folder name. Updated whenever the input is
        // re-picked, as long as the output is still empty or still holds the previous auto value
        // (a hand-edited output is left alone).
        if (_fieldControls.TryGetValue("out", out Control? outControl) && TextBoxOf(outControl) is { } output)
        {
            string current = output.Text.Trim();
            bool mayReplace = current.Length == 0 ||
                (_autoOutput is not null && string.Equals(current, _autoOutput, StringComparison.OrdinalIgnoreCase));
            var info = new DirectoryInfo(directory);
            if (mayReplace && info.Name.Length > 0)
            {
                output.Text = Path.Combine(info.Parent?.FullName ?? directory, info.Name + ".pkg");
                _autoOutput = output.Text;
            }
        }

        // 2. Identity from sce_sys/param.json (the folder itself, or one nested level).
        string? paramJson = FindParamJson(directory);
        if (paramJson is null)
            return;
        try
        {
            using JsonDocument document = JsonDocument.Parse(File.ReadAllText(paramJson));
            JsonElement root = document.RootElement;
            SetFieldValue("contentId", GetString(root, "contentId"));
            SetFieldValue("titleId", GetString(root, "titleId"));
            SetFieldValue("title", ReadTitle(root));
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            // A missing or malformed param.json leaves the identity fields untouched.
        }
    }

    private static string? FindParamJson(string directory)
    {
        string direct = Path.Combine(directory, "sce_sys", "param.json");
        if (File.Exists(direct))
            return direct;
        try
        {
            foreach (string child in Directory.EnumerateDirectories(directory))
            {
                string nested = Path.Combine(child, "sce_sys", "param.json");
                if (File.Exists(nested))
                    return nested;
            }
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
        return null;
    }

    private static string? GetString(JsonElement root, string name) =>
        root.ValueKind == JsonValueKind.Object && root.TryGetProperty(name, out JsonElement value) &&
        value.ValueKind == JsonValueKind.String
            ? value.GetString()
            : null;

    private static string? ReadTitle(JsonElement root)
    {
        string? title = null;
        if (root.ValueKind == JsonValueKind.Object &&
            root.TryGetProperty("localizedParameters", out JsonElement locals) &&
            locals.ValueKind == JsonValueKind.Object)
        {
            if (locals.TryGetProperty("default", out JsonElement def))
                title = GetString(def, "titleName");
            if (string.IsNullOrEmpty(title) && locals.TryGetProperty("en-US", out JsonElement en))
                title = GetString(en, "titleName");
        }
        return string.IsNullOrEmpty(title) ? GetString(root, "titleName") : title;
    }

    private void SetFieldValue(string id, string? value)
    {
        if (string.IsNullOrEmpty(value))
            return;
        if (_fieldControls.TryGetValue(id, out Control? control) && TextBoxOf(control) is { } box)
            box.Text = value;
    }

    /// <summary>Unwraps the TextBox from a path field (a TableLayoutPanel) or a plain text field.</summary>
    private static TextBox? TextBoxOf(Control? control) => control switch
    {
        TextBox box => box,
        TableLayoutPanel panel => panel.Controls.OfType<TextBox>().FirstOrDefault(),
        _ => null,
    };

    private static string ResolveStartDirectory(string current)
    {
        if (File.Exists(current))
            return Path.GetDirectoryName(current) ?? string.Empty;
        if (Directory.Exists(current))
            return current;
        // A not-yet-existing output path: start in its directory so the Save dialog opens there.
        string? parent = Path.GetDirectoryName(current);
        if (!string.IsNullOrEmpty(parent) && Directory.Exists(parent))
            return parent;
        if (File.Exists(LastBrowsedPath))
            return Path.GetDirectoryName(LastBrowsedPath) ?? string.Empty;
        return Directory.Exists(LastBrowsedPath) ? LastBrowsedPath : string.Empty;
    }

    private void RaiseRun()
    {
        if (_current is null)
            return;
        var rendered = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach ((string id, Control control) in _fieldControls)
        {
            rendered[id] = control switch
            {
                TextBox text => text.Text.Trim(),
                ComboBox combo => ExtractComboValue(combo.SelectedItem?.ToString() ?? string.Empty),
                CheckBox check => check.Checked ? "1" : "0",
                NumericUpDown numeric => numeric.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
                TableLayoutPanel panel when panel.Controls.OfType<TrackBar>().FirstOrDefault() is { } track =>
                    track.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
                TableLayoutPanel panel => panel.Controls.OfType<TextBox>().FirstOrDefault()?.Text.Trim() ?? string.Empty,
                _ => string.Empty,
            };
        }
        RunRequested?.Invoke(_current, CommandValues.Merge(_current, rendered, ShowAdvanced));
    }

    private static string ExtractComboValue(string value)
    {
        int separator = value.IndexOf(" - ", StringComparison.Ordinal);
        return separator >= 0 ? value[..separator] : value;
    }

    private enum PathInputMode
    {
        OpenFile,
        SaveFile,
        Folder,
    }
}
