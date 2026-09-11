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
    private CommandDef? _current;

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
            int height = field.Kind == FieldKind.MultiText ? 92 : 32;
            var row = new TableLayoutPanel { Dock = DockStyle.Top, Height = height, ColumnCount = 2, RowCount = 1 };
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
            row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            row.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            row.Controls.Add(new Label
            {
                Text = field.Label,
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(0, 0, 8, 0),
            }, 0, 0);
            Control input = MakeInput(field);
            input.Dock = DockStyle.Fill;
            _fieldControls[field.Id] = input;
            row.Controls.Add(input, 1, 0);
            rows.Add(row);
        }
        for (int index = rows.Count - 1; index >= 0; index--)
            _fields.Controls.Add(rows[index]);
        _fields.ResumeLayout(true);
    }

    private Control MakeInput(CommandField field) => field.Kind switch
    {
        FieldKind.File => MakePathInput(field, PathInputMode.OpenFile),
        FieldKind.SaveFile => MakePathInput(field, PathInputMode.SaveFile),
        FieldKind.Folder => MakePathInput(field, PathInputMode.Folder),
        FieldKind.Combo => MakeCombo(field),
        FieldKind.Check => new CheckBox
        {
            Text = field.Hint,
            Checked = field.Default == "1",
            AutoSize = true,
            Padding = new Padding(0, 5, 0, 0),
        },
        FieldKind.MultiText => new TextBox
        {
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            AcceptsReturn = true,
            Text = field.Default,
            PlaceholderText = field.Hint,
            Font = new Font("Cascadia Mono", 9f),
        },
        FieldKind.Numeric => MakeNumeric(field),
        FieldKind.Slider => MakeSlider(field),
        _ => new TextBox { Text = field.Default, PlaceholderText = field.Hint },
    };

    private static Control MakeNumeric(CommandField field)
    {
        var numeric = new NumericUpDown
        {
            Minimum = field.Minimum,
            Maximum = field.Maximum,
            Increment = field.Increment,
            TextAlign = HorizontalAlignment.Left,
        };
        numeric.Value = int.TryParse(field.Default, out int value)
            ? Math.Clamp(value, field.Minimum, field.Maximum)
            : Math.Clamp(0, field.Minimum, field.Maximum);
        return numeric;
    }

    private static Control MakeSlider(CommandField field)
    {
        int initial = int.TryParse(field.Default, out int value)
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

    private static Control MakeCombo(CommandField field)
    {
        var combo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        for (int index = 0; index < field.Choices.Length; index++)
        {
            string remark = field.ChoiceRemarks is { } remarks && index < remarks.Length ? remarks[index] : string.Empty;
            combo.Items.Add(remark.Length == 0 ? field.Choices[index] : $"{field.Choices[index]} - {remark}");
        }
        if (combo.Items.Count > 0)
        {
            int selected = Array.IndexOf(field.Choices, field.Default);
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
        var box = new TextBox { Dock = DockStyle.Fill, Text = field.Default, PlaceholderText = field.Hint };
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
            if (current.Length > 0 && File.Exists(current))
                fileDialog.FileName = current;
            if (fileDialog.ShowDialog(FindForm()) == DialogResult.OK)
            {
                box.Text = fileDialog.FileName;
                LastBrowsedPath = fileDialog.FileName;
            }
        }
    }

    private static string ResolveStartDirectory(string current)
    {
        if (File.Exists(current))
            return Path.GetDirectoryName(current) ?? string.Empty;
        if (Directory.Exists(current))
            return current;
        if (File.Exists(LastBrowsedPath))
            return Path.GetDirectoryName(LastBrowsedPath) ?? string.Empty;
        return Directory.Exists(LastBrowsedPath) ? LastBrowsedPath : string.Empty;
    }

    private void RaiseRun()
    {
        if (_current is null)
            return;
        var values = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach ((string id, Control control) in _fieldControls)
        {
            values[id] = control switch
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
        RunRequested?.Invoke(_current, values);
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
