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
        _split.Panel1MinSize = 175;
        _split.Panel2MinSize = 380;
        if (_split.Width > 600)
            _split.SplitterDistance = 235;
    }

    private void SelectCommand(CommandDef? command)
    {
        if (command is null)
            return;
        _current = command;
        _description.Text = $"{command.Title} — {command.Description}";
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
        _ => new TextBox { Text = field.Default, PlaceholderText = field.Hint },
    };

    private static Control MakeCombo(CommandField field)
    {
        var combo = new ComboBox { DropDownStyle = ComboBoxStyle.DropDownList };
        for (int index = 0; index < field.Choices.Length; index++)
        {
            string remark = field.ChoiceRemarks is { } remarks && index < remarks.Length ? remarks[index] : string.Empty;
            combo.Items.Add(remark.Length == 0 ? field.Choices[index] : $"{field.Choices[index]} — {remark}");
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
        if (mode == PathInputMode.Folder)
        {
            using var dialog = new FolderBrowserDialog { Description = field.Label, UseDescriptionForTitle = true };
            if (dialog.ShowDialog(FindForm()) == DialogResult.OK)
                box.Text = dialog.SelectedPath;
            return;
        }
        FileDialog fileDialog = mode == PathInputMode.OpenFile ? new OpenFileDialog() : new SaveFileDialog();
        using (fileDialog)
        {
            fileDialog.Title = field.Label;
            fileDialog.Filter = field.Filter.Length > 0 ? field.Filter : "All files (*.*)|*.*";
            if (fileDialog.ShowDialog(FindForm()) == DialogResult.OK)
                box.Text = fileDialog.FileName;
        }
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
                TableLayoutPanel panel => panel.Controls.OfType<TextBox>().FirstOrDefault()?.Text.Trim() ?? string.Empty,
                _ => string.Empty,
            };
        }
        RunRequested?.Invoke(_current, values);
    }

    private static string ExtractComboValue(string value)
    {
        int separator = value.IndexOf(" — ", StringComparison.Ordinal);
        return separator >= 0 ? value[..separator] : value;
    }

    private enum PathInputMode
    {
        OpenFile,
        SaveFile,
        Folder,
    }
}
