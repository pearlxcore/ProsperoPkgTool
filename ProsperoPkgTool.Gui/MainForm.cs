using ProsperoPkgTool.Sony;

namespace ProsperoPkgTool.Gui;

public sealed class MainForm : Form
{
    private readonly TextBox _toolPath = new() { Dock = DockStyle.Fill };
    private readonly ComboBox _commands = new() { Dock = DockStyle.Fill, DropDownStyle = ComboBoxStyle.DropDownList };
    private readonly TextBox _arguments = new()
    {
        Dock = DockStyle.Fill,
        Multiline = true,
        ScrollBars = ScrollBars.Vertical,
        AcceptsReturn = true,
        Font = new Font("Consolas", 9f),
    };
    private readonly RichTextBox _output = new()
    {
        Dock = DockStyle.Fill,
        ReadOnly = true,
        BackColor = Color.FromArgb(24, 24, 24),
        ForeColor = Color.Gainsboro,
        Font = new Font("Consolas", 9f),
    };
    private readonly Button _run = new() { Text = "Run", AutoSize = true };
    private readonly Button _cancel = new() { Text = "Cancel", AutoSize = true, Enabled = false };
    private readonly ToolStripStatusLabel _statusText = new("Ready");
    private CancellationTokenSource? _cancellation;

    public MainForm()
    {
        Text = "ProsperoPkgTool";
        Width = 1000;
        Height = 720;
        MinimumSize = new Size(720, 500);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9f);

        foreach (SonyCommandDefinition command in SonyCommandRegistry.All)
            _commands.Items.Add(new CommandItem(command));
        _commands.SelectedIndex = 0;

        try
        {
            _toolPath.Text = SonyToolLocator.Resolve();
        }
        catch (FileNotFoundException)
        {
        }

        Controls.Add(BuildLayout());
        _run.Click += async (_, _) => await RunSelectedAsync();
        _cancel.Click += (_, _) => _cancellation?.Cancel();
    }

    private Control BuildLayout()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Padding = new Padding(10),
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 170));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));

        var settings = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 3, RowCount = 3 };
        settings.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        settings.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        settings.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        settings.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        settings.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        settings.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        settings.Controls.Add(new Label { Text = "Sony tool", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        settings.Controls.Add(_toolPath, 1, 0);
        var browse = new Button { Text = "Browse...", AutoSize = true };
        browse.Click += (_, _) => BrowseTool();
        settings.Controls.Add(browse, 2, 0);

        settings.Controls.Add(new Label { Text = "Command", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
        settings.Controls.Add(_commands, 1, 1);
        var buttons = new FlowLayoutPanel { AutoSize = true, FlowDirection = FlowDirection.LeftToRight };
        buttons.Controls.Add(_run);
        buttons.Controls.Add(_cancel);
        settings.Controls.Add(buttons, 2, 1);

        settings.Controls.Add(new Label
        {
            Text = "Arguments\n(one per line)",
            AutoSize = true,
            Anchor = AnchorStyles.Left | AnchorStyles.Top,
        }, 0, 2);
        settings.Controls.Add(_arguments, 1, 2);
        settings.SetColumnSpan(_arguments, 2);

        var status = new StatusStrip();
        status.Items.Add(_statusText);
        root.Controls.Add(settings, 0, 0);
        root.Controls.Add(_output, 0, 1);
        root.Controls.Add(status, 0, 2);
        return root;
    }

    private void BrowseTool()
    {
        using var dialog = new OpenFileDialog
        {
            Filter = "Prospero Publishing CLI (prospero-pub-cmd.exe)|prospero-pub-cmd.exe|Executables (*.exe)|*.exe",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(this) == DialogResult.OK)
            _toolPath.Text = dialog.FileName;
    }

    private async Task RunSelectedAsync()
    {
        if (_commands.SelectedItem is not CommandItem item)
            return;

        string tool;
        try
        {
            tool = SonyToolLocator.Resolve(_toolPath.Text);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException)
        {
            MessageBox.Show(this, exception.Message, "Sony tool not found", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        string[] arguments = _arguments.Lines
            .Select(line => line.Trim())
            .Where(line => line.Length > 0)
            .ToArray();
        _output.Clear();
        AppendLine($"> {item.Definition.Name} {string.Join(" ", arguments)}", false);
        SetRunning(true);
        _cancellation = new CancellationTokenSource();

        try
        {
            var backend = new SonyPublishingBackend(tool);
            SonyProcessResult result = await backend.RunAsync([item.Definition.Name, .. arguments], line =>
            {
                if (IsDisposed)
                    return;
                BeginInvoke(() => AppendLine(line.Text, line.IsError));
            }, _cancellation.Token);
            AppendLine($"Exited with code {result.ExitCode} after {result.Elapsed.TotalSeconds:F1}s.", !result.Success);
            _statusText.Text = result.Success ? "Completed" : $"Failed ({result.ExitCode})";
        }
        catch (OperationCanceledException)
        {
            AppendLine("Cancelled.", true);
            _statusText.Text = "Cancelled";
        }
        catch (Exception exception)
        {
            AppendLine(exception.Message, true);
            _statusText.Text = "Failed";
        }
        finally
        {
            _cancellation.Dispose();
            _cancellation = null;
            SetRunning(false);
        }
    }

    private void AppendLine(string text, bool error)
    {
        _output.SelectionColor = error ? Color.LightCoral : Color.Gainsboro;
        _output.AppendText(text + Environment.NewLine);
        _output.ScrollToCaret();
    }

    private void SetRunning(bool running)
    {
        _run.Enabled = !running;
        _cancel.Enabled = running;
        _commands.Enabled = !running;
        _toolPath.Enabled = !running;
        _statusText.Text = running ? "Running..." : _statusText.Text;
    }

    private sealed record CommandItem(SonyCommandDefinition Definition)
    {
        public override string ToString() => $"{Definition.Group} — {Definition.Name}";
    }
}

