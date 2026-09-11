using System.Diagnostics;

namespace ProsperoPkgTool.Gui;

/// <summary>
/// Main GUI window. The GUI drives only ProsperoPkgTool's native, clean-room operations -
/// there is no Sony-tool integration and no GPL fPKG backend.
/// </summary>
public sealed class MainForm : Form
{
    private readonly PackageBar _packageBar = new();
    private readonly OperationsPane _packageOperations = new();
    private readonly OperationsPane _toolOperations = new();
    private readonly OutputConsole _output = new();
    private readonly TabControl _operationTabs = new() { Dock = DockStyle.Fill };
    private readonly SplitContainer _outputSplit = new()
    {
        Dock = DockStyle.Fill,
        Orientation = Orientation.Horizontal,
        FixedPanel = FixedPanel.Panel1,
    };
    private readonly ToolStripStatusLabel _packageStatus = new("No package selected");
    private readonly ToolStripStatusLabel _operationStatus = new("Ready");
    private readonly ToolStripStatusLabel _lastRunStatus = new("Never run");
    private readonly string _settingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "ProsperoPkgTool", "gui.settings.txt");
    private readonly bool _persistSettings;

    private CancellationTokenSource? _cancellation;
    private Process? _process;
    private OperationsPane _activePane;
    private int _savedOutputSplitter = 300;
    private int _savedPackageSplitter = 235;
    private int _savedToolSplitter = 235;

    public MainForm(bool persistSettings = true)
    {
        _persistSettings = persistSettings;
        Text = "ProsperoPkgTool GUI (native, clean-room)";
        Width = 1180;
        Height = 840;
        MinimumSize = new Size(860, 590);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 9f);
        KeyPreview = true;
        _activePane = _packageOperations;

        _packageOperations.SetCommands(CommandRegistry.PackageOperations);
        _toolOperations.SetCommands(CommandRegistry.ToolOperations);

        BuildLayout();
        WireEvents();
        if (_persistSettings)
            LoadSettings();
    }

    internal void SelectOperationTab(int index) =>
        _operationTabs.SelectedIndex = Math.Clamp(index, 0, _operationTabs.TabPages.Count - 1);

    private void BuildLayout()
    {
        _operationTabs.TabPages.Add(CreateTab("Package", _packageOperations));
        _operationTabs.TabPages.Add(CreateTab("Build & Tools", _toolOperations));
        _outputSplit.Panel1.Controls.Add(_operationTabs);
        _outputSplit.Panel2.Controls.Add(_output);

        var status = new StatusStrip();
        _packageStatus.Spring = true;
        _packageStatus.TextAlign = ContentAlignment.MiddleLeft;
        _operationStatus.BorderSides = ToolStripStatusLabelBorderSides.Left;
        _lastRunStatus.BorderSides = ToolStripStatusLabelBorderSides.Left;
        status.Items.Add(_packageStatus);
        status.Items.Add(_operationStatus);
        status.Items.Add(_lastRunStatus);

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            Margin = new Padding(0),
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 150));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));
        _packageBar.Dock = DockStyle.Fill;
        status.Dock = DockStyle.Fill;
        root.Controls.Add(_packageBar, 0, 0);
        root.Controls.Add(_outputSplit, 0, 1);
        root.Controls.Add(status, 0, 2);
        Controls.Add(root);
    }

    private static TabPage CreateTab(string title, Control content)
    {
        var page = new TabPage(title) { Padding = new Padding(4) };
        page.Controls.Add(content);
        return page;
    }

    private void WireEvents()
    {
        foreach (OperationsPane pane in new[] { _packageOperations, _toolOperations })
        {
            pane.RunRequested += async (command, values) => await RunOperationAsync(command, values);
            pane.CancelRequested += CancelOperation;
            pane.SelectionChanged += command =>
            {
                if (command is not null)
                    _operationStatus.Text = command.Title;
            };
        }
        _operationTabs.SelectedIndexChanged += (_, _) =>
        {
            _activePane = _operationTabs.SelectedIndex == 1 ? _toolOperations : _packageOperations;
        };
        _output.CancelRequested += CancelOperation;
        _packageBar.PackageChanged += (_, _) =>
        {
            _packageStatus.Text = _packageBar.PackagePath.Length == 0
                ? "No package selected"
                : Path.GetFileName(_packageBar.PackagePath);
        };
        KeyDown += (_, eventArgs) =>
        {
            if (eventArgs.KeyCode == Keys.F5)
            {
                _activePane.RunCurrent();
                eventArgs.Handled = true;
            }
            else if (eventArgs.KeyCode == Keys.Escape && _cancellation is not null)
            {
                CancelOperation();
                eventArgs.Handled = true;
            }
        };
        FormClosing += OnFormClosing;
    }

    private async Task RunOperationAsync(CommandDef command, IReadOnlyDictionary<string, string> values)
    {
        if (_cancellation is not null)
            return;

        var effective = new Dictionary<string, string>(values, StringComparer.Ordinal);
        if (command.UsesSelectedPackage)
        {
            if (string.IsNullOrWhiteSpace(_packageBar.PackagePath))
            {
                Warn("Select a PS5 package in the package bar first.", "Package required");
                return;
            }
            effective["pkg"] = _packageBar.PackagePath;
            effective["passcode"] = _packageBar.Passcode;
        }

        string[] commandArguments;
        try
        {
            commandArguments = command.BuildArgs(effective);
        }
        catch (ArgumentException exception)
        {
            Warn(exception.Message, "Missing input");
            return;
        }

        if (command.Confirmation.Length > 0 &&
            MessageBox.Show(this, command.Confirmation, "Confirm operation",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            return;

        string executable;
        try
        {
            executable = ResolveCliExecutable();
        }
        catch (FileNotFoundException exception)
        {
            Warn(exception.Message, "ProsperoPkgTool not found");
            return;
        }

        var allArguments = new List<string> { command.CliWord };
        allArguments.AddRange(commandArguments);

        TabPage outputPage = _output.StartRun(command.Name);
        _output.AppendLine(outputPage, $"> {Path.GetFileName(executable)} {FormatArguments(allArguments)}");
        _operationStatus.Text = $"Running {command.Name}...";
        SetRunning(true);
        _cancellation = new CancellationTokenSource();
        var stopwatch = Stopwatch.StartNew();

        try
        {
            var startInfo = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Environment.CurrentDirectory,
            };
            foreach (string argument in allArguments)
                startInfo.ArgumentList.Add(argument);

            _process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
            _process.OutputDataReceived += (_, eventArgs) =>
            {
                if (eventArgs.Data is not null)
                    _output.AppendLine(outputPage, eventArgs.Data);
            };
            _process.ErrorDataReceived += (_, eventArgs) =>
            {
                if (eventArgs.Data is not null)
                    _output.AppendLine(outputPage, "[stderr] " + eventArgs.Data);
            };
            if (!_process.Start())
                throw new InvalidOperationException("The ProsperoPkgTool process did not start.");
            _process.BeginOutputReadLine();
            _process.BeginErrorReadLine();

            await _process.WaitForExitAsync(_cancellation.Token);
            _process.WaitForExit();
            int exitCode = _process.ExitCode;
            stopwatch.Stop();
            _output.FinishRun(outputPage, exitCode, stopwatch.Elapsed);
            _operationStatus.Text = exitCode == 0 ? "Completed" : $"Failed ({exitCode})";
            _lastRunStatus.Text = $"{command.Name}: {DateTime.Now:HH:mm:ss}";
            if (exitCode == 0 && command.UsesSelectedPackage)
                _packageBar.AddRecent(_packageBar.PackagePath);
        }
        catch (OperationCanceledException)
        {
            TryKillProcess();
            stopwatch.Stop();
            _output.CancelRun(outputPage);
            _operationStatus.Text = "Cancelled";
        }
        catch (Exception exception)
        {
            stopwatch.Stop();
            _output.ErrorRun(outputPage, exception.Message);
            _operationStatus.Text = "Failed";
        }
        finally
        {
            _process?.Dispose();
            _process = null;
            _cancellation.Dispose();
            _cancellation = null;
            SetRunning(false);
        }
    }

    private void SetRunning(bool running)
    {
        _packageOperations.SetRunning(running);
        _toolOperations.SetRunning(running);
        _output.SetRunning(running);
        _operationTabs.Enabled = !running;
    }

    private void CancelOperation()
    {
        _cancellation?.Cancel();
        TryKillProcess();
    }

    private void TryKillProcess()
    {
        try
        {
            if (_process is { HasExited: false })
                _process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
        }
    }

    private static string ResolveCliExecutable()
    {
        string besideGui = Path.Combine(AppContext.BaseDirectory, "ProsperoPkgTool.exe");
        if (File.Exists(besideGui))
            return besideGui;

        DirectoryInfo? directory = new(AppContext.BaseDirectory);
        while (directory is not null)
        {
            foreach (string configuration in new[] { "Release", "Debug" })
            {
                string candidate = Path.Combine(directory.FullName, "ProsperoPkgTool", "bin", configuration,
                    "net10.0", "ProsperoPkgTool.exe");
                if (File.Exists(candidate))
                    return candidate;
            }
            directory = directory.Parent;
        }
        throw new FileNotFoundException("ProsperoPkgTool.exe was not found. Build the complete solution so the GUI can run CLI operations.");
    }

    private static string FormatArguments(IEnumerable<string> arguments) => string.Join(" ", arguments.Select(argument =>
        argument.Any(char.IsWhiteSpace) ? $"\"{argument.Replace("\"", "\\\"")}\"" : argument));

    private void LoadSettings()
    {
        if (!File.Exists(_settingsPath))
            return;
        try
        {
            string[] lines = File.ReadAllLines(_settingsPath);
            foreach (string line in lines)
            {
                int separator = line.IndexOf('=');
                if (separator < 0)
                    continue;
                string name = line[..separator];
                string value = line[(separator + 1)..];
                switch (name)
                {
                    case "package": _packageBar.SetPackagePath(value); break;
                    case "passcode": _packageBar.SetPasscode(value); break;
                    case "recent": _packageBar.AddRecent(value); break;
                    case "width" when int.TryParse(value, out int width): Width = Math.Max(MinimumSize.Width, width); break;
                    case "height" when int.TryParse(value, out int height): Height = Math.Max(MinimumSize.Height, height); break;
                    case "tab" when int.TryParse(value, out int tab): _operationTabs.SelectedIndex = Math.Clamp(tab, 0, 1); break;
                    case "browse": OperationsPane.LastBrowsedPath = value; break;
                    case "outputSplitter" when int.TryParse(value, out int output): _savedOutputSplitter = output; break;
                    case "packageSplitter" when int.TryParse(value, out int package): _savedPackageSplitter = package; break;
                    case "toolSplitter" when int.TryParse(value, out int tool): _savedToolSplitter = tool; break;
                }
            }
        }
        catch (IOException)
        {
        }
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        ConfigureMinSizes(_outputSplit, 160, 180);
        SetSplitter(_outputSplit, _savedOutputSplitter);
        SetSplitter(_packageOperations.Split, _savedPackageSplitter);
        SetSplitter(_toolOperations.Split, _savedToolSplitter);
    }

    /// <summary>
    /// Sets a split container's panel minimums only when the container is large enough to hold
    /// them. <see cref="SplitContainer"/> throws from its <c>ApplyPanel2MinSize</c> path when a
    /// minimum exceeds the available span (or when the current <c>SplitterDistance</c> would fall
    /// outside the new range), so short/small windows must skip this step rather than crash.
    /// </summary>
    private static void ConfigureMinSizes(SplitContainer split, int panel1Min, int panel2Min)
    {
        int span = split.Orientation == Orientation.Horizontal ? split.ClientSize.Height : split.ClientSize.Width;
        if (span < panel1Min + panel2Min + split.SplitterWidth)
            return;
        split.Panel1MinSize = panel1Min;
        split.Panel2MinSize = panel2Min;
    }

    private static void SetSplitter(SplitContainer split, int distance)
    {
        int span = split.Orientation == Orientation.Horizontal ? split.ClientSize.Height : split.ClientSize.Width;
        int minimum = split.Panel1MinSize;
        int maximum = span - split.Panel2MinSize - split.SplitterWidth;
        if (maximum < minimum)
            return;
        split.SplitterDistance = Math.Clamp(distance, minimum, maximum);
    }

    private void SaveSettings()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_settingsPath)!);
            var lines = new List<string>
            {
                "package=" + _packageBar.PackagePath,
                "passcode=" + _packageBar.Passcode,
                "width=" + Width,
                "height=" + Height,
                "tab=" + _operationTabs.SelectedIndex,
                "browse=" + OperationsPane.LastBrowsedPath,
                "outputSplitter=" + _outputSplit.SplitterDistance,
                "packageSplitter=" + _packageOperations.Split.SplitterDistance,
                "toolSplitter=" + _toolOperations.Split.SplitterDistance,
            };
            lines.AddRange(_packageBar.GetRecents().Reverse().Select(path => "recent=" + path));
            File.WriteAllLines(_settingsPath, lines);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs eventArgs)
    {
        if (_cancellation is not null && MessageBox.Show(this,
                "An operation is still running. Cancel it and close?", "Operation running",
                MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
        {
            eventArgs.Cancel = true;
            return;
        }
        CancelOperation();
        if (_persistSettings)
            SaveSettings();
    }

    private void Warn(string message, string title) =>
        MessageBox.Show(this, message, title, MessageBoxButtons.OK, MessageBoxIcon.Warning);
}
