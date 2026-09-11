using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Gui;

public sealed class PackageBar : UserControl
{
    private readonly TextBox _path = new();
    private readonly TextBox _passcode = new();
    private readonly ComboBox _recents = new();
    private readonly Label _badge = new();
    private readonly Label _summary = new();
    private readonly Label _warning = new();
    private readonly List<string> _recentPaths = [];
    private CancellationTokenSource? _summaryCancellation;

    public PackageBar()
    {
        Height = 150;
        Dock = DockStyle.Top;
        BackColor = Color.FromArgb(244, 246, 250);
        Padding = new Padding(10, 6, 10, 6);
        BuildLayout();
    }

    public event EventHandler? PackageChanged;
    public string PackagePath => _path.Text.Trim();
    public string Passcode => _passcode.Text.Trim();

    public void SetPackagePath(string path) => _path.Text = path;
    public void SetPasscode(string passcode) => _passcode.Text = passcode;
    public IReadOnlyList<string> GetRecents() => _recentPaths;

    public void AddRecent(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;
        _recentPaths.RemoveAll(item => item.Equals(path, StringComparison.OrdinalIgnoreCase));
        _recentPaths.Insert(0, path);
        if (_recentPaths.Count > 12)
            _recentPaths.RemoveRange(12, _recentPaths.Count - 12);
        SetRecents(_recentPaths);
    }

    public void SetRecents(IEnumerable<string> paths)
    {
        string[] snapshot = paths.Where(File.Exists).Distinct(StringComparer.OrdinalIgnoreCase).Take(12).ToArray();
        _recentPaths.Clear();
        _recentPaths.AddRange(snapshot);
        _recents.Items.Clear();
        foreach (string path in snapshot)
            _recents.Items.Add($"{Path.GetFileName(path)} - {path}");
    }

    private void BuildLayout()
    {
        var packageRow = new TableLayoutPanel { Dock = DockStyle.Top, Height = 32, ColumnCount = 4, RowCount = 1 };
        packageRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
        packageRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        packageRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 34));
        packageRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 230));
        packageRow.Controls.Add(new Label { Text = "Package", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
        _path.Dock = DockStyle.Fill;
        _path.TextChanged += (_, _) => OnPathChanged();
        packageRow.Controls.Add(_path, 1, 0);
        var browse = new Button { Text = "...", Dock = DockStyle.Fill };
        browse.Click += (_, _) => Browse();
        packageRow.Controls.Add(browse, 2, 0);
        _recents.Dock = DockStyle.Fill;
        _recents.DropDownStyle = ComboBoxStyle.DropDownList;
        _recents.SelectedIndexChanged += (_, _) =>
        {
            if (_recents.SelectedIndex >= 0 && _recents.SelectedIndex < _recentPaths.Count)
                _path.Text = _recentPaths[_recents.SelectedIndex];
        };
        packageRow.Controls.Add(_recents, 3, 0);

        var passcodeRow = new TableLayoutPanel { Dock = DockStyle.Top, Height = 32, ColumnCount = 2, RowCount = 1 };
        passcodeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 80));
        passcodeRow.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        passcodeRow.Controls.Add(new Label { Text = "Passcode", Dock = DockStyle.Fill, TextAlign = ContentAlignment.MiddleLeft }, 0, 0);
        _passcode.Dock = DockStyle.Fill;
        _passcode.Text = CommandDef.DefaultPasscode;
        _passcode.MaxLength = 32;
        _passcode.Font = new Font("Cascadia Mono", 9f);
        _passcode.TextChanged += (_, _) => PackageChanged?.Invoke(this, EventArgs.Empty);
        passcodeRow.Controls.Add(_passcode, 1, 0);

        var summaryRow = new Panel { Dock = DockStyle.Top, Height = 52 };
        _badge.Dock = DockStyle.Left;
        _badge.Width = 105;
        _badge.TextAlign = ContentAlignment.MiddleCenter;
        _badge.Font = new Font("Segoe UI", 9f, FontStyle.Bold);
        _badge.ForeColor = Color.White;
        _badge.BackColor = Color.Gray;
        _badge.Text = "NO PACKAGE";
        _summary.Dock = DockStyle.Fill;
        _summary.Padding = new Padding(8, 5, 8, 3);
        _summary.AutoEllipsis = true;
        _summary.Text = "Select a PS5 package to load its native FIH/CNT summary.";
        summaryRow.Controls.Add(_summary);
        summaryRow.Controls.Add(_badge);

        _warning.Dock = DockStyle.Top;
        _warning.Height = 22;
        _warning.Padding = new Padding(4, 2, 4, 0);
        _warning.ForeColor = Color.Firebrick;
        _warning.AutoEllipsis = true;

        Controls.Add(_warning);
        Controls.Add(summaryRow);
        Controls.Add(passcodeRow);
        Controls.Add(packageRow);
    }

    private void Browse()
    {
        using var dialog = new OpenFileDialog
        {
            Title = "Select PS5 package",
            Filter = "PS5 packages (*.pkg)|*.pkg|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        if (dialog.ShowDialog(FindForm()) == DialogResult.OK)
            _path.Text = dialog.FileName;
    }

    private void OnPathChanged()
    {
        PackageChanged?.Invoke(this, EventArgs.Empty);
        _summaryCancellation?.Cancel();
        if (!File.Exists(PackagePath))
        {
            ClearSummary();
            return;
        }
        _summaryCancellation = new CancellationTokenSource();
        _ = LoadSummaryAsync(PackagePath, _summaryCancellation.Token);
    }

    private async Task LoadSummaryAsync(string path, CancellationToken cancellationToken)
    {
        _summary.Text = "Reading native FIH/CNT metadata...";
        _warning.Text = string.Empty;
        try
        {
            ProsperoPackageInspection package = await Task.Run(() => ProsperoPackageReader.Read(path), cancellationToken);
            if (cancellationToken.IsCancellationRequested)
                return;
            string segments = string.Join("  ", package.Segments.Select(segment => $"{segment.Name}=0x{segment.Size:X}"));
            _summary.Text =
                $"Content ID: {package.Cnt.ContentId}    Entries: {package.Entries.Count}    Size: {package.FileSize / 1024d / 1024d:F2} MiB\n" +
                segments;
            _badge.Text = package.Kind switch
            {
                ProsperoPackageKind.FinalizedDebug => "FIH DEBUG",
                ProsperoPackageKind.FinalizedRetail => "FIH RETAIL",
                _ => "CNT META",
            };
            _badge.BackColor = package.Kind switch
            {
                ProsperoPackageKind.FinalizedDebug => Color.FromArgb(30, 112, 164),
                ProsperoPackageKind.FinalizedRetail => Color.FromArgb(118, 70, 150),
                _ => Color.FromArgb(90, 90, 90),
            };
            _warning.Text = package.Structure.IsValid
                ? "Native structure passed. Run native outer-PFS decrypt with the passcode to inspect the inner image."
                : $"Native structure failed: {package.Structure.Issues.First(issue => issue.IsError).Message}";
            _warning.ForeColor = package.Structure.IsValid ? Color.DarkGoldenrod : Color.Firebrick;
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception exception)
        {
            if (cancellationToken.IsCancellationRequested || IsDisposed || Disposing)
                return;
            _badge.Text = "INVALID";
            _badge.BackColor = Color.Firebrick;
            _summary.Text = exception is InvalidDataException
                ? "Unsupported or malformed PS5 package."
                : "Could not read the selected package.";
            _warning.ForeColor = Color.Firebrick;
            _warning.Text = exception.Message;
        }
    }

    private void ClearSummary()
    {
        _badge.Text = "NO PACKAGE";
        _badge.BackColor = Color.Gray;
        _summary.Text = "Select a PS5 package to load its native FIH/CNT summary.";
        _warning.Text = string.Empty;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _summaryCancellation?.Cancel();
            _summaryCancellation?.Dispose();
        }
        base.Dispose(disposing);
    }
}
