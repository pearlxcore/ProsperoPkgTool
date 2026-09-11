using System.Collections.Concurrent;
using System.Text;

namespace ProsperoPkgTool.Gui;

public sealed class OutputConsole : UserControl
{
    private const int MaxTabs = 12;
    private const int MaxCharacters = 100_000;
    private const int KeepCharacters = 60_000;
    private readonly TabControl _tabs = new() { Dock = DockStyle.Fill };
    private readonly List<TabPage> _pages = [];
    private readonly HashSet<TabPage> _running = [];
    private readonly Button _cancel = new() { Text = "Cancel", Width = 90, Enabled = false };
    private readonly ConcurrentQueue<(TabPage Page, string Text)> _pending = new();
    private readonly System.Windows.Forms.Timer _flushTimer = new() { Interval = 100 };

    public OutputConsole()
    {
        Dock = DockStyle.Fill;
        BuildLayout();
        _flushTimer.Tick += (_, _) => FlushPending();
        _flushTimer.Start();
    }

    public event Action? CancelRequested;

    public bool AnyRunning => _running.Count > 0;

    public void SetRunning(bool running) => _cancel.Enabled = running;

    public TabPage StartRun(string name)
    {
        if (_pages.Count >= MaxTabs)
        {
            TabPage? victim = _pages.FirstOrDefault(page => !_running.Contains(page));
            if (victim is not null)
                Remove(victim);
        }
        var page = new TabPage($"{name} · {DateTime.Now:HH:mm}") { Padding = new Padding(4) };
        page.Controls.Add(CreateTextBox());
        _pages.Add(page);
        _running.Add(page);
        _tabs.TabPages.Add(page);
        _tabs.SelectedTab = page;
        return page;
    }

    public void AppendLine(TabPage page, string text) => _pending.Enqueue((page, text));

    public void FinishRun(TabPage page, int exitCode, TimeSpan elapsed)
    {
        _running.Remove(page);
        bool success = exitCode == 0;
        page.Text = $"{(success ? "✓" : "✗")} {page.Text}";
        AppendLine(page, string.Empty);
        AppendLine(page, success
            ? $"=== EXIT 0 in {elapsed.TotalSeconds:F1}s ==="
            : $"=== FAILED (exit {exitCode}) in {elapsed.TotalSeconds:F1}s ===");
        FlushPending();
    }

    public void CancelRun(TabPage page)
    {
        _running.Remove(page);
        page.Text = $"✗ {page.Text}";
        AppendLine(page, string.Empty);
        AppendLine(page, "=== CANCELLED ===");
        FlushPending();
    }

    public void ErrorRun(TabPage page, string message)
    {
        _running.Remove(page);
        page.Text = $"✗ {page.Text}";
        AppendLine(page, string.Empty);
        AppendLine(page, $"=== ERROR: {message} ===");
        FlushPending();
    }

    private void BuildLayout()
    {
        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 34,
            Padding = new Padding(6, 3, 6, 3),
            FlowDirection = FlowDirection.LeftToRight,
        };
        var close = new Button { Text = "Close tab", Width = 90 };
        close.Click += (_, _) => CloseSelected();
        var clear = new Button { Text = "Clear finished", Width = 105 };
        clear.Click += (_, _) => ClearFinished();
        _cancel.Click += (_, _) =>
        {
            _cancel.Enabled = false;
            CancelRequested?.Invoke();
        };
        toolbar.Controls.Add(_cancel);
        toolbar.Controls.Add(close);
        toolbar.Controls.Add(clear);

        var welcome = new TabPage("welcome") { Padding = new Padding(4) };
        TextBox welcomeText = CreateTextBox();
        welcomeText.WordWrap = true;
        welcomeText.Text =
            "ProsperoPkgTool GUI (native, clean-room)" + Environment.NewLine + Environment.NewLine +
            "1. Select a PS5 .pkg in the package bar. Native FIH/CNT metadata is loaded without any external tool." + Environment.NewLine +
            "2. Choose a Package or Tools operation." + Environment.NewLine +
            "3. Press Run or double-click an operation. Each run opens a separate output tab." + Environment.NewLine + Environment.NewLine +
            "All operations are native and clean-room: structural inspection, CNT entry listing, and " +
            "outer-PFS decryption run entirely within ProsperoPkgTool. No Sony software is required.";
        welcome.Controls.Add(welcomeText);
        _tabs.TabPages.Add(welcome);
        Controls.Add(_tabs);
        Controls.Add(toolbar);
    }

    private static TextBox CreateTextBox() => new()
    {
        Dock = DockStyle.Fill,
        Multiline = true,
        ReadOnly = true,
        ScrollBars = ScrollBars.Both,
        WordWrap = false,
        Font = new Font("Cascadia Mono", 9f),
        BackColor = Color.FromArgb(28, 30, 34),
        ForeColor = Color.FromArgb(225, 225, 225),
        BorderStyle = BorderStyle.None,
    };

    private void FlushPending()
    {
        if (_pending.IsEmpty || !IsHandleCreated)
            return;
        var grouped = new Dictionary<TabPage, StringBuilder>();
        while (_pending.TryDequeue(out var item))
        {
            if (!grouped.TryGetValue(item.Page, out StringBuilder? builder))
            {
                builder = new StringBuilder();
                grouped[item.Page] = builder;
            }
            builder.AppendLine(item.Text);
        }
        foreach ((TabPage page, StringBuilder builder) in grouped)
        {
            TextBox? box = page.Controls.OfType<TextBox>().FirstOrDefault();
            if (box is null)
                continue;
            if (box.TextLength > MaxCharacters)
            {
                int start = box.TextLength - KeepCharacters;
                int newline = box.Text.IndexOf('\n', start);
                box.Text = box.Text[(newline >= 0 ? newline + 1 : start)..];
            }
            box.AppendText(builder.ToString());
            box.SelectionStart = box.TextLength;
            box.ScrollToCaret();
        }
    }

    private void CloseSelected()
    {
        TabPage? page = _tabs.SelectedTab;
        if (page is null || !_pages.Contains(page))
            return;
        if (_running.Contains(page) && MessageBox.Show(FindForm(), "This operation is still running. Close its output tab?",
                "Operation running", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
            return;
        Remove(page);
    }

    private void ClearFinished()
    {
        foreach (TabPage page in _pages.Where(page => !_running.Contains(page)).ToArray())
            Remove(page);
    }

    private void Remove(TabPage page)
    {
        _tabs.TabPages.Remove(page);
        _pages.Remove(page);
        _running.Remove(page);
        page.Dispose();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            _flushTimer.Dispose();
        base.Dispose(disposing);
    }
}
