namespace ProsperoPkgTool.Gui;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        if (args.Length is 2 or 3 && args[0] == "--screenshot")
        {
            string outputPath = args[1];
            using var form = new MainForm(persistSettings: false);
            if (args.Length == 3 && int.TryParse(args[2], out int tab))
                form.SelectOperationTab(tab);
            form.Show();
            Application.DoEvents();
            using var bitmap = new Bitmap(form.ClientSize.Width, form.ClientSize.Height);
            form.DrawToBitmap(bitmap, form.ClientRectangle);
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
            bitmap.Save(outputPath);
            File.WriteAllLines(outputPath + ".layout.txt", DescribeControls(form));
            return;
        }
        Application.Run(new MainForm());
    }

    private static IEnumerable<string> DescribeControls(Control root, string prefix = "")
    {
        yield return $"{prefix}{root.GetType().Name} bounds={root.Bounds} dock={root.Dock} text={root.Text}";
        foreach (Control child in root.Controls)
            foreach (string line in DescribeControls(child, prefix + "  "))
                yield return line;
    }
}
