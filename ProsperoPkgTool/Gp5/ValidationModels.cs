namespace ProsperoPkgTool.Gp5;

public enum ValidationSeverity
{
    Warning,
    Error,
}

public sealed record ValidationIssue(
    ValidationSeverity Severity,
    string Code,
    string Message,
    string? Path = null);

public sealed class ValidationReport
{
    private readonly List<ValidationIssue> _issues = [];

    public IReadOnlyList<ValidationIssue> Issues => _issues;
    public bool IsValid => _issues.All(issue => issue.Severity != ValidationSeverity.Error);
    public int ErrorCount => _issues.Count(issue => issue.Severity == ValidationSeverity.Error);
    public int WarningCount => _issues.Count(issue => issue.Severity == ValidationSeverity.Warning);

    public void Error(string code, string message, string? path = null) =>
        _issues.Add(new ValidationIssue(ValidationSeverity.Error, code, message, path));

    public void Warning(string code, string message, string? path = null) =>
        _issues.Add(new ValidationIssue(ValidationSeverity.Warning, code, message, path));

    public void AddRange(IEnumerable<ValidationIssue> issues) => _issues.AddRange(issues);
}

