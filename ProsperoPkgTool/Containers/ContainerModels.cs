namespace ProsperoPkgTool.Containers;

[Flags]
public enum ContainerCapabilities
{
    None = 0,
    Inspect = 1 << 0,
    List = 1 << 1,
    Extract = 1 << 2,
    Verify = 1 << 3,
    Create = 1 << 4,
    Edit = 1 << 5,
    Repair = 1 << 6,
}

public enum ContainerBackendStatus
{
    Available,
    Planned,
    Experimental,
}

public sealed record ContainerBackendDescriptor(
    string FormatId,
    string DisplayName,
    ContainerBackendStatus Status,
    ContainerCapabilities Capabilities);

public sealed record ContainerInfo(
    string FormatId,
    string Path,
    long Length,
    IReadOnlyDictionary<string, string> Properties);

public sealed record ContainerEntry(string Path, long Length, bool IsDirectory);

public sealed record VerificationIssue(string Code, string Message, bool IsError);

public sealed record VerificationResult(bool IsValid, IReadOnlyList<VerificationIssue> Issues);

