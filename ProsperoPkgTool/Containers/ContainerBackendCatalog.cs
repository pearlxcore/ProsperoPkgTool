namespace ProsperoPkgTool.Containers;

public static class ContainerBackendCatalog
{
    public static IReadOnlyList<ContainerBackendDescriptor> All { get; } =
    [
        new("ps5-pkg", "PS5 CNT/FIH fake/debug package", ContainerBackendStatus.Experimental,
            ContainerCapabilities.Inspect | ContainerCapabilities.List |
            ContainerCapabilities.Extract | ContainerCapabilities.Verify |
            ContainerCapabilities.Create),
        new("ffpkg", "FFPKG / UFS2 image", ContainerBackendStatus.Planned,
            ContainerCapabilities.None),
        new("ffpfsc", "FFPFSC compressed image", ContainerBackendStatus.Planned,
            ContainerCapabilities.None),
        new("exfat", "Raw exFAT image", ContainerBackendStatus.Planned,
            ContainerCapabilities.None),
        new("folder", "Unpacked application folder", ContainerBackendStatus.Planned,
            ContainerCapabilities.None),
    ];
}
