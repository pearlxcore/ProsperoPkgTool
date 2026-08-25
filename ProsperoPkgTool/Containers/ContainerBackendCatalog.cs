namespace ProsperoPkgTool.Containers;

public static class ContainerBackendCatalog
{
    public static IReadOnlyList<ContainerBackendDescriptor> All { get; } =
    [
        new("sony-pkg", "Sony CNT/FIH package", ContainerBackendStatus.Available,
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

