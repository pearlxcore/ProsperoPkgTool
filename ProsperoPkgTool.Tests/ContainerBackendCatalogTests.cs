using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class ContainerBackendCatalogTests
{
    [Fact]
    public void CatalogReservesAllPlannedFormats()
    {
        string[] formats = ContainerBackendCatalog.All.Select(item => item.FormatId).ToArray();
        Assert.Contains("ps5-pkg", formats);
        Assert.Contains("ffpkg", formats);
        Assert.Contains("ffpfsc", formats);
        Assert.Contains("exfat", formats);
        Assert.Contains("folder", formats);
    }

    [Fact]
    public void NativePs5PackageBackendIsExperimental()
    {
        ContainerBackendDescriptor backend = Assert.Single(ContainerBackendCatalog.All,
            item => item.FormatId == "ps5-pkg");
        Assert.Equal(ContainerBackendStatus.Experimental, backend.Status);
        Assert.True(backend.Capabilities.HasFlag(ContainerCapabilities.Create));
    }
}
