using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class ContainerBackendCatalogTests
{
    [Fact]
    public void CatalogReservesAllPlannedFormats()
    {
        string[] formats = ContainerBackendCatalog.All.Select(item => item.FormatId).ToArray();
        Assert.Contains("sony-pkg", formats);
        Assert.Contains("ffpkg", formats);
        Assert.Contains("ffpfsc", formats);
        Assert.Contains("exfat", formats);
        Assert.Contains("folder", formats);
    }

    [Fact]
    public void OnlySonyBackendIsAvailableInFoundationMilestone()
    {
        ContainerBackendDescriptor available = Assert.Single(ContainerBackendCatalog.All,
            item => item.Status == ContainerBackendStatus.Available);
        Assert.Equal("sony-pkg", available.FormatId);
        Assert.True(available.Capabilities.HasFlag(ContainerCapabilities.Create));
    }
}

