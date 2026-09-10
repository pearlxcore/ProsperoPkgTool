using System.Security.Cryptography;
using ProsperoPkgTool.Content;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Coverage for the embedded debug <c>sce_sys/about/right.sprx</c> module. The expected SHA-256 is
/// the fixed module shared by every reference debug package and the original tool's injected file.
/// </summary>
public sealed class ProsperoRightSprxTests
{
    private const string ExpectedSha256 = "ACB7D999F31FFC73BBFFF703C7866455A89F35F8A7F4FEEBC152EDF40F707D50";

    [Fact]
    public void Get_ReturnsFixedDebugModule()
    {
        byte[]? module = ProsperoRightSprx.Get();

        Assert.NotNull(module);
        Assert.Equal(ProsperoRightSprx.Size, module!.Length);
        Assert.Equal(ProsperoRightSprx.Magic, System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(module));
        Assert.Equal(ExpectedSha256, Convert.ToHexString(SHA256.HashData(module)));
        Assert.True(ProsperoRightSprx.IsRightSprx(module));
    }

    [Fact]
    public void Get_ReturnsIndependentCopies()
    {
        byte[] first = ProsperoRightSprx.Get()!;
        first[0] = 0;

        Assert.Equal(ProsperoRightSprx.Magic,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(ProsperoRightSprx.Get()!));
    }

    [Fact]
    public void IsRightSprx_RejectsWrongSizeOrMagic()
    {
        Assert.False(ProsperoRightSprx.IsRightSprx([]));
        Assert.False(ProsperoRightSprx.IsRightSprx(new byte[ProsperoRightSprx.Size]));
    }
}
