using System.Buffers.Binary;
using System.Reflection;

namespace ProsperoPkgTool.Content;

/// <summary>
/// The fixed PS5 debug <c>sce_sys/about/right.sprx</c> rights module injected into an application
/// package when the source tree does not ship one. Every reference debug package carries the same
/// 12,752-byte fake-signed SELF (magic <c>0xEEF51454</c>), so the bytes are embedded as a resource.
/// </summary>
public static class ProsperoRightSprx
{
    /// <summary>Fixed size of the debug <c>right.sprx</c> module, in bytes.</summary>
    public const int Size = 12752;

    /// <summary>SELF container magic (little-endian) at offset 0 of the module.</summary>
    public const uint Magic = 0xEEF51454;

    private const string ResourceName = "ProsperoPkgTool.Resources.right.sprx";

    /// <summary>
    /// Returns a copy of the embedded debug <c>right.sprx</c>, or <c>null</c> when the resource is
    /// unavailable (for example in a trimmed test host).
    /// </summary>
    public static byte[]? Get()
    {
        using Stream? stream = typeof(ProsperoRightSprx).GetTypeInfo().Assembly
            .GetManifestResourceStream(ResourceName);
        if (stream is null)
            return null;
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        return memory.ToArray();
    }

    /// <summary>Returns whether a buffer is the debug <c>right.sprx</c> module.</summary>
    public static bool IsRightSprx(ReadOnlySpan<byte> data) =>
        data.Length == Size && BinaryPrimitives.ReadUInt32LittleEndian(data) == Magic;
}
