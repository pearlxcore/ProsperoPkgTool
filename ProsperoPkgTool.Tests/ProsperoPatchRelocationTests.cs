using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class ProsperoPatchRelocationTests
{
    [Fact]
    public void MaterializeEncryptedVirtualImage_UsesOriginAndGatheredSources()
    {
        string directory = Path.Combine(Path.GetTempPath(), "ProsperoPatchRelocationTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string patchPath = Path.Combine(directory, "patch.pkg");
        string referencePath = Path.Combine(directory, "reference.pkg");
        try
        {
            byte[] patch = Blocks(4, 0x80);
            byte[] reference = Blocks(4, 0x20);
            File.WriteAllBytes(patchPath, patch);
            File.WriteAllBytes(referencePath, reference);
            var tables = new ProsperoPatchRelocation.Tables(
                [uint.MaxValue, 1, uint.MaxValue],
                [0, uint.MaxValue, 2],
                [uint.MaxValue, 1, uint.MaxValue],
                [0, 1, 0x10000002]);

            byte[] actual = ProsperoPatchRelocation.MaterializeEncryptedVirtualImage(patchPath, referencePath, tables);

            Assert.Equal(reference.AsSpan(0x10000, 0x10000).ToArray(), actual.AsSpan(0, 0x10000).ToArray());
            Assert.Equal(patch.AsSpan(0x20000, 0x10000).ToArray(), actual.AsSpan(0x10000, 0x10000).ToArray());
        }
        finally
        {
            if (Directory.Exists(directory))
                Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void MaterializeEncryptedVirtualImage_RejectsAmbiguousSource()
    {
        string file = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(file, new byte[0x20000]);
            var tables = new ProsperoPatchRelocation.Tables(
                [uint.MaxValue, 1], [0, 1], [uint.MaxValue, 1], [0, 1]);
            Assert.Throws<InvalidDataException>(() =>
                ProsperoPatchRelocation.MaterializeEncryptedVirtualImage(file, file, tables));
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static byte[] Blocks(int count, byte seed)
    {
        var result = new byte[count * 0x10000];
        for (int block = 0; block < count; block++)
            result.AsSpan(block * 0x10000, 0x10000).Fill((byte)(seed + block));
        return result;
    }
}
