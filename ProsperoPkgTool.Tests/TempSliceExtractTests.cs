using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>Temporary investigation harness: extract targeted 64 KiB pfs_image.dat data
/// blocks for byte-level inspection of the compressed framing. Not a permanent test.</summary>
public sealed class TempSliceExtractTests
{
    private const string PackagePath = @"C:\Users\User\Desktop\New folder\ps5 pkg\PPSA03530-bd-nw.pkg";
    private const string ContentId = "UP1004-PPSA03530_00-GTAVICECITY00001";
    private const string Passcode = "00000000000000000000000000000000";
    private const string OutDir = @"C:\Users\User\AppData\Local\Temp\opencode\slices";

    [Fact(Skip = "Manual reverse-engineering extraction harness; requires a local retail package and writes user-local output.")]
    public void Extract_TargetDataBlocks()
    {
        Directory.CreateDirectory(OutDir);

        using var stream = File.OpenRead(PackagePath);
        stream.Position = 0x10;
        Span<byte> fih = stackalloc byte[16];
        stream.ReadExactly(fih);
        long pfsOffset = BitConverter.ToInt64(fih[..8]);
        long pfsSize = BitConverter.ToInt64(fih.Slice(8, 8));

        var pfs = OuterPfsReader.Open(stream, pfsOffset, pfsSize);
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);

        // Blocks 0-3 and 16-19 contain the genuinely-compressed cbi[6..31] entries.
        foreach (int block in new[] { 0, 1, 2, 3, 16, 17, 18, 19 })
        {
            byte[] data = pfs.ReadInnerImageBlock(xts, block);
            File.WriteAllBytes(Path.Combine(OutDir, $"block_{block:D3}.bin"), data);
        }
    }
}
