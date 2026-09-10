using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Native;

/// <summary>
/// Clean-room native decryption of a PS5 package's outer PFS image, built entirely on
/// ProsperoPkgTool's own crypto/container primitives (no Sony tools, no third-party GPL
/// code). Given a content id and passcode it derives the EKPFS, locates and verifies the
/// outer superblock, and decrypts the inner image stream. This is the first native reader
/// milestone; full inner-image (Kraken) decoding is a separate milestone.
/// </summary>
public static class CleanRoomDecrypt
{
    public sealed record Result(
        string ContentId,
        string PackageKind,
        int SuperblockIndex,
        int BlockCount,
        string SeedHex,
        bool SuperblockIcvValid,
        bool KeystoneFound,
        long InnerImageLength,
        string? InnerImagePath);

    public static Result DecryptOuter(string packagePath, string passcode, string? outputPath)
    {
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(packagePath);
        if (inspection.Fih is not { } fih)
            throw new InvalidDataException("Package has no FIH header; expected a finalized image.");
        if (inspection.Kind == ProsperoPackageKind.FinalizedPatchDebug)
            throw new InvalidDataException("Patch outer-PFS decryption is disabled until patch PFS/NAPS overlay semantics are verified.");
        string contentId = inspection.Cnt.ContentId;
        if (contentId.Length == 0)
            throw new InvalidDataException("Package CNT has an empty content id.");

        using var stream = File.OpenRead(Path.GetFullPath(packagePath));
        var pfs = OuterPfsReader.Open(stream, checked((long)fih.PfsOffset), checked((long)fih.PfsSize));

        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(contentId, passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);

        bool icvValid = pfs.VerifySuperblockIcv();
        byte[] innerImage = pfs.ReadInnerImage(xts);

        bool keystoneFound = Contains(innerImage, "keystone"u8.ToArray());
        string? written = null;
        if (outputPath is not null)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
            File.WriteAllBytes(outputPath, innerImage);
            written = outputPath;
        }

        return new Result(
            contentId,
            inspection.Kind.ToString(),
            pfs.SuperblockIndex,
            pfs.BlockCount,
            Convert.ToHexString(pfs.Seed).ToLowerInvariant(),
            icvValid,
            keystoneFound,
            innerImage.Length,
            written);
    }

    private static bool Contains(byte[] haystack, byte[] needle)
    {
        for (int i = 0; i + needle.Length <= haystack.Length; i++)
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
                return true;
        return false;
    }
}
