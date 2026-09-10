using System.Buffers.Binary;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Byte-exact validation of the clean-room outer-PFS builder against the real Sony-built debug
/// package. The fixture's outer PFS is decrypted to plaintext, re-built with the same seed and
/// inode timestamps, and the two plaintext images must be identical byte-for-byte.
/// </summary>
public sealed class ProsperoOuterPfsBuilderTests
{
    private const string ContentId = "IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX";
    private const string Passcode = "12345678923456789102123901202333";

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    [Fact]
    public void DebugPackage_RebuildOuterPfs_MatchesByteExact()
    {
        // ---- Read the fixture's outer image (ciphertext + plaintext superblock). ----
        using var stream = File.OpenRead(Fixture("test.pkg"));
        stream.Position = 0x10;
        Span<byte> fih = stackalloc byte[16];
        stream.ReadExactly(fih);
        long pfsOffset = BitConverter.ToInt64(fih[..8]);
        long pfsSize = BitConverter.ToInt64(fih.Slice(8, 8));

        OuterPfsReader pfs = OuterPfsReader.Open(stream, pfsOffset, pfsSize);
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        (byte[] tweakKey, byte[] dataKey) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
        using var xts = new AesXts(dataKey, tweakKey);

        // Decrypt the whole fixture image to plaintext using the reader's block walk.
        byte[] fixturePlain = DecryptAll(pfs, xts);

        // Read Sony's build parameters from the superblock: seed + inode timestamps.
        // The embedded S64 inode-sig starts at sb+0x50: Time1_sec at +0x18 (= sb+0x68),
        // Time1_nsec at +0x38 (= sb+0x88).
        ReadOnlySpan<byte> sb = pfs.Superblock;
        long tsSec = BinaryPrimitives.ReadInt64LittleEndian(sb[0x68..]);
        uint tsNsec = BinaryPrimitives.ReadUInt32LittleEndian(sb[0x88..]);

        // ---- Rebuild the outer image with our builder. ----
        byte[] naps = pfs.ReadNaps(xts);
        byte[] innerImage = pfs.ReadInnerImage(xts);

        // Pull the real dinode fields from the fixture so the rebuild uses Sony's own values.
        IReadOnlyDictionary<string, OuterFile> files = pfs.EnumerateOuterFiles(xts);
        OuterFile innerFile = files["pfs_image.dat"];
        OuterFile napsFile = files["naps_pkg_layout.dat"];

        // ReadInnerImage returns block-padded data; trim to the stored file size.
        byte[] innerData = innerImage.AsSpan(0, (int)innerFile.Size).ToArray();

        var outerFiles = new List<OuterPfsFile>
        {
            new()
            {
                Name = "pfs_image.dat",
                Data = innerData,
                SizeCompressed = innerFile.SizeCompressed,
                Signed = false,
            },
            new()
            {
                Name = "naps_pkg_layout.dat",
                Data = naps,
                SizeCompressed = napsFile.SizeCompressed,
                Signed = true,
            },
        };

        var parameters = new OuterPfsBuildParameters
        {
            TimestampSeconds = tsSec,
            TimestampNanoseconds = tsNsec,
            Seed = pfs.Seed,
        };

        OuterPfsBuildResult result = ProsperoOuterPfsBuilder.BuildPlaintext(outerFiles, parameters);

        // The fixture image: 4 inner data blocks + 1 naps + 5 metadata = 10 blocks.
        Assert.Equal(fixturePlain.Length, result.Plaintext.Length);
        Assert.Equal(pfs.BlockCount, result.BlockCount);
        Assert.Equal(pfs.SuperblockIndex, result.SuperblockIndex);

        // Byte-exact comparison of the whole plaintext image.
        Assert.Equal(fixturePlain, result.Plaintext);
    }

    private static byte[] DecryptAll(OuterPfsReader pfs, AesXts xts)
    {
        // Build a per-block signed/plain classification from the inode tree.
        bool[] signed = new bool[pfs.BlockCount];
        Array.Fill(signed, true);
        // The superblock is plaintext (reader returns it as-is regardless of the flag).
        signed[pfs.SuperblockIndex] = false;
        foreach (KeyValuePair<string, OuterFile> kv in pfs.EnumerateOuterFiles(xts))
        {
            if (!kv.Value.Signed)
                foreach (int b in kv.Value.BlockIndexes)
                    signed[b] = false;
        }

        byte[] result = new byte[pfs.BlockCount * (int)OuterPfsReader.BlockSize];
        for (int i = 0; i < pfs.BlockCount; i++)
        {
            byte[] plain = pfs.ReadBlock(xts, i, signed[i]);
            plain.CopyTo(result, i * (int)OuterPfsReader.BlockSize);
        }
        return result;
    }
}
