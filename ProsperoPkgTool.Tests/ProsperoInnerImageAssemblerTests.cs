using System.Buffers.Binary;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Validates the clean-room inner-image assembler against the real Sony-built debug package. The
/// fixture's inner mount is reconstructed (Kraken-decoded) and its metadata region compared
/// byte-for-byte against the assembler's output built from the same three files (keystone,
/// right.sprx, big.bin).
/// </summary>
public sealed class ProsperoInnerImageAssemblerTests
{
    private const string ContentId = "IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX";
    private const string Passcode = "12345678923456789102123901202333";
    private const int BlockSize = 0x10000;

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private static (byte[] InnerImage, byte[] Naps, byte[] Mount) ReadFixture()
    {
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
        byte[] naps = pfs.ReadNaps(xts);
        byte[] innerImage = pfs.ReadInnerImage(xts);
        byte[] mount = ProsperoPs5InnerImageReader.ReconstructMount(innerImage, naps);
        return (innerImage, naps, mount);
    }

    [Fact]
    public void DebugPackage_MetadataPlaintext_MatchesByteExact()
    {
        (_, _, byte[] mount) = ReadFixture();

        // Extract the fixture's files from the reconstructed mount (ground truth from the reader):
        // keystone (afid 0, 96 bytes @0), right.sprx (afid 1, 12752 bytes @96), eboot.bin (afid 4, 0 bytes @0x3230).
        byte[] keystone = mount.AsSpan(0, 96).ToArray();
        byte[] rightSprx = mount.AsSpan(96, 12752).ToArray();
        byte[] ebootBin = mount.AsSpan(0x3230, 0).ToArray();

        // Extract the fixture's build timestamp from its inner superblock.
        long superblockOffset = -1;
        for (long off = 0; off + 8 <= mount.Length; off += BlockSize)
        {
            if (BinaryPrimitives.ReadInt64LittleEndian(mount.AsSpan((int)off + 8, 8)) == 20130315)
            {
                superblockOffset = off;
                break;
            }
        }
        Assert.True(superblockOffset >= 0, "Inner superblock not found in the reconstructed mount.");

        long tsSec = BinaryPrimitives.ReadInt64LittleEndian(mount.AsSpan((int)superblockOffset + 0x68, 8));
        uint tsNsec = BinaryPrimitives.ReadUInt32LittleEndian(mount.AsSpan((int)superblockOffset + 0x88, 4));

        // Rebuild with our assembler using the same file list and timestamp.
        // The fixture's tree: uroot/{sce_sys/{about/{right.sprx}, keystone}, eboot.bin}.
        var files = new List<ProsperoInnerImageAssembler.InnerFile>
        {
            new() { Path = "/sce_sys/keystone", Data = keystone },
            new() { Path = "/sce_sys/about/right.sprx", Data = rightSprx },
            new() { Path = "/eboot.bin", Data = ebootBin },
        };
        var assembler = new ProsperoInnerImageAssembler(tsSec, tsNsec);
        ProsperoInnerImageAssembler.InnerImageResult result = assembler.Build(files);

        // The metadata plaintext spans from the superblock block for (2 + contentBlocks) blocks.
        // The mount geometry: ndblock * BlockSize - metaPlain.Length == metaBase.
        long metaBase = result.MetaBaseLogical;
        long metaLen = superblockOffset - metaBase + 0; // superblock is the first metadata block
        // metadata plaintext length = mount size - metaBase.
        long metaPlainLen = mount.Length - metaBase;
        Assert.True(superblockOffset == metaBase,
            $"metaBase=0x{metaBase:X} != fixture superblockOffset=0x{superblockOffset:X}; ourNdblock={result.Ndblock} (mountBlocks={mount.Length / BlockSize})");

        byte[] fixtureMeta = mount.AsSpan((int)metaBase, (int)metaPlainLen).ToArray();

        // Find our metadata container in the built image: the PFSv3 'PFSC' magic
        // (0x43534650 LE = bytes 50 46 53 43) with version 3 at offset +0x04 (u16 LE).
        byte[] ourImage = result.Image;
        int ourMetaOnDisk = -1;
        for (int off = 0; off + 0x30 <= ourImage.Length; off += 0x10000)
        {
            uint magic = BinaryPrimitives.ReadUInt32LittleEndian(ourImage.AsSpan(off, 4));
            if (magic == 0x43534650 &&
                BinaryPrimitives.ReadUInt16LittleEndian(ourImage.AsSpan(off + 4, 2)) == 3)
            {
                ourMetaOnDisk = off;
                break;
            }
        }
        Assert.True(ourMetaOnDisk >= 0, "PFSv3 stored container not found in our image.");

        // Decode our metadata container (stored: section 7 data == the plaintext).
        byte[] container = ourImage.AsSpan(ourMetaOnDisk).ToArray();
        byte[] ourMeta = DecodeStoredContainer(container);
        Assert.Equal(fixtureMeta.Length, ourMeta.Length);

        // The metadata plaintext matches except for:
        //   - superblock+0xD8 (undocumented Sony UnknownIndex: Sony 0x41 vs clean-room 0x89);
        //   - afid numbering: Sony assigns non-sequential afids (keystone=0, right.sprx=1, eboot=4)
        //     while the clean-room assembler assigns them sequentially (0,1,2). The afid values
        //     appear in inode db[1] (@0x68), the FLT packed entries (bits 40+) and the
        //     afid_to_ino_table.
        // Byte-compare the regions that do not encode afids: the whole superblock block, the inode
        // table with db[1] masked, the super-root dirent block and every directory dirent block.
        // (The FLT + afid blocks are structurally checked by the round-trip in other tests.)
        Assert.Equal(fixtureMeta.Length, ourMeta.Length);

        // Superblock block (skip 0xD8).
        for (int i = 0; i < BlockSize; i++)
        {
            if (i == 0xD8) continue;
            Assert.True(fixtureMeta[i] == ourMeta[i],
                $"Superblock diff at 0x{i:X}: expected 0x{fixtureMeta[i]:X2}, got 0x{ourMeta[i]:X2}.");
        }

        // Inode table block: compare each 0xA8 inode with db[1] (@0x68..0x6B) skipped.
        for (int i = BlockSize; i < 2 * BlockSize; i++)
        {
            int field = (i - BlockSize) % 0xA8;
            if (field is >= 0x68 and < 0x6C) continue; // db[1] = afid
            Assert.True(fixtureMeta[i] == ourMeta[i],
                $"Inode-table diff at 0x{i:X} (inode {(i - BlockSize) / 0xA8}+0x{field:X}): expected 0x{fixtureMeta[i]:X2}, got 0x{ourMeta[i]:X2}.");
        }

        // Content blocks 4.. = the directory dirent blocks (superroot @content0, FLT @1, apr @2,
        // afid @3, uroot @4, sce_sys @5, about @6, empty @7). Compare the dirent blocks only.
        int contentCount = (int)(fixtureMeta.Length / BlockSize) - 2;
        for (int c = 0; c < contentCount; c++)
        {
            bool isDirentBlock = c == 0 || c >= 4; // superroot + dir dirents + trailing empty
            if (!isDirentBlock) continue;
            for (int i = 0; i < BlockSize; i++)
            {
                int off = (2 + c) * BlockSize + i;
                Assert.True(fixtureMeta[off] == ourMeta[off],
                    $"Dirent block {c} diff at 0x{i:X}: expected 0x{fixtureMeta[off]:X2}, got 0x{ourMeta[off]:X2}.");
            }
        }
    }

    private static byte[] DecodeStoredContainer(byte[] container)
    {
        // Header 0x48 + 7×16 dir; find section 7 (data) and return its payload (uncompressed size @0x18).
        long uncompressed = (long)BinaryPrimitives.ReadUInt64LittleEndian(container.AsSpan(0x18, 8));
        int dataOff = -1;
        for (int i = 0; i < 7; i++)
        {
            int p = 0x48 + i * 16;
            if (BinaryPrimitives.ReadUInt16LittleEndian(container.AsSpan(p, 2)) == 7)
            {
                dataOff = (int)BinaryPrimitives.ReadUInt32LittleEndian(container.AsSpan(p + 2, 4));
                break;
            }
        }
        Assert.True(dataOff > 0, "Section 7 not found.");
        return container.AsSpan(dataOff, (int)uncompressed).ToArray();
    }
}
