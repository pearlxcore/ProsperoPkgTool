using System.Buffers.Binary;
using System.Security.Cryptography;
using ProsperoPkgTool.Content;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Coverage for the clean-room UCP archive reader/writer/digest-repair used by the trophy2/uds
/// <c>.ucp</c> entries. The byte-parity fixture was produced by the reference engine
/// (<c>LibProsperoPkg 1.2.0</c>) as a black box for the same logical entry set.
/// </summary>
public sealed class ProsperoUcpArchiveTests
{
    // LibProsperoPkg 1.2.0 ProsperoUcp.Build for:
    //   TROPCONF.UTF8 = "<conf>hello world</conf>"
    //   TROPUSR.DAT   = empty
    //   trophy00.trp  = 0x00..0x63
    //   zzz.bin       = DE AD BE EF 00 11 22
    private const string ReferenceUcpHex =
        "b228c60a000000010000000000000210000000040000004000000000d8379fb87a44f5ffbdd843072705beb269951e83" +
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
        "54524f50434f4e462e555446380000000000000000000000000000000000000000000000000001600000000000000018" +
        "0000000000000000000000000000000054524f505553522e444154000000000000000000000000000000000000000000" +
        "000000000000018000000000000000000000000000000000000000000000000074726f70687930302e74727000000000" +
        "000000000000000000000000000000000000000000000190000000000000006400000000000000000000000000000000" +
        "7a7a7a2e62696e0000000000000000000000000000000000000000000000000000000000000002000000000000000007" +
        "000000000000000000000000000000003c636f6e663e68656c6c6f20776f726c643c2f636f6e663e0000000000000000" +
        "00000000000000000000000000000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f" +
        "505152535455565758595a5b5c5d5e5f60616263000000000000000000000000deadbeef001122000000000000000000";

    private static ProsperoUcpArchive.Entry[] SampleEntries() =>
    [
        new("trophy00.trp", Enumerable.Range(0, 100).Select(i => (byte)i).ToArray()),
        new("TROPCONF.UTF8", System.Text.Encoding.ASCII.GetBytes("<conf>hello world</conf>")),
        new("TROPUSR.DAT", []),
        new("zzz.bin", [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22]),
    ];

    [Fact]
    public void Build_MatchesReferenceEngineByteForByte()
    {
        byte[] expected = Convert.FromHexString(ReferenceUcpHex);
        byte[] actual = ProsperoUcpArchive.Build(SampleEntries());

        Assert.Equal(expected, actual);
        Assert.Equal(0xB228C60Au, BinaryPrimitives.ReadUInt32BigEndian(actual));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(actual.AsSpan(4)));
        Assert.Equal((ulong)actual.Length, BinaryPrimitives.ReadUInt64BigEndian(actual.AsSpan(8)));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32BigEndian(actual.AsSpan(16)));
        Assert.Equal(0x40u, BinaryPrimitives.ReadUInt32BigEndian(actual.AsSpan(20)));
    }

    [Fact]
    public void Read_ReturnsEntriesOrderedByName()
    {
        byte[] archive = ProsperoUcpArchive.Build(SampleEntries());
        IReadOnlyList<ProsperoUcpArchive.Entry> entries = ProsperoUcpArchive.Read(archive);

        Assert.Equal(["TROPCONF.UTF8", "TROPUSR.DAT", "trophy00.trp", "zzz.bin"],
            entries.Select(e => e.Name));
        Assert.Equal(24, entries[0].Data.Length);
        Assert.Empty(entries[1].Data);
        Assert.Equal(100, entries[2].Data.Length);
        Assert.Equal([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22], entries[3].Data);
    }

    [Fact]
    public void Digest_IsSha1OverFileWithDigestFieldZeroed()
    {
        byte[] archive = ProsperoUcpArchive.Build(SampleEntries());
        byte[] clone = (byte[])archive.Clone();
        Array.Clear(clone, 0x1C, 20);

        Assert.Equal(SHA1.HashData(clone), archive.AsSpan(0x1C, 20).ToArray());
        Assert.True(ProsperoUcpArchive.VerifyDigest(archive));
    }

    [Fact]
    public void RepairIfNeeded_FixesTamperedBlob()
    {
        byte[] archive = ProsperoUcpArchive.Build(SampleEntries());
        byte[] tampered = (byte[])archive.Clone();
        tampered[^1] ^= 0xFF; // last blob byte

        Assert.False(ProsperoUcpArchive.VerifyDigest(tampered));
        byte[] repaired = ProsperoUcpArchive.RepairIfNeeded(tampered);

        Assert.NotSame(tampered, repaired);
        Assert.True(ProsperoUcpArchive.VerifyDigest(repaired));
        // Repair touches only the digest field.
        Assert.Equal(tampered.AsSpan(0, 0x1C).ToArray(), repaired.AsSpan(0, 0x1C).ToArray());
        Assert.Equal(tampered.AsSpan(0x30).ToArray(), repaired.AsSpan(0x30).ToArray());
    }

    [Fact]
    public void RepairIfNeeded_FixesTamperedDigestAndKeepsValidUnchanged()
    {
        byte[] archive = ProsperoUcpArchive.Build(SampleEntries());
        byte[] badDigest = (byte[])archive.Clone();
        badDigest[0x1C] ^= 0x01;

        Assert.True(ProsperoUcpArchive.VerifyDigest(ProsperoUcpArchive.RepairIfNeeded(badDigest)));
        Assert.Same(archive, ProsperoUcpArchive.RepairIfNeeded(archive));
    }

    [Fact]
    public void IsUcp_RejectsGarbageAndShortBuffers()
    {
        Assert.False(ProsperoUcpArchive.IsUcp([]));
        Assert.False(ProsperoUcpArchive.IsUcp(new byte[128]));
        Assert.False(ProsperoUcpArchive.VerifyDigest(new byte[128]));
        Assert.Throws<InvalidDataException>(() => ProsperoUcpArchive.WithRepairedDigest(new byte[128]));
    }

    [Theory]
    [InlineData("trophy2/trophy00.ucp", true)]
    [InlineData("uds/uds00.ucp", true)]
    [InlineData("trophy2/trophy01.UCP", true)]
    [InlineData("trophy2/trophy00.trp", false)]
    [InlineData("about/right.sprx", false)]
    [InlineData("icon0.png", false)]
    public void IsRepairableSceSysPath_MatchesOnlyTrophyAndUdsUcp(string path, bool expected) =>
        Assert.Equal(expected, ProsperoUcpArchive.IsRepairableSceSysPath(path));
}
