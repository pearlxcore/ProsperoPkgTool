using System.Buffers.Binary;
using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

public sealed class ProsperoPackageReaderTests
{
    [Fact]
    public void ReadsFinalizedSegmentsAndCntMetadata()
    {
        using var fixture = new PackageFixture();

        ProsperoPackageInspection package = ProsperoPackageReader.Read(fixture.Path);

        Assert.Equal(ProsperoPackageKind.FinalizedDebug, package.Kind);
        Assert.True(package.Structure.IsValid);
        Assert.Equal((ushort)3, package.Fih?.FormatVersion);
        Assert.Equal("UP0000-PPSA12345_00-TESTPACKAGE00000", package.Cnt.ContentId);
        Assert.Equal((uint)12, package.Cnt.EntryCount);
        Assert.Equal((ushort)2, package.Cnt.Version);
        Assert.Equal((ushort)1, package.Cnt.Flags);
        Assert.Equal("playgo-chunk.dat", package.Entries[0].Name);
        Assert.Equal("entry-names", package.Entries[5].DisplayName);
        Assert.Collection(package.Segments,
            segment => Assert.Equal(("FIH", 0L, 0x10000L), (segment.Name, segment.Offset, segment.Size)),
            segment => Assert.Equal(("PFS", 0x10000L, 0x20000L), (segment.Name, segment.Offset, segment.Size)),
            segment => Assert.Equal(("SC", 0x30000L, 0x10000L), (segment.Name, segment.Offset, segment.Size)),
            segment => Assert.Equal(("SI", 0x40000L, 0x100L), (segment.Name, segment.Offset, segment.Size)));
    }

    [Fact]
    public void ReportsUnsupportedFihVersionWithoutReadingOutOfBounds()
    {
        using var fixture = new PackageFixture(formatVersion: 2);

        ProsperoPackageInspection package = ProsperoPackageReader.Read(fixture.Path);

        Assert.False(package.Structure.IsValid);
        Assert.Contains(package.Structure.Issues, issue => issue.Code == "FIH_VERSION" && issue.IsError);
    }

    [Fact]
    public void RejectsUnknownMagic()
    {
        string path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"ProsperoPkgTool-Bad-{Guid.NewGuid():N}.pkg");
        try
        {
            File.WriteAllBytes(path, [1, 2, 3, 4]);
            Assert.Throws<InvalidDataException>(() => ProsperoPackageReader.Read(path));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void ParsesRealSonyPackageGroundTruth()
    {
        // A real Sony-built debug package (content id IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX,
        // passcode 12345678923456789102123901202333) whose CNT header/geometry is verified
        // byte-exact against FINDINGS.md §04. This locks the reader to the true field map,
        // which the synthetic fixture alone cannot (it was originally written to the wrong
        // offsets and would pass for the wrong reasons).
        string path = System.IO.Path.Combine(AppContext.BaseDirectory, "Fixtures", "test.pkg");

        ProsperoPackageInspection package = ProsperoPackageReader.Read(path);

        Assert.Equal(ProsperoPackageKind.FinalizedDebug, package.Kind);
        Assert.True(package.Structure.IsValid, string.Join("; ", package.Structure.Issues.Select(i => $"{i.Code}:{i.Message}")));
        Assert.Equal((ushort)3, package.Fih?.FormatVersion);
        Assert.Equal("IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX", package.Cnt.ContentId);
        Assert.Equal((ushort)2, package.Cnt.Version);
        Assert.Equal((ushort)1, package.Cnt.Flags);
        Assert.Equal((uint)0x0C, package.Cnt.Unk0C);
        Assert.Equal((uint)13, package.Cnt.EntryCount);
        Assert.Equal((ushort)6, package.Cnt.ScEntryCount);
        Assert.Equal((ushort)13, package.Cnt.EntryCount2);
        Assert.Equal((uint)0x3560, package.Cnt.EntryTableOffset);
        Assert.Equal((uint)0x18A0, package.Cnt.MainEntDataSize);
        Assert.Equal((ulong)0x2000, package.Cnt.BodyOffset);
        Assert.Equal((ulong)0x4E000, package.Cnt.BodySize);
        Assert.Equal((uint)0, package.Cnt.DrmType);
        Assert.Equal((uint)0x20, package.Cnt.ContentType);
        Assert.Equal((uint)0x02020000, package.Cnt.ContentFlags);
        Assert.Equal(13, package.Entries.Count);

        // Named entries decode via the entry_names blob (leading NUL sentinel + NUL-separated).
        Assert.Equal("playgo-chunk.dat", package.Entries[7].Name);
        Assert.Equal("icon0.png", package.Entries[8].Name);
        Assert.Equal("icon0.dds", package.Entries[9].Name);
        Assert.Equal("param.json", package.Entries[10].Name);
        Assert.Equal("playgo-hash-table.dat", package.Entries[11].Name);
        Assert.Equal("playgo-ficm.dat", package.Entries[12].Name);

        // Entry-table field map (id, data offset, data size) locked to the real package,
        // confirming the reader's DataOffset@0x10 / DataSize@0x14 placement.
        Assert.Equal((0x00000001u, 0x3700u, 0x01A0u), (package.Entries[0].Id, package.Entries[0].DataOffset, package.Entries[0].DataSize));
        Assert.Equal((0x00000020u, 0x2B80u, 0x0800u), (package.Entries[2].Id, package.Entries[2].DataOffset, package.Entries[2].DataSize));
        Assert.Equal((0x00001001u, 0x3FD0u, 0x01A0u), (package.Entries[7].Id, package.Entries[7].DataOffset, package.Entries[7].DataSize));
        Assert.Equal((0x00001280u, 0xB140u, 0x40094u), (package.Entries[9].Id, package.Entries[9].DataOffset, package.Entries[9].DataSize));
        Assert.Equal((0x00002010u, 0x4B1E0u, 0x0050u), (package.Entries[11].Id, package.Entries[11].DataOffset, package.Entries[11].DataSize));
        Assert.Equal((0x00002011u, 0x4B230u, 0x0016u), (package.Entries[12].Id, package.Entries[12].DataOffset, package.Entries[12].DataSize));

        // Segment geometry: FIH[0,0x10000) PFS[0x10000,0xA0000) SC[0xB0000,0x50000) SI[0x100000,0x33F3).
        Assert.Collection(package.Segments,
            segment => Assert.Equal(("FIH", 0L, 0x10000L), (segment.Name, segment.Offset, segment.Size)),
            segment => Assert.Equal(("PFS", 0x10000L, 0xA0000L), (segment.Name, segment.Offset, segment.Size)),
            segment => Assert.Equal(("SC", 0xB0000L, 0x50000L), (segment.Name, segment.Offset, segment.Size)),
            segment => Assert.Equal(("SI", 0x100000L, 0x33F3L), (segment.Name, segment.Offset, segment.Size)));
    }

    private sealed class PackageFixture : IDisposable
    {
        public PackageFixture(ushort formatVersion = 3)
        {
            Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"ProsperoPkgTool-Fih-{Guid.NewGuid():N}.pkg");
            byte[] image = new byte[0x40100];
            image[0] = 0x7F;
            image[1] = (byte)'F';
            image[2] = (byte)'I';
            image[3] = (byte)'H';
            image[5] = 0;
            BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(0x06, 2), formatVersion);
            BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(0x10, 8), 0x10000);
            BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(0x18, 8), 0x20000);
            BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(0x58, 8), 0x30000);

            Span<byte> cnt = image.AsSpan(0x30000);
            cnt[0] = 0x7F;
            cnt[1] = (byte)'C';
            cnt[2] = (byte)'N';
            cnt[3] = (byte)'T';
            // CNT header field map matches the real format (FINDINGS.md §04):
            // 0x04 u16 version, 0x06 u16 flags, 0x0C u32 constant 0x0C, 0x10 u32 entry count.
            BinaryPrimitives.WriteUInt16BigEndian(cnt.Slice(0x04, 2), 2);
            BinaryPrimitives.WriteUInt16BigEndian(cnt.Slice(0x06, 2), 1);
            BinaryPrimitives.WriteUInt32BigEndian(cnt.Slice(0x0C, 4), 0x0C);
            BinaryPrimitives.WriteUInt32BigEndian(cnt.Slice(0x10, 4), 12);
            BinaryPrimitives.WriteUInt16BigEndian(cnt.Slice(0x14, 2), 6);
            BinaryPrimitives.WriteUInt16BigEndian(cnt.Slice(0x16, 2), 12);
            BinaryPrimitives.WriteUInt32BigEndian(cnt.Slice(0x18, 4), 0x5A0);
            BinaryPrimitives.WriteUInt32BigEndian(cnt.Slice(0x1C, 4), 0x18A0);
            BinaryPrimitives.WriteUInt64BigEndian(cnt.Slice(0x20, 8), 0x2000);
            BinaryPrimitives.WriteUInt64BigEndian(cnt.Slice(0x28, 8), 0x4E0);
            "UP0000-PPSA12345_00-TESTPACKAGE00000"u8.CopyTo(cnt.Slice(0x40, 36));
            BinaryPrimitives.WriteUInt32BigEndian(cnt.Slice(0x70, 4), 0x20);
            BinaryPrimitives.WriteUInt32BigEndian(cnt.Slice(0x74, 4), 0x02020000);
            for (int index = 0; index < 12; index++)
                BinaryPrimitives.WriteUInt32BigEndian(cnt.Slice(0x5A0 + index * 0x20 + 4, 4), uint.MaxValue);
            Span<byte> playGoEntry = cnt.Slice(0x5A0, 0x20);
            BinaryPrimitives.WriteUInt32BigEndian(playGoEntry, 0x00001001);
            BinaryPrimitives.WriteUInt32BigEndian(playGoEntry.Slice(4, 4), 0);
            BinaryPrimitives.WriteUInt32BigEndian(playGoEntry.Slice(0x10, 4), 0x2200);
            BinaryPrimitives.WriteUInt32BigEndian(playGoEntry.Slice(0x14, 4), 1);
            Span<byte> nameEntry = cnt.Slice(0x5A0 + 5 * 0x20, 0x20);
            BinaryPrimitives.WriteUInt32BigEndian(nameEntry, 0x00000200);
            BinaryPrimitives.WriteUInt32BigEndian(nameEntry.Slice(0x10, 4), 0x2100);
            BinaryPrimitives.WriteUInt32BigEndian(nameEntry.Slice(0x14, 4), 0x20);
            "playgo-chunk.dat\0"u8.CopyTo(cnt.Slice(0x2100));
            image[0x40000] = (byte)'P';
            image[0x40001] = (byte)'K';
            image[0x40002] = 0x03;
            image[0x40003] = 0x04;
            File.WriteAllBytes(Path, image);
        }

        public string Path { get; }

        public void Dispose() => File.Delete(Path);
    }
}

public sealed class ProsperoPackageContentTests
{
    private static ProsperoCntEntry Entry(uint flags1, uint dataSize) =>
        new(0x2000, 0, flags1, 0, 0, dataSize, null);

    [Fact]
    public void CntDigestLengths_NonEncryptedEntry_UsesExactSizeOnly()
    {
        Assert.Equal([0x100L], ProsperoPackageContent.CntDigestLengths(Entry(0, 0x100)));
    }

    [Fact]
    public void CntDigestLengths_EncryptedAlignedEntry_UsesExactSizeOnly()
    {
        // 0xA0 is already 16-byte aligned, so the reference-padded length equals the exact size.
        Assert.Equal([0xA0L], ProsperoPackageContent.CntDigestLengths(Entry(0x80000000, 0xA0)));
    }

    [Fact]
    public void CntDigestLengths_EncryptedUnalignedEntry_AcceptsExactThenPadded()
    {
        // A reference writer hashes the 16-byte-padded length; this writer hashes the exact size.
        // Both must be accepted, exact first.
        Assert.Equal([0x402L, 0x410L], ProsperoPackageContent.CntDigestLengths(Entry(0x80000000, 0x402)));
    }

    [Fact]
    public void CntDigestLengths_EncryptedEntry_PaddingRoundsUpNotDown()
    {
        Assert.Equal([0x20L], ProsperoPackageContent.CntDigestLengths(Entry(0x80000000, 0x20)));
        Assert.Equal([0x11L, 0x20L], ProsperoPackageContent.CntDigestLengths(Entry(0x80000000, 0x11)));
    }
}
