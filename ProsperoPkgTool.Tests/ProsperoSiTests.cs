using System.Buffers.Binary;
using System.Text;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Round-trip and known-answer coverage for the SI (install-metadata) segment builders — the
/// STORED ZIP writer, the CRC-32/CRC-32C reducers, the naps_meta_18/300 builders, and the
/// pfsimage.xml emitter. Ground truth comes from the real Sony-built debug package checked in at
/// <c>Fixtures/test.pkg</c> (SI at offset 0x100000) and the extracted members under
/// <c>Fixtures/si_*.bin</c>.
/// </summary>
public sealed class ProsperoSiTests
{
    private const string ContentId = "IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX";
    private const string Passcode = "12345678923456789102123901202333";
    private const int SiOffset = 0x100000;

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    // ---- CRC known-answer tests -----------------------------------------------------------

    [Fact]
    public void ZipCrc32_Ascii123456789_Is0xCBF43926()
    {
        // Standard PKZIP CRC-32 of the 9-byte ASCII string "123456789" — the canonical KAT.
        byte[] data = Encoding.ASCII.GetBytes("123456789");
        Assert.Equal(0xCBF43926u, ZipCrc32.Compute(data));
    }

    [Fact]
    public void Crc32C_Ascii123456789_Is0xE3069283()
    {
        // CRC-32C (Castagnoli) of "123456789" — the canonical KAT from RFC 3720 §B.4.
        byte[] data = Encoding.ASCII.GetBytes("123456789");
        Assert.Equal(0xE3069283u, ProsperoCrc32C.Compute(data));
    }

    [Fact]
    public void ZipCrc32_Empty_IsZero()
    {
        Assert.Equal(0u, ZipCrc32.Compute([]));
    }

    [Fact]
    public void Crc32C_Empty_IsZero()
    {
        Assert.Equal(0u, ProsperoCrc32C.Compute([]));
    }

    // ---- naps_meta_300 known-answer (fixture ground truth) --------------------------------

    [Fact]
    public void BuildMeta300FromInnerImageSize_MatchesFixtureMember()
    {
        // The fixture's inner-image size (FIH 0xA0) is 0x40000; the meta300 descriptor bytes
        // recovered from the SI are the 48-byte blob in si_meta300.bin. R = 0x40000 − 0x10000
        // = 0x30000, kindId = 0x3E9, last field = 0x10000.
        byte[] expected = File.ReadAllBytes(Fixture("si_meta300.bin"));
        Assert.Equal(48, expected.Length);

        byte[] actual = ProsperoNapsMeta.BuildMeta300FromInnerImageSize(0x40000);
        Assert.Equal(expected, actual);

        // Spot-check the six u64 fields (LE): {0, 0, R, 0x3E9, R, 0x10000}.
        Assert.Equal(0u, BinaryPrimitives.ReadUInt64LittleEndian(actual.AsSpan(0x00, 8)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt64LittleEndian(actual.AsSpan(0x08, 8)));
        Assert.Equal(0x30000u, BinaryPrimitives.ReadUInt64LittleEndian(actual.AsSpan(0x10, 8)));
        Assert.Equal(0x3E9u, BinaryPrimitives.ReadUInt64LittleEndian(actual.AsSpan(0x18, 8)));
        Assert.Equal(0x30000u, BinaryPrimitives.ReadUInt64LittleEndian(actual.AsSpan(0x20, 8)));
        Assert.Equal(0x10000u, BinaryPrimitives.ReadUInt64LittleEndian(actual.AsSpan(0x28, 8)));
    }

    [Fact]
    public void BuildMeta300FromInnerImageSize_TooSmall_Throws()
    {
        // An inner-image size smaller than one 0x10000 block is not a valid nwonly image.
        Assert.Throws<ArgumentOutOfRangeException>(
            () => ProsperoNapsMeta.BuildMeta300FromInnerImageSize(0x100));
    }

    // ---- playgo-chunk.crc known-answer (fixture ground truth) -----------------------------

    [Fact]
    public void BuildChunkCrc_FixtureMountImage_MatchesFixtureMember()
    {
        // The fixture's mount image (without the trailing SI) is [0, 0x100000) of test.pkg.
        // The CRC file in the SI is 16 blocks × LE u32 = 64 bytes.
        byte[] pkg = File.ReadAllBytes(Fixture("test.pkg"));
        byte[] expected = File.ReadAllBytes(Fixture("si_playgo_chunk_crc.bin"));
        Assert.Equal(64, expected.Length);

        byte[] actual = ProsperoSiArchive.BuildChunkCrc(pkg.AsSpan(0, SiOffset));
        Assert.Equal(expected, actual);
    }

    // ---- ZIP writer round-trip -------------------------------------------------------------

    [Fact]
    public void WriteZip_RoundTrips_MemberContents()
    {
        // WriteZip → parse back: contents, names, CRCs, and STORED framing must round-trip.
        byte[] a = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        byte[] b = new byte[100];
        Random.Shared.NextBytes(b);
        byte[] c = Encoding.UTF8.GetBytes("nested/deep/path.txt\n");

        var members = new List<ProsperoSiMember>
        {
            new("common/etc/a.dat", a),
            new("common/etc/b.bin", b),
            new("config/x/y/c.txt", c),
        };
        byte[] zip = ProsperoSiArchive.WriteZip(members);

        // The ZIP must start with the local-file-header signature and end with the EOCD signature.
        Assert.Equal(0x04034b50u, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(0, 4)));
        Assert.Equal(0x06054b50u, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(zip.Length - 22, 4)));

        IReadOnlyList<(string Name, byte[] Content)> parsed = ParseStoredZip(zip);
        Assert.Equal(members.Count, parsed.Count);
        for (int i = 0; i < members.Count; i++)
        {
            Assert.Equal(members[i].Path, parsed[i].Name);
            Assert.Equal(members[i].Content, parsed[i].Content);
        }
    }

    [Fact]
    public void WriteZip_SingleMember_SignaturesAndCrc()
    {
        // Verify the exact STORED framing fields against the documented SI layout.
        byte[] content = Encoding.ASCII.GetBytes("hello\n");
        byte[] zip = ProsperoSiArchive.WriteZip([new ProsperoSiMember("a/b.dat", content)]);

        // Local file header (30 + nameLen + content bytes).
        Assert.Equal(0x04034b50u, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(0, 4)));
        Assert.Equal(20, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(4, 2)));   // version needed
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(6, 2)));   // flags
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(8, 2)));   // method = STORED
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(10, 2)));  // DOS time = 0
        Assert.Equal(0x0021, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(12, 2))); // DOS date
        uint crc = ZipCrc32.Compute(content);
        Assert.Equal(crc, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(14, 4)));
        Assert.Equal((uint)content.Length, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(18, 4))); // comp size
        Assert.Equal((uint)content.Length, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(22, 4))); // uncomp size
        Assert.Equal(7, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(26, 2)));  // name len ("a/b.dat")
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(28, 2)));  // extra len

        // Central-directory entry after the local member.
        int cdOff = 30 + 7 + content.Length;
        Assert.Equal(0x02014b50u, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(cdOff, 4)));
        Assert.Equal(0, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(cdOff + 4, 2))); // version made by = 0
        Assert.Equal(20, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(cdOff + 6, 2)));
        Assert.Equal(crc, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(cdOff + 16, 4)));

        // EOCD record at the tail.
        int eocd = cdOff + 46 + 7;
        Assert.Equal(0x06054b50u, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(eocd, 4)));
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(eocd + 8, 2)));  // entries on disk
        Assert.Equal(1, BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(eocd + 10, 2))); // total entries
    }

    [Fact]
    public void WriteZip_EmptyMemberSet_ProducesEmptyArchive()
    {
        // A zero-member ZIP is the EOCD record only (22 bytes).
        byte[] zip = ProsperoSiArchive.WriteZip(Array.Empty<ProsperoSiMember>());
        Assert.Equal(22, zip.Length);
        Assert.Equal(0x06054b50u, BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(0, 4)));
    }

    // ---- fixture SI ZIP framing round-trip ------------------------------------------------

    [Fact]
    public void FixtureSiZip_StoredZipCrcs_MatchStoredValues()
    {
        // For every member of the fixture SI ZIP, ZipCrc32 over the extracted content must equal
        // the stored CRC in the ZIP header (this is the property the console's SI walker enforces).
        byte[] pkg = File.ReadAllBytes(Fixture("test.pkg"));
        byte[] si = pkg.AsSpan(SiOffset).ToArray();
        IReadOnlyList<(string Name, byte[] Content, uint StoredCrc)> members = ParseStoredZipWithCrc(si);

        // The fixture carries the canonical 8-member set.
        Assert.Equal(8, members.Count);
        Assert.Equal("common/etc/naps_meta_18.dat", members[0].Name);
        Assert.Equal("common/etc/naps_meta_300.dat", members[1].Name);
        Assert.Equal("common/etc/naps_meta_301.dat", members[2].Name);
        Assert.Equal("common/etc/naps_meta_302.dat", members[3].Name);
        Assert.Equal("common/etc/naps_meta_308.dat", members[4].Name);
        Assert.Equal("common/etc/pfsimage.xml", members[5].Name);
        Assert.Equal("common/etc/playgo-chunk.dat", members[6].Name);
        Assert.Equal($"config/{ContentId}/playgo-chunk.crc", members[7].Name);

        foreach ((string _, byte[] content, uint storedCrc) in members)
        {
            uint actual = ZipCrc32.Compute(content);
            Assert.Equal(storedCrc, actual);
        }

        // The four meta300 descriptors are identical 48-byte blobs (crc 0xB16AF1F2).
        uint meta300Crc = ZipCrc32.Compute(members[1].Content);
        Assert.Equal(0xB16AF1F2u, meta300Crc);
        Assert.Equal(meta300Crc, ZipCrc32.Compute(members[2].Content));
        Assert.Equal(meta300Crc, ZipCrc32.Compute(members[3].Content));
        Assert.Equal(meta300Crc, ZipCrc32.Compute(members[4].Content));

        // The remaining known CRCs.
        Assert.Equal(0xB6041196u, ZipCrc32.Compute(members[0].Content)); // naps_meta_18
        Assert.Equal(0x55789BD4u, ZipCrc32.Compute(members[5].Content)); // pfsimage.xml
        Assert.Equal(0x0B8FBF9Du, ZipCrc32.Compute(members[6].Content)); // playgo-chunk.dat
        Assert.Equal(0x038A1DE0u, ZipCrc32.Compute(members[7].Content)); // playgo-chunk.crc
    }

    // ---- naps_meta_18 self-consistency ----------------------------------------------------

    [Fact]
    public void BuildMeta18_Decrypt_RoundTrips_TagSequence()
    {
        // Build → encrypt → decrypt must yield a TLV plaintext whose tag sequence and key fields
        // match the documented record set. Uses a synthetic 2-block inner image + 0x10000-byte
        // mount image so the test is independent of the fixture.
        ulong innerImageSize = 0x20000;
        byte[] mountImage = new byte[0x20000];
        // Plant a plaintext superblock at block 1 so rhsh/LocateSuperblock succeed.
        BinaryPrimitives.WriteUInt64LittleEndian(mountImage.AsSpan(0x10000, 8), 2);
        mountImage[0x10008] = 0x0B; mountImage[0x10009] = 0x2A;
        mountImage[0x1000A] = 0x33; mountImage[0x1000B] = 0x01;

        var contentFiles = new List<(string, long)> { ("sce_sys/keystone", 96) };
        byte[] blob = ProsperoNapsMeta.BuildMeta18WithMetadataEntry(
            innerImageSize, mountImage, contentFiles, pfsImageSize: 0x10000);

        // The encrypted blob is a multiple of 16 bytes and non-empty.
        Assert.True(blob.Length > 0);
        Assert.Equal(0, blob.Length % 16);

        byte[] plain = ProsperoNapsMeta.DecryptMeta18(blob);
        Assert.Equal(blob.Length, plain.Length);

        // Walk the TLV records and collect their tags; verify the documented order.
        List<(string Tag, long Len, byte[] Payload)> records = ParseTlv(plain);
        List<string> tags = records.Select(r => r.Tag).ToList();
        Assert.Contains("phdr", tags);
        Assert.Contains("file", tags);
        Assert.Contains("ibcl", tags);
        Assert.Contains("i2ob", tags);
        Assert.Contains("i2op", tags);
        Assert.Contains("ihsh", tags);
        Assert.Contains("rhsh", tags);
        Assert.Contains("fstr", tags);
        Assert.Contains("twek", tags);
        Assert.Contains("obdg", tags);
        Assert.Contains("pgpl", tags);
        Assert.Contains("pgil", tags);
        Assert.Contains("pgpi", tags);
        Assert.Contains("pgpu", tags);

        // phdr u32s = [1, 0x30, innerBlocks, innerImageSize, 1, blockSize].
        (string _, long _, byte[] phdr) = records.First(r => r.Tag == "phdr");
        Assert.Equal(0x18, phdr.Length);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x00, 4)));
        Assert.Equal(0x30u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x04, 4)));
        Assert.Equal(2u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x08, 4))); // 0x20000/0x10000
        Assert.Equal(0x20000u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x0C, 4)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x10, 4)));
        Assert.Equal(0x10000u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x14, 4)));

        // twek = [0, 4, 0, 0, 0] (five u32s, only the second is non-zero).
        (string _, long _, byte[] twek) = records.First(r => r.Tag == "twek");
        Assert.Equal(0x14, twek.Length);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x00, 4)));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x04, 4)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x08, 4)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x0C, 4)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x10, 4)));

        // pgpl/pgil/pgpi/pgpu are identical and equal BuildMeta300FromInnerImageSize.
        byte[] expectedDesc = ProsperoNapsMeta.BuildMeta300FromInnerImageSize(innerImageSize);
        foreach (string tag in new[] { "pgpl", "pgil", "pgpi", "pgpu" })
        {
            (string _, long _, byte[] p) = records.First(r => r.Tag == tag);
            Assert.Equal(expectedDesc, p);
        }

        // fstr content = "sce_sys/keystone\0*PFSmetadata\0" (the metadata pseudo-entry is appended
        // by BuildMeta18WithMetadataEntry to the caller's content-file list).
        (string _, long _, byte[] fstr) = records.First(r => r.Tag == "fstr");
        Assert.Equal("sce_sys/keystone\0*PFSmetadata\0", Encoding.ASCII.GetString(fstr));
    }

    [Fact]
    public void DecryptMeta18_Fixture_TlvRecords_MatchDocumentedStructure()
    {
        // Decrypt the fixture's naps_meta_18 blob and verify the record structure matches the
        // ground-truth analysis. ihsh is keyed (SHA3 of on-disk bytes with an off-console key the
        // console derives), so its per-block digests cannot be reproduced; only the structural
        // fields and the unkeyed records are asserted.
        byte[] encrypted = File.ReadAllBytes(Fixture("si_meta18.bin"));
        Assert.Equal(3088, encrypted.Length);

        byte[] plain = ProsperoNapsMeta.DecryptMeta18(encrypted);
        Assert.Equal(encrypted.Length, plain.Length);

        List<(string Tag, long Len, byte[] Payload)> records = ParseTlv(plain);

        // The fixture's record order matches the reference builder's order.
        string[] expectedOrder =
        [
            "phdr", "file", "ibcl", "i2ob", "i2op", "ihsh", "rhsh", "fstr",
            "twek", "obdg", "pgpl", "pgil", "pgpi", "pgpu"
        ];
        // The trailing pad record is not present in the fixture (Sony aligned without it); our
        // reference implementation always writes one. Compare the records that ARE present in
        // fixture order against the documented prefix.
        Assert.True(records.Count >= expectedOrder.Length);
        for (int i = 0; i < expectedOrder.Length; i++)
            Assert.Equal(expectedOrder[i], records[i].Tag);

        // phdr u32s = [1, 0x30, 4, 0x40000, 1, 0x10000] (the fixture's inner-image size = 0x40000).
        (string _, long _, byte[] phdr) = records[0];
        Assert.Equal(0x18, phdr.Length);
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x00, 4)));
        Assert.Equal(0x30u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x04, 4)));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x08, 4)));
        Assert.Equal(0x40000u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x0C, 4)));
        Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x10, 4)));
        Assert.Equal(0x10000u, BinaryPrimitives.ReadUInt32LittleEndian(phdr.AsSpan(0x14, 4)));

        // twek u32s = [0, 4, 0, 0, 0].
        (string _, long _, byte[] twek) = records.First(r => r.Tag == "twek");
        Assert.Equal(0x14, twek.Length);
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x00, 4)));
        Assert.Equal(4u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x04, 4)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x08, 4)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x0C, 4)));
        Assert.Equal(0u, BinaryPrimitives.ReadUInt32LittleEndian(twek.AsSpan(0x10, 4)));

        // fstr = "sce_sys/keystone\0sce_sys/about/right.sprx\0*PFSmetadata\0".
        (string _, long _, byte[] fstr) = records.First(r => r.Tag == "fstr");
        Assert.Equal("sce_sys/keystone\0sce_sys/about/right.sprx\0*PFSmetadata\0",
            Encoding.ASCII.GetString(fstr));

        // pgpl/pgil/pgpi/pgpu all equal BuildMeta300FromInnerImageSize(0x40000).
        byte[] expectedDesc = ProsperoNapsMeta.BuildMeta300FromInnerImageSize(0x40000);
        foreach (string tag in new[] { "pgpl", "pgil", "pgpi", "pgpu" })
        {
            (string _, long _, byte[] p) = records.First(r => r.Tag == tag);
            Assert.Equal(expectedDesc, p);
        }
    }

    // ---- pfsimage.xml emission ------------------------------------------------------------

    [Fact]
    public void BuildPfsImageXml_EmitsRequiredSections()
    {
        var options = new ProsperoPfsImageXmlOptions
        {
            ContentId = ContentId,
            TitleName = "Test App",
            ContentVersion = "01.000.000",
            PackageSize = 0x100000,
            PfsImageSize = 0xA0000,
            ContainerSize = 0x50000,
            MandatorySize = 0x3E90,
            BodyOffset = 0x2000,
            Entries = [new ProsperoPfsImageEntry("param.json", 0x3900, 0x58F)],
        };

        string xml = ProsperoSiArchive.BuildPfsImageXml(options);
        Assert.Contains("<package-configuration version=\"1.0\" type=\"package-info\">", xml);
        Assert.Contains("<content-id>IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX</content-id>", xml);
        Assert.Contains("<titleName>Test App</titleName>", xml);
        Assert.Contains("<package-size>1048576</package-size>", xml);
        Assert.Contains("<digests version=\"1.2\" major-param-version=\"0\">", xml);
        Assert.Contains("<content-digest>", xml);
        Assert.Contains("<game-digest>", xml);
        Assert.Contains("<header-digest>", xml);
        Assert.Contains("<system-digest>", xml);
        Assert.Contains("<param-digest>", xml);
        Assert.Contains("<package-digest>", xml);
        Assert.Contains("<container nth-of-image=\"1\">", xml);
        Assert.Contains("<container-size>0x0000000000050000</container-size>", xml);
        Assert.Contains("<mount-image nth-of-image=\"1\" nested-image=\"yes\">", xml);
        Assert.Contains("<pfs-image-offset>0x0000000000010000</pfs-image-offset>", xml);
        Assert.Contains("<pfs-image-size>0x00000000000a0000</pfs-image-size>", xml);
        Assert.Contains("<fixed-info-size>0x00010000</fixed-info-size>", xml);
        Assert.Contains("<entries nth-of-image=\"1\" num=\"1\">", xml);
        Assert.Contains("name=\"param.json\"", xml);
        Assert.Contains("</package-configuration>", xml);
    }

    // ---- end-to-end img_create appends an SI segment readable by the package reader --------

    [Fact]
    public async Task ImgCreate_AppendsSi_ReadableByPackageReader()
    {
        using var fixture = new SourceFixture();
        byte[] eboot = [0x7F, (byte)'E', (byte)'L', (byte)'F', 0x02, 0x01, 0x01, 0x00];
        File.WriteAllBytes(Path.Combine(fixture.Root, "eboot.bin"), eboot);
        Directory.CreateDirectory(Path.Combine(fixture.Root, "sce_sys", "about"));
        byte[] sprx = Enumerable.Range(0, 256).Select(i => (byte)(i * 7)).ToArray();
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "about", "right.sprx"), sprx);

        string output = Path.Combine(fixture.Root, "out.pkg");
        int result = await CliApplication.RunAsync(
            ["img_create", fixture.Root, "--out", output, "--passcode", Passcode]);
        Assert.Equal(0, result);

        // The package reader detects and accepts the trailing SI segment.
        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(output);
        Assert.Equal(ProsperoPackageKind.FinalizedDebug, inspection.Kind);

        ProsperoPackageSegment? si = inspection.Segments.FirstOrDefault(s => s.Name == "SI");
        Assert.NotNull(si);
        Assert.True(si!.Size >= 22, "SI segment must be at least a 22-byte empty ZIP.");

        // The SI begins with a ZIP local-file-header signature.
        using var stream = File.OpenRead(output);
        byte[] sig = new byte[4];
        stream.Position = si.Offset;
        stream.ReadExactly(sig);
        Assert.Equal((byte)'P', sig[0]);
        Assert.Equal((byte)'K', sig[1]);
        Assert.Equal(0x03, sig[2]);
        Assert.Equal(0x04, sig[3]);

        // The members written by the builder must all be STORED and CRC-valid.
        byte[] pkg = File.ReadAllBytes(output);
        byte[] siBytes = pkg.AsSpan((int)si.Offset, (int)si.Size).ToArray();
        IReadOnlyList<(string Name, byte[] Content, uint StoredCrc)> members = ParseStoredZipWithCrc(siBytes);
        Assert.NotEmpty(members);
        // The reference engine omits common/etc/pfsimage.xml from the debug SI; the builder follows
        // that canonical member set.
        Assert.DoesNotContain(members, m => m.Name == "common/etc/pfsimage.xml");
        Assert.Contains(members, m => m.Name == "common/etc/naps_meta_18.dat");
        Assert.Contains(members, m => m.Name == "common/etc/playgo-chunk.dat");
        Assert.Contains(members, m => m.Name == $"config/{ContentId}/playgo-chunk.crc");
        foreach ((string _, byte[] content, uint storedCrc) in members)
            Assert.Equal(storedCrc, ZipCrc32.Compute(content));
    }

    // ---- helpers --------------------------------------------------------------------------

    /// <summary>
    /// Minimal STORED-ZIP parser: returns (name, content) for each member. Assumes the canonical
    /// SI framing (no extras, STORED, madeBy=0); used only for round-trip tests on our own output.
    /// </summary>
    private static IReadOnlyList<(string Name, byte[] Content)> ParseStoredZip(byte[] zip)
    {
        var result = new List<(string, byte[])>();
        int p = 0;
        while (p + 4 <= zip.Length)
        {
            uint sig = BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(p, 4));
            if (sig == 0x06054b50u)
                break; // EOCD
            if (sig != 0x04034b50u)
                break; // not a local file header

            int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(p + 26, 2));
            int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(p + 28, 2));
            int compLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(p + 18, 4));
            string name = Encoding.ASCII.GetString(zip.AsSpan(p + 30, nameLen));
            int dataStart = p + 30 + nameLen + extraLen;
            byte[] content = zip.AsSpan(dataStart, compLen).ToArray();
            result.Add((name, content));
            p = dataStart + compLen;
        }
        return result;
    }

    /// <summary>STORED-ZIP parser that also returns the stored CRC per member.</summary>
    private static IReadOnlyList<(string Name, byte[] Content, uint StoredCrc)> ParseStoredZipWithCrc(byte[] zip)
    {
        var result = new List<(string, byte[], uint)>();
        int p = 0;
        while (p + 4 <= zip.Length)
        {
            uint sig = BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(p, 4));
            if (sig == 0x06054b50u || sig != 0x04034b50u)
                break;

            uint crc = BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(p + 14, 4));
            int compLen = (int)BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan(p + 18, 4));
            int nameLen = BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(p + 26, 2));
            int extraLen = BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(p + 28, 2));
            string name = Encoding.ASCII.GetString(zip.AsSpan(p + 30, nameLen));
            int dataStart = p + 30 + nameLen + extraLen;
            byte[] content = zip.AsSpan(dataStart, compLen).ToArray();
            result.Add((name, content, crc));
            p = dataStart + compLen;
        }
        return result;
    }

    /// <summary>Parses the naps_meta_18 TLV plaintext into (tag, length, payload) records.</summary>
    private static List<(string Tag, long Len, byte[] Payload)> ParseTlv(byte[] plain)
    {
        var records = new List<(string, long, byte[])>();
        int p = 0;
        while (p + 16 <= plain.Length)
        {
            // Tag is stored reversed.
            char t0 = (char)plain[p + 3];
            char t1 = (char)plain[p + 2];
            char t2 = (char)plain[p + 1];
            char t3 = (char)plain[p];
            string tag = $"{t0}{t1}{t2}{t3}";
            // Version + 3 zero bytes follow, then u64 LE length.
            long len = (long)BinaryPrimitives.ReadUInt64LittleEndian(plain.AsSpan(p + 8, 8));
            if (len < 0 || p + 16 + len > plain.Length)
                break;
            byte[] payload = plain.AsSpan(p + 16, (int)len).ToArray();
            records.Add((tag, len, payload));
            p += 16 + (int)len;
        }
        return records;
    }

    private sealed class SourceFixture : IDisposable
    {
        public SourceFixture()
        {
            Root = Path.Combine(Path.GetTempPath(), "ProsperoPkgTool-SiTests-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path.Combine(Root, "sce_sys"));
            File.WriteAllBytes(Path.Combine(Root, "eboot.bin"), [0x7F, (byte)'E', (byte)'L', (byte)'F']);
            File.WriteAllBytes(Path.Combine(Root, "sce_sys", "icon0.png"), [0x89, (byte)'P', (byte)'N', (byte)'G']);
            File.WriteAllText(Path.Combine(Root, "sce_sys", "param.json"), $$"""
                {
                  "titleId": "PPSX40000",
                  "contentId": "{{ContentId}}",
                  "contentVersion": "01.000.000",
                  "applicationCategoryType": 0,
                  "pubtools": { "creationDate": "2026-08-25 12:00:00" }
                }
                """);
        }

        public string Root { get; }

        public void Dispose()
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }
}
