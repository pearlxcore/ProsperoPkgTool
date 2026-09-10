using System.Buffers.Binary;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Validates the clean-room CNT builder against the real Sony-built debug package. The RSA-wrapped
/// key entries use fresh random padding per call (matching the reference), so those payloads are not
/// byte-reproducible; this test locks the structural layer: the entry table (ids, offsets, sizes),
/// the body layout, and the header's geometry fields.
/// </summary>
public sealed class ProsperoCntBuilderTests
{
    private const string ContentId = "IV9999-PPSX40000_00-XXXXXXXXXXXXXXXX";
    private const string Passcode = "12345678923456789102123901202333";

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    // The fixture's CNT region starts at pkg offset 0xB0000.
    private const int FixtureCntBase = 0xB0000;

    private static byte[] ReadFixtureCntRegion(int offset, int size)
    {
        byte[] pkg = File.ReadAllBytes(Fixture("test.pkg"));
        byte[] buf = new byte[size];
        Buffer.BlockCopy(pkg, FixtureCntBase + offset, buf, 0, size);
        return buf;
    }

    private static string Hex(byte[] d) => Convert.ToHexString(d).ToLowerInvariant();

    [Fact]
    public void RsaKeys_AreAvailableAndWellFormed()
    {
        Assert.True(ProsperoRsaKeys.IsAvailable);

        // Seven passcode moduli + mount-image + metadata, all 384 bytes.
        Assert.Equal(7 * 384, ProsperoRsaKeys.PasscodeBlob.Length);
        Assert.Equal(384, ProsperoRsaKeys.MountImageModulus.Length);
        Assert.Equal(384, ProsperoRsaKeys.MetadataModulus.Length);

        // The published PKG-metadata modulus fingerprint (first 16 bytes).
        Assert.Equal(
            "AB1DBD4339493316A35C404E2C2297B8",
            Convert.ToHexString(ProsperoRsaKeys.MetadataModulus[..16]));
    }

    [Fact]
    public void EntryKeys_HasExactSize()
    {
        byte[] entry = ProsperoRsaKeys.BuildEntryKeysEntry(ContentId, Passcode);
        Assert.Equal(2944, entry.Length); // 32 seed + 7×32 digests + 7×384 wrapped keys
    }

    [Fact]
    public void ImageKey_HasExactSize()
    {
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        byte[] entry = ProsperoRsaKeys.BuildImageKeyEntry(ekpfs);
        Assert.Equal(0x800, entry.Length);
    }

    [Fact]
    public void Build_ProducesValidHeaderAndEntryTable()
    {
        // Minimal entry set: the six SC entries + param.json + imagedigs + playgo descriptors.
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        List<ProsperoCntBuilder.Entry> entries = ProsperoCntBuilder.BuildStandardEntries(ContentId, Passcode, ekpfs);

        byte[] paramJson = "{}"u8.ToArray();
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.ParamJson, Name = "param.json", Data = paramJson,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.ParamJson),
        });

        byte[] imagedigs = new byte[10 * 32];
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.Imagedigs, Name = null, Data = imagedigs,
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.Imagedigs),
        });

        var parameters = new CntBuildParameters { ContentId = ContentId, Passcode = Passcode };
        byte[] image = new byte[10 * 0x10000];
        byte[] seed = new byte[16];
        byte[] imageDigest = new byte[32];

        byte[] cnt = ProsperoCntBuilder.Build(entries, parameters, image, seed, imageDigest);

        // Header geometry.
        Assert.True(cnt.Length >= 0x1000 + 384);
        Assert.Equal((byte)0x7F, cnt[0]);
        Assert.Equal((byte)'C', cnt[1]);
        Assert.Equal((byte)'N', cnt[2]);
        Assert.Equal((byte)'T', cnt[3]);
        Assert.Equal(2, BinaryPrimitives.ReadUInt16BigEndian(cnt.AsSpan(0x04, 2)));     // version
        Assert.Equal(1, BinaryPrimitives.ReadUInt16BigEndian(cnt.AsSpan(0x06, 2)));     // flags
        Assert.Equal(0x0Cu, BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x0C, 4))); // constant
        Assert.Equal((uint)entries.Count, BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x10, 4)));
        Assert.Equal((ulong)0x2000, BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x20, 8))); // body offset
        ulong bodySize = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x28, 8));
        // body_offset + body_size is block-aligned (the PFS image starts on a 0x10000 boundary).
        Assert.Equal(0UL, (0x2000UL + bodySize) % 0x10000);
        ulong pfsImageOffset = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x410, 8));
        Assert.Equal(0x10000UL, pfsImageOffset);                                        // FIH-relative
        ulong pfsImageSize = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x418, 8));
        Assert.Equal((ulong)image.Length, pfsImageSize);

        // The container holds the body, then the image.
        Assert.Equal(0x2000 + (long)bodySize + image.Length, cnt.Length);

        // Entry table: ids are sorted, offsets 16-byte aligned, and inside the body.
        uint entryCount = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x10, 4));
        uint tableOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x18, 4));
        uint prevId = 0;
        for (int i = 0; i < entryCount; i++)
        {
            ReadOnlySpan<byte> row = cnt.AsSpan((int)tableOffset + i * 32, 32);
            uint id = BinaryPrimitives.ReadUInt32BigEndian(row);
            uint flags1 = BinaryPrimitives.ReadUInt32BigEndian(row[8..]);
            uint dataOffset = BinaryPrimitives.ReadUInt32BigEndian(row[16..]);
            uint dataSize = BinaryPrimitives.ReadUInt32BigEndian(row[20..]);
            Assert.True(id > prevId, "entry ids must be sorted ascending");
            prevId = id;
            Assert.True(dataOffset >= 0x2000);
            Assert.Equal(0u, dataOffset % 16);
            Assert.True(dataOffset + dataSize <= 0x2000 + bodySize);
            _ = flags1;
        }

        // Round-trip through my own reader.
        string tmp = Path.Combine(Path.GetTempPath(), $"ProsperoPkgTool-Cnt-{Guid.NewGuid():N}.bin");
        try
        {
            File.WriteAllBytes(tmp, cnt);
            ProsperoPackageInspection package = ProsperoPackageReader.Read(tmp);
            Assert.Equal(ProsperoPackageKind.MetadataContainer, package.Kind);
            Assert.Equal(ContentId, package.Cnt.ContentId);
            Assert.Equal(entryCount, package.Cnt.EntryCount);
            Assert.Equal((int)entryCount, package.Entries.Count);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    // ---- General-digests rollup/ordering tests ---------------------------------------------

    // Fixture GD slot ground truth (from the read_fixture_entries.ps1 dump). The two non-zero slots
    // we reproduce are the system-digest (concat of SHA3-256(icon0.png 0x1200) ‖ SHA3-256(icon0.dds
    // 0x1280)) at +0x80 and the playgo-digest (concat over 0x1001 / 0x2010 / 0x2011) at +0xE0.
    private const string FixtureSystemDigestHex = "224f509caa33c546";
    private const string FixturePlaygoDigestHex = "920bb08812d02cdf";

    private record FixtureEntryPayload(uint Id, int DataOffset, int DataSize);

    // Fixture entry-table rows (id → CNT-relative data offset + size), per the ground-truth dump.
    private static readonly FixtureEntryPayload[] FixtureSystemEntries =
    [
        new(0x1200, 0x4170, 0x6FC6),   // icon0.png
        new(0x1280, 0xB140, 0x40094), // icon0.dds
    ];

    private static readonly FixtureEntryPayload[] FixturePlaygoEntries =
    [
        new(0x1001, 0x3FD0, 0x1A0),    // playgo-chunk.dat
        new(0x2010, 0x4B1E0, 0x50),   // playgo-hash-table.dat
        new(0x2011, 0x4B230, 0x16),    // playgo-ficm.dat
    ];

    [Fact]
    public void Fixture_SystemDigestRollupMatchesSlot()
    {
        byte[] pkg = File.ReadAllBytes(Fixture("test.pkg"));

        // Per-entry SHA3-256 of the icon0.png + icon0.dds payloads, concatenated in ascending id
        // order, then SHA3-256 of the concatenation.
        using var ms = new MemoryStream();
        foreach (FixtureEntryPayload e in FixtureSystemEntries.OrderBy(e => e.Id))
        {
            byte[] payload = new byte[e.DataSize];
            Buffer.BlockCopy(pkg, FixtureCntBase + e.DataOffset, payload, 0, e.DataSize);
            ms.Write(Sha3.Sha3_256(payload));
        }
        byte[] rollup = Sha3.Sha3_256(ms.ToArray());

        // Read the fixture GD system slot (+0x80 in the 0x1E0-byte GD entry, located at CNT+0x3380).
        byte[] gdPayload = ReadFixtureCntRegion(0x3380, 0x1E0);
        byte[] fixtureSlot = new byte[32];
        Buffer.BlockCopy(gdPayload, 0x80, fixtureSlot, 0, 32);

        Assert.Equal(fixtureSlot, rollup);
        Assert.True(fixtureSlot.AsSpan().StartsWith(Convert.FromHexString(FixtureSystemDigestHex)));
    }

    [Fact]
    public void Fixture_PlaygoDigestRollupMatchesSlot()
    {
        byte[] pkg = File.ReadAllBytes(Fixture("test.pkg"));

        using var ms = new MemoryStream();
        foreach (FixtureEntryPayload e in FixturePlaygoEntries.OrderBy(e => e.Id))
        {
            byte[] payload = new byte[e.DataSize];
            Buffer.BlockCopy(pkg, FixtureCntBase + e.DataOffset, payload, 0, e.DataSize);
            ms.Write(Sha3.Sha3_256(payload));
        }
        byte[] rollup = Sha3.Sha3_256(ms.ToArray());

        byte[] gdPayload = ReadFixtureCntRegion(0x3380, 0x1E0);
        byte[] fixtureSlot = new byte[32];
        Buffer.BlockCopy(gdPayload, 0xE0, fixtureSlot, 0, 32);

        Assert.Equal(fixtureSlot, rollup);
        Assert.True(fixtureSlot.AsSpan().StartsWith(Convert.FromHexString(FixturePlaygoDigestHex)));
    }

    [Fact]
    public void Build_SystemAndPlaygoSlotsMatchFixtureRollups()
    {
        // Build a CNT with the same icon0.png / icon0.dds / playgo payloads the fixture carries, and
        // confirm the builder's System + Playgo general-digest slots reproduce the fixture's values.
        byte[] pkg = File.ReadAllBytes(Fixture("test.pkg"));

        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        List<ProsperoCntBuilder.Entry> entries = ProsperoCntBuilder.BuildStandardEntries(ContentId, Passcode, ekpfs);

        // System-media entries (icon0.png 0x1200, icon0.dds 0x1280) with their fixture payloads.
        foreach (FixtureEntryPayload e in FixtureSystemEntries)
        {
            byte[] data = new byte[e.DataSize];
            Buffer.BlockCopy(pkg, FixtureCntBase + e.DataOffset, data, 0, e.DataSize);
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = (CntEntryId)e.Id,
                Name = e.Id == 0x1200 ? "icon0.png" : "icon0.dds",
                Data = data,
                Flags1 = ProsperoCntBuilder.Flags1For((CntEntryId)e.Id),
            });
        }

        // Playgo entries (0x1001, 0x2010, 0x2011).
        foreach (FixtureEntryPayload e in FixturePlaygoEntries)
        {
            byte[] data = new byte[e.DataSize];
            Buffer.BlockCopy(pkg, FixtureCntBase + e.DataOffset, data, 0, e.DataSize);
            entries.Add(new ProsperoCntBuilder.Entry
            {
                Id = (CntEntryId)e.Id,
                Name = e.Id switch
                {
                    0x1001 => "playgo-chunk.dat",
                    0x2010 => "playgo-hash-table.dat",
                    0x2011 => "playgo-ficm.dat",
                    _ => null,
                },
                Data = data,
                Flags1 = ProsperoCntBuilder.Flags1For((CntEntryId)e.Id),
            });
        }

        // param.json is required for the Param slot.
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.ParamJson, Name = "param.json", Data = "{}"u8.ToArray(),
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.ParamJson),
        });

        // imagedigs placeholder (mandatory entry the geometry descriptor locates).
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.Imagedigs, Name = null, Data = new byte[10 * 32],
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.Imagedigs),
        });

        var parameters = new CntBuildParameters { ContentId = ContentId, Passcode = Passcode };
        byte[] image = new byte[10 * 0x10000];
        byte[] cnt = ProsperoCntBuilder.Build(entries, parameters, image, new byte[16], new byte[32]);

        // Locate the GD entry payload in the built CNT via the entry table.
        uint tableOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x18, 4));
        uint count = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x10, 4));
        int gdRowOff = -1;
        for (int i = 0; i < count; i++)
        {
            ReadOnlySpan<byte> row = cnt.AsSpan((int)tableOffset + i * 32, 32);
            if (BinaryPrimitives.ReadUInt32BigEndian(row) == (uint)CntEntryId.GeneralDigests)
            {
                gdRowOff = i * 32;
                break;
            }
        }
        Assert.True(gdRowOff >= 0, "GD entry not found in built CNT");
        uint gdOff = BinaryPrimitives.ReadUInt32BigEndian(
            cnt.AsSpan((int)tableOffset + gdRowOff + 16, 4));

        // System slot (+0x80).
        byte[] builtSystem = new byte[32];
        Buffer.BlockCopy(cnt, (int)gdOff + 0x80, builtSystem, 0, 32);

        // Playgo slot (+0xE0).
        byte[] builtPlaygo = new byte[32];
        Buffer.BlockCopy(cnt, (int)gdOff + 0xE0, builtPlaygo, 0, 32);

        // Re-read fixture slots.
        byte[] fixtureGd = ReadFixtureCntRegion(0x3380, 0x1E0);
        byte[] fixtureSystem = new byte[32];
        Buffer.BlockCopy(fixtureGd, 0x80, fixtureSystem, 0, 32);
        byte[] fixturePlaygo = new byte[32];
        Buffer.BlockCopy(fixtureGd, 0xE0, fixturePlaygo, 0, 32);

        Assert.Equal(fixtureSystem, builtSystem);
        Assert.Equal(fixturePlaygo, builtPlaygo);
    }

    [Fact]
    public void Build_DigestTableAndBodyDigestCoverFinalGeneralDigests()
    {
        // Regression: the pre-reorder code wrote the GD entry AFTER the per-entry digest table, so
        // the GD row in the digest table (and the body digest) covered a zeroed placeholder. After
        // the reorder, the GD payload is finalized before the digest-table pass, so the GD row in
        // the digest table == SHA3-256(final GD payload) and bodyDigest == SHA3-256(final body).
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        List<ProsperoCntBuilder.Entry> entries = ProsperoCntBuilder.BuildStandardEntries(ContentId, Passcode, ekpfs);

        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.ParamJson, Name = "param.json", Data = "{}"u8.ToArray(),
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.ParamJson),
        });
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.Imagedigs, Name = null, Data = new byte[10 * 32],
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.Imagedigs),
        });

        var parameters = new CntBuildParameters { ContentId = ContentId, Passcode = Passcode };
        byte[] image = new byte[10 * 0x10000];
        byte[] cnt = ProsperoCntBuilder.Build(entries, parameters, image, new byte[16], new byte[32]);

        // Locate the GD entry.
        uint tableOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x18, 4));
        uint count = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x10, 4));
        int gdRowOff = -1, digestsRowOff = -1;
        for (int i = 0; i < count; i++)
        {
            ReadOnlySpan<byte> row = cnt.AsSpan((int)tableOffset + i * 32, 32);
            uint id = BinaryPrimitives.ReadUInt32BigEndian(row);
            if (id == (uint)CntEntryId.GeneralDigests) gdRowOff = i * 32;
            if (id == (uint)CntEntryId.Digests) digestsRowOff = i * 32;
        }
        Assert.True(gdRowOff >= 0 && digestsRowOff >= 0);

        uint gdOff = BinaryPrimitives.ReadUInt32BigEndian(
            cnt.AsSpan((int)tableOffset + gdRowOff + 16, 4));
        uint gdSize = BinaryPrimitives.ReadUInt32BigEndian(
            cnt.AsSpan((int)tableOffset + gdRowOff + 20, 4));
        Assert.Equal(0x1E0u, gdSize);

        uint digestsOff = BinaryPrimitives.ReadUInt32BigEndian(
            cnt.AsSpan((int)tableOffset + digestsRowOff + 16, 4));

        // The GD row in the per-entry digest table (slot gdRowOff/32, 32 bytes) == SHA3-256(GD payload).
        byte[] gdPayload = new byte[gdSize];
        Buffer.BlockCopy(cnt, (int)gdOff, gdPayload, 0, (int)gdSize);
        byte[] expectedGdRow = Sha3.Sha3_256(gdPayload);

        byte[] gdRow = new byte[32];
        Buffer.BlockCopy(cnt, (int)digestsOff + gdRowOff, gdRow, 0, 32);

        Assert.Equal(expectedGdRow, gdRow);

        // bodyDigest @ 0x160 == SHA3-256(body region [BodyOffset, BodyOffset+bodySize)).
        ulong bodySize = BinaryPrimitives.ReadUInt64BigEndian(cnt.AsSpan(0x28, 8));
        byte[] body = new byte[bodySize];
        Buffer.BlockCopy(cnt, (int)ProsperoCntBuilder.BodyOffset, body, 0, (int)bodySize);
        byte[] expectedBodyDigest = Sha3.Sha3_256(body);
        byte[] bodyDigest = new byte[32];
        Buffer.BlockCopy(cnt, 0x160, bodyDigest, 0, 32);

        Assert.Equal(expectedBodyDigest, bodyDigest);
    }

    [Fact]
    public void Build_StampsPfsSignedDigestBeforeHeaderSlotAndSelfSeal()
    {
        // The reference (original-tool and fpkg-gui) stamps CNT+0x460 = SHA3-256(final FIH header)
        // BEFORE computing the GeneralDigests header slot (whose preimage spans 0x400..0x480) and the
        // package self-seal at 0xFE0. This locks that ordering: the supplied digest must appear at
        // 0x460, the header slot must hash the stamped bytes, and 0xFE0 must seal the result.
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        List<ProsperoCntBuilder.Entry> entries = ProsperoCntBuilder.BuildStandardEntries(ContentId, Passcode, ekpfs);
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.ParamJson, Name = "param.json", Data = "{}"u8.ToArray(),
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.ParamJson),
        });
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.Imagedigs, Name = null, Data = new byte[10 * 32],
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.Imagedigs),
        });

        var parameters = new CntBuildParameters { ContentId = ContentId, Passcode = Passcode };
        byte[] image = new byte[10 * 0x10000];
        byte[] signedDigest = Sha3.Sha3_256("fih-header"u8.ToArray());

        byte[] cnt = ProsperoCntBuilder.Build(
            entries, parameters, image, new byte[16], new byte[32],
            pfsSignedDigest: signedDigest);

        // 0x460 carries the supplied digest.
        Assert.Equal(signedDigest, cnt.AsSpan(0x460, 32).ToArray());

        // The GD header slot hashes the preimage WITH the stamped 0x460 (and 0x410 forced to 0x10000).
        uint tableOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x18, 4));
        uint count = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x10, 4));
        uint gdOff = 0;
        for (int i = 0; i < count; i++)
        {
            ReadOnlySpan<byte> row = cnt.AsSpan((int)tableOffset + i * 32, 32);
            if (BinaryPrimitives.ReadUInt32BigEndian(row) == (uint)CntEntryId.GeneralDigests)
                gdOff = BinaryPrimitives.ReadUInt32BigEndian(row[16..]);
        }
        byte[] headerSlot = cnt.AsSpan((int)gdOff + 0x60, 32).ToArray();

        byte[] preimage = new byte[0x40 + 0x80];
        Buffer.BlockCopy(cnt, 0, preimage, 0, 0x40);
        Buffer.BlockCopy(cnt, 0x400, preimage, 0x40, 0x80);
        BinaryPrimitives.WriteUInt64BigEndian(preimage.AsSpan(0x40 + 0x10), 0x10000);
        Assert.Equal(Sha3.Sha3_256(preimage), headerSlot);

        // The package self-seal covers the finalized header (including 0x460 and the header slot).
        byte[] expectedSeal = Sha3.Sha3_256(cnt.AsSpan(0, ProsperoCntBuilder.PackageDigestStoredOffset));
        Assert.Equal(expectedSeal, cnt.AsSpan(ProsperoCntBuilder.PackageDigestStoredOffset, 32).ToArray());
    }

    [Fact]
    public void Build_EncryptsProtectedEntriesAndHashesPaddedCiphertext()
    {
        byte[] ekpfs = ProsperoKeys.ComputeEkpfs(ContentId, Passcode);
        List<ProsperoCntBuilder.Entry> entries = ProsperoCntBuilder.BuildStandardEntries(ContentId, Passcode, ekpfs);

        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.ParamJson, Name = "param.json", Data = "{}"u8.ToArray(),
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.ParamJson),
        });
        // A protected entry with an unaligned payload (the real nptitle.dat body size is 0x402).
        // It is added before imagedigs so imagedigs physically follows it in the body.
        byte[] plaintext = new byte[0x402];
        for (int i = 0; i < plaintext.Length; i++)
            plaintext[i] = (byte)(i * 7 + 1);
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.NptitleDat, Name = null, Data = plaintext,
            Flags1 = 0x80000000, Flags2 = 3u << 12,
        });
        entries.Add(new ProsperoCntBuilder.Entry
        {
            Id = CntEntryId.Imagedigs, Name = null, Data = new byte[10 * 32],
            Flags1 = ProsperoCntBuilder.Flags1For(CntEntryId.Imagedigs),
        });

        var parameters = new CntBuildParameters { ContentId = ContentId, Passcode = Passcode };
        byte[] cnt = ProsperoCntBuilder.Build(entries, parameters, new byte[10 * 0x10000], new byte[16], new byte[32]);

        uint tableOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x18, 4));
        uint count = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan(0x10, 4));
        int RowOf(uint id)
        {
            for (int i = 0; i < count; i++)
                if (BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan((int)tableOffset + i * 32, 4)) == id)
                    return i;
            return -1;
        }

        int protectedRow = RowOf((uint)CntEntryId.NptitleDat);
        int nextRow = RowOf((uint)CntEntryId.Imagedigs);
        Assert.True(protectedRow >= 0 && nextRow >= 0);

        uint protectedOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan((int)tableOffset + protectedRow * 32 + 16, 4));
        uint protectedSize = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan((int)tableOffset + protectedRow * 32 + 20, 4));
        uint nextOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan((int)tableOffset + nextRow * 32 + 16, 4));

        // The meta row records the logical size; the layout advances by the padded stored length.
        Assert.Equal(0x402u, protectedSize);
        Assert.Equal(protectedOffset + 0x410u, nextOffset);

        // The stored bytes are ciphertext that decrypts back to the zero-padded plaintext.
        byte[] metaRow = cnt.AsSpan((int)tableOffset + protectedRow * 32, 32).ToArray();
        byte[] storedCipher = cnt.AsSpan((int)protectedOffset, 0x410).ToArray();
        Assert.False(storedCipher.AsSpan(0, plaintext.Length).SequenceEqual(plaintext),
            "A protected entry must be stored encrypted.");

        byte[] round = ProsperoEntryCipher.Decrypt(storedCipher, metaRow, ContentId, Passcode, 3, publisherProfile: true);
        Assert.Equal(plaintext, round[..plaintext.Length]);
        Assert.All(round[plaintext.Length..], b => Assert.Equal(0, b));

        // The digest-table slot covers the padded ciphertext, not the logical payload.
        int digestsRow = RowOf((uint)CntEntryId.Digests);
        uint digestsOffset = BinaryPrimitives.ReadUInt32BigEndian(cnt.AsSpan((int)tableOffset + digestsRow * 32 + 16, 4));
        byte[] digestSlot = cnt.AsSpan((int)digestsOffset + protectedRow * 32, 32).ToArray();
        Assert.Equal(Sha3.Sha3_256(storedCipher), digestSlot);
    }
}
