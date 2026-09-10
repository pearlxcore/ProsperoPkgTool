using System.Buffers.Binary;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Content;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Coverage for the decrypted-backup converter (milestone 10): SELF classification, module
/// substitution, launch-readiness reporting, and the end-to-end <c>convert</c> command.
/// </summary>
public sealed class ProsperoBackupConverterTests
{
    private const string ContentId = "IV0001-PPSA01234_00-TESTPACKAGE00001";
    private const string Passcode = "12345678923456789102123901202333";
    private const ulong GenuineAuthority = 0x4500000000000001UL;

    // ---- ProsperoSelfReader ----

    [Fact]
    public void SelfReader_RoundTripsAuthorityIdFromFakeSelf()
    {
        byte[] rawElf = BuildMinimalRawElf();
        byte[] fself = ProsperoSelfBuilder.MakeFself(rawElf);

        Assert.True(ProsperoSelfReader.IsSelf(fself));
        ProsperoSelfImage image = ProsperoSelfReader.Parse(fself);
        Assert.NotNull(image.ExtInfo);
        Assert.Equal(0x3100000000000001UL, image.ExtInfo!.AuthorityId);
        Assert.Equal(fself.Length, (int)image.FileSize);
        Assert.True(ProsperoSelfReader.TryReadAuthorityId(fself, out ulong authority));
        Assert.Equal(image.ExtInfo.AuthorityId, authority);
    }

    [Fact]
    public void SelfReader_RejectsNonSelf()
    {
        Assert.False(ProsperoSelfReader.TryParse([1, 2, 3, 4], out _));
        Assert.False(ProsperoSelfReader.IsSelf([0x7F, (byte)'E', (byte)'L', (byte)'F']));
    }

    // ---- ProsperoLaunchReadiness ----

    [Fact]
    public void LaunchReadiness_ClassifiesRawFakeGenuineAndData()
    {
        Assert.Equal(ModuleAuthorityKind.RawElf,
            ProsperoLaunchReadiness.InspectModule("eboot.bin", BuildMinimalRawElf()).Kind);

        byte[] rawElf = BuildMinimalRawElf();
        Assert.Equal(ModuleAuthorityKind.FakeAuthoritySelf,
            ProsperoLaunchReadiness.InspectModule("lib.prx", ProsperoSelfBuilder.MakeFself(rawElf)).Kind);
        Assert.Equal(ModuleAuthorityKind.GenuineAuthoritySelf,
            ProsperoLaunchReadiness.InspectModule("lib.prx",
                ProsperoSelfBuilder.MakeFself(rawElf, new FselfOptions { AuthorityId = GenuineAuthority })).Kind);
        Assert.Equal(ModuleAuthorityKind.NotExecutable,
            ProsperoLaunchReadiness.InspectModule("data.bin", [1, 2, 3, 4]).Kind);
    }

    [Fact]
    public void LaunchReadiness_ReportsParamSfoAndMissingEboot()
    {
        using var fixture = new BackupFixture(withParamJson: false, withEboot: false);
        Directory.CreateDirectory(Path.Combine(fixture.Root, "sce_sys"));
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "param.sfo"), new byte[16]);

        ProsperoLaunchReadinessReport report = ProsperoLaunchReadiness.InspectAppRoot(fixture.Root);

        Assert.False(report.HasEboot);
        Assert.False(report.HasParamJson);
        Assert.True(report.HasParamSfo);
        Assert.False(report.IsLaunchReady);
        Assert.Contains(report.Issues, i => i.Contains("No eboot.bin"));
        Assert.Contains(report.Issues, i => i.Contains("param.sfo"));
    }

    // ---- ProsperoDebugLicense ----

    [Fact]
    public void DebugLicense_DerivesEkpfsAndNeverRequiresRif()
    {
        ProsperoDebugLicense license = ProsperoDebugLicense.Create(ContentId, Passcode);
        Assert.False(license.RequiresRif);
        Assert.Equal(ProsperoKeys.ComputeEkpfs(ContentId, Passcode), license.DeriveEkpfs());
        // Independently derived by the reference engine (LibProsperoPkg 1.2.0 ProsperoPfsKeys.DeriveEkpfs).
        Assert.Equal(
            Convert.FromHexString("4F9555AEF46E3917ED1CE05D4592BECB99EBD1B900A2DB37DA0C715FAD5E4268"),
            license.DeriveEkpfs());
        Assert.Throws<ArgumentException>(() => ProsperoDebugLicense.Create(ContentId, "short"));
        Assert.Equal(ProsperoDebugLicense.DefaultPasscode, ProsperoDebugLicense.Create(ContentId).Passcode);
    }

    // ---- ProsperoBackupConverter.Stage ----

    [Fact]
    public void Stage_SubstitutesSignedModuleWithDecryptedElf()
    {
        using var fixture = new BackupFixture();
        byte[] rawElf = BuildMinimalRawElf();
        fixture.WriteSignedEboot(rawElf, GenuineAuthority);
        fixture.WriteDecrypted("eboot.bin", rawElf);

        ProsperoBackupStagingResult staging = fixture.Stage();

        Assert.Contains("eboot.bin", staging.SubstitutedModules);
        Assert.Empty(staging.UnresolvedModules);
        Assert.Equal(rawElf, File.ReadAllBytes(Path.Combine(staging.StagingFolder, "eboot.bin")));
        // The decrypted subtree itself is never a staging-tree member.
        Assert.False(Directory.Exists(Path.Combine(staging.StagingFolder, "decrypted")));
        ModuleLaunchReadiness eboot = Assert.Single(staging.LaunchReadiness.Modules, m => m.Path == "eboot.bin");
        Assert.Equal(ModuleAuthorityKind.RawElf, eboot.Kind);
        Assert.True(staging.LaunchReadiness.IsLaunchReady);
    }

    [Fact]
    public void Stage_NoDecryptedSubtree_FlagsGenuineModuleAsUnresolved()
    {
        using var fixture = new BackupFixture();
        fixture.WriteSignedEboot(BuildMinimalRawElf(), GenuineAuthority);

        ProsperoBackupStagingResult staging = fixture.Stage();

        Assert.Contains("eboot.bin", staging.UnresolvedModules);
        Assert.Contains(staging.Warnings, w => w.Contains("will not run"));
        ModuleLaunchReadiness eboot = Assert.Single(staging.LaunchReadiness.Modules, m => m.Path == "eboot.bin");
        Assert.Equal(ModuleAuthorityKind.GenuineAuthoritySelf, eboot.Kind);
        Assert.False(staging.LaunchReadiness.IsLaunchReady);
    }

    [Fact]
    public void Stage_KeepsAlreadyFakeAuthoritySelf()
    {
        using var fixture = new BackupFixture();
        File.WriteAllBytes(Path.Combine(fixture.Root, "eboot.bin"), ProsperoSelfBuilder.MakeFself(BuildMinimalRawElf()));

        ProsperoBackupStagingResult staging = fixture.Stage();

        Assert.Contains("eboot.bin", staging.PlaintextModules);
        Assert.Empty(staging.UnresolvedModules);
        ModuleLaunchReadiness eboot = Assert.Single(staging.LaunchReadiness.Modules, m => m.Path == "eboot.bin");
        Assert.Equal(ModuleAuthorityKind.FakeAuthoritySelf, eboot.Kind);
        Assert.True(staging.LaunchReadiness.IsLaunchReady);
    }

    [Fact]
    public void Stage_UseEmbeddedRightSprx_DropsBackupModule()
    {
        using var fixture = new BackupFixture();
        fixture.WriteSignedEboot(BuildMinimalRawElf(), GenuineAuthority);
        Directory.CreateDirectory(Path.Combine(fixture.Root, "sce_sys", "about"));
        File.WriteAllBytes(Path.Combine(fixture.Root, "sce_sys", "about", "right.sprx"), new byte[64]);

        ProsperoBackupStagingResult staging = fixture.Stage(useEmbeddedRightSprx: true);

        Assert.False(File.Exists(Path.Combine(staging.StagingFolder, "sce_sys", "about", "right.sprx")));
    }

    // ---- End-to-end convert command ----

    [Fact]
    public async Task Convert_EndToEnd_BuildsLaunchReadyDebugPackage()
    {
        using var fixture = new BackupFixture();
        byte[] rawElf = BuildMinimalRawElf();
        fixture.WriteSignedEboot(rawElf, GenuineAuthority);
        fixture.WriteDecrypted("eboot.bin", rawElf);
        string output = Path.Combine(fixture.Root, "converted.pkg");

        int result = await CliApplication.RunAsync(
            ["convert", fixture.Root, "--out", output, "--passcode", Passcode]);
        Assert.Equal(0, result);
        Assert.True(File.Exists(output));

        ProsperoPackageInspection inspection = ProsperoPackageReader.Read(output);
        Assert.Equal(ProsperoPackageKind.FinalizedDebug, inspection.Kind);
        Assert.Equal(ContentId, inspection.Cnt.ContentId);

        // The substituted raw ELF was fake-signed by the build.
        ProsperoDecodedPackage decoded = ProsperoPackageContent.Read(output, Passcode);
        IReadOnlyList<ProsperoInnerPfsReader.Entry> entries = ProsperoInnerPfsReader.Enumerate(decoded.Mount);
        ProsperoInnerPfsReader.Entry eboot = Assert.Single(entries, e => e.Path == "/uroot/eboot.bin");
        Assert.Equal(ProsperoSelfBuilder.MakeFself(rawElf), ProsperoInnerPfsReader.ReadFile(decoded.Mount, eboot));
    }

    [Fact]
    public async Task Convert_UnresolvedModule_ReturnsNotLaunchReadyExitCode()
    {
        using var fixture = new BackupFixture();
        fixture.WriteSignedEboot(BuildMinimalRawElf(), GenuineAuthority);
        string output = Path.Combine(fixture.Root, "unresolved.pkg");

        int result = await CliApplication.RunAsync(
            ["convert", fixture.Root, "--out", output, "--passcode", Passcode]);

        Assert.Equal(5, result);
        Assert.True(File.Exists(output));
    }

    // ---- Helpers ----

    private static byte[] BuildMinimalRawElf()
    {
        byte[] elf = new byte[0x180];
        byte[] ident = [0x7F, (byte)'E', (byte)'L', (byte)'F', 0x02, 0x01, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0];
        ident.CopyTo(elf, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x10), 2);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x12), 0x3E);
        BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(0x14), 1);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x18), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x20), 0x40);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x34), 0x40);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x36), 0x38);
        BinaryPrimitives.WriteUInt16LittleEndian(elf.AsSpan(0x38), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(0x40), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(elf.AsSpan(0x44), 5);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x48), 0x100);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x50), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x58), 0x1000);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x60), 0x40);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x68), 0x40);
        BinaryPrimitives.WriteUInt64LittleEndian(elf.AsSpan(0x70), 0x1000);
        for (int i = 0; i < 0x40; i++)
            elf[0x100 + i] = (byte)(0xD0 + i);
        return elf;
    }

    private sealed class BackupFixture : IDisposable
    {
        public BackupFixture(bool withParamJson = true, bool withEboot = true)
        {
            Root = Path.Combine(Path.GetTempPath(), "ProsperoPkgTool-Convert-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(Path.Combine(Root, "sce_sys"));
            if (withParamJson)
            {
                File.WriteAllText(Path.Combine(Root, "sce_sys", "param.json"), $$"""
                    {
                      "titleId": "PPSA01234",
                      "contentId": "{{ContentId}}",
                      "contentVersion": "01.000.000",
                      "applicationCategoryType": 0,
                      "pubtools": { "creationDate": "2026-08-25 12:00:00" }
                    }
                    """);
            }
            if (withEboot)
                File.WriteAllBytes(Path.Combine(Root, "eboot.bin"), [0x7F, (byte)'E', (byte)'L', (byte)'F']);
        }

        public string Root { get; }

        public void WriteSignedEboot(byte[] rawElf, ulong authorityId) =>
            File.WriteAllBytes(Path.Combine(Root, "eboot.bin"),
                ProsperoSelfBuilder.MakeFself(rawElf, new FselfOptions { AuthorityId = authorityId }));

        public void WriteDecrypted(string relativePath, byte[] data)
        {
            string target = Path.Combine(Root, "decrypted", relativePath);
            Directory.CreateDirectory(Path.GetDirectoryName(target)!);
            File.WriteAllBytes(target, data);
        }

        public ProsperoBackupStagingResult Stage(bool useEmbeddedRightSprx = false) =>
            ProsperoBackupConverter.Stage(new ProsperoBackupConversionOptions
            {
                BackupFolder = Root,
                OutputFolder = Root,
                ContentId = ContentId,
                Passcode = Passcode,
                UseEmbeddedRightSprx = useEmbeddedRightSprx,
            });

        public void Dispose()
        {
            if (Directory.Exists(Root))
                Directory.Delete(Root, recursive: true);
        }
    }
}
