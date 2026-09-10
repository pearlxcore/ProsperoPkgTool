using System.Text;
using ProsperoPkgTool.Containers;

namespace ProsperoPkgTool.Tests;

/// <summary>
/// Locks the canonical publisher <c>param.json</c> normalisation: source values are preserved, the
/// application defaults are filled, keys are sorted ordinally, and the document is emitted as
/// CRLF-terminated UTF-8 without a BOM.
/// </summary>
public sealed class ProsperoPublisherParamJsonTests
{
    private const string MinimalSource = """
        {
          "titleId": "PPSA01234",
          "contentId": "IV0001-PPSA01234_00-TESTPACKAGE00001",
          "contentVersion": "01.000.000",
          "applicationCategoryType": 0,
          "pubtools": { "creationDate": "2026-09-09 00:00:00" }
        }
        """;

    [Fact]
    public void Build_ExpandsMinimalSource_ToCanonicalDocument()
    {
        byte[] output = ProsperoPublisherParamJson.Build(
            Encoding.UTF8.GetBytes(MinimalSource), DateTime.UnixEpoch, 0);

        // The reference publisher emits this exact document (modulo the stamped creationDate).
        Assert.Equal(1143, output.Length);
        Assert.Equal((byte)'{', output[0]); // no UTF-8 BOM
        string text = Encoding.UTF8.GetString(output);
        Assert.StartsWith("{\r\n  \"addcont\": {", text, StringComparison.Ordinal);
        Assert.EndsWith("}\r\n", text, StringComparison.Ordinal);
        Assert.DoesNotContain("\n\n", text, StringComparison.Ordinal);
        Assert.Contains("\"creationDate\": \"1970-01-01 00:00:00\"", text, StringComparison.Ordinal);
        Assert.Contains("\"toolVersion\": \"2.79\"", text, StringComparison.Ordinal);
        Assert.Contains("\"applicationDrmType\": \"standard\"", text, StringComparison.Ordinal);
        Assert.Contains("\"requiredSystemSoftwareVersion\": \"0x0000000000000000\"", text, StringComparison.Ordinal);
        Assert.Contains("\"sdkVersion\": \"0x0000000000000000\"", text, StringComparison.Ordinal);
        Assert.Contains("\"contentBadgeType\": 1", text, StringComparison.Ordinal);
        Assert.Contains("\"conceptId\": \"10000000\"", text, StringComparison.Ordinal);
        Assert.Contains("\"masterVersion\": \"01.00\"", text, StringComparison.Ordinal);
        Assert.Contains("\"versionFileUri\": \"" + new string(' ', 255) + "\"", text, StringComparison.Ordinal);
        Assert.Contains(new string(' ', 19), text, StringComparison.Ordinal); // addcont.serviceIdForSharing

        // Ordinal key order: uppercase object keys sort before lowercase ones.
        int addcont = text.IndexOf("\"addcont\"", StringComparison.Ordinal);
        int ageLevel = text.IndexOf("\"ageLevel\"", StringComparison.Ordinal);
        int versionFileUri = text.IndexOf("\"versionFileUri\"", StringComparison.Ordinal);
        Assert.True(addcont < ageLevel && ageLevel < versionFileUri);
        Assert.Contains("\"JP\": 0,\r\n    \"US\": 0,\r\n    \"default\": 0", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Build_PreservesSourceValuesAndReplacesPublTools()
    {
        const string source = """
            {
              "titleId": "PPSA01234",
              "contentId": "IV0001-PPSA01234_00-TESTPACKAGE00001",
              "contentVersion": "02.003.004",
              "applicationDrmType": "freemium",
              "versionFileUri": "https://example.invalid/v.json",
              "requiredSystemSoftwareVersion": "0x0500000000000000",
              "pubtools": { "creationDate": "2020-01-01 00:00:00", "loudnessSnd0": { "x": 1 } }
            }
            """;

        byte[] output = ProsperoPublisherParamJson.Build(
            Encoding.UTF8.GetBytes(source), new DateTime(2024, 5, 6, 7, 8, 9, DateTimeKind.Utc), 0);
        string text = Encoding.UTF8.GetString(output);

        Assert.Contains("\"contentVersion\": \"02.003.004\"", text, StringComparison.Ordinal);
        Assert.Contains("\"applicationDrmType\": \"freemium\"", text, StringComparison.Ordinal);
        Assert.Contains("\"requiredSystemSoftwareVersion\": \"0x0500000000000000\"", text, StringComparison.Ordinal);
        Assert.Contains("\"creationDate\": \"2024-05-06 07:08:09\"", text, StringComparison.Ordinal);
        Assert.Contains("\"loudnessSnd0\": {", text, StringComparison.Ordinal);
        Assert.StartsWith("https://example.invalid/v.json", text[(text.IndexOf("\"versionFileUri\": \"", StringComparison.Ordinal) + 19)..], StringComparison.Ordinal);
    }

    [Fact]
    public void ResolveSdkVersion_NonElf_ReturnsZero()
    {
        Assert.Equal(0UL, ProsperoPublisherParamJson.ResolveSdkVersion(new byte[64]));
    }

    [Fact]
    public void Build_RejectsOversizedVersionFileUri()
    {
        string source = $$"""
            { "titleId": "PPSA01234", "contentId": "IV0001-PPSA01234_00-TESTPACKAGE00001",
              "versionFileUri": "{{new string('a', 256)}}" }
            """;
        Assert.Throws<InvalidDataException>(() =>
            ProsperoPublisherParamJson.Build(Encoding.UTF8.GetBytes(source), DateTime.UnixEpoch, 0));
    }
}
