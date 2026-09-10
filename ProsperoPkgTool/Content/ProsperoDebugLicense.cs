using System.Text;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Content;

/// <summary>
/// The debug grant for a content id + passcode. A debug image derives its mount key from public
/// inputs only (the content id and the passcode), so the mount path consumes no license record.
/// This type computes that derived key and states the "no rif required" decision in one place. It
/// never holds or fabricates a per-device secret.
/// </summary>
public sealed class ProsperoDebugLicense
{
    /// <summary>Length in bytes of the derived EKPFS.</summary>
    public const int EkpfsSize = 32;

    /// <summary>Required passcode length.</summary>
    public const int PasscodeLength = 32;

    /// <summary>Maximum content-id length in bytes.</summary>
    public const int ContentIdMaxLength = 0x24;

    /// <summary>The all-zero passcode, the debug default.</summary>
    public static string DefaultPasscode => new('0', PasscodeLength);

    /// <summary>The package content id the derived key binds to.</summary>
    public required string ContentId { get; init; }

    /// <summary>The 32-character passcode. The all-zero passcode is the debug default.</summary>
    public required string Passcode { get; init; }

    /// <summary>
    /// A debug grant never requires a license record. The mount path recomputes the EKPFS from the
    /// content id and passcode, so no rif is consumed.
    /// </summary>
    public bool RequiresRif => false;

    /// <summary>
    /// Builds a debug grant for <paramref name="contentId"/>. The passcode defaults to the all-zero
    /// debug passcode when omitted.
    /// </summary>
    /// <exception cref="ArgumentException">The content id or passcode is malformed.</exception>
    public static ProsperoDebugLicense Create(string contentId, string? passcode = null)
    {
        string pass = passcode ?? DefaultPasscode;
        var license = new ProsperoDebugLicense { ContentId = contentId, Passcode = pass };
        if (!license.Validate(out string? error))
            throw new ArgumentException(error, nameof(contentId));
        return license;
    }

    /// <summary>Derives the 32-byte EKPFS from the content id and passcode.</summary>
    public byte[] DeriveEkpfs() => ProsperoKeys.ComputeEkpfs(ContentId, Passcode);

    /// <summary>
    /// Derives the AES-XTS (tweak, data) key pair for the outer-PFS image from the given 16-byte
    /// superblock <paramref name="seed"/>.
    /// </summary>
    public (byte[] TweakKey, byte[] DataKey) DeriveImageEncryptionKeys(byte[] seed) =>
        ProsperoKeys.DeriveOuterPfsXtsKeys(DeriveEkpfs(), seed);

    /// <summary>
    /// Checks that the content id and passcode are well-formed. Returns <see langword="true"/> when
    /// usable; otherwise <paramref name="error"/> describes the first problem.
    /// </summary>
    public bool Validate(out string? error)
    {
        if (string.IsNullOrEmpty(ContentId) || Encoding.ASCII.GetByteCount(ContentId) > ContentIdMaxLength)
        {
            error = $"A content id is 1..{ContentIdMaxLength} ASCII bytes.";
            return false;
        }
        if (string.IsNullOrEmpty(Passcode) || Passcode.Length != PasscodeLength)
        {
            error = $"A passcode is exactly {PasscodeLength} characters.";
            return false;
        }
        error = null;
        return true;
    }

    /// <summary>Returns the content id and rif requirement for diagnostics.</summary>
    public override string ToString() => $"DebugLicense({ContentId}, rif required={RequiresRif})";
}
