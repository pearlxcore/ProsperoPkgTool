using System.Security.Cryptography;
using System.Text;

namespace ProsperoPkgTool.Crypto;

/// <summary>
/// PS5 `sce_sys/keystone` validator (FINDINGS.md §4.6). A keystone is 96 bytes:
/// ASCII "keystone" + LE u16 version + pad to 0x20, then a passcode fingerprint HMAC at
/// 0x20 and a MAC over the first 0x40 bytes at 0x40.
///
/// The HMAC keys are hardcoded constants recovered from the publishing binary and verified
/// byte-exact against a real keystone. Version 3 is current; version 2 keys are provided
/// for older packages.
/// </summary>
public static class Keystone
{
    public const int Size = 96;

    // v3 (current) HMAC keys.
    private static readonly byte[] FingerprintKeyV3 = Convert.FromHexString(
        "fe2f86dc4c110c93b1f687d2da21b87862fd16e31dc0f0a8321035fddf6c56b7");
    private static readonly byte[] MacKeyV3 = Convert.FromHexString(
        "4bac100583dc7ed2178d0ce199fee9a2d72c7b7b0a10b72fe4be51d8bca18828");

    // v2 (older) key families.
    private static readonly byte[] FingerprintKeyV2 = Convert.FromHexString(
        "c74405f67424ba342bc1276251bbc2f555f16025b6a1b6714780dbaec852fa2f");
    private static readonly byte[] MacKeyV2 = Convert.FromHexString(
        "783d6f3ae91c0e0712fcaab7950bde06855cf7a22dcdbde127e9bfcbad0ff0fe");

    /// <summary>Parse the keystone version (LE u16 at offset 8). Returns 0 if malformed.</summary>
    public static int GetVersion(ReadOnlySpan<byte> keystone)
    {
        if (keystone.Length < Size)
            return 0;
        if (!keystone[..8].SequenceEqual("keystone"u8))
            return 0;
        return keystone[8] | (keystone[9] << 8);
    }

    /// <summary>Compute the passcode fingerprint for the given keystone version.</summary>
    public static byte[] ComputeFingerprint(string passcode, int version)
    {
        byte[] key = version >= 3 ? FingerprintKeyV3 : FingerprintKeyV2;
        return HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(passcode));
    }

    /// <summary>Compute the keystone MAC over the first 0x40 bytes for the given version.</summary>
    public static byte[] ComputeMac(ReadOnlySpan<byte> keystone, int version)
    {
        if (keystone.Length < 0x40)
            throw new ArgumentException("Keystone must be at least 0x40 bytes to MAC.", nameof(keystone));
        byte[] key = version >= 3 ? MacKeyV3 : MacKeyV2;
        return HMACSHA256.HashData(key, keystone[..0x40].ToArray());
    }

    /// <summary>Validate a keystone against a passcode: both the fingerprint (0x20) and MAC (0x40)
    /// must match. Returns true only when the keystone structure and both HMACs verify.</summary>
    public static bool Validate(ReadOnlySpan<byte> keystone, string passcode)
    {
        int version = GetVersion(keystone);
        if (version == 0 || keystone.Length < Size)
            return false;

        byte[] expectedFingerprint = ComputeFingerprint(passcode, version);
        if (!keystone.Slice(0x20, 32).SequenceEqual(expectedFingerprint))
            return false;

        byte[] expectedMac = ComputeMac(keystone, version);
        return keystone.Slice(0x40, 32).SequenceEqual(expectedMac);
    }

    /// <summary>
    /// Create a 96-byte debug keystone (version 3) for the given passcode: ASCII "keystone" magic,
    /// version 3, padding, the passcode fingerprint at 0x20 and the MAC over the first 0x40 bytes
    /// at 0x40.
    /// </summary>
    public static byte[] Create(string passcode)
    {
        byte[] keystone = new byte[Size];
        "keystone"u8.CopyTo(keystone.AsSpan(0));
        keystone[8] = 3; // version 3 (LE u16)
        keystone[9] = 0;
        // 0x0A..0x1F: zero padding.
        byte[] fingerprint = ComputeFingerprint(passcode, version: 3);
        fingerprint.CopyTo(keystone, 0x20);
        byte[] mac = ComputeMac(keystone, version: 3);
        mac.CopyTo(keystone, 0x40);
        return keystone;
    }
}
