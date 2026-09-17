using System.Buffers.Binary;
using System.Text.Json;
using System.Security.Cryptography;
using ProsperoPkgTool.Containers;
using ProsperoPkgTool.Crypto;

if (args.Length is < 1 or > 3)
{
    Console.Error.WriteLine("Usage: ProsperoPkgTool.Diagnostics <package.pkg> [passcode] [--verify]. Dumps raw NAPS; optional lazy manifest and eboot SHA-256.");
    return 2;
}
try
{
    var inspection = ProsperoPackageReader.Read(args[0]);
    var fih = inspection.Fih ?? throw new InvalidDataException("Package has no FIH.");
    using var stream = File.OpenRead(args[0]);
    byte[] header = new byte[0x60];
    stream.ReadExactly(header);
    long outerOffset = checked((long)BinaryPrimitives.ReadUInt64LittleEndian(header.AsSpan(0x20))) - 0x10000;
    int hint = outerOffset >= 0 && outerOffset % 0x10000 == 0 && outerOffset < (long)fih.PfsSize
        ? checked((int)(outerOffset / 0x10000)) : -1;
    var pfs = OuterPfsReader.Open(stream, checked((long)fih.PfsOffset), checked((long)fih.PfsSize), hint);
    string passcode = args.Length >= 2 && args[1] != "--verify" ? args[1] : new string('0', 32);
    byte[] ekpfs = ProsperoKeys.ComputeEkpfs(inspection.Cnt.ContentId, passcode);
    var (tweak, data) = ProsperoKeys.DeriveOuterPfsXtsKeys(ekpfs, pfs.Seed);
    using var xts = new AesXts(data, tweak);
    byte[] naps = pfs.ReadNaps(xts);
    var counts = ProsperoNapsLayout.DecodeHeader(naps);
    long cbiBase = ProsperoNapsLayout.ComputeCblockInfoBase(naps);
    var records = new List<object>();
    for (int i = 0; i < counts.NumCblockInfo; i++)
    {
        long offset = cbiBase + i * 9L;
        if (offset > naps.Length - 9) throw new InvalidDataException($"Truncated CblockInfo record {i}.");
        var entry = ProsperoNapsLayout.DecodeCblockInfoEntry(naps.AsSpan((int)offset, 9));
        records.Add(new { Index = i, Raw = Convert.ToHexString(entry.Raw), entry.IsRunBase,
            entry.CoffsetStartMod256K, entry.CoffsetEndMod256K, entry.CoffsetStart256K,
            entry.UoffsetStart, entry.ClenEvenMinus1, entry.Even, entry.Odd,
            entry.KdePredictor, entry.TweakIdxStart, entry.KeyTableIdx });
    }
    object? verification = null;
    int exitCode = 0;
    if (args.Contains("--verify"))
    {
        try
        {
            using var package = ProsperoPackageContent.ReadFileBacked(args[0], passcode);
            var plan = package.Blocks as NapsBlockPlan;
            string? ebootSha256 = null;
            var eboot = package.Entries.FirstOrDefault(e => !e.IsDirectory && e.Path == "/uroot/eboot.bin");
            if (eboot is not null)
            {
                using var mount = package.OpenMount();
                mount.Position = eboot.LogicalOffset;
                using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                byte[] buffer = new byte[0x10000];
                long remaining = eboot.Size;
                while (remaining > 0)
                {
                    int length = (int)Math.Min(remaining, buffer.Length);
                    mount.ReadExactly(buffer.AsSpan(0, length));
                    hash.AppendData(buffer, 0, length);
                    remaining -= length;
                }
                ebootSha256 = Convert.ToHexString(hash.GetHashAndReset());
            }
            verification = new { plan?.Dialect, plan?.Diagnostics, package.MountLength,
                Stored = package.Blocks.Count(b => !b.IsKraken && !b.IsAlias && !b.IsZeroHole),
                Kraken = package.Blocks.Count(b => b.IsKraken), ZeroFill = package.Blocks.Count(b => b.IsZeroHole),
                Alias = package.Blocks.Count(b => b.IsAlias), EbootSha256 = ebootSha256,
                FileCount = package.Entries.Count(e => !e.IsDirectory),
                UserFileCount = package.Entries.Count(e => !e.IsDirectory && e.Path.StartsWith("/uroot/", StringComparison.Ordinal)),
                Entries = package.Entries };
        }
        catch (Exception ex)
        {
            verification = new { Error = ex.Message };
            exitCode = 1;
        }
    }
    Console.WriteLine(JsonSerializer.Serialize(new { Package = Path.GetFullPath(args[0]),
        pfs.InnerImageLength, Counts = counts, CblockInfoBase = cbiBase, Records = records, Verification = verification },
        new JsonSerializerOptions { WriteIndented = true }));
    return exitCode;
}
catch (Exception ex)
{
    Console.Error.WriteLine(ex);
    return 1;
}
