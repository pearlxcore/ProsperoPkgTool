using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>
/// Builder for the NAPS metadata records (<c>common/etc/naps_meta_*.dat</c>) streamed into the SI
/// (install-metadata) segment of a debug finalized image.
///
/// <list type="bullet">
///   <item><c>naps_meta_300/301/302/308.dat</c> all carry the same 48-byte plaintext descriptor:
///   six little-endian u64 fields fully derived from the inner-image geometry (no key material):
///   {0, 0, R, 0x3E9, R, 0x10000} where R = innerImageSize − 0x10000.</item>
///   <item><c>naps_meta_18.dat</c> is a back-to-back TLV record stream (16-byte per-record header:
///   reversed 4-char tag, version byte, 3 zero bytes, u64 payload length) carrying the inner-image
///   geometry (phdr), the content-file table (file), the per-block info tables (ibcl/i2ob/i2op/
///   ihsh) computed over the compressed inner-image NAPS block map, the root digest (rhsh), the
///   content-file path table (fstr), a fixed tweak marker (twek), the outer digest (obdg) and the
///   four 48-byte descriptor records (pgpl/pgil/pgpi/pgpu). The stream is padded to a 16-byte
///   multiple with a trailing zero record and encrypted with AES-128-XTS under a fixed embedded
///   key set; the whole file is one XTS data unit.</item>
/// </list>
/// </summary>
public static class ProsperoNapsMeta
{
    /// <summary>On-disk size of each <c>naps_meta_300/301/302/308</c> descriptor record.</summary>
    public const int Meta300Length = 48;

    /// <summary>The constant NAPS-meta kind/version id (<c>0x3E9</c> = 1001).</summary>
    public const ulong Meta300KindId = 0x3E9;

    /// <summary>PFS block size stored at offset 0x28 of the descriptor.</summary>
    public const ulong PfsBlockSizeConst = 0x10000;

    /// <summary>The four ids that share the 48-byte descriptor record.</summary>
    public static ReadOnlySpan<int> Meta300Ids => [300, 301, 302, 308];

    /// <summary>Pseudo content-file name appended for the inner PFS metadata region.</summary>
    public const string PfsMetadataFileName = "*PFSmetadata";

    /// <summary>Block size used for the meta18 block tables and the outer identity map.</summary>
    private const int Meta18BlockSize = 0x10000;

    /// <summary>256 KiB uncompressed NAPS block used by the inner-image geometry.</summary>
    private const long Meta18UBlock = 0x40000;

    // ---- naps_meta_300 descriptor ----------------------------------------------------------

    /// <summary>
    /// Builds the 48-byte descriptor from the inner-image data-region size
    /// <paramref name="innerImageDataRegionSize"/> (= innerImageSize − 0x10000).
    /// Layout: u64{0}=0, u64{1}=0, u64{2}=R, u64{3}=0x3E9, u64{4}=R, u64{5}=0x10000.
    /// </summary>
    public static byte[] BuildMeta300(ulong innerImageDataRegionSize)
    {
        byte[] record = new byte[Meta300Length];
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(0x10), innerImageDataRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(0x18), Meta300KindId);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(0x20), innerImageDataRegionSize);
        BinaryPrimitives.WriteUInt64LittleEndian(record.AsSpan(0x28), PfsBlockSizeConst);
        return record;
    }

    /// <summary>
    /// Builds the 48-byte descriptor from the block-aligned inner-image size (the value the FIH
    /// stamps at offset 0xA0). Equivalent to <see cref="BuildMeta300(ulong)"/> with
    /// <c>innerImageSize - PfsBlockSizeConst</c>.
    /// </summary>
    public static byte[] BuildMeta300FromInnerImageSize(ulong innerImageSize)
    {
        if (innerImageSize < PfsBlockSizeConst)
            throw new ArgumentOutOfRangeException(nameof(innerImageSize),
                $"inner-image size 0x{innerImageSize:X} is smaller than one 0x{PfsBlockSizeConst:X} block");
        return BuildMeta300(innerImageSize - PfsBlockSizeConst);
    }

    // ---- naps_meta_18 TLV metric blob ------------------------------------------------------

    // Fixed AES-128-XTS key set for the naps_meta_18 data unit. Constant across all packages.
    private static readonly byte[] Meta18DataKey =
        [0x02, 0x2D, 0xCA, 0xF6, 0xD1, 0x11, 0xE5, 0x8F, 0x25, 0x93, 0x6E, 0xF5, 0x46, 0x93, 0x45, 0xAB];
    private static readonly byte[] Meta18TweakKey =
        [0xAD, 0xAC, 0x16, 0x37, 0x60, 0xDA, 0x51, 0x46, 0x98, 0xC2, 0x45, 0xAB, 0x4C, 0x9C, 0x42, 0x6C];
    private static readonly byte[] Meta18Tweak =
        [0x3C, 0xBA, 0x10, 0x7D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    /// <summary>
    /// Builds the encrypted <c>naps_meta_18.dat</c> metric blob for a finalized image. When
    /// <paramref name="inner"/> is supplied, the per-block tables (ibcl/i2ob/i2op/ihsh) and the
    /// <c>file</c> record describe the compressed inner-image NAPS block map (afid raw extents +
    /// data-region hole ublocks + metadata ublocks); when null, an identity map over the outer
    /// mount image is emitted instead. <c>rhsh</c>/<c>obdg</c> always cover the outer image.
    /// </summary>
    /// <param name="innerImageSize">Block-aligned inner-image size (FIH offset 0xA0).</param>
    /// <param name="mountImage">The finalized FIH+PFS+CNT mount image; the outer digests cover it.</param>
    /// <param name="contentFiles">Inner content files in load order: root-relative path and plain size.</param>
    /// <param name="inner">The assembled inner-image result (optional; enables the inner block map).</param>
    /// <returns>The encrypted blob (length a multiple of 16), or empty when inputs are insufficient.</returns>
    public static byte[] BuildMeta18(
        ulong innerImageSize, ReadOnlySpan<byte> mountImage,
        IReadOnlyList<(string Path, long Size)> contentFiles,
        ProsperoInnerImageAssembler.InnerImageResult? inner = null,
        long? mountLengthOverride = null,
        byte[]? obdgOverride = null,
        byte[]? rhshOverride = null)
    {
        ArgumentNullException.ThrowIfNull(contentFiles);
        // The streamed caller supplies the mount length without materializing the image, and the
        // outer digests (rhsh/obdg) precomputed over that stream.
        long mountLength = mountLengthOverride ?? mountImage.Length;
        if (innerImageSize < PfsBlockSizeConst || mountLength < Meta18BlockSize)
            return [];

        uint innerBlocks = (uint)(innerImageSize / PfsBlockSizeConst);
        int outerBlocks = (int)(mountLength / Meta18BlockSize);

        List<Meta18Block>? blocks = inner is not null ? BuildInnerBlocks(inner) : null;
        int metaFirstBlockIndex = blocks is null ? -1 : blocks.FindIndex(b => b.Tail == Meta300KindId);
        int blockCount = blocks?.Count ?? outerBlocks;

        var plain = new List<byte>(4096);

        // phdr: [ver=1, 0x30, innerBlocks, innerImageSize, 1, blockSize] (six u32 LE).
        Span<byte> phdrBody = stackalloc byte[0x18];
        WriteU32(phdrBody, 0x00, 1);
        WriteU32(phdrBody, 0x04, 0x30);
        WriteU32(phdrBody, 0x08, innerBlocks);
        WriteU32(phdrBody, 0x0C, (uint)innerImageSize);
        WriteU32(phdrBody, 0x10, 1);
        WriteU32(phdrBody, 0x14, (uint)PfsBlockSizeConst);
        WriteRecord(plain, "phdr", 1, phdrBody);

        // file: one 0x18 entry per content file [u64 size, u32 index, u32 type, u32 field10, u32 flag].
        // Real (afid) files get index = their position, type 1, field10 0, flag 0 for the first file
        // else 1; the "*PFSmetadata" pseudo-file gets the first metadata block's index, type 3,
        // field10 0x3E9, flag 0.
        {
            var body = new byte[Math.Max(contentFiles.Count, 1) * 0x18];
            for (int i = 0; i < contentFiles.Count; i++)
            {
                Span<byte> e = body.AsSpan(i * 0x18, 0x18);
                bool isMeta = blocks is not null && contentFiles[i].Path == PfsMetadataFileName;
                uint idx = isMeta && metaFirstBlockIndex >= 0 ? (uint)metaFirstBlockIndex : (uint)i;
                uint type = isMeta ? 3u : 1u;
                uint field10 = isMeta ? (uint)Meta300KindId : 0u;
                uint flag = isMeta ? 0u : (i == 0 ? 0u : 1u);
                BinaryPrimitives.WriteUInt64LittleEndian(e[..8], (ulong)Math.Max(contentFiles[i].Size, 0));
                WriteU32(e, 0x08, idx);
                WriteU32(e, 0x0C, type);
                WriteU32(e, 0x10, field10);
                WriteU32(e, 0x14, flag);
            }
            WriteRecord(plain, "file", 2, body);
        }

        // ibcl: one class byte per block. Inner path: 0x01 when the block's owning content file has
        // flag 1, else 0x0F. Outer path: all 0x0F.
        {
            byte[] body;
            if (blocks is not null)
            {
                body = new byte[blocks.Count];
                for (int i = 0; i < blocks.Count; i++)
                    body[i] = blocks[i].OwnerFlag == 1 ? (byte)0x01 : (byte)0x0F;
            }
            else
            {
                body = new byte[outerBlocks];
                Array.Fill(body, (byte)0x0F);
            }
            WriteRecord(plain, "ibcl", 1, body);
        }

        // i2ob: 0x28 per block. Inner path: [+0x00 u64 co (offset in pfs_image.dat), +0x08 u32 cs
        // (= c0+c1), +0x0C u32 ps (plaintext coverage), +0x10 u32 c0, +0x14 u32 c1, +0x18 u32 mb
        // (= co>>16), +0x1C 0, +0x20 u32 1, +0x24 u32 flag (0x40090000 afid | 0x40110000 hole |
        // 0x40450000 meta two-sub-chunk | 0x40050000 meta single)].
        {
            var body = new byte[blockCount * 0x28];
            for (int i = 0; i < blockCount; i++)
            {
                Span<byte> e = body.AsSpan(i * 0x28, 0x28);
                if (blocks is not null)
                {
                    Meta18Block b = blocks[i];
                    BinaryPrimitives.WriteUInt64LittleEndian(e[..8], b.Co);
                    WriteU32(e, 0x08, b.Cs);
                    WriteU32(e, 0x0C, b.Ps);
                    WriteU32(e, 0x10, b.C0);
                    WriteU32(e, 0x14, b.C1);
                    WriteU32(e, 0x18, (uint)(b.Co >> 16));
                    WriteU32(e, 0x20, 1);
                    WriteU32(e, 0x24, b.Flag);
                }
                else
                {
                    BinaryPrimitives.WriteUInt64LittleEndian(e[..8], (ulong)(i * Meta18BlockSize));
                    WriteU32(e, 0x08, (uint)Meta18BlockSize);
                    WriteU32(e, 0x0C, (uint)Meta18BlockSize);
                    WriteU32(e, 0x10, (uint)Meta18BlockSize);
                    WriteU32(e, 0x18, (uint)((ulong)(i * Meta18BlockSize) >> 16));
                    WriteU32(e, 0x20, 1);
                    WriteU32(e, 0x24, 0x40090000u);
                }
            }
            WriteRecord(plain, "i2ob", 1, body);
        }

        // i2op: 0x10 per block [u64 co, u64 co>>16] — a pure projection of i2ob.
        {
            var body = new byte[blockCount * 0x10];
            for (int i = 0; i < blockCount; i++)
            {
                Span<byte> e = body.AsSpan(i * 0x10, 0x10);
                ulong co = blocks is not null ? blocks[i].Co : (ulong)(i * Meta18BlockSize);
                BinaryPrimitives.WriteUInt64LittleEndian(e[..8], co);
                BinaryPrimitives.WriteUInt64LittleEndian(e.Slice(8, 8), co >> 16);
            }
            WriteRecord(plain, "i2op", 1, body);
        }

        // ihsh: 0x30 per block [u32 idx, u32 size, 32B digest, u64 tail]. Inner path: holes carry
        // idx=0/size=ps and SHA3-256 of the zero-filled hole block; afid/metadata blocks carry a
        // best-effort SHA3-256 of the block's on-disk bytes with tail 0 / 0x3E9 (the console's
        // keyed 40-byte ICV is not reproducible off-console). Outer path: per-block SHA3-256 of the
        // mount image block.
        {
            var body = new byte[blockCount * 0x30];
            byte[] zeroBlock = new byte[Meta18UBlock];
            using Stream? innerStream = blocks is not null ? inner!.OpenImage() : null;
            for (int i = 0; i < blockCount; i++)
            {
                Span<byte> e = body.AsSpan(i * 0x30, 0x30);
                if (blocks is not null)
                {
                    Meta18Block b = blocks[i];
                    if (b.IsHole)
                    {
                        WriteU32(e, 0x00, 0);
                        WriteU32(e, 0x04, b.Ps);
                        Sha3.Sha3_256(zeroBlock.AsSpan(0, (int)b.Ps)).CopyTo(e.Slice(0x08, 32));
                    }
                    else
                    {
                        byte[] h = Sha3.Sha3_256(ReadInnerBlock(innerStream!, b.OnDiskOffset, (int)b.OnDiskLen));
                        h.AsSpan(0, 32).CopyTo(e.Slice(0x08, 32));
                        BinaryPrimitives.WriteUInt64LittleEndian(e.Slice(0x28, 8), b.Tail);
                    }
                }
                else
                {
                    WriteU32(e, 0x00, (uint)i);
                    WriteU32(e, 0x04, (uint)Meta18BlockSize);
                    int start = i * Meta18BlockSize;
                    int len = Math.Min(Meta18BlockSize, mountImage.Length - start);
                    Sha3.Sha3_256(mountImage.Slice(start, len)).CopyTo(e.Slice(0x08, 32));
                }
            }
            WriteRecord(plain, "ihsh", 1, body);
        }

        // rhsh: root digest over the plaintext outer superblock block, remainder zero (176 bytes).
        {
            var body = new byte[0xB0];
            if (rhshOverride is { Length: > 0 })
                rhshOverride.AsSpan(0, Math.Min(rhshOverride.Length, body.Length)).CopyTo(body);
            else
            {
                int sb = ProsperoFihBuilder.LocateSuperblock(mountImage);
                if (sb >= 0)
                    Sha3.Sha3_256(mountImage.Slice(sb, Meta18BlockSize)).CopyTo(body);
            }
            WriteRecord(plain, "rhsh", 1, body);
        }

        // fstr: content-file relative paths, each (including the last) NUL-terminated ASCII.
        {
            var sb = new StringBuilder();
            foreach ((string path, _) in contentFiles)
            {
                sb.Append(path.Replace('\\', '/'));
                sb.Append('\0');
            }
            WriteRecord(plain, "fstr", 1, Encoding.ASCII.GetBytes(sb.ToString()));
        }

        // twek: fixed marker [0, 4, 0, 0, 0].
        Span<byte> twekBody = stackalloc byte[0x14];
        twekBody.Clear();
        WriteU32(twekBody, 0x04, 4);
        WriteRecord(plain, "twek", 1, twekBody);

        // obdg: outer digest over the whole finalized image, remainder zero (128 bytes).
        {
            var body = new byte[0x80];
            if (obdgOverride is { Length: > 0 })
                obdgOverride.AsSpan(0, Math.Min(obdgOverride.Length, body.Length)).CopyTo(body);
            else
                Sha3.Sha3_256(mountImage).CopyTo(body);
            WriteRecord(plain, "obdg", 1, body);
        }

        // pgpl/pgil/pgpi/pgpu: the four identical 48-byte descriptors.
        byte[] desc = BuildMeta300FromInnerImageSize(innerImageSize);
        WriteRecord(plain, "pgpl", 1, desc);
        WriteRecord(plain, "pgil", 1, desc);
        WriteRecord(plain, "pgpi", 1, desc);
        WriteRecord(plain, "pgpu", 1, desc);

        // Trailing pad record sized so the plaintext ends on a 16-byte boundary.
        int pad = (16 - (plain.Count % 16)) % 16;
        WriteRecord(plain, "zero", 1, new byte[pad]);

        return AesXtsTransform(plain.ToArray(), encrypt: true);
    }

    /// <summary>
    /// Convenience wrapper used by package builders: appends the <see cref="PfsMetadataFileName"/>
    /// pseudo-entry (sized to <paramref name="pfsImageSize"/>) to the content-file list before
    /// delegating to <see cref="BuildMeta18"/>.
    /// </summary>
    public static byte[] BuildMeta18WithMetadataEntry(
        ulong innerImageSize, ReadOnlySpan<byte> mountImage,
        IReadOnlyList<(string Path, long Size)> contentFiles, long pfsImageSize,
        ProsperoInnerImageAssembler.InnerImageResult? inner = null,
        long? mountLengthOverride = null,
        byte[]? obdgOverride = null,
        byte[]? rhshOverride = null)
    {
        var all = new List<(string, long)>(contentFiles.Count + 1);
        all.AddRange(contentFiles);
        all.Add((PfsMetadataFileName, pfsImageSize));
        return BuildMeta18(innerImageSize, mountImage, all, inner, mountLengthOverride, obdgOverride, rhshOverride);
    }

    /// <summary>
    /// Streaming SHA3-256 over <paramref name="stream"/> (from its current position to EOF). Used to
    /// compute the naps_meta_18 <c>obdg</c> record over a file-backed mount image that is too large
    /// to materialize as a span.
    /// </summary>
    public static byte[] Sha3Stream(Stream stream) => Sha3.Sha3_256(stream);

    /// <summary>
    /// Decrypts an encrypted <c>naps_meta_18.dat</c> blob back into its TLV plaintext
    /// (round-trip helper for tests/introspection).
    /// </summary>
    public static byte[] DecryptMeta18(ReadOnlySpan<byte> encrypted) =>
        AesXtsTransform(encrypted.ToArray(), encrypt: false);

    // ---- inner-image NAPS block map --------------------------------------------------------

    /// <summary>
    /// One entry of the compressed inner-image NAPS block map: <see cref="Co"/> is the block's byte
    /// offset inside the packed <c>pfs_image.dat</c>; <see cref="Cs"/> its stored size (== C0+C1);
    /// <see cref="Ps"/> the plaintext byte span it covers; <see cref="C0"/>/<see cref="C1"/> the two
    /// 0x20000 sub-chunk sizes; <see cref="Flag"/> the block-class word; <see cref="OwnerFlag"/>
    /// drives ibcl; <see cref="Tail"/> is the ihsh trailer (0x3E9 for metadata). For a real
    /// (non-hole) block, <see cref="OnDiskOffset"/>/<see cref="OnDiskLen"/> locate its bytes in the image.
    /// </summary>
    private readonly record struct Meta18Block(
        ulong Co, uint Cs, uint Ps, uint C0, uint C1, uint Flag,
        bool IsHole, uint OwnerFlag, ulong Tail, long OnDiskOffset, uint OnDiskLen);

    /// <summary>
    /// Derives the compressed inner-image NAPS block map: the afid raw extents (placements, afid
    /// order), the data-region hole ublocks tiling <c>[DataEndLogical, MetaBaseLogical)</c> by
    /// 256 KiB, and the metadata ublocks (the stored PFSv3 container's 256 KiB plaintext chunks at
    /// their on-disk offsets).
    /// </summary>
    private static List<Meta18Block> BuildInnerBlocks(ProsperoInnerImageAssembler.InnerImageResult inner)
    {
        var blocks = new List<Meta18Block>();

        // 1) afid raw extents: one entry per placed file (afid order). Raw, so cs=ps=c0=size,
        //    c1=0, flag 0x40090000. The first afid (keystone) has owner flag 0, the rest 1.
        IReadOnlyList<ProsperoInnerImageAssembler.Placement> placements = inner.Placements;
        for (int i = 0; i < placements.Count; i++)
        {
            ProsperoInnerImageAssembler.Placement p = placements[i];
            uint cs = (uint)p.OnDiskSize;
            blocks.Add(new Meta18Block(
                Co: (ulong)p.OnDiskOffset, Cs: cs, Ps: (uint)p.UncompressedSize, C0: cs, C1: 0,
                Flag: 0x40090000u, IsHole: false, OwnerFlag: i == 0 ? 0u : 1u, Tail: 0,
                OnDiskOffset: p.OnDiskOffset, OnDiskLen: cs));
        }

        // 2) data-region hole ublocks tiling [DataEndLogical, MetaBaseLogical) by 256 KiB. Each hole
        //    compresses to 0x10 bytes (two 8-byte 0x20000 sub-chunks); identical-plaintext holes
        //    reuse the same compressed offset (dedup, stride 0x10 from BlockInfoOnDiskOffset).
        //    flag 0x40110000.
        long padding = inner.MetaBaseLogical - inner.DataEndLogical;
        if (padding > 0)
        {
            int nblk = (int)((padding + Meta18UBlock - 1) / Meta18UBlock);
            var holeCo = new Dictionary<uint, ulong>();
            ulong cursor = (ulong)inner.BlockInfoOnDiskOffset;
            for (int k = 0; k < nblk; k++)
            {
                uint ps = (uint)Math.Min(Meta18UBlock, padding - (long)k * Meta18UBlock);
                if (!holeCo.TryGetValue(ps, out ulong co))
                {
                    co = cursor;
                    holeCo[ps] = co;
                    cursor += 0x10;
                }
                blocks.Add(new Meta18Block(
                    Co: co, Cs: 0x10, Ps: ps, C0: 8, C1: 8, Flag: 0x40110000u,
                    IsHole: true, OwnerFlag: 0, Tail: 0, OnDiskOffset: 0, OnDiskLen: 0));
            }
        }

        // 3) metadata ublocks: the PFSv3 container's data section (plaintext chunks of up to 256 KiB)
        //    at their on-disk offsets. co = MetadataOnDiskOffset + dataSectionOffset + cumulative cs.
        //    Stored chunks: c0 = cs, c1 = 0, flag 0x40050000. Kraken chunks: c0/c1 are the two
        //    128-KiB sub-chunk compressed sizes, flag 0x40450000 (two sub-chunks) or 0x40050000
        //    (single short sub-chunk).
        byte[] container = inner.CompressedMetadata;
        int dataOffset = 0;
        if (container.Length >= 0xB0)
            dataOffset = (int)BinaryPrimitives.ReadUInt32LittleEndian(container.AsSpan(0xAA, 4));
        ulong metaCursor = (ulong)inner.MetadataOnDiskOffset + (ulong)dataOffset;
        foreach (ProsperoPfsv3Writer.CompressedBlock b in inner.MetadataBlocks)
        {
            bool compressed = b.Flags != 0 && b.CompressedSize < b.UncompressedSize;
            uint c0 = compressed
                ? (uint)(b.MultiChunk ? b.FirstChunkCompressedSize : b.CompressedSize)
                : (uint)b.CompressedSize;
            uint c1 = compressed && b.MultiChunk ? (uint)(b.CompressedSize - b.FirstChunkCompressedSize) : 0u;
            uint flag = compressed && b.MultiChunk ? 0x40450000u : 0x40050000u;
            blocks.Add(new Meta18Block(
                Co: metaCursor, Cs: (uint)b.CompressedSize, Ps: (uint)b.UncompressedSize, C0: c0, C1: c1,
                Flag: flag, IsHole: false, OwnerFlag: 0, Tail: Meta300KindId,
                OnDiskOffset: (long)metaCursor, OnDiskLen: (uint)b.CompressedSize));
            metaCursor += (uint)b.CompressedSize;
        }

        return blocks;
    }

    /// <summary>Bounds-safe read of a real block's stored bytes from the (possibly file-backed) inner image.</summary>
    private static byte[] ReadInnerBlock(Stream stream, long offset, int length)
    {
        if (stream is null || offset < 0 || length <= 0 || offset >= stream.Length)
            return [];
        int avail = (int)Math.Min((long)length, stream.Length - offset);
        var buffer = new byte[avail];
        stream.Position = offset;
        int read = 0;
        while (read < avail)
        {
            int n = stream.Read(buffer, read, avail - read);
            if (n <= 0) break;
            read += n;
        }
        if (read < avail) Array.Resize(ref buffer, read);
        return buffer;
    }

    // ---- internals -------------------------------------------------------------------------

    private static void WriteU32(Span<byte> dst, int offset, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(dst.Slice(offset, 4), value);

    /// <summary>
    /// Emits one TLV record: 4-byte tag stored in reverse character order, version byte, three zero
    /// bytes, then the payload length as a little-endian u64 and the payload itself.
    /// </summary>
    private static void WriteRecord(List<byte> dst, string tag, byte version, ReadOnlySpan<byte> payload)
    {
        dst.Add((byte)tag[3]);
        dst.Add((byte)tag[2]);
        dst.Add((byte)tag[1]);
        dst.Add((byte)tag[0]);
        dst.Add(version);
        dst.Add(0);
        dst.Add(0);
        dst.Add(0);
        Span<byte> len = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(len, (ulong)payload.Length);
        for (int i = 0; i < 8; i++) dst.Add(len[i]);
        foreach (byte b in payload) dst.Add(b);
    }

    /// <summary>AES-128-XTS over the whole buffer as one data unit (length must be a multiple of 16).
    /// With <paramref name="encrypt"/> false this decrypts instead (identical pipeline, inverse
    /// data-cipher direction).</summary>
    private static byte[] AesXtsTransform(byte[] input, bool encrypt) =>
        AesXtsTransform(input, Meta18DataKey, Meta18TweakKey, Meta18Tweak, encrypt);

    private static byte[] AesXtsTransform(
        byte[] input, ReadOnlySpan<byte> dataKey, ReadOnlySpan<byte> tweakKey,
        ReadOnlySpan<byte> initialTweak, bool encrypt)
    {
        using Aes aesData = Aes.Create();
        aesData.Mode = CipherMode.ECB;
        aesData.Padding = PaddingMode.None;
        aesData.Key = dataKey.ToArray();
        using Aes aesTweak = Aes.Create();
        aesTweak.Mode = CipherMode.ECB;
        aesTweak.Padding = PaddingMode.None;
        aesTweak.Key = tweakKey.ToArray();

        using ICryptoTransform dataCipher = encrypt ? aesData.CreateEncryptor() : aesData.CreateDecryptor();
        using ICryptoTransform tweakEnc = aesTweak.CreateEncryptor();

        byte[] tweak = tweakEnc.TransformFinalBlock(initialTweak.ToArray(), 0, 16);
        var output = new byte[input.Length];
        var buffer = new byte[16];
        for (int i = 0; i < input.Length; i += 16)
        {
            for (int j = 0; j < 16; j++) buffer[j] = (byte)(input[i + j] ^ tweak[j]);
            byte[] transformed = dataCipher.TransformFinalBlock(buffer, 0, 16);
            for (int j = 0; j < 16; j++) output[i + j] = (byte)(transformed[j] ^ tweak[j]);
            MultiplyTweakByAlpha(tweak);
        }
        return output;
    }

    /// <summary>Multiplies the little-endian 128-bit tweak by x in GF(2^128) (reduction poly 0x87).</summary>
    private static void MultiplyTweakByAlpha(byte[] tweak)
    {
        int carry = 0;
        for (int i = 0; i < 16; i++)
        {
            int b = tweak[i];
            tweak[i] = (byte)(((b << 1) | carry) & 0xFF);
            carry = (b >> 7) & 1;
        }
        if (carry != 0) tweak[0] ^= 0x87;
    }
}
