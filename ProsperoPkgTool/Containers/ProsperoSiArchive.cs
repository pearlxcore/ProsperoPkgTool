using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using ProsperoPkgTool.Crypto;

namespace ProsperoPkgTool.Containers;

/// <summary>One member (stored file) of the SI ZIP.</summary>
/// <param name="Path">ZIP entry path with forward slashes (e.g. <c>common/etc/pfsimage.xml</c>).</param>
/// <param name="Content">Raw, already-final bytes of the member.</param>
public readonly record struct ProsperoSiMember(string Path, byte[] Content);

/// <summary>
/// One <c>&lt;entry&gt;</c> of the <c>pfsimage.xml</c> <c>&lt;entries&gt;</c> table: a single CNT
/// (sce_sys) file with its byte offset inside the container body and size.
/// </summary>
public readonly record struct ProsperoPfsImageEntry(string Name, long Offset, long Size);

/// <summary>
/// Self-consistent inputs for the <c>pfsimage.xml</c> <c>&lt;chunkinfo&gt;</c> section, which
/// describes the PlayGo chunk layout of a package (single scenario / single chunk for a debug
/// nwonly image). All sizes are derived from the finalized image geometry.
/// </summary>
public sealed class ProsperoChunkInfoModel
{
    public int PlayGoChunkDatSize { get; set; }
    public string Sdk { get; set; } = "0x00850000";
    public string Disps { get; set; } = "0x0011";
    public ulong LanguageMask { get; set; } = 0xffffffffffffffff;
    public long TotalSize { get; set; }
    public long Outer0Size { get; set; }
    public long Outer1Size { get; set; }
}

/// <summary>
/// Structural inputs for the reproducible parts of <c>common/etc/pfsimage.xml</c>. Every
/// builder-known field is emitted verbatim; keyed finalization products (body/content/game/header/
/// system/param/package/sblock/fixed-info digests) are emitted verbatim when supplied, otherwise as
/// all-zero placeholders and reported via the warnings collection.
/// </summary>
public sealed class ProsperoPfsImageXmlOptions
{
    public string ContentId { get; set; } = "";
    public string TitleName { get; set; } = "";
    public string ContentVersion { get; set; } = "01.000.000";
    public string DrmType { get; set; } = "none";
    public string? ApplicationDrmType { get; set; }
    public string ContentType { get; set; } = "PS5GD";
    public string ApplicationType { get; set; } = "free";
    public long PackageSize { get; set; }
    public long PfsImageOffset { get; set; } = 0x10000;
    public long PfsImageSize { get; set; }
    public byte[]? PfsImageSeed { get; set; }
    public string MasterVersion { get; set; } = "01.00";
    public string? LongName { get; set; }
    public ulong LongNameMasterValue { get; set; }
    public string RequiredSystemVersion { get; set; } = "00.000.000.00000000";
    public string RequiredSystemSoftwareVersion { get; set; } = "0x0000000000000000";
    public string SdkVersion { get; set; } = "0x0000000000000000";
    public uint VersionDate { get; set; } = 0x20200722;
    public uint VersionHash { get; set; } = 0x01fe52e9;
    public long ContainerSize { get; set; } = 0x50000;
    public long MandatorySize { get; set; }
    public long BodyOffset { get; set; } = 0x2000;
    public long SupplementalOffset { get; set; } = 0x50000;
    public IReadOnlyList<ProsperoPfsImageEntry> Entries { get; set; } = [];

    public byte[]? BodyDigest { get; set; }
    public byte[]? ContentDigest { get; set; }
    public byte[]? GameDigest { get; set; }
    public byte[]? HeaderDigest { get; set; }
    public byte[]? SystemDigest { get; set; }
    public byte[]? ParamDigest { get; set; }
    public byte[]? PackageDigest { get; set; }
    public byte[]? SblockDigest { get; set; }
    public byte[]? FixedInfoDigest { get; set; }

    /// <summary>Assembled inner-image result (preferred). When supplied, the
    /// <c>&lt;nested-image&gt;</c> section is emitted from the node list / placements.</summary>
    public ProsperoInnerImageAssembler.InnerImageResult? NestedInner { get; set; }

    /// <summary>Outer PFS tree snapshot for the <c>&lt;pfs-image&gt;</c> section; omitted when null.</summary>
    public OuterPfsTreeInfo? OuterPfsTree { get; set; }

    public ProsperoChunkInfoModel? ChunkInfo { get; set; }
}

/// <summary>Snapshot of the outer PFS tree for XML introspection.</summary>
public sealed class OuterPfsTreeInfo
{
    public int BlockSize { get; init; } = ProsperoOuterPfsBuilder.BlockSize;
    public long ImageBlocks { get; init; }
    public int InodeCount { get; init; }
    public int DinodeBlockCount { get; init; } = 1;
    public int DinodeBlock { get; init; }
    public long DinodeSize { get; init; } = ProsperoOuterPfsBuilder.BlockSize;
    public uint DinodeFlags { get; init; } = 0x0002000c;
    public uint RootInode { get; init; }
    public byte[]? Seed { get; init; }
    public byte[]? SuperblockIcv { get; init; }
    public bool Signed { get; init; }
    public bool Encrypted { get; init; }
    public OuterPfsTreeNode? Root { get; init; }
}

public sealed class OuterPfsTreeNode
{
    public string Name { get; init; } = "";
    public bool IsDirectory { get; init; }
    public uint Inode { get; init; }
    public long StoredSize { get; init; }
    public long PlainSize { get; init; }
    public uint Flags { get; init; }
    public ushort Mode { get; init; }
    public ushort Nlink { get; init; } = 1;
    public int StartBlock { get; init; }
    public bool Internal { get; init; }
    public List<OuterPfsTreeNode> Children { get; } = [];
}

/// <summary>
/// Builds the debug-variant SI (install-metadata) segment — a ZIP container with a fixed member
/// set. The custom STORED ZIP writer here emits the exact framing the console loader expects:
/// every member STORED, no extra fields, central-directory "version made by" = 0, deterministic
/// DOS time/date. <see cref="BuildDebugSiSegment"/> is the high-level entry point that builds the
/// full member set from values the package builder has already produced; the ZIP writer,
/// <c>pfsimage.xml</c> emitter, and member assembler are the lower-level pieces.
/// </summary>
public static class ProsperoSiArchive
{
    public const string PfsImageXmlPath = "common/etc/pfsimage.xml";
    public const string PlayGoChunkDatPath = "common/etc/playgo-chunk.dat";
    public const string NapsMeta18Path = "common/etc/naps_meta_18.dat";

    private const int ChunkCrcBlockSize = 0x10000;
    private const int SupplementalOffset = 0x50000;

    /// <summary>
    /// Builds the canonical debug SI member set. <paramref name="pfsImageXml"/> is written unless
    /// <paramref name="includePfsImageXml"/> is false (the reference engine omits it);
    /// <paramref name="playGoChunkDat"/> is copied when present; the keyed NAPS blobs are included
    /// only when supplied and never fabricated. The per-content-id <c>playgo-chunk.crc</c> is either
    /// supplied verbatim or, when <paramref name="finalizedMountImage"/> is given, computed
    /// reproducibly from it with CRC-32C.
    /// </summary>
    public static IReadOnlyList<ProsperoSiMember> BuildMembers(
        string contentId,
        byte[]? pfsImageXml,
        byte[]? playGoChunkDat = null,
        byte[]? napsMeta18 = null,
        byte[]? napsMeta300 = null,
        byte[]? playGoChunkCrc = null,
        ReadOnlySpan<byte> finalizedMountImage = default,
        bool includePfsImageXml = true)
    {
        ArgumentException.ThrowIfNullOrEmpty(contentId);

        playGoChunkCrc ??= finalizedMountImage is { Length: > 0 }
            ? BuildChunkCrc(finalizedMountImage)
            : null;

        var members = new List<ProsperoSiMember>();

        if (napsMeta18 is not null)
            members.Add(new(NapsMeta18Path, napsMeta18));
        if (napsMeta300 is not null)
        {
            foreach (int id in ProsperoNapsMeta.Meta300Ids)
                members.Add(new($"common/etc/naps_meta_{id}.dat", napsMeta300));
        }

        if (includePfsImageXml && pfsImageXml is not null)
            members.Add(new(PfsImageXmlPath, pfsImageXml));

        if (playGoChunkDat is not null)
            members.Add(new(PlayGoChunkDatPath, playGoChunkDat));
        if (playGoChunkCrc is not null)
            members.Add(new($"config/{contentId}/playgo-chunk.crc", playGoChunkCrc));

        return members;
    }

    /// <summary>
    /// Builds the complete debug SI segment bytes from values the package build has already
    /// produced. Returns the raw ZIP container bytes ready to append to the FIH.
    /// </summary>
    /// <param name="pfsImageXml">Fully-populated reproducible pfsimage.xml options.</param>
    /// <param name="playGoChunkDat">CNT PlayGo chunk descriptor bytes, or null to omit.</param>
    /// <param name="mountImage">The finalized FIH+PFS+CNT mount image.</param>
    /// <param name="innerImageSize">Block-aligned inner <c>pfs_image.dat</c> size (FIH 0xA0).</param>
    /// <param name="contentFiles">Inner content files for the naps_meta_18 file/fstr table.</param>
    /// <param name="warnings">Optional sink for all-zero-placeholder notices.</param>
    public static byte[] BuildDebugSiSegment(
        ProsperoPfsImageXmlOptions pfsImageXml, byte[]? playGoChunkDat,
        ReadOnlySpan<byte> mountImage, ulong innerImageSize,
        IReadOnlyList<(string Path, long Size)> contentFiles,
        ICollection<string>? warnings = null, bool includePfsImageXml = true)
    {
        ArgumentNullException.ThrowIfNull(pfsImageXml);

        byte[]? napsMeta300 = null;
        if (innerImageSize >= ProsperoNapsMeta.PfsBlockSizeConst)
            napsMeta300 = ProsperoNapsMeta.BuildMeta300FromInnerImageSize(innerImageSize);

        byte[]? napsMeta18 = null;
        if (innerImageSize >= ProsperoNapsMeta.PfsBlockSizeConst && mountImage.Length >= 0x10000)
        {
            // Forward the assembled inner result so meta18 describes the compressed inner-image
            // NAPS block map (placements + holes + metadata ublocks), matching the Sony fixture;
            // callers without an assembled inner fall back to the outer identity map (null).
            byte[] blob = ProsperoNapsMeta.BuildMeta18WithMetadataEntry(
                innerImageSize, mountImage, contentFiles, pfsImageXml.PfsImageSize, pfsImageXml.NestedInner);
            if (blob.Length > 0)
                napsMeta18 = blob;
        }

        byte[]? xmlBytes = includePfsImageXml
            ? Encoding.UTF8.GetBytes(BuildPfsImageXml(pfsImageXml, warnings))
            : null;

        IReadOnlyList<ProsperoSiMember> members = BuildMembers(
            pfsImageXml.ContentId,
            xmlBytes,
            playGoChunkDat: playGoChunkDat,
            napsMeta18: napsMeta18,
            napsMeta300: napsMeta300,
            finalizedMountImage: mountImage,
            includePfsImageXml: includePfsImageXml);

        return WriteZip(members);
    }

    /// <summary>
    /// Builds <c>config/&lt;content-id&gt;/playgo-chunk.crc</c>: 4 bytes (LE u32) per 64 KiB
    /// block of the finalized mount image, in block order. CRC-32C per block; trailing partial
    /// blocks reduce over their actual length.
    /// </summary>
    public static byte[] BuildChunkCrc(ReadOnlySpan<byte> mountImage)
    {
        if (mountImage.Length == 0)
            return [];

        int blockCount = (mountImage.Length + ChunkCrcBlockSize - 1) / ChunkCrcBlockSize;
        byte[] crc = new byte[blockCount * 4];
        for (int i = 0; i < blockCount; i++)
        {
            int start = i * ChunkCrcBlockSize;
            int len = Math.Min(ChunkCrcBlockSize, mountImage.Length - start);
            uint value = ProsperoCrc32C.Compute(mountImage.Slice(start, len));
            BinaryPrimitives.WriteUInt32LittleEndian(crc.AsSpan(i * 4), value);
        }
        return crc;
    }

    /// <summary>
    /// Streaming counterpart of <see cref="BuildChunkCrc(ReadOnlySpan{byte})"/>: computes the same
    /// per-64-KiB-block CRC-32C table over <paramref name="mountStream"/> without materializing the
    /// image. Reads exactly <paramref name="length"/> bytes from the stream's current position.
    /// </summary>
    public static byte[] BuildChunkCrc(Stream mountStream, long length)
    {
        ArgumentNullException.ThrowIfNull(mountStream);
        if (length <= 0)
            return [];

        long blockCount = (length + ChunkCrcBlockSize - 1) / ChunkCrcBlockSize;
        byte[] crc = new byte[blockCount * 4];
        byte[] buffer = new byte[ChunkCrcBlockSize];
        long position = 0;
        for (long i = 0; i < blockCount; i++)
        {
            int len = (int)Math.Min(ChunkCrcBlockSize, length - position);
            int read = ReadFully(mountStream, buffer, len);
            uint value = ProsperoCrc32C.Compute(buffer.AsSpan(0, read));
            BinaryPrimitives.WriteUInt32LittleEndian(crc.AsSpan((int)(i * 4)), value);
            position += len;
        }
        return crc;
    }

    /// <summary>
    /// Streaming counterpart of <see cref="BuildDebugSiSegment"/> for a file-backed mount image.
    /// The <c>naps_meta_18</c> root/outer digests (<c>rhsh</c>/<c>obdg</c>) and the
    /// <c>playgo-chunk.crc</c> table are computed from <paramref name="mountStream"/> (+ the supplied
    /// plaintext superblock block) rather than an in-memory span; the stream position is saved and
    /// restored.
    /// </summary>
    public static byte[] BuildDebugSiSegmentFromStream(
        ProsperoPfsImageXmlOptions pfsImageXml, byte[]? playGoChunkDat,
        Stream mountStream, long mountLength, ulong innerImageSize,
        IReadOnlyList<(string Path, long Size)> contentFiles,
        byte[]? outerSuperblockBlock, ICollection<string>? warnings = null,
        bool includePfsImageXml = true)
    {
        ArgumentNullException.ThrowIfNull(pfsImageXml);
        ArgumentNullException.ThrowIfNull(mountStream);

        long saved = mountStream.CanSeek ? mountStream.Position : 0;

        byte[]? napsMeta300 = null;
        if (innerImageSize >= ProsperoNapsMeta.PfsBlockSizeConst)
            napsMeta300 = ProsperoNapsMeta.BuildMeta300FromInnerImageSize(innerImageSize);

        byte[]? napsMeta18 = null;
        if (innerImageSize >= ProsperoNapsMeta.PfsBlockSizeConst && mountLength >= 0x10000)
        {
            byte[]? rhshOverride = null;
            if (outerSuperblockBlock is { Length: > 0 })
            {
                var rhshBody = new byte[0xB0];
                Sha3.Sha3_256(outerSuperblockBlock).CopyTo(rhshBody);
                rhshOverride = rhshBody;
            }

            var obdgBody = new byte[0x80];
            mountStream.Position = 0;
            ProsperoNapsMeta.Sha3Stream(mountStream).CopyTo(obdgBody);

            byte[] blob = ProsperoNapsMeta.BuildMeta18WithMetadataEntry(
                innerImageSize, default, contentFiles, pfsImageXml.PfsImageSize, pfsImageXml.NestedInner,
                mountLengthOverride: mountLength, obdgOverride: obdgBody, rhshOverride: rhshOverride);
            if (blob.Length > 0)
                napsMeta18 = blob;
        }

        byte[]? xmlBytes = includePfsImageXml
            ? Encoding.UTF8.GetBytes(BuildPfsImageXml(pfsImageXml, warnings))
            : null;

        byte[]? chunkCrc = null;
        if (mountLength > 0)
        {
            mountStream.Position = 0;
            chunkCrc = BuildChunkCrc(mountStream, mountLength);
        }

        IReadOnlyList<ProsperoSiMember> members = BuildMembers(
            pfsImageXml.ContentId,
            xmlBytes,
            playGoChunkDat: playGoChunkDat,
            napsMeta18: napsMeta18,
            napsMeta300: napsMeta300,
            playGoChunkCrc: chunkCrc,
            includePfsImageXml: includePfsImageXml);

        byte[] result = WriteZip(members);

        if (mountStream.CanSeek)
            mountStream.Position = saved;
        return result;
    }

    private static int ReadFully(Stream stream, byte[] buffer, int length)
    {
        int read = 0;
        while (read < length)
        {
            int n = stream.Read(buffer, read, length - read);
            if (n <= 0)
                break;
            read += n;
        }
        return read;
    }

    // ---- pfsimage.xml emission -------------------------------------------------------------

    public static string BuildPfsImageXml(ProsperoPfsImageXmlOptions options, ICollection<string>? warnings = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentException.ThrowIfNullOrEmpty(options.ContentId);

        NoteIfPlaceholder(options.ContentDigest, "content-digest", reproducible: true);
        NoteIfPlaceholder(options.GameDigest, "game-digest", reproducible: true);
        NoteIfPlaceholder(options.HeaderDigest, "header-digest", reproducible: true);
        NoteIfPlaceholder(options.SystemDigest, "system-digest", reproducible: true);
        NoteIfPlaceholder(options.ParamDigest, "param-digest", reproducible: true);
        NoteIfPlaceholder(options.PackageDigest, "package-digest", reproducible: true);
        NoteIfPlaceholder(options.BodyDigest, "body-digest", reproducible: true);

        string seedBlock = Indent(FormatDigest(
            options.PfsImageSeed is { Length: > 0 } s ? s : default), "      ");

        long containerSize = options.ContainerSize;
        long bodyOffset = options.BodyOffset;
        long bodySize = containerSize - bodyOffset;
        long containerOffset = options.PfsImageOffset + options.PfsImageSize;
        long mountImageSize = containerOffset + containerSize;

        string longName = options.LongName ?? BuildLongName(options);

        var sb = new StringBuilder(8192);
        sb.Append("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        sb.Append("<package-configuration version=\"1.0\" type=\"package-info\">\n");
        sb.Append($"  <config version=\"{options.ContentVersion}\" metadata=\"0\" primary=\"yes\">\n");
        sb.Append($"    <content-id>{options.ContentId}</content-id>\n");
        sb.Append($"    <primary-id>{options.ContentId}</primary-id>\n");
        sb.Append($"    <longname>{longName}</longname>\n");
        sb.Append($"    <required-system-version>{options.RequiredSystemVersion}</required-system-version>\n");
        sb.Append($"    <drm-type>{options.DrmType}</drm-type>\n");
        sb.Append($"    <content-type>{options.ContentType}</content-type>\n");
        sb.Append($"    <application-type>{options.ApplicationType}</application-type>\n");
        sb.Append("    <num-of-images>1</num-of-images>\n");
        sb.Append($"    <package-size>{options.PackageSize}</package-size>\n");
        sb.Append($"    <version-date>0x{options.VersionDate:x8}</version-date>\n");
        sb.Append($"    <version-hash>0x{options.VersionHash:x8}</version-hash>\n");
        sb.Append("  </config>\n");
        sb.Append("  <digests version=\"1.2\" major-param-version=\"0\">\n");
        sb.Append($"    <content-digest>\n      {Indent(FormatDigest(options.ContentDigest), "      ")}\n    </content-digest>\n");
        sb.Append($"    <game-digest>\n      {Indent(FormatDigest(options.GameDigest), "      ")}\n    </game-digest>\n");
        sb.Append($"    <header-digest>\n      {Indent(FormatDigest(options.HeaderDigest), "      ")}\n    </header-digest>\n");
        sb.Append($"    <system-digest>\n      {Indent(FormatDigest(options.SystemDigest), "      ")}\n    </system-digest>\n");
        sb.Append($"    <param-digest>\n      {Indent(FormatDigest(options.ParamDigest), "      ")}\n    </param-digest>\n");
        sb.Append($"    <package-digest>\n      {Indent(FormatDigest(options.PackageDigest), "      ")}\n    </package-digest>\n");
        sb.Append("  </digests>\n");
        sb.Append("  <params>\n");
        sb.Append($"    <applicationDrmType>{options.ApplicationDrmType ?? options.ApplicationType}</applicationDrmType>\n");
        sb.Append($"    <contentId>{options.ContentId}</contentId>\n");
        sb.Append($"    <contentVersion>{options.ContentVersion}</contentVersion>\n");
        sb.Append($"    <masterVersion>{options.MasterVersion}</masterVersion>\n");
        sb.Append($"    <requiredSystemSoftwareVersion>{options.RequiredSystemSoftwareVersion}</requiredSystemSoftwareVersion>\n");
        sb.Append($"    <sdkVersion>{options.SdkVersion}</sdkVersion>\n");
        sb.Append($"    <titleName>{options.TitleName}</titleName>\n");
        sb.Append("  </params>\n");
        sb.Append("  <container nth-of-image=\"1\">\n");
        sb.Append($"    <container-size>{Hex16(containerSize)}</container-size>\n");
        sb.Append($"    <mandatory-size>{Hex16(options.MandatorySize)}</mandatory-size>\n");
        sb.Append($"    <body-offset>{Hex16(bodyOffset)}</body-offset>\n");
        sb.Append($"    <body-size>{Hex16(bodySize)}</body-size>\n");
        sb.Append($"    <body-digest>\n      {Indent(FormatDigest(options.BodyDigest), "      ")}\n    </body-digest>\n");
        sb.Append($"    <promote-size>{Hex8(containerSize)}</promote-size>\n");
        sb.Append("  </container>\n");
        sb.Append("  <mount-image nth-of-image=\"1\" nested-image=\"yes\">\n");
        sb.Append("    <pfs-offset-align>0x0000000000010000</pfs-offset-align>\n");
        sb.Append("    <pfs-size-align>0x0000000000010000</pfs-size-align>\n");
        sb.Append($"    <pfs-image-offset>{Hex16(options.PfsImageOffset)}</pfs-image-offset>\n");
        sb.Append($"    <pfs-image-size>{Hex16(options.PfsImageSize)}</pfs-image-size>\n");
        sb.Append("    <fixed-info-size>0x00010000</fixed-info-size>\n");
        sb.Append($"    <pfs-image-seed>\n      {seedBlock}\n    </pfs-image-seed>\n");
        sb.Append($"    <sblock-digest>\n      {Indent(FormatDigest(options.SblockDigest ?? options.GameDigest), "      ")}\n    </sblock-digest>\n");
        sb.Append($"    <fixed-info-digest>\n      {Indent(FormatDigest(options.FixedInfoDigest), "      ")}\n    </fixed-info-digest>\n");
        sb.Append($"    <mount-image-offset>{Hex16(0)}</mount-image-offset>\n");
        sb.Append($"    <mount-image-size>{Hex16(mountImageSize)}</mount-image-size>\n");
        sb.Append($"    <container-offset>{Hex16(containerOffset)}</container-offset>\n");
        sb.Append($"    <supplemental-offset>{Hex16(options.SupplementalOffset)}</supplemental-offset>\n");
        sb.Append("  </mount-image>\n");
        if (options.Entries is { Count: > 0 } entries)
        {
            sb.Append($"  <entries nth-of-image=\"1\" num=\"{entries.Count}\">\n");
            foreach (ProsperoPfsImageEntry e in entries)
                sb.Append($"    <entry offset=\"{Hex8(e.Offset)}\" size=\"{Hex8(e.Size)}\" name=\"{e.Name}\"/>\n");
            sb.Append("  </entries>\n");
        }
        AppendIntrospectionSections(sb, options);
        sb.Append("</package-configuration>\n");
        return sb.ToString();

        void NoteIfPlaceholder(byte[]? value, string field, bool reproducible)
        {
            if (value is null || value.Length == 0)
                warnings?.Add(reproducible
                    ? $"pfsimage.xml <{field}> emitted as all-zero placeholder (reproducible — supply it from the builder/produced CNT)."
                    : $"pfsimage.xml <{field}> emitted as all-zero placeholder (keyed finalization product, not reproducible off-console).");
        }
    }

    /// <summary>
    /// Derives the <c>&lt;longname&gt;</c>: <c>{content-id}-C{version-digits}-M{master-16-hex}-{type-code}</c>,
    /// where version digits are the content version with dots removed and the type code drops a
    /// leading <c>PS5</c> (so <c>PS5GD</c> becomes <c>GD</c>).
    /// </summary>
    private static string BuildLongName(ProsperoPfsImageXmlOptions o)
    {
        string versionDigits = o.ContentVersion.Replace(".", "", StringComparison.Ordinal);
        string typeCode = o.ContentType.StartsWith("PS5", StringComparison.OrdinalIgnoreCase)
            ? o.ContentType[3..]
            : o.ContentType;
        string master16 = o.LongNameMasterValue.ToString("x16", CultureInfo.InvariantCulture);
        return $"{o.ContentId}-C{versionDigits}-M{master16}-{typeCode}";
    }

    private static void AppendIntrospectionSections(StringBuilder sb, ProsperoPfsImageXmlOptions options)
    {
        if (options.ChunkInfo is { } chunk)
            AppendChunkInfo(sb, options.ContentId, chunk);
        if (options.OuterPfsTree is { } outer)
            AppendPfsImage(sb, outer, options.PfsImageOffset);
        if (options.NestedInner is { } innerResult)
            AppendNestedImageFromInner(sb, innerResult);
    }

    private static void AppendChunkInfo(StringBuilder sb, string contentId, ProsperoChunkInfoModel c)
    {
        string lang = "0x" + c.LanguageMask.ToString("x16", CultureInfo.InvariantCulture);
        sb.Append($"  <chunkinfo size=\"{c.PlayGoChunkDatSize}\" nested=\"true\" sdk=\"{c.Sdk}\" disps=\"{c.Disps}\">\n");
        sb.Append($"    <contentid>{contentId}</contentid>\n");
        sb.Append($"    <languages default=\"1\">{lang}</languages>\n");
        sb.Append("    <scenarios num=\"1\" default=\"0\" groups=\"0\">\n");
        sb.Append("      <scenario id=\"0\" type=\"33\" name=\"Scenario #0\">\n");
        sb.Append($"        <overall initials=\"1\" num=\"1\" init-size=\"{c.TotalSize}\" total=\"{c.TotalSize}\">0</overall>\n");
        sb.Append($"        <default initials=\"1\" num=\"1\" init-size=\"{c.TotalSize}\" total=\"{c.TotalSize}\">0</default>\n");
        sb.Append("      </scenario>\n");
        sb.Append("    </scenarios>\n");
        sb.Append("    <chunks num=\"1\" default=\"0xffffffffffffffff\">\n");
        sb.Append($"      <chunk id=\"0\" flag=\"0x80\" locus=\"0x03\" language=\"{lang}\" disps=\"{c.Disps}\" num=\"2\" size=\"{c.TotalSize}\" name=\"Chunk #0\">0 1</chunk>\n");
        sb.Append("    </chunks>\n");
        sb.Append("    <outers num=\"2\" overlapped=\"0\" language-overlapped=\"0\">\n");
        sb.Append($"      <outer id=\"0\" image=\"0\" offset=\"{Hex16Blob(0)}\" size=\"{Hex16Blob(c.Outer0Size)}\" chunks=\"1\"/>\n");
        sb.Append($"      <outer id=\"1\" image=\"0\" offset=\"{Hex16Blob(c.Outer0Size)}\" size=\"{Hex16Blob(c.Outer1Size)}\" chunks=\"1\"/>\n");
        sb.Append("    </outers>\n");
        sb.Append("  </chunkinfo>\n");
    }

    private static void AppendPfsImage(StringBuilder sb, OuterPfsTreeInfo info, long pfsImageOffset)
    {
        long metadata = (long)info.DinodeBlock * info.BlockSize;
        sb.Append($"  <pfs-image version=\"2\" readonly=\"true\" offset=\"{pfsImageOffset}\" metadata=\"{metadata}\">\n");
        string signed = info.Signed ? " signed=\"true\"" : "";
        string encrypted = info.Encrypted ? " encrypted=\"true\"" : "";
        sb.Append($"    <sblock{signed}{encrypted} ignore-case=\"true\" index-size=\"32\" blocks=\"{info.DinodeBlockCount}\" backups=\"0\">\n");
        sb.Append($"      <image-size block-size=\"{info.BlockSize}\" num=\"{info.ImageBlocks}\">{Hex16Blob(info.ImageBlocks * info.BlockSize)}</image-size>\n");
        sb.Append($"      <super-inode blocks=\"{info.DinodeBlockCount}\" inodes=\"{info.InodeCount}\" root=\"{info.RootInode}\">\n");
        sb.Append($"        <inode size=\"{info.DinodeSize}\" links=\"1\" mode=\"0x0000\" imode=\"{Imode(info.DinodeFlags)}\" index=\"{info.DinodeBlock}\"/>\n");
        sb.Append("      </super-inode>\n");
        sb.Append($"      <seed>{Hex16Blob(info.Seed, 16)}</seed>\n");
        sb.Append($"      <icv>{Hex16Blob(info.SuperblockIcv, 32)}</icv>\n");
        sb.Append("    </sblock>\n");
        if (info.Root is { } root)
            AppendOuterNode(sb, root, info.BlockSize, "    ");
        sb.Append("  </pfs-image>\n");
    }

    private static void AppendOuterNode(StringBuilder sb, OuterPfsTreeNode n, int blockSize, string pad)
    {
        string child = pad + "  ";
        if (n.IsDirectory)
        {
            string tag = n.Name.Length == 0 ? "root" : "dir";
            sb.Append($"{pad}<{tag} size=\"{n.StoredSize}\" links=\"{n.Nlink}\" imode=\"{Imode(n.Flags)}\" index=\"{n.StartBlock}\" inode=\"{n.Inode}\" name=\"{n.Name}\">\n");
            foreach (OuterPfsTreeNode c in n.Children)
                AppendOuterNode(sb, c, blockSize, child);
            sb.Append($"{pad}</{tag}>\n");
        }
        else
        {
            sb.Append($"{pad}<file size=\"{n.StoredSize}\" imode=\"{Imode(n.Flags)}\" index=\"{n.StartBlock}\" inode=\"{n.Inode}\" name=\"{n.Name}\"/>\n");
        }
    }

    /// <summary>
    /// Emits the <c>&lt;nested-image&gt;</c> section from the assembled inner image result
    /// (inode/placement metadata). Files carry <c>offset</c> = on-disk packed data offset (from
    /// placements), <c>poffset</c> = logical mount offset, afid and imode. Directories carry
    /// <c>poffset</c> only.
    /// </summary>
    private static void AppendNestedImageFromInner(
        StringBuilder sb, ProsperoInnerImageAssembler.InnerImageResult inner)
    {
        const int BLK = ProsperoInnerImageAssembler.BlockSize;
        IReadOnlyList<ProsperoInnerImageAssembler.MetaNodeInfo> nodes = inner.Nodes;
        long metaBase = inner.MetaBaseLogical;

        var onDiskByLogical = new Dictionary<ulong, long>();
        foreach (ProsperoInnerImageAssembler.Placement p in inner.Placements)
            onDiskByLogical[(ulong)p.LogicalOffset] = p.OnDiskOffset;

        var childrenOf = new Dictionary<int, List<ProsperoInnerImageAssembler.MetaNodeInfo>>();
        ProsperoInnerImageAssembler.MetaNodeInfo? superRoot = null;
        foreach (ProsperoInnerImageAssembler.MetaNodeInfo n in nodes)
        {
            if (n.IsDirectory && n.Name.Length == 0) { superRoot = n; continue; }
            if (!childrenOf.TryGetValue(n.ParentInode, out var list))
                childrenOf[n.ParentInode] = list = new List<ProsperoInnerImageAssembler.MetaNodeInfo>();
            list.Add(n);
        }
        if (superRoot is null) return;

        int regularFiles = nodes.Count(n => !n.IsDirectory && n.ParentInode != -1);
        long metaPlain = inner.MetadataPlaintext.Length;
        long metaComp = inner.CompressedMetadata.Length;

        sb.Append("  <nested-image version=\"2\" readonly=\"true\" offset=\"0\">\n");
        sb.Append("    <sblock ignore-case=\"true\" index-size=\"32\" blocks=\"1\" backups=\"0\">\n");
        sb.Append($"      <image-size block-size=\"{BLK}\" num=\"{inner.Ndblock}\">{Hex16Blob(inner.Ndblock * BLK)}</image-size>\n");
        sb.Append($"      <super-inode blocks=\"1\" inodes=\"{nodes.Count}\" root=\"0\">\n");
        sb.Append($"        <inode size=\"{BLK}\" links=\"1\" mode=\"0x0000\" imode=\"0x00000010\" index=\"{metaBase / BLK + 1}\"/>\n");
        sb.Append("      </super-inode>\n");
        sb.Append("    </sblock>\n");
        sb.Append($"    <metadata size=\"{metaComp}\" plain=\"{metaPlain}\" comp=\"{CompLabel(metaComp, metaPlain, BLK)}\" offset=\"{inner.MetadataOnDiskOffset}\" poffset=\"{metaBase}\" afid=\"{regularFiles + 1}\"/>\n");
        AppendInnerMountNode(sb, superRoot, childrenOf, onDiskByLogical, "    ");
        sb.Append("  </nested-image>\n");
    }

    private static void AppendInnerMountNode(
        StringBuilder sb, ProsperoInnerImageAssembler.MetaNodeInfo n,
        Dictionary<int, List<ProsperoInnerImageAssembler.MetaNodeInfo>> childrenOf,
        Dictionary<ulong, long> onDiskByLogical, string pad)
    {
        const int BLK = ProsperoInnerImageAssembler.BlockSize;
        string child = pad + "  ";
        if (n.IsDirectory)
        {
            bool isRoot = n.Name.Length == 0;
            int key = isRoot ? -1 : (int)n.Inode;
            string tag = isRoot ? "root" : "dir";
            string mode = isRoot ? "" : $" mode=\"{Mode4(n.Mode)}\"";
            sb.Append($"{pad}<{tag} plain=\"{BLK}\" poffset=\"{n.LogicalOffset}\" links=\"{n.Nlink}\"{mode} imode=\"{Imode(n.Flags)}\" inode=\"{n.Inode}\" name=\"{n.Name}\">\n");
            if (childrenOf.TryGetValue(key, out var kids))
                foreach (ProsperoInnerImageAssembler.MetaNodeInfo c in kids.OrderBy(c => c.Inode))
                    AppendInnerMountNode(sb, c, childrenOf, onDiskByLogical, child);
            sb.Append($"{pad}</{tag}>\n");
        }
        else if (n.ParentInode == -1)
        {
            // PFS-internal flat-path / afid table (no data-region file, no afid attribute).
            sb.Append($"{pad}<file plain=\"{n.Size}\" poffset=\"{n.LogicalOffset}\" imode=\"{Imode(n.Flags)}\" inode=\"{n.Inode}\" name=\"{n.Name}\"/>\n");
        }
        else
        {
            long onDisk = onDiskByLogical.TryGetValue(n.LogicalOffset, out var od) ? od : (long)n.LogicalOffset;
            sb.Append($"{pad}<file size=\"{n.Size}\" plain=\"{n.Size}\" offset=\"{onDisk}\" mode=\"{Mode4(n.Mode)}\" imode=\"{Imode(n.Flags)}\" inode=\"{n.Inode}\" afid=\"{n.Afid}\" chunk=\"0\" name=\"{n.Name}\"/>\n");
        }
    }

    /// <summary>
    /// Formats a 32-byte digest exactly the way <c>pfsimage.xml</c> does: lowercase
    /// <c>0xNN 0xNN …</c>, sixteen bytes per line. An empty span yields an all-zero block.
    /// </summary>
    public static string FormatDigest(ReadOnlySpan<byte> digest)
    {
        ReadOnlySpan<byte> src = digest.IsEmpty ? stackalloc byte[32] : digest;
        var sb = new StringBuilder(src.Length * 5);
        for (int i = 0; i < src.Length; i++)
        {
            if (i != 0) sb.Append(i % 16 == 0 ? '\n' : ' ');
            sb.Append("0x").Append(src[i].ToString("x2", CultureInfo.InvariantCulture));
        }
        return sb.ToString();
    }

    private static string Indent(string digest, string pad) => digest.Replace("\n", "\n" + pad);
    private static string Hex16(long v) => "0x" + v.ToString("x16", CultureInfo.InvariantCulture);
    private static string Hex8(long v) => "0x" + v.ToString("x8", CultureInfo.InvariantCulture);
    private static string Imode(uint flags) => "0x" + flags.ToString("x8", CultureInfo.InvariantCulture);
    private static string Mode4(ushort mode) => "0x" + mode.ToString("x4", CultureInfo.InvariantCulture);
    private static string Hex16Blob(long v) => "0x" + v.ToString("x16", CultureInfo.InvariantCulture);

    private static string Hex16Blob(byte[]? data, int len)
    {
        var sb = new StringBuilder(2 + len * 2);
        sb.Append("0x");
        for (int i = 0; i < len; i++)
            sb.Append((data != null && i < data.Length ? data[i] : (byte)0).ToString("X2", CultureInfo.InvariantCulture));
        return sb.ToString();
    }

    private static string CompLabel(long stored, long plain, int blockSize)
    {
        long pct = plain > 0 ? (long)Math.Round(stored * 100.0 / plain) : 0;
        long a = blockSize > 0 ? (stored + blockSize - 1) / blockSize : 0;
        long b = blockSize > 0 ? (plain + blockSize - 1) / blockSize : 0;
        return $"{pct}% ({a}/{b})";
    }

    // ---- custom STORED ZIP writer ----------------------------------------------------------

    /// <summary>
    /// Serialises <paramref name="members"/> into a ZIP using STORED entries (no compression)
    /// with the exact SI framing the console loader requires: no extra fields, central-directory
    /// "version made by" = 0, deterministic DOS date 0x0021 (1980-01-01) / time 0, forward slashes.
    /// </summary>
    public static byte[] WriteZip(IReadOnlyList<ProsperoSiMember> members)
    {
        ArgumentNullException.ThrowIfNull(members);

        const ushort VersionNeeded = 20;
        const ushort DosTime = 0;
        const ushort DosDate = 0x0021;

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms, Encoding.ASCII, leaveOpen: true);
        var local = new (uint Crc, int Size, int NameLen, long Offset)[members.Count];

        for (int i = 0; i < members.Count; i++)
        {
            ProsperoSiMember m = members[i];
            byte[] name = Encoding.ASCII.GetBytes(m.Path);
            uint crc = ZipCrc32.Compute(m.Content);
            long off = ms.Position;
            local[i] = (crc, m.Content.Length, name.Length, off);

            w.Write(0x04034b50u);                  // local file header signature
            w.Write(VersionNeeded);
            w.Write((ushort)0);                    // general purpose flag
            w.Write((ushort)0);                    // method = stored
            w.Write(DosTime);
            w.Write(DosDate);
            w.Write(crc);
            w.Write((uint)m.Content.Length);       // compressed size (== uncompressed for STORED)
            w.Write((uint)m.Content.Length);       // uncompressed size
            w.Write((ushort)name.Length);
            w.Write((ushort)0);                    // extra field length
            w.Write(name);
            w.Write(m.Content);
        }

        long cdStart = ms.Position;
        for (int i = 0; i < members.Count; i++)
        {
            byte[] name = Encoding.ASCII.GetBytes(members[i].Path);
            w.Write(0x02014b50u);                  // central directory header signature
            w.Write((ushort)0);                    // version made by = 0
            w.Write(VersionNeeded);
            w.Write((ushort)0);                    // general purpose flag
            w.Write((ushort)0);                    // method = stored
            w.Write(DosTime);
            w.Write(DosDate);
            w.Write(local[i].Crc);
            w.Write((uint)local[i].Size);           // compressed size
            w.Write((uint)local[i].Size);           // uncompressed size
            w.Write((ushort)name.Length);
            w.Write((ushort)0);                    // extra field length
            w.Write((ushort)0);                    // comment length
            w.Write((ushort)0);                    // disk number start
            w.Write((ushort)0);                    // internal attributes
            w.Write(0u);                            // external attributes
            w.Write((uint)local[i].Offset);        // relative offset of local header
            w.Write(name);
        }
        long cdSize = ms.Position - cdStart;

        w.Write(0x06054b50u);                      // end of central directory signature
        w.Write((ushort)0);                         // disk number
        w.Write((ushort)0);                         // disk with central directory
        w.Write((ushort)members.Count);             // entries on this disk
        w.Write((ushort)members.Count);             // total entries
        w.Write((uint)cdSize);
        w.Write((uint)cdStart);
        w.Write((ushort)0);                         // comment length
        w.Flush();
        return ms.ToArray();
    }
}
