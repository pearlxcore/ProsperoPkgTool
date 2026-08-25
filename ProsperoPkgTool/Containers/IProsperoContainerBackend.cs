namespace ProsperoPkgTool.Containers;

public interface IProsperoContainerBackend
{
    ContainerBackendDescriptor Descriptor { get; }

    ValueTask<bool> DetectAsync(Stream stream, CancellationToken cancellationToken = default);

    Task<ContainerInfo> ReadInfoAsync(string path, CancellationToken cancellationToken = default);

    IAsyncEnumerable<ContainerEntry> ListAsync(string path, CancellationToken cancellationToken = default);

    Task ExtractAsync(string path, string outputDirectory, CancellationToken cancellationToken = default);

    Task<VerificationResult> VerifyAsync(string path, CancellationToken cancellationToken = default);
}

