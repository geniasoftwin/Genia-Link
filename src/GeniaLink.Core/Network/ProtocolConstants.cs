namespace GeniaLink.Core.Network;

public static class ProtocolConstants
{
    public const int Version = 3;
    public const int Port = 47500;
    public const int PairingPort = 47501;
    public const int DiscoveryPort = 47502;
    public const int IdentityBindingPort = 47503;
    public const int MaxChunkSize = 256 * 1024;
    public const int MaxEncryptedFrameSize = MaxChunkSize + 8192;
    public const long MaxFileSize = 100L * 1024 * 1024 * 1024;
    public const int MaxBatchFiles = 10_000;
    public const int MaxPreviewBytes = 192 * 1024;
    public const int MaxTextPreviewBytes = 64 * 1024;
    public const int MaxRelativeDirectoryCharacters = 2048;
    public const int MaxRelativeDirectoryDepth = 64;
    public const long FreeSpaceReserveBytes = 64L * 1024 * 1024;
    public static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan PairingTimeout = TimeSpan.FromMinutes(2);
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan TransferIoTimeout = TimeSpan.FromSeconds(30);
    public static readonly TimeSpan VerificationTimeout = TimeSpan.FromMinutes(10);
    public static readonly TimeSpan DiscoveryInterval = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan DiscoveryExpiry = TimeSpan.FromSeconds(8);
    public static readonly TimeSpan PartialRetention = TimeSpan.FromDays(7);
}
