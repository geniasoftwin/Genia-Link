using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Security;

namespace GeniaLink.Core.Transfers;

public static class RemoteFolderClient
{
    public static async Task<IReadOnlyList<RemoteFileEntry>> ListFilesAsync(
        IPAddress targetAddress,
        int port,
        Guid localDeviceId,
        string localDeviceName,
        Guid expectedRemoteDeviceId,
        ReadOnlyMemory<byte> trustedSharedKey,
        CancellationToken cancellationToken)
    {
        await using var session = await OpenSessionAsync(
            targetAddress,
            port,
            localDeviceId,
            localDeviceName,
            expectedRemoteDeviceId,
            trustedSharedKey,
            cancellationToken).ConfigureAwait(false);

        await TransferIo.SendAsync(session.Channel, TransferProtocol.CreateBrowseRequest(), cancellationToken).ConfigureAwait(false);
        var startMessage = await TransferIo.ReceiveAsync(session.Channel, cancellationToken).ConfigureAwait(false);
        var count = TransferProtocol.ParseBrowseListStart(startMessage);
        if (count < 0 || count > ProtocolConstants.MaxBatchFiles)
        {
            throw new InvalidDataException("Remote Genia Link folder contains too many files.");
        }

        var results = new List<RemoteFileEntry>(count);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        for (var index = 0; index < count; index++)
        {
            var entryMessage = await TransferIo.ReceiveAsync(session.Channel, cancellationToken).ConfigureAwait(false);
            var entry = TransferProtocol.ParseBrowseEntry(entryMessage);
            if (!FileSafety.IsSafeRelativeFilePath(entry.RelativePath) ||
                entry.FileSize < 0 ||
                entry.FileSize > ProtocolConstants.MaxFileSize ||
                !paths.Add(entry.RelativePath))
            {
                throw new InvalidDataException("Remote Genia Link folder returned invalid file metadata.");
            }

            results.Add(entry);
        }

        var endMessage = await TransferIo.ReceiveAsync(session.Channel, cancellationToken).ConfigureAwait(false);
        TransferProtocol.ParseBrowseListEnd(endMessage);
        return results;
    }

    public static async Task<RemoteFilePreview> GetPreviewAsync(
        IPAddress targetAddress,
        int port,
        Guid localDeviceId,
        string localDeviceName,
        Guid expectedRemoteDeviceId,
        ReadOnlyMemory<byte> trustedSharedKey,
        string relativePath,
        CancellationToken cancellationToken)
    {
        var normalizedPath = FileSafety.NormalizeRelativeFilePath(relativePath);
        await using var session = await OpenSessionAsync(
            targetAddress,
            port,
            localDeviceId,
            localDeviceName,
            expectedRemoteDeviceId,
            trustedSharedKey,
            cancellationToken).ConfigureAwait(false);

        await TransferIo.SendAsync(
            session.Channel,
            TransferProtocol.CreatePreviewRequest(normalizedPath),
            cancellationToken).ConfigureAwait(false);
        var response = await TransferIo.ReceiveAsync(session.Channel, cancellationToken).ConfigureAwait(false);
        var preview = TransferProtocol.ParsePreviewResponse(response);
        if (!string.Equals(preview.RelativePath, normalizedPath, StringComparison.Ordinal) ||
            !FileSafety.IsSafeRelativeFilePath(preview.RelativePath) ||
            preview.Data.Length > ProtocolConstants.MaxPreviewBytes)
        {
            throw new InvalidDataException("Remote Genia Link preview response is invalid.");
        }

        return preview;
    }

    public static async Task RequestDownloadAsync(
        IPAddress targetAddress,
        int port,
        int localTransferPort,
        Guid localDeviceId,
        string localDeviceName,
        Guid expectedRemoteDeviceId,
        ReadOnlyMemory<byte> trustedSharedKey,
        IReadOnlyList<string> relativePaths,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(relativePaths);
        if (relativePaths.Count == 0 || relativePaths.Count > ProtocolConstants.MaxBatchFiles)
        {
            throw new ArgumentException("The remote download selection is empty or too large.", nameof(relativePaths));
        }

        if (localTransferPort != ProtocolConstants.Port)
        {
            throw new ArgumentOutOfRangeException(nameof(localTransferPort), "Remote downloads must return through the Genia Link transfer port.");
        }

        var normalized = new List<string>(relativePaths.Count);
        var unique = new HashSet<string>(StringComparer.Ordinal);
        foreach (var path in relativePaths)
        {
            var safe = FileSafety.NormalizeRelativeFilePath(path);
            if (!unique.Add(safe))
            {
                continue;
            }

            normalized.Add(safe);
        }

        if (normalized.Count == 0)
        {
            throw new ArgumentException("The remote download selection contains no valid unique files.", nameof(relativePaths));
        }

        await using var session = await OpenSessionAsync(
            targetAddress,
            port,
            localDeviceId,
            localDeviceName,
            expectedRemoteDeviceId,
            trustedSharedKey,
            cancellationToken).ConfigureAwait(false);

        await TransferIo.SendAsync(
            session.Channel,
            TransferProtocol.CreateDownloadRequestStart(normalized.Count, localTransferPort),
            cancellationToken).ConfigureAwait(false);

        foreach (var path in normalized)
        {
            await TransferIo.SendAsync(
                session.Channel,
                TransferProtocol.CreateDownloadRequestItem(path),
                cancellationToken).ConfigureAwait(false);
        }

        await TransferIo.SendAsync(session.Channel, TransferProtocol.CreateDownloadRequestCommit(), cancellationToken).ConfigureAwait(false);
        var response = await TransferIo.ReceiveAsync(session.Channel, cancellationToken).ConfigureAwait(false);
        switch (TransferProtocol.GetMessageType(response))
        {
            case MessageType.DownloadRequestAccepted:
                var acceptedCount = TransferProtocol.ParseDownloadRequestAccepted(response);
                if (acceptedCount != normalized.Count)
                {
                    throw new InvalidDataException("Remote device accepted a different download file count.");
                }

                return;
            case MessageType.DownloadRequestRejected:
                throw new IOException("Remote device rejected the download request: " + TransferProtocol.ParseDownloadRequestRejected(response));
            default:
                throw new InvalidDataException("Unexpected response to remote download request.");
        }
    }

    private static async Task<RemoteSession> OpenSessionAsync(
        IPAddress targetAddress,
        int port,
        Guid localDeviceId,
        string localDeviceName,
        Guid expectedRemoteDeviceId,
        ReadOnlyMemory<byte> trustedSharedKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(targetAddress);
        if (!LocalNetworkPolicy.IsAllowedAddress(targetAddress))
        {
            throw new InvalidOperationException("Genia Link remote browsing is restricted to local/private IPv4 addresses.");
        }

        if (localDeviceId == Guid.Empty || expectedRemoteDeviceId == Guid.Empty)
        {
            throw new ArgumentException("Device identifiers must not be empty.");
        }

        if (string.IsNullOrWhiteSpace(localDeviceName))
        {
            throw new ArgumentException("Local device name must not be empty.", nameof(localDeviceName));
        }

        if (trustedSharedKey.Length != 32)
        {
            throw new ArgumentException("Trusted shared key must contain 32 bytes.", nameof(trustedSharedKey));
        }

        var tcp = new TcpClient(targetAddress.AddressFamily) { NoDelay = true };
        try
        {
            using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                connectCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
                await tcp.ConnectAsync(targetAddress, port, connectCts.Token).ConfigureAwait(false);
            }

            var networkStream = tcp.GetStream();
            byte[] sessionKey;
            using (var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                handshakeCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
                sessionKey = await TrustedSessionHandshake.CreateClientSessionKeyAsync(
                    networkStream,
                    localDeviceId,
                    expectedRemoteDeviceId,
                    trustedSharedKey,
                    handshakeCts.Token).ConfigureAwait(false);
            }

            try
            {
                var channel = new SecureChannel(networkStream, sessionKey, SecureChannelRole.Client, leaveOpen: false);
                try
                {
                    using var helloCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                    helloCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
                    await channel.SendAsync(
                        TransferProtocol.CreateHello(localDeviceId, localDeviceName),
                        helloCts.Token).ConfigureAwait(false);
                    var reply = await channel.ReceiveAsync(helloCts.Token).ConfigureAwait(false);
                    var (version, remoteDeviceId, _) = TransferProtocol.ParseHello(reply, MessageType.HelloAck);
                    if (version != ProtocolConstants.Version || remoteDeviceId != expectedRemoteDeviceId)
                    {
                        throw new InvalidDataException("The remote Genia Link identity or protocol version changed unexpectedly.");
                    }

                    return new RemoteSession(tcp, channel, sessionKey);
                }
                catch
                {
                    await channel.DisposeAsync().ConfigureAwait(false);
                    throw;
                }
            }
            catch
            {
                CryptographicOperations.ZeroMemory(sessionKey);
                throw;
            }
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private sealed class RemoteSession(
        TcpClient tcp,
        SecureChannel channel,
        byte[] sessionKey) : IAsyncDisposable
    {
        public SecureChannel Channel { get; } = channel;

        public async ValueTask DisposeAsync()
        {
            try
            {
                await Channel.DisposeAsync().ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sessionKey);
                tcp.Dispose();
            }
        }
    }
}
