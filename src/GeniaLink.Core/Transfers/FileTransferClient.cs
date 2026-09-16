using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Security;

namespace GeniaLink.Core.Transfers;

public static class FileTransferClient
{
    public static Task SendFilesAsync(
        IPAddress targetAddress,
        int port,
        Guid localDeviceId,
        Guid expectedRemoteDeviceId,
        ReadOnlyMemory<byte> trustedSharedKey,
        IEnumerable<string> filePaths,
        IProgress<TransferProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(filePaths);
        var sources = filePaths
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(path => new TransferFileSource(Path.GetFullPath(path), string.Empty))
            .ToArray();
        return SendFilesAsync(
            targetAddress,
            port,
            localDeviceId,
            expectedRemoteDeviceId,
            trustedSharedKey,
            sources,
            progress,
            cancellationToken);
    }

    public static async Task SendFilesAsync(
        IPAddress targetAddress,
        int port,
        Guid localDeviceId,
        Guid expectedRemoteDeviceId,
        ReadOnlyMemory<byte> trustedSharedKey,
        IReadOnlyList<TransferFileSource> files,
        IProgress<TransferProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(targetAddress);
        ArgumentNullException.ThrowIfNull(files);
        if (!LocalNetworkPolicy.IsAllowedAddress(targetAddress))
        {
            throw new InvalidOperationException("Genia Link transfers are restricted to local/private IPv4 addresses.");
        }

        if (localDeviceId == Guid.Empty)
        {
            throw new ArgumentException("Local device ID must not be empty.", nameof(localDeviceId));
        }

        if (expectedRemoteDeviceId == Guid.Empty)
        {
            throw new ArgumentException("Expected remote device ID must not be empty.", nameof(expectedRemoteDeviceId));
        }

        if (trustedSharedKey.Length != 32)
        {
            throw new ArgumentException("Trusted shared key must contain 32 bytes.", nameof(trustedSharedKey));
        }

        if (files.Count == 0 || files.Count > ProtocolConstants.MaxBatchFiles)
        {
            throw new ArgumentException("The transfer batch is empty or too large.", nameof(files));
        }

        using var tcp = new TcpClient(targetAddress.AddressFamily) { NoDelay = true };
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
            await using var channel = new SecureChannel(networkStream, sessionKey, SecureChannelRole.Client);
            await SendHelloAsync(channel, localDeviceId, expectedRemoteDeviceId, cancellationToken).ConfigureAwait(false);

            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();
                await SendOneFileAsync(channel, file, progress, cancellationToken).ConfigureAwait(false);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
        }
    }

    private static async Task SendHelloAsync(
        SecureChannel channel,
        Guid localDeviceId,
        Guid expectedRemoteDeviceId,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
        await channel.SendAsync(
            TransferProtocol.CreateHello(localDeviceId, Environment.MachineName),
            timeoutCts.Token).ConfigureAwait(false);

        var reply = await channel.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
        var (version, remoteDeviceId, _) = TransferProtocol.ParseHello(reply, MessageType.HelloAck);
        if (version != ProtocolConstants.Version || remoteDeviceId != expectedRemoteDeviceId)
        {
            throw new InvalidDataException("The remote Genia Link identity or protocol version changed unexpectedly.");
        }
    }

    private static async Task SendOneFileAsync(
        SecureChannel channel,
        TransferFileSource source,
        IProgress<TransferProgress>? progress,
        CancellationToken cancellationToken)
    {
        var fullPath = Path.GetFullPath(source.FullPath);
        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("Selected file does not exist.", fullPath);
        }

        var fileName = Path.GetFileName(fullPath);
        if (!FileSafety.IsSafeFileName(fileName))
        {
            throw new InvalidDataException($"File name is not safe to transfer: {fileName}");
        }

        var relativeDirectory = FileSafety.NormalizeRelativeDirectory(source.RelativeDirectory);
        await using var file = new FileStream(
            fullPath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            ProtocolConstants.MaxChunkSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        if (file.Length < 0 || file.Length > ProtocolConstants.MaxFileSize)
        {
            throw new InvalidDataException($"File size is outside the allowed range: {fileName}");
        }

        var hash = await ComputeSha256Async(file, cancellationToken).ConfigureAwait(false);
        try
        {
            file.Position = 0;
            var transferId = Guid.NewGuid();
            var offer = new FileOffer(transferId, fileName, relativeDirectory, file.Length, hash);
            await TransferIo.SendAsync(channel, TransferProtocol.CreateFileOffer(offer), cancellationToken).ConfigureAwait(false);

            long resumeOffset;
            using (var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                timeoutCts.CancelAfter(ProtocolConstants.VerificationTimeout);
                var response = await channel.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
                switch (TransferProtocol.GetMessageType(response))
                {
                    case MessageType.FileAccept:
                        var accepted = TransferProtocol.ParseFileAccept(response);
                        if (accepted.TransferId != transferId || accepted.ResumeOffset < 0 || accepted.ResumeOffset > file.Length)
                        {
                            throw new InvalidDataException("Invalid resume offset from remote device.");
                        }

                        resumeOffset = accepted.ResumeOffset;
                        break;
                    case MessageType.FileReject:
                        var rejection = TransferProtocol.ParseFileReject(response);
                        if (rejection.TransferId != transferId)
                        {
                            throw new InvalidDataException("Transfer identifier mismatch in rejection.");
                        }

                        throw new IOException($"Remote device rejected {fileName}: {rejection.Reason}");
                    default:
                        throw new InvalidDataException("Unexpected response to file offer.");
                }
            }

            file.Position = resumeOffset;
            long sent = resumeOffset;
            if (sent > 0)
            {
                progress?.Report(new TransferProgress(fileName, sent, file.Length, false));
            }

            var buffer = ArrayPool<byte>.Shared.Rent(ProtocolConstants.MaxChunkSize);
            try
            {
                while (true)
                {
                    var read = await file.ReadAsync(buffer.AsMemory(0, ProtocolConstants.MaxChunkSize), cancellationToken).ConfigureAwait(false);
                    if (read == 0)
                    {
                        break;
                    }

                    await TransferIo.SendAsync(
                        channel,
                        TransferProtocol.CreateFileChunk(transferId, sent, buffer.AsSpan(0, read)),
                        cancellationToken).ConfigureAwait(false);

                    sent = checked(sent + read);
                    progress?.Report(new TransferProgress(fileName, sent, file.Length, false));
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer.AsSpan(0, ProtocolConstants.MaxChunkSize));
                ArrayPool<byte>.Shared.Return(buffer);
            }

            if (sent != file.Length)
            {
                throw new IOException("Selected file changed while it was being sent.");
            }

            await TransferIo.SendAsync(channel, TransferProtocol.CreateFileComplete(transferId), cancellationToken).ConfigureAwait(false);
            using var resultCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            resultCts.CancelAfter(ProtocolConstants.VerificationTimeout);
            var resultMessage = await channel.ReceiveAsync(resultCts.Token).ConfigureAwait(false);
            var result = TransferProtocol.ParseTransferResult(resultMessage);
            if (result.TransferId != transferId || !result.Success)
            {
                throw new IOException(result.Message);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static async Task<byte[]> ComputeSha256Async(FileStream file, CancellationToken cancellationToken)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = ArrayPool<byte>.Shared.Rent(ProtocolConstants.MaxChunkSize);
        try
        {
            while (true)
            {
                var read = await file.ReadAsync(buffer.AsMemory(0, ProtocolConstants.MaxChunkSize), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                hash.AppendData(buffer, 0, read);
            }

            return hash.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, ProtocolConstants.MaxChunkSize));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
