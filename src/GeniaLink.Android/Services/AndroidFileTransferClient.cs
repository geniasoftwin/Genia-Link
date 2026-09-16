using System.Buffers;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Android.Content;
using GeniaLink.Android.Models;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Security;

namespace GeniaLink.Android.Services;

internal static class AndroidFileTransferClient
{
    public static async Task SendFilesAsync(
        ContentResolver resolver,
        IPAddress targetAddress,
        int port,
        Guid localDeviceId,
        string localDeviceName,
        Guid expectedRemoteDeviceId,
        ReadOnlyMemory<byte> trustedSharedKey,
        IReadOnlyList<SelectedDocument> documents,
        IProgress<TransferProgress>? progress,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(targetAddress);
        ArgumentNullException.ThrowIfNull(documents);
        if (!LocalNetworkPolicy.IsAllowedAddress(targetAddress))
        {
            throw new InvalidOperationException("Genia Link transfers are restricted to local/private IPv4 addresses.");
        }

        if (localDeviceId == Guid.Empty || expectedRemoteDeviceId == Guid.Empty)
        {
            throw new ArgumentException("Device identifiers must not be empty.");
        }

        if (trustedSharedKey.Length != 32)
        {
            throw new ArgumentException("Trusted shared key must contain 32 bytes.", nameof(trustedSharedKey));
        }

        if (documents.Count == 0 || documents.Count > ProtocolConstants.MaxBatchFiles)
        {
            throw new ArgumentException("The transfer batch is empty or too large.", nameof(documents));
        }

        var prepared = new List<PreparedDocument>(documents.Count);
        try
        {
            foreach (var document in documents)
            {
                cancellationToken.ThrowIfCancellationRequested();
                log?.Invoke($"Проверка целостности перед отправкой: {document.DisplayName}");
                prepared.Add(await PrepareDocumentAsync(resolver, document, cancellationToken).ConfigureAwait(false));
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
                await SendHelloAsync(channel, localDeviceId, localDeviceName, expectedRemoteDeviceId, cancellationToken)
                    .ConfigureAwait(false);

                foreach (var document in prepared)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    await SendOneFileAsync(resolver, channel, document, progress, log, cancellationToken).ConfigureAwait(false);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sessionKey);
            }
        }
        finally
        {
            foreach (var document in prepared)
            {
                CryptographicOperations.ZeroMemory(document.Sha256);
            }
        }
    }

    private static async Task<PreparedDocument> PrepareDocumentAsync(
        ContentResolver resolver,
        SelectedDocument document,
        CancellationToken cancellationToken)
    {
        if (!FileSafety.IsSafeFileName(document.DisplayName))
        {
            throw new InvalidDataException($"Unsafe transfer file name: {document.DisplayName}");
        }

        if (!FileSafety.IsSafeRelativeDirectory(document.RelativeDirectory))
        {
            throw new InvalidDataException($"Unsafe transfer relative directory: {document.RelativeDirectory}");
        }

        using var uri = document.GetUri();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        await using var stream = resolver.OpenInputStream(uri)
            ?? throw new IOException($"Не удалось открыть файл: {document.DisplayName}");

        var buffer = ArrayPool<byte>.Shared.Rent(ProtocolConstants.MaxChunkSize);
        long size = 0;
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, ProtocolConstants.MaxChunkSize), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                size = checked(size + read);
                if (size > ProtocolConstants.MaxFileSize)
                {
                    throw new InvalidDataException($"File is larger than the protocol limit: {document.DisplayName}");
                }

                hash.AppendData(buffer, 0, read);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, ProtocolConstants.MaxChunkSize));
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (document.ReportedSize is long reportedSize && reportedSize != size)
        {
            throw new IOException($"Размер файла изменился во время подготовки: {document.DisplayName}");
        }

        return new PreparedDocument(document, size, hash.GetHashAndReset());
    }

    private static async Task SendHelloAsync(
        SecureChannel channel,
        Guid localDeviceId,
        string localDeviceName,
        Guid expectedRemoteDeviceId,
        CancellationToken cancellationToken)
    {
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
        await channel.SendAsync(
            TransferProtocol.CreateHello(localDeviceId, localDeviceName),
            timeoutCts.Token).ConfigureAwait(false);

        var reply = await channel.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
        var (version, remoteDeviceId, _) = TransferProtocol.ParseHello(reply, MessageType.HelloAck);
        if (version != ProtocolConstants.Version || remoteDeviceId != expectedRemoteDeviceId)
        {
            throw new InvalidDataException("The remote Genia Link identity or protocol version changed unexpectedly.");
        }
    }

    private static async Task SendOneFileAsync(
        ContentResolver resolver,
        SecureChannel channel,
        PreparedDocument document,
        IProgress<TransferProgress>? progress,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        var transferId = Guid.NewGuid();
        var offer = new FileOffer(
            transferId,
            document.Source.DisplayName,
            FileSafety.NormalizeRelativeDirectory(document.Source.RelativeDirectory),
            document.Size,
            document.Sha256);
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
                    if (accepted.TransferId != transferId || accepted.ResumeOffset < 0 || accepted.ResumeOffset > document.Size)
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

                    throw new IOException($"Remote device rejected {document.Source.DisplayName}: {rejection.Reason}");
                default:
                    throw new InvalidDataException("Unexpected response to file offer.");
            }
        }

        using var uri = document.Source.GetUri();
        await using var stream = resolver.OpenInputStream(uri)
            ?? throw new IOException($"Не удалось повторно открыть файл: {document.Source.DisplayName}");

        if (resumeOffset > 0)
        {
            log?.Invoke($"Докачка {document.Source.DisplayName}: продолжение с {AndroidDocumentAccess.FormatBytes(resumeOffset)}.");
            await SkipExactlyAsync(stream, resumeOffset, cancellationToken).ConfigureAwait(false);
            progress?.Report(new TransferProgress(document.Source.DisplayName, resumeOffset, document.Size, false));
        }

        var buffer = ArrayPool<byte>.Shared.Rent(ProtocolConstants.MaxChunkSize);
        long sent = resumeOffset;
        try
        {
            while (true)
            {
                var read = await stream.ReadAsync(buffer.AsMemory(0, ProtocolConstants.MaxChunkSize), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                var nextTotal = checked(sent + read);
                if (nextTotal > document.Size)
                {
                    throw new IOException($"Файл изменился во время отправки: {document.Source.DisplayName}");
                }

                await TransferIo.SendAsync(
                    channel,
                    TransferProtocol.CreateFileChunk(transferId, sent, buffer.AsSpan(0, read)),
                    cancellationToken).ConfigureAwait(false);

                sent = nextTotal;
                progress?.Report(new TransferProgress(document.Source.DisplayName, sent, document.Size, false));
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, ProtocolConstants.MaxChunkSize));
            ArrayPool<byte>.Shared.Return(buffer);
        }

        if (sent != document.Size)
        {
            throw new IOException($"Файл изменился во время отправки: {document.Source.DisplayName}");
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

    private static async Task SkipExactlyAsync(Stream stream, long bytes, CancellationToken cancellationToken)
    {
        if (bytes <= 0)
        {
            return;
        }

        if (stream.CanSeek)
        {
            stream.Seek(bytes, SeekOrigin.Begin);
            return;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(ProtocolConstants.MaxChunkSize);
        try
        {
            var remaining = bytes;
            while (remaining > 0)
            {
                var wanted = (int)Math.Min(buffer.Length, remaining);
                var read = await stream.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken).ConfigureAwait(false);
                if (read <= 0)
                {
                    throw new EndOfStreamException("Source file ended before the requested resume offset.");
                }

                remaining -= read;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, ProtocolConstants.MaxChunkSize));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private sealed record PreparedDocument(SelectedDocument Source, long Size, byte[] Sha256);
}
