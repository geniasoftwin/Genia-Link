using System.Buffers;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Security;

namespace GeniaLink.Core.Transfers;

public static class FileTransferServer
{
    private static readonly SemaphoreSlim RemoteDownloadSendGate = new(1, 1);
    public static async Task RunAsync(
        int port,
        Guid localDeviceId,
        Func<Guid, byte[]?> sharedKeyResolver,
        Func<Guid, TrustedSessionAuthorization?> sessionAuthorizationResolver,
        string destinationDirectory,
        IProgress<TransferProgress>? progress,
        Action<string, long>? transferStarted,
        Action<string, bool, string>? transferEnded,
        Action<Guid, IPAddress>? authenticatedPeerSeen,
        Func<string, CancellationToken, Task<byte[]?>>? imagePreviewProvider,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sharedKeyResolver);
        ArgumentNullException.ThrowIfNull(sessionAuthorizationResolver);
        if (localDeviceId == Guid.Empty)
        {
            throw new ArgumentException("Local device ID must not be empty.", nameof(localDeviceId));
        }

        Directory.CreateDirectory(destinationDirectory);
        FileSafety.CleanupStaleResumeParts(
            destinationDirectory,
            DateTimeOffset.UtcNow - ProtocolConstants.PartialRetention);

        var listener = new TcpListener(IPAddress.Any, port);
        try
        {
            listener.Start(backlog: 4);
            log?.Invoke($"Encrypted receiver active on TCP {port}.");

            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                using (client)
                {
                    client.NoDelay = true;
                    if (client.Client.RemoteEndPoint is not IPEndPoint remoteEndPoint ||
                        !LocalNetworkPolicy.IsAllowedAddress(remoteEndPoint.Address))
                    {
                        log?.Invoke("Rejected transfer connection from a non-local address.");
                        continue;
                    }

                    log?.Invoke($"Incoming encrypted connection from {remoteEndPoint}.");
                    try
                    {
                        await HandleClientAsync(
                            client,
                            localDeviceId,
                            sharedKeyResolver,
                            sessionAuthorizationResolver,
                            destinationDirectory,
                            progress,
                            transferStarted,
                            transferEnded,
                            remoteEndPoint.Address,
                            authenticatedPeerSeen,
                            imagePreviewProvider,
                            log,
                            cancellationToken).ConfigureAwait(false);
                    }
                    catch (TrustedSessionRevokedException ex)
                    {
                        log?.Invoke($"GNP/1 M2.5.2.1 active transfer session terminated after trust invalidation: {ex.Message}");
                    }
                    catch (AuthenticationException ex)
                    {
                        log?.Invoke($"Rejected untrusted connection: {ex.Message}");
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        log?.Invoke("Connection timed out and was closed.");
                    }
                    catch (EndOfStreamException)
                    {
                        log?.Invoke("Transfer session completed; remote device disconnected normally.");
                    }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or SocketException or CryptographicException)
                    {
                        log?.Invoke($"Connection ended safely: {ex.Message}");
                    }
                }
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task HandleClientAsync(
        TcpClient client,
        Guid localDeviceId,
        Func<Guid, byte[]?> sharedKeyResolver,
        Func<Guid, TrustedSessionAuthorization?> sessionAuthorizationResolver,
        string destinationDirectory,
        IProgress<TransferProgress>? progress,
        Action<string, long>? transferStarted,
        Action<string, bool, string>? transferEnded,
        IPAddress remoteAddress,
        Action<Guid, IPAddress>? authenticatedPeerSeen,
        Func<string, CancellationToken, Task<byte[]?>>? imagePreviewProvider,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        var networkStream = client.GetStream();
        ServerHandshakeResult handshake;
        using (var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            handshakeCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
            handshake = await TrustedSessionHandshake.CreateServerSessionKeyAsync(
                networkStream,
                localDeviceId,
                sharedKeyResolver,
                handshakeCts.Token).ConfigureAwait(false);
        }

        var authorization = sessionAuthorizationResolver(handshake.RemoteDeviceId)
            ?? throw new AuthenticationException("Authenticated device is no longer Active and trusted.");
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, authorization.LifetimeToken);
        var sessionToken = sessionCts.Token;

        try
        {
            await using var channel = new SecureChannel(networkStream, handshake.SessionKey, SecureChannelRole.Server);
            using (var helloCts = CancellationTokenSource.CreateLinkedTokenSource(sessionToken))
            {
                helloCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
                var hello = await channel.ReceiveAsync(helloCts.Token).ConfigureAwait(false);
                var (version, remoteDeviceId, deviceName) = TransferProtocol.ParseHello(hello, MessageType.Hello);
                if (version != ProtocolConstants.Version || remoteDeviceId != handshake.RemoteDeviceId)
                {
                    throw new AuthenticationException("Authenticated device identity changed or protocol versions do not match.");
                }

                log?.Invoke($"Authenticated trusted device: {SanitizeForLog(deviceName)}.");
                await channel.SendAsync(
                    TransferProtocol.CreateHelloAck(localDeviceId, Environment.MachineName),
                    helloCts.Token).ConfigureAwait(false);
                authenticatedPeerSeen?.Invoke(remoteDeviceId, remoteAddress);
            }

            ReceiveState? state = null;
            var offeredFiles = 0;
            try
            {
                while (!sessionToken.IsCancellationRequested)
                {
                    var message = await TransferIo.ReceiveAsync(channel, sessionToken).ConfigureAwait(false);
                    switch (TransferProtocol.GetMessageType(message))
                    {
                        case MessageType.FileOffer:
                            if (state is not null)
                            {
                                throw new InvalidDataException("A second file was offered before the current transfer completed.");
                            }

                            offeredFiles = checked(offeredFiles + 1);
                            if (offeredFiles > ProtocolConstants.MaxBatchFiles)
                            {
                                throw new InvalidDataException("Transfer batch exceeds the safety file-count limit.");
                            }

                            state = await AcceptOfferAsync(
                                channel,
                                message,
                                destinationDirectory,
                                handshake.RemoteDeviceId,
                                authorization.TrustRelationshipId,
                                transferStarted,
                                log,
                                sessionToken).ConfigureAwait(false);
                            break;

                        case MessageType.FileChunk:
                            if (state is null)
                            {
                                throw new InvalidDataException("Received file data without an accepted offer.");
                            }

                            await ReceiveChunkAsync(state, message, progress, sessionToken).ConfigureAwait(false);
                            break;

                        case MessageType.FileComplete:
                            if (state is null)
                            {
                                throw new InvalidDataException("Received completion without an active file transfer.");
                            }

                            var transferId = TransferProtocol.ParseTransferId(message, MessageType.FileComplete);
                            if (transferId != state.TransferId)
                            {
                                throw new InvalidDataException("Transfer identifier mismatch.");
                            }

                            await FinishTransferAsync(
                                channel,
                                state,
                                destinationDirectory,
                                transferEnded,
                                log,
                                sessionToken).ConfigureAwait(false);
                            await state.DisposeAsync().ConfigureAwait(false);
                            state = null;
                            break;

                        case MessageType.BrowseRequest:
                            if (state is not null)
                            {
                                throw new InvalidDataException("Remote browsing cannot start during an active incoming file.");
                            }

                            TransferProtocol.ParseBrowseRequest(message);
                            await SendBrowseListAsync(channel, destinationDirectory, sessionToken).ConfigureAwait(false);
                            break;

                        case MessageType.PreviewRequest:
                            if (state is not null)
                            {
                                throw new InvalidDataException("Remote preview cannot start during an active incoming file.");
                            }

                            await HandlePreviewRequestAsync(
                                channel,
                                message,
                                destinationDirectory,
                                imagePreviewProvider,
                                sessionToken).ConfigureAwait(false);
                            break;

                        case MessageType.DownloadRequestStart:
                            if (state is not null)
                            {
                                throw new InvalidDataException("Remote download cannot start during an active incoming file.");
                            }

                            await HandleDownloadRequestAsync(
                                channel,
                                message,
                                destinationDirectory,
                                remoteAddress,
                                localDeviceId,
                                handshake.RemoteDeviceId,
                                sharedKeyResolver,
                                log,
                                sessionToken,
                                cancellationToken,
                                authorization.LifetimeToken).ConfigureAwait(false);
                            return;

                        default:
                            throw new InvalidDataException("Unexpected message in transfer session.");
                    }
                }
            }
            finally
            {
                if (state is not null)
                {
                    if (!state.EndReported)
                    {
                        state.EndReported = true;
                        transferEnded?.Invoke(
                            state.FileName,
                            false,
                            authorization.LifetimeToken.IsCancellationRequested
                                ? "Доверие отозвано. Частичные данные сохранены, но прежняя докачка больше не авторизована."
                                : "Соединение прервано. Частично полученные данные сохранены для докачки.");
                    }

                    await state.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
        catch (OperationCanceledException) when (authorization.LifetimeToken.IsCancellationRequested)
        {
            throw new TrustedSessionRevokedException();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(handshake.SessionKey);
        }
    }

    private static async Task SendBrowseListAsync(
        SecureChannel channel,
        string sharedFolder,
        CancellationToken cancellationToken)
    {
        var files = EnumerateSharedFiles(sharedFolder);
        await TransferIo.SendAsync(
            channel,
            TransferProtocol.CreateBrowseListStart(files.Length),
            cancellationToken).ConfigureAwait(false);
        foreach (var file in files)
        {
            await TransferIo.SendAsync(
                channel,
                TransferProtocol.CreateBrowseEntry(file.Entry),
                cancellationToken).ConfigureAwait(false);
        }

        await TransferIo.SendAsync(channel, TransferProtocol.CreateBrowseListEnd(), cancellationToken).ConfigureAwait(false);
    }

    private static async Task HandlePreviewRequestAsync(
        SecureChannel channel,
        byte[] requestMessage,
        string sharedFolder,
        Func<string, CancellationToken, Task<byte[]?>>? imagePreviewProvider,
        CancellationToken cancellationToken)
    {
        var relativePath = FileSafety.NormalizeRelativeFilePath(TransferProtocol.ParsePreviewRequest(requestMessage));
        RemoteFilePreview preview;
        try
        {
            var fullPath = FileSafety.ResolveSharedFilePath(sharedFolder, relativePath);
            if (RemotePreviewPolicy.IsImagePath(relativePath) && imagePreviewProvider is not null)
            {
                var data = await imagePreviewProvider(fullPath, cancellationToken).ConfigureAwait(false);
                preview = data is { Length: > 0 }
                    ? RemotePreviewPolicy.CreateImagePreview(relativePath, data)
                    : RemotePreviewPolicy.Unavailable(relativePath, "Не удалось подготовить миниатюру изображения.");
            }
            else if (RemotePreviewPolicy.IsTextPath(relativePath))
            {
                await using var input = new FileStream(
                    fullPath,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.Read,
                    bufferSize: 64 * 1024,
                    useAsync: true);
                preview = await RemotePreviewPolicy.CreateTextPreviewAsync(input, relativePath, cancellationToken).ConfigureAwait(false);
            }
            else
            {
                preview = RemotePreviewPolicy.Unavailable(
                    relativePath,
                    "Для этого типа файла доступна информация о размере и дате; содержимое не загружалось.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            preview = RemotePreviewPolicy.Unavailable(relativePath, "Файл недоступен для безопасного предпросмотра.");
        }

        await TransferIo.SendAsync(
            channel,
            TransferProtocol.CreatePreviewResponse(preview),
            cancellationToken).ConfigureAwait(false);
    }

    private static async Task HandleDownloadRequestAsync(
        SecureChannel channel,
        byte[] startMessage,
        string sharedFolder,
        IPAddress remoteAddress,
        Guid localDeviceId,
        Guid remoteDeviceId,
        Func<Guid, byte[]?> sharedKeyResolver,
        Action<string>? log,
        CancellationToken sessionCancellationToken,
        CancellationToken serviceCancellationToken,
        CancellationToken trustLifetimeToken)
    {
        var (count, returnTransferPort) = TransferProtocol.ParseDownloadRequestStart(startMessage);
        if (count <= 0 || count > ProtocolConstants.MaxBatchFiles || returnTransferPort != ProtocolConstants.Port)
        {
            await TransferIo.SendAsync(
                channel,
                TransferProtocol.CreateDownloadRequestRejected("Invalid download request metadata."),
                sessionCancellationToken).ConfigureAwait(false);
            return;
        }

        var paths = new List<string>(count);
        var unique = new HashSet<string>(StringComparer.Ordinal);
        try
        {
            for (var index = 0; index < count; index++)
            {
                var itemMessage = await TransferIo.ReceiveAsync(channel, sessionCancellationToken).ConfigureAwait(false);
                var path = FileSafety.NormalizeRelativeFilePath(TransferProtocol.ParseDownloadRequestItem(itemMessage));
                if (!unique.Add(path))
                {
                    throw new InvalidDataException("Remote download request contains duplicate paths.");
                }

                paths.Add(path);
            }

            var commit = await TransferIo.ReceiveAsync(channel, sessionCancellationToken).ConfigureAwait(false);
            TransferProtocol.ParseDownloadRequestCommit(commit);

            var sources = paths.Select(path =>
            {
                var fullPath = FileSafety.ResolveSharedFilePath(sharedFolder, path);
                var separator = path.LastIndexOf('/');
                var relativeDirectory = separator < 0 ? string.Empty : path[..separator];
                return new TransferFileSource(fullPath, relativeDirectory);
            }).ToArray();

            var sharedKey = sharedKeyResolver(remoteDeviceId);
            if (sharedKey is null || sharedKey.Length != 32)
            {
                if (sharedKey is not null)
                {
                    CryptographicOperations.ZeroMemory(sharedKey);
                }

                throw new AuthenticationException("Trusted key for the requesting device is unavailable.");
            }

            await TransferIo.SendAsync(
                channel,
                TransferProtocol.CreateDownloadRequestAccepted(sources.Length),
                sessionCancellationToken).ConfigureAwait(false);

            // The callback transfer is intentionally started after this command session returns.
            // This avoids overlapping two secure sessions during the Android selection-dialog transition
            // and also keeps the receiver free to accept the callback/other trusted connections.
            _ = SendRequestedFilesAfterCommandSessionAsync(
                remoteAddress,
                returnTransferPort,
                localDeviceId,
                remoteDeviceId,
                sharedKey,
                sources,
                log,
                serviceCancellationToken,
                trustLifetimeToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or AuthenticationException)
        {
            log?.Invoke($"Remote Genia Link folder request rejected safely: {SanitizeForLog(ex.Message)}");
            try
            {
                await TransferIo.SendAsync(
                    channel,
                    TransferProtocol.CreateDownloadRequestRejected("Requested Genia Link file is unavailable or unsafe."),
                    sessionCancellationToken).ConfigureAwait(false);
            }
            catch (Exception sendEx) when (sendEx is IOException or OperationCanceledException or InvalidDataException or CryptographicException)
            {
            }
        }
    }

    private static async Task SendRequestedFilesAfterCommandSessionAsync(
        IPAddress remoteAddress,
        int returnTransferPort,
        Guid localDeviceId,
        Guid remoteDeviceId,
        byte[] sharedKey,
        TransferFileSource[] sources,
        Action<string>? log,
        CancellationToken serviceCancellationToken,
        CancellationToken trustLifetimeToken)
    {
        using var callbackCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCancellationToken, trustLifetimeToken);
        var cancellationToken = callbackCts.Token;
        var gateHeld = false;
        try
        {
            await Task.Delay(150, cancellationToken).ConfigureAwait(false);
            await RemoteDownloadSendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            gateHeld = true;
            log?.Invoke($"Trusted device requested {sources.Length} file(s) from the Genia Link folder.");
            await FileTransferClient.SendFilesAsync(
                remoteAddress,
                returnTransferPort,
                localDeviceId,
                remoteDeviceId,
                sharedKey,
                sources,
                progress: null,
                cancellationToken).ConfigureAwait(false);
            log?.Invoke("Remote Genia Link folder download completed successfully.");
        }
        catch (OperationCanceledException) when (trustLifetimeToken.IsCancellationRequested)
        {
            log?.Invoke("GNP/1 M2.5.2.1 remote-folder callback terminated because trust was revoked or forgotten.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            log?.Invoke("Remote Genia Link folder callback canceled safely.");
        }
        catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or InvalidDataException or AuthenticationException or CryptographicException or InvalidOperationException or ArgumentException)
        {
            log?.Invoke($"Remote Genia Link folder callback failed safely: {SanitizeForLog(ex.Message)}");
        }
        finally
        {
            if (gateHeld)
            {
                RemoteDownloadSendGate.Release();
            }

            CryptographicOperations.ZeroMemory(sharedKey);
        }
    }

    private static SharedFile[] EnumerateSharedFiles(string sharedFolder)
    {
        var root = Path.GetFullPath(sharedFolder);
        Directory.CreateDirectory(root);
        if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("The Genia Link folder must not be a symbolic link or junction.");
        }

        var results = new List<SharedFile>();
        var pending = new Stack<(DirectoryInfo Directory, string RelativeDirectory, int Depth)>();
        pending.Push((new DirectoryInfo(root), string.Empty, 0));

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            if (current.Depth > ProtocolConstants.MaxRelativeDirectoryDepth)
            {
                continue;
            }

            FileSystemInfo[] entries;
            try
            {
                entries = current.Directory.GetFileSystemInfos();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                continue;
            }

            foreach (var entry in entries.OrderBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase))
            {
                if ((entry.Attributes & FileAttributes.ReparsePoint) != 0)
                {
                    continue;
                }

                if (entry is DirectoryInfo directory)
                {
                    if (string.Equals(directory.Name, ".genialink-resume", StringComparison.OrdinalIgnoreCase) ||
                        !FileSafety.IsSafePathSegment(directory.Name))
                    {
                        continue;
                    }

                    var relativeDirectory = string.IsNullOrEmpty(current.RelativeDirectory)
                        ? directory.Name
                        : current.RelativeDirectory + "/" + directory.Name;
                    if (FileSafety.IsSafeRelativeDirectory(relativeDirectory))
                    {
                        pending.Push((directory, relativeDirectory, current.Depth + 1));
                    }

                    continue;
                }

                if (entry is not FileInfo file ||
                    !FileSafety.IsSafeFileName(file.Name) ||
                    file.Length < 0 ||
                    file.Length > ProtocolConstants.MaxFileSize)
                {
                    continue;
                }

                var relativePath = string.IsNullOrEmpty(current.RelativeDirectory)
                    ? file.Name
                    : current.RelativeDirectory + "/" + file.Name;
                if (!FileSafety.IsSafeRelativeFilePath(relativePath))
                {
                    continue;
                }

                results.Add(new SharedFile(
                    new RemoteFileEntry(
                        relativePath,
                        file.Length,
                        new DateTimeOffset(file.LastWriteTimeUtc).ToUnixTimeSeconds()),
                    file.FullName));
                if (results.Count > ProtocolConstants.MaxBatchFiles)
                {
                    throw new InvalidDataException("Genia Link folder contains more files than the remote-browser safety limit.");
                }
            }
        }

        return results
            .OrderBy(item => item.Entry.RelativePath, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    private sealed record SharedFile(RemoteFileEntry Entry, string FullPath);

    private static async Task<ReceiveState?> AcceptOfferAsync(
        SecureChannel channel,
        byte[] message,
        string destinationDirectory,
        Guid remoteDeviceId,
        string trustRelationshipId,
        Action<string, long>? transferStarted,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        var offer = TransferProtocol.ParseFileOffer(message);
        string? rejection = null;

        if (!FileSafety.IsSafeFileName(offer.FileName))
        {
            rejection = "Unsafe file name.";
        }
        else if (!FileSafety.IsSafeRelativeDirectory(offer.RelativeDirectory))
        {
            rejection = "Unsafe relative directory.";
        }
        else if (offer.FileSize < 0 || offer.FileSize > ProtocolConstants.MaxFileSize)
        {
            rejection = "File size is outside the allowed range.";
        }
        else if (offer.Sha256.Length != 32)
        {
            rejection = "Invalid SHA-256 value.";
        }

        if (rejection is not null)
        {
            await TransferIo.SendAsync(
                channel,
                TransferProtocol.CreateFileReject(offer.TransferId, rejection),
                cancellationToken).ConfigureAwait(false);
            log?.Invoke($"Rejected incoming file: {rejection}");
            return null;
        }

        var partPath = FileSafety.GetResumePartPath(
            destinationDirectory,
            offer.RelativeDirectory,
            offer.FileName,
            offer.FileSize,
            offer.Sha256,
            remoteDeviceId,
            trustRelationshipId);

        var stream = new FileStream(
            partPath,
            FileMode.OpenOrCreate,
            FileAccess.ReadWrite,
            FileShare.None,
            ProtocolConstants.MaxChunkSize,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        try
        {
            if (stream.Length > offer.FileSize)
            {
                stream.SetLength(0);
            }

            var resumeOffset = stream.Length;
            if (!HasFreeSpace(destinationDirectory, offer.FileSize - resumeOffset))
            {
                stream.Dispose();
                await TransferIo.SendAsync(
                    channel,
                    TransferProtocol.CreateFileReject(offer.TransferId, "Not enough free disk space."),
                    cancellationToken).ConfigureAwait(false);
                log?.Invoke($"Rejected incoming file {offer.FileName}: insufficient free space.");
                return null;
            }

            var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            try
            {
                await HashExistingPrefixAsync(stream, hash, cancellationToken).ConfigureAwait(false);
                stream.Position = resumeOffset;
                var state = new ReceiveState(offer, partPath, stream, hash, resumeOffset);
                await TransferIo.SendAsync(
                    channel,
                    TransferProtocol.CreateFileAccept(offer.TransferId, resumeOffset),
                    cancellationToken).ConfigureAwait(false);

                transferStarted?.Invoke(offer.FileName, offer.FileSize);
                log?.Invoke(resumeOffset > 0
                    ? $"Resuming {offer.FileName} from {resumeOffset:N0} of {offer.FileSize:N0} bytes."
                    : $"Receiving {offer.FileName} ({offer.FileSize:N0} bytes).");
                return state;
            }
            catch
            {
                hash.Dispose();
                throw;
            }
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    private static async Task HashExistingPrefixAsync(
        FileStream stream,
        IncrementalHash hash,
        CancellationToken cancellationToken)
    {
        stream.Position = 0;
        var remaining = stream.Length;
        if (remaining == 0)
        {
            return;
        }

        var buffer = ArrayPool<byte>.Shared.Rent(ProtocolConstants.MaxChunkSize);
        try
        {
            while (remaining > 0)
            {
                var wanted = (int)Math.Min(buffer.Length, remaining);
                var read = await stream.ReadAsync(buffer.AsMemory(0, wanted), cancellationToken).ConfigureAwait(false);
                if (read <= 0)
                {
                    throw new EndOfStreamException("Resume part ended unexpectedly while verifying its prefix.");
                }

                hash.AppendData(buffer, 0, read);
                remaining -= read;
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(buffer.AsSpan(0, ProtocolConstants.MaxChunkSize));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task ReceiveChunkAsync(
        ReceiveState state,
        byte[] message,
        IProgress<TransferProgress>? progress,
        CancellationToken cancellationToken)
    {
        var chunk = TransferProtocol.ParseFileChunk(message);
        if (chunk.TransferId != state.TransferId || chunk.Offset != state.BytesReceived)
        {
            throw new InvalidDataException("Invalid transfer offset.");
        }

        var nextTotal = checked(state.BytesReceived + chunk.Data.Length);
        if (nextTotal > state.ExpectedSize)
        {
            throw new InvalidDataException("Received more data than the offered file size.");
        }

        await state.Stream.WriteAsync(chunk.Data, cancellationToken).ConfigureAwait(false);
        state.Hash.AppendData(chunk.Data);
        state.BytesReceived = nextTotal;
        progress?.Report(new TransferProgress(state.FileName, state.BytesReceived, state.ExpectedSize, true));
    }

    private static async Task FinishTransferAsync(
        SecureChannel channel,
        ReceiveState state,
        string destinationDirectory,
        Action<string, bool, string>? transferEnded,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        var success = false;
        var message = "Transfer failed.";
        var deletePart = false;

        try
        {
            if (state.BytesReceived != state.ExpectedSize)
            {
                throw new InvalidDataException("Received byte count does not match the offered size.");
            }

            var actualHash = state.Hash.GetHashAndReset();
            try
            {
                if (!CryptographicOperations.FixedTimeEquals(actualHash, state.ExpectedHash))
                {
                    deletePart = true;
                    throw new InvalidDataException("SHA-256 integrity verification failed. Resume data was discarded.");
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(actualHash);
            }

            await state.Stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            state.Stream.Dispose();
            state.StreamClosed = true;

            var finalPath = FileSafety.GetUniqueDestinationPath(
                destinationDirectory,
                state.RelativeDirectory,
                state.FileName);
            File.Move(state.PartPath, finalPath, overwrite: false);
            success = true;
            message = state.ResumeOffset > 0
                ? "Transfer resumed, completed, and SHA-256 verified."
                : "Transfer completed and SHA-256 verified.";
            log?.Invoke($"Saved: {finalPath}");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            message = ex.Message;
            if (!state.StreamClosed)
            {
                state.Stream.Dispose();
                state.StreamClosed = true;
            }

            if (deletePart)
            {
                TryDelete(state.PartPath);
            }

            log?.Invoke($"Transfer rejected safely: {ex.Message}");
        }

        if (!state.EndReported)
        {
            state.EndReported = true;
            transferEnded?.Invoke(state.FileName, success, message);
        }

        await TransferIo.SendAsync(
            channel,
            TransferProtocol.CreateTransferResult(state.TransferId, success, message),
            cancellationToken).ConfigureAwait(false);
    }

    private static bool HasFreeSpace(string destinationDirectory, long requiredBytes)
    {
        if (requiredBytes <= 0)
        {
            return true;
        }

        try
        {
            var root = Path.GetPathRoot(Path.GetFullPath(destinationDirectory));
            if (string.IsNullOrWhiteSpace(root))
            {
                return true;
            }

            var drive = new DriveInfo(root);
            return drive.AvailableFreeSpace >= checked(requiredBytes + ProtocolConstants.FreeSpaceReserveBytes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or OverflowException)
        {
            return false;
        }
    }

    private static string SanitizeForLog(string value)
    {
        var sanitized = new string(value
            .Where(ch => !char.IsControl(ch) && CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.Format)
            .Take(80)
            .ToArray());
        return string.IsNullOrWhiteSpace(sanitized) ? "Unnamed device" : sanitized;
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    private sealed class ReceiveState : IAsyncDisposable
    {
        public ReceiveState(
            FileOffer offer,
            string partPath,
            FileStream stream,
            IncrementalHash hash,
            long resumeOffset)
        {
            TransferId = offer.TransferId;
            FileName = offer.FileName;
            RelativeDirectory = offer.RelativeDirectory;
            ExpectedSize = offer.FileSize;
            ExpectedHash = offer.Sha256.ToArray();
            PartPath = partPath;
            Stream = stream;
            Hash = hash;
            BytesReceived = resumeOffset;
            ResumeOffset = resumeOffset;
        }

        public Guid TransferId { get; }
        public string FileName { get; }
        public string RelativeDirectory { get; }
        public long ExpectedSize { get; }
        public byte[] ExpectedHash { get; }
        public string PartPath { get; }
        public FileStream Stream { get; }
        public IncrementalHash Hash { get; }
        public long BytesReceived { get; set; }
        public long ResumeOffset { get; }
        public bool StreamClosed { get; set; }
        public bool EndReported { get; set; }

        public ValueTask DisposeAsync()
        {
            if (!StreamClosed)
            {
                Stream.Dispose();
                StreamClosed = true;
            }

            Hash.Dispose();
            CryptographicOperations.ZeroMemory(ExpectedHash);
            return ValueTask.CompletedTask;
        }
    }
}
