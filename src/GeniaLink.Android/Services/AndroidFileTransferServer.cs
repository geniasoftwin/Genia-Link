using System.Buffers;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using Android.Content;
using Android.Graphics;
using Android.Provider;
using Android.OS;
using Android.Webkit;
using GeniaLink.Android.Models;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Security;
using GeniaLink.Core.Transfers;

namespace GeniaLink.Android.Services;

internal static class AndroidFileTransferServer
{
    private static readonly SemaphoreSlim RemoteDownloadSendGate = new(1, 1);
    private const string DownloadRootRelativePath = "Download/Genia Link/";
    private const string IdColumn = "_id";
    private const string DisplayNameColumn = "_display_name";
    private const string MimeTypeColumn = "mime_type";
    private const string RelativePathColumn = "relative_path";
    private const string IsPendingColumn = "is_pending";
    private const string DateModifiedColumn = "date_modified";
    private const string DateAddedColumn = "date_added";
    private const int MaxPendingResumeRows = 64;

    public static async Task RunAsync(
        ContentResolver resolver,
        AndroidResumeIndex resumeIndex,
        string externalStoragePath,
        int port,
        Guid localDeviceId,
        string localDeviceName,
        Func<Guid, byte[]?> sharedKeyResolver,
        Func<Guid, TrustedSessionAuthorization?> sessionAuthorizationResolver,
        IProgress<TransferProgress>? progress,
        Action<string, long>? transferStarted,
        Action<string, bool, string>? transferEnded,
        Action<Guid, IPAddress>? authenticatedPeerSeen,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(resumeIndex);
        ArgumentException.ThrowIfNullOrWhiteSpace(externalStoragePath);
        ArgumentNullException.ThrowIfNull(sharedKeyResolver);
        ArgumentNullException.ThrowIfNull(sessionAuthorizationResolver);
        if (localDeviceId == Guid.Empty)
        {
            throw new ArgumentException("Local device ID must not be empty.", nameof(localDeviceId));
        }

        CleanupStaleResumeRows(resolver, resumeIndex, log);
        var listener = new TcpListener(IPAddress.Any, port);
        try
        {
            listener.Start(backlog: 4);
            log?.Invoke($"Encrypted Android receiver active on TCP {port}.");

            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (System.OperationCanceledException) when (cancellationToken.IsCancellationRequested)
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

                    log?.Invoke($"Incoming encrypted transfer connection from {remoteEndPoint}.");
                    try
                    {
                        await HandleClientAsync(
                            resolver,
                            resumeIndex,
                            externalStoragePath,
                            client,
                            localDeviceId,
                            localDeviceName,
                            sharedKeyResolver,
                            sessionAuthorizationResolver,
                            progress,
                            transferStarted,
                            transferEnded,
                            remoteEndPoint.Address,
                            authenticatedPeerSeen,
                            log,
                            cancellationToken).ConfigureAwait(false);
                    }
                    catch (TrustedSessionRevokedException ex)
                    {
                        log?.Invoke($"GNP/1 M2.5.2.1 active Android transfer session terminated after trust invalidation: {ex.Message}");
                    }
                    catch (AuthenticationException ex)
                    {
                        log?.Invoke($"Rejected untrusted connection: {ex.Message}");
                    }
                    catch (System.OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (System.OperationCanceledException)
                    {
                        log?.Invoke("Transfer connection timed out and was closed.");
                    }
                    catch (EndOfStreamException)
                    {
                        log?.Invoke("Transfer session completed; remote device disconnected.");
                    }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or SocketException or CryptographicException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException)
                    {
                        log?.Invoke($"Transfer connection ended safely: {ex.Message}");
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
        ContentResolver resolver,
        AndroidResumeIndex resumeIndex,
        string externalStoragePath,
        TcpClient client,
        Guid localDeviceId,
        string localDeviceName,
        Func<Guid, byte[]?> sharedKeyResolver,
        Func<Guid, TrustedSessionAuthorization?> sessionAuthorizationResolver,
        IProgress<TransferProgress>? progress,
        Action<string, long>? transferStarted,
        Action<string, bool, string>? transferEnded,
        IPAddress remoteAddress,
        Action<Guid, IPAddress>? authenticatedPeerSeen,
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

                log?.Invoke($"Authenticated trusted sender: {SanitizeForLog(deviceName)}.");
                await channel.SendAsync(
                    TransferProtocol.CreateHelloAck(localDeviceId, localDeviceName),
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
                                resolver,
                                resumeIndex,
                                externalStoragePath,
                                channel,
                                message,
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
                                resolver,
                                resumeIndex,
                                channel,
                                state,
                                progress,
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
                            await SendBrowseListAsync(resolver, channel, sessionToken).ConfigureAwait(false);
                            break;

                        case MessageType.PreviewRequest:
                            if (state is not null)
                            {
                                throw new InvalidDataException("Remote preview cannot start during an active incoming file.");
                            }

                            await HandlePreviewRequestAsync(
                                resolver,
                                channel,
                                message,
                                sessionToken).ConfigureAwait(false);
                            break;

                        case MessageType.DownloadRequestStart:
                            if (state is not null)
                            {
                                throw new InvalidDataException("Remote download cannot start during an active incoming file.");
                            }

                            await HandleDownloadRequestAsync(
                                resolver,
                                channel,
                                message,
                                remoteAddress,
                                localDeviceId,
                                localDeviceName,
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
                                : "Соединение прервано. Частичные данные сохранены для докачки.");
                    }

                    TryTouchResumeIndex(resumeIndex, state.ResumeKey, log);
                    await state.DisposeAsync().ConfigureAwait(false);
                }
            }
        }
        catch (System.OperationCanceledException) when (authorization.LifetimeToken.IsCancellationRequested)
        {
            throw new TrustedSessionRevokedException();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(handshake.SessionKey);
        }
    }

    private static async Task SendBrowseListAsync(
        ContentResolver resolver,
        SecureChannel channel,
        CancellationToken cancellationToken)
    {
        var files = EnumerateSharedFiles(resolver);
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
        ContentResolver resolver,
        SecureChannel channel,
        byte[] requestMessage,
        CancellationToken cancellationToken)
    {
        var relativePath = FileSafety.NormalizeRelativeFilePath(TransferProtocol.ParsePreviewRequest(requestMessage));
        RemoteFilePreview preview;
        try
        {
            var catalog = EnumerateSharedFiles(resolver)
                .ToDictionary(item => item.Entry.RelativePath, StringComparer.Ordinal);
            if (!catalog.TryGetValue(relativePath, out var file))
            {
                preview = RemotePreviewPolicy.Unavailable(relativePath, "Файл больше не найден в Downloads/Genia Link.");
            }
            else
            {
                using var uri = global::Android.Net.Uri.Parse(file.Document.UriString);
                if (uri is null)
                {
                    preview = RemotePreviewPolicy.Unavailable(relativePath, "Файл недоступен для предпросмотра.");
                }
                else if (RemotePreviewPolicy.IsImagePath(relativePath))
                {
                    var jpeg = CreateImagePreview(resolver, uri, cancellationToken);
                    preview = jpeg is { Length: > 0 }
                        ? RemotePreviewPolicy.CreateImagePreview(relativePath, jpeg)
                        : RemotePreviewPolicy.Unavailable(relativePath, "Не удалось подготовить миниатюру изображения.");
                }
                else if (RemotePreviewPolicy.IsTextPath(relativePath))
                {
                    await using var input = resolver.OpenInputStream(uri)
                        ?? throw new IOException("Android Downloads provider did not open the preview file.");
                    preview = await RemotePreviewPolicy.CreateTextPreviewAsync(input, relativePath, cancellationToken).ConfigureAwait(false);
                }
                else
                {
                    preview = RemotePreviewPolicy.Unavailable(
                        relativePath,
                        "Для этого типа файла доступна информация о размере и дате; содержимое не загружалось.");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or Java.Lang.SecurityException or Java.Lang.IllegalArgumentException)
        {
            preview = RemotePreviewPolicy.Unavailable(relativePath, "Файл недоступен для безопасного предпросмотра.");
        }

        await TransferIo.SendAsync(
            channel,
            TransferProtocol.CreatePreviewResponse(preview),
            cancellationToken).ConfigureAwait(false);
    }

    private static byte[]? CreateImagePreview(
        ContentResolver resolver,
        global::Android.Net.Uri uri,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        using var bounds = new BitmapFactory.Options { InJustDecodeBounds = true };
        using (var boundsStream = resolver.OpenInputStream(uri))
        {
            if (boundsStream is null)
            {
                return null;
            }

            _ = BitmapFactory.DecodeStream(boundsStream, null, bounds);
        }

        if (bounds.OutWidth <= 0 || bounds.OutHeight <= 0)
        {
            return null;
        }

        var sample = 1;
        while (bounds.OutWidth / sample > 1400 || bounds.OutHeight / sample > 1400)
        {
            sample = checked(sample * 2);
        }

        using var options = new BitmapFactory.Options { InSampleSize = sample };
        using var input = resolver.OpenInputStream(uri);
        if (input is null)
        {
            return null;
        }

        using var decoded = BitmapFactory.DecodeStream(input, null, options);
        if (decoded is null)
        {
            return null;
        }

        foreach (var maxDimension in new[] { 1024, 768, 512 })
        {
            cancellationToken.ThrowIfCancellationRequested();
            Bitmap target = decoded;
            Bitmap? scaled = null;
            try
            {
                var largest = Math.Max(decoded.Width, decoded.Height);
                if (largest > maxDimension)
                {
                    var scale = maxDimension / (double)largest;
                    var width = Math.Max(1, (int)Math.Round(decoded.Width * scale, MidpointRounding.AwayFromZero));
                    var height = Math.Max(1, (int)Math.Round(decoded.Height * scale, MidpointRounding.AwayFromZero));
                    scaled = Bitmap.CreateScaledBitmap(decoded, width, height, true);
                    if (scaled is null)
                    {
                        continue;
                    }

                    target = scaled;
                }

                foreach (var quality in new[] { 82, 68, 54 })
                {
                    using var output = new MemoryStream();
                    if (!target.Compress(Bitmap.CompressFormat.Jpeg ?? throw new InvalidOperationException("JPEG compression is unavailable."), quality, output))
                    {
                        continue;
                    }

                    if (output.Length <= ProtocolConstants.MaxPreviewBytes)
                    {
                        return output.ToArray();
                    }
                }
            }
            finally
            {
                if (scaled is not null && !ReferenceEquals(scaled, decoded))
                {
                    scaled.Dispose();
                }
            }
        }

        return null;
    }

    private static async Task HandleDownloadRequestAsync(
        ContentResolver resolver,
        SecureChannel channel,
        byte[] startMessage,
        IPAddress remoteAddress,
        Guid localDeviceId,
        string localDeviceName,
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

            var catalog = EnumerateSharedFiles(resolver)
                .ToDictionary(item => item.Entry.RelativePath, StringComparer.Ordinal);
            var documents = paths.Select(path =>
            {
                if (!catalog.TryGetValue(path, out var file))
                {
                    throw new FileNotFoundException("Requested Genia Link file no longer exists.");
                }

                return file.Document;
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
                TransferProtocol.CreateDownloadRequestAccepted(documents.Length),
                sessionCancellationToken).ConfigureAwait(false);

            // Start the callback only after the browse/download command connection has been allowed
            // to close. Several vendor Android builds are unstable when the incoming foreground transfer
            // begins while the multi-choice dialog and command session are still being torn down.
            _ = SendRequestedDocumentsAfterCommandSessionAsync(
                resolver,
                remoteAddress,
                returnTransferPort,
                localDeviceId,
                localDeviceName,
                remoteDeviceId,
                sharedKey,
                documents,
                log,
                serviceCancellationToken,
                trustLifetimeToken);
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or AuthenticationException or Java.Lang.SecurityException or Java.Lang.IllegalArgumentException)
        {
            log?.Invoke($"Remote Android Genia Link folder request rejected safely: {SanitizeForLog(ex.Message)}");
            try
            {
                await TransferIo.SendAsync(
                    channel,
                    TransferProtocol.CreateDownloadRequestRejected("Requested Genia Link file is unavailable or unsafe."),
                    sessionCancellationToken).ConfigureAwait(false);
            }
            catch (Exception sendEx) when (sendEx is IOException or System.OperationCanceledException or InvalidDataException or CryptographicException)
            {
            }
        }
    }

    private static async Task SendRequestedDocumentsAfterCommandSessionAsync(
        ContentResolver resolver,
        IPAddress remoteAddress,
        int returnTransferPort,
        Guid localDeviceId,
        string localDeviceName,
        Guid remoteDeviceId,
        byte[] sharedKey,
        SelectedDocument[] documents,
        Action<string>? log,
        CancellationToken serviceCancellationToken,
        CancellationToken trustLifetimeToken)
    {
        using var callbackCts = CancellationTokenSource.CreateLinkedTokenSource(serviceCancellationToken, trustLifetimeToken);
        var cancellationToken = callbackCts.Token;
        PowerManager.WakeLock? wakeLock = null;
        var gateHeld = false;
        try
        {
            await Task.Delay(150, cancellationToken).ConfigureAwait(false);
            await RemoteDownloadSendGate.WaitAsync(cancellationToken).ConfigureAwait(false);
            gateHeld = true;
            var powerManager = global::Android.App.Application.Context.GetSystemService(Context.PowerService) as PowerManager;
            wakeLock = powerManager?.NewWakeLock(WakeLockFlags.Partial, "GeniaLink:RemoteFolderSend");
            wakeLock?.Acquire(6 * 60 * 60 * 1000L);
            log?.Invoke($"Trusted device requested {documents.Length} file(s) from Android Downloads/Genia Link.");
            await AndroidFileTransferClient.SendFilesAsync(
                resolver,
                remoteAddress,
                returnTransferPort,
                localDeviceId,
                localDeviceName,
                remoteDeviceId,
                sharedKey,
                documents,
                progress: null,
                log,
                cancellationToken).ConfigureAwait(false);
            log?.Invoke("Remote Android Genia Link folder download completed successfully.");
        }
        catch (System.OperationCanceledException) when (trustLifetimeToken.IsCancellationRequested)
        {
            log?.Invoke("GNP/1 M2.5.2.1 Android remote-folder callback terminated because trust was revoked or forgotten.");
        }
        catch (System.OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            log?.Invoke("Remote Android Genia Link folder callback canceled safely.");
        }
        catch (Exception ex) when (ex is IOException or SocketException or InvalidDataException or AuthenticationException or CryptographicException or InvalidOperationException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException)
        {
            log?.Invoke($"Remote Android Genia Link folder callback failed safely: {SanitizeForLog(ex.Message)}");
        }
        finally
        {
            if (wakeLock?.IsHeld == true)
            {
                wakeLock.Release();
            }

            wakeLock?.Dispose();
            if (gateHeld)
            {
                RemoteDownloadSendGate.Release();
            }

            CryptographicOperations.ZeroMemory(sharedKey);
        }
    }

    private static AndroidSharedFile[] EnumerateSharedFiles(ContentResolver resolver)
    {
        var collection = MediaStore.Downloads.ExternalContentUri
            ?? throw new IOException("Android Downloads collection is unavailable.");
        var results = new List<AndroidSharedFile>();
        using var cursor = resolver.Query(
            collection,
            [IdColumn, DisplayNameColumn, "_size", RelativePathColumn, DateModifiedColumn],
            $"{IsPendingColumn}=?",
            ["0"],
            null);
        if (cursor is null)
        {
            return [];
        }

        while (cursor.MoveToNext())
        {
            var displayName = cursor.IsNull(1) ? string.Empty : cursor.GetString(1) ?? string.Empty;
            var size = cursor.IsNull(2) ? -1 : cursor.GetLong(2);
            var storedRelativePath = cursor.IsNull(3) ? string.Empty : cursor.GetString(3) ?? string.Empty;
            var modified = cursor.IsNull(4) ? 0 : cursor.GetLong(4);
            if (!TryGetSharedRelativeDirectory(storedRelativePath, out var relativeDirectory) ||
                !FileSafety.IsSafeFileName(displayName) ||
                size < 0 ||
                size > ProtocolConstants.MaxFileSize)
            {
                continue;
            }

            var relativePath = string.IsNullOrEmpty(relativeDirectory)
                ? displayName
                : relativeDirectory + "/" + displayName;
            if (!FileSafety.IsSafeRelativeFilePath(relativePath))
            {
                continue;
            }

            using var uri = ContentUris.WithAppendedId(collection, cursor.GetLong(0));
            if (uri is null)
            {
                continue;
            }

            var uriString = uri.ToString();
            if (string.IsNullOrWhiteSpace(uriString))
            {
                continue;
            }

            results.Add(new AndroidSharedFile(
                new RemoteFileEntry(relativePath, size, modified),
                new SelectedDocument(uriString, displayName, size, relativeDirectory)));
            if (results.Count > ProtocolConstants.MaxBatchFiles)
            {
                throw new InvalidDataException("Android Genia Link folder contains more files than the remote-browser safety limit.");
            }
        }

        return results
            .OrderBy(item => item.Entry.RelativePath, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    private static bool TryGetSharedRelativeDirectory(string mediaStoreRelativePath, out string relativeDirectory)
    {
        var normalized = mediaStoreRelativePath.Trim().Replace('\\', '/').Trim('/');
        while (normalized.Contains("//", StringComparison.Ordinal))
        {
            normalized = normalized.Replace("//", "/", StringComparison.Ordinal);
        }

        var root = DownloadRootRelativePath.Trim('/');
        if (string.Equals(normalized, root, StringComparison.Ordinal))
        {
            relativeDirectory = string.Empty;
            return true;
        }

        var prefix = root + "/";
        if (!normalized.StartsWith(prefix, StringComparison.Ordinal))
        {
            relativeDirectory = string.Empty;
            return false;
        }

        relativeDirectory = normalized[prefix.Length..];
        return FileSafety.IsSafeRelativeDirectory(relativeDirectory);
    }

    private sealed record AndroidSharedFile(RemoteFileEntry Entry, SelectedDocument Document);

    private static async Task<ReceiveState?> AcceptOfferAsync(
        ContentResolver resolver,
        AndroidResumeIndex resumeIndex,
        string externalStoragePath,
        SecureChannel channel,
        byte[] message,
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
            await TransferIo.SendAsync(channel, TransferProtocol.CreateFileReject(offer.TransferId, rejection), cancellationToken)
                .ConfigureAwait(false);
            log?.Invoke($"Rejected incoming file: {rejection}");
            return null;
        }

        var relativePath = BuildDownloadRelativePath(offer.RelativeDirectory);
        var resumeKey = FileSafety.CreateResumeKey(
            offer.RelativeDirectory,
            offer.FileName,
            offer.FileSize,
            offer.Sha256,
            remoteDeviceId,
            trustRelationshipId);
        var partialName = $".genialink-{resumeKey}.part";
        global::Android.Net.Uri? contentUri = null;
        var createdNew = false;

        var indexedEntry = resumeIndex.GetMatching(resumeKey, relativePath, partialName, offer.FileSize, offer.Sha256);
        if (indexedEntry is not null)
        {
            try
            {
                contentUri = global::Android.Net.Uri.Parse(indexedEntry.UriString);
                if (contentUri is null || !IsExpectedPendingDownload(resolver, contentUri, relativePath, partialName))
                {
                    contentUri?.Dispose();
                    contentUri = null;
                    TryRemoveResumeIndex(resumeIndex, resumeKey, log);
                }
                else
                {
                    log?.Invoke($"Найдена сохранённая докачка для {offer.FileName}.");
                }
            }
            catch (Exception ex) when (ex is Java.Lang.IllegalArgumentException or Java.Lang.SecurityException or InvalidOperationException)
            {
                contentUri?.Dispose();
                contentUri = null;
                TryRemoveResumeIndex(resumeIndex, resumeKey, log);
            }
        }

        if (contentUri is null)
        {
            // If the key existed but its metadata no longer matched, discard that private
            // index entry before trying the deterministic MediaStore migration lookup.
            TryRemoveResumeIndex(resumeIndex, resumeKey, log);

            // Migration/fallback for partial transfers created by earlier RC builds that
            // did not persist the exact MediaStore URI in the app-private resume index.
            contentUri = FindPendingDownload(resolver, relativePath, partialName);
            if (contentUri is not null)
            {
                resumeIndex.Upsert(resumeKey, contentUri, relativePath, partialName, offer.FileSize, offer.Sha256);
                log?.Invoke($"Восстановлен индекс докачки для {offer.FileName}.");
            }
        }

        if (contentUri is null)
        {
            if (resumeIndex.Count >= MaxPendingResumeRows)
            {
                await TransferIo.SendAsync(
                    channel,
                    TransferProtocol.CreateFileReject(offer.TransferId, "Too many unfinished transfers. Retry after old partial transfers expire."),
                    cancellationToken).ConfigureAwait(false);
                return null;
            }

            contentUri = CreatePendingDownload(resolver, relativePath, partialName);
            try
            {
                resumeIndex.Upsert(resumeKey, contentUri, relativePath, partialName, offer.FileSize, offer.Sha256);
            }
            catch
            {
                TryDelete(resolver, contentUri);
                contentUri.Dispose();
                throw;
            }

            createdNew = true;
        }

        Stream? output = null;
        IncrementalHash? hash = null;
        try
        {
            hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            long resumeOffset;

            // Some Android/MediaStore implementations (including MagicOS builds) do not
            // materialize a newly inserted pending Downloads row until its output stream
            // is opened at least once. Reading a brand-new zero-byte row before opening
            // it for output can therefore fail and abort the encrypted session. A new
            // transfer has no prefix to verify, so its correct resume offset is simply 0.
            if (createdNew)
            {
                resumeOffset = 0;
            }
            else
            {
                try
                {
                    resumeOffset = await HashPendingPrefixAsync(
                        resolver,
                        contentUri,
                        hash,
                        offer.FileSize,
                        cancellationToken).ConfigureAwait(false);
                }
                catch (Exception ex) when (IsRecoverableResumeStateFailure(ex))
                {
                    // A previous interrupted attempt may have left a MediaStore row whose
                    // backing file was never created (or is otherwise unreadable). Do not
                    // let that stale resume state permanently poison future transfers.
                    hash.Dispose();
                    hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                    TryDelete(resolver, contentUri);
                    TryRemoveResumeIndex(resumeIndex, resumeKey, log);
                    contentUri.Dispose();
                    contentUri = CreatePendingDownload(resolver, relativePath, partialName);
                    resumeIndex.Upsert(resumeKey, contentUri, relativePath, partialName, offer.FileSize, offer.Sha256);
                    createdNew = true;
                    resumeOffset = 0;
                    log?.Invoke($"Сброшено повреждённое состояние докачки для {offer.FileName}; передача начнётся заново.");
                }
            }

            if (!HasFreeSpace(externalStoragePath, offer.FileSize - resumeOffset))
            {
                hash.Dispose();
                hash = null;
                if (createdNew)
                {
                    TryDelete(resolver, contentUri);
                    TryRemoveResumeIndex(resumeIndex, resumeKey, log);
                }

                await TransferIo.SendAsync(
                    channel,
                    TransferProtocol.CreateFileReject(offer.TransferId, "Not enough free storage space."),
                    cancellationToken).ConfigureAwait(false);
                return null;
            }

            output = resolver.OpenOutputStream(contentUri, resumeOffset == 0 ? "w" : "wa")
                ?? throw new IOException("Android Downloads provider did not open an output stream.");

            var state = new ReceiveState(offer, resumeKey, relativePath, contentUri, output, hash, resumeOffset);
            hash = null;
            output = null;
            await TransferIo.SendAsync(
                channel,
                TransferProtocol.CreateFileAccept(offer.TransferId, resumeOffset),
                cancellationToken).ConfigureAwait(false);
            transferStarted?.Invoke(offer.FileName, offer.FileSize);
            log?.Invoke(resumeOffset > 0
                ? $"Докачка {offer.FileName}: продолжение с {AndroidDocumentAccess.FormatBytes(resumeOffset)}."
                : $"Получение: {offer.FileName} ({AndroidDocumentAccess.FormatBytes(offer.FileSize)}).");
            return state;
        }
        catch
        {
            output?.Dispose();
            hash?.Dispose();
            if (createdNew)
            {
                TryDelete(resolver, contentUri);
                TryRemoveResumeIndex(resumeIndex, resumeKey, log);
            }

            contentUri.Dispose();
            throw;
        }
    }

    private static bool IsRecoverableResumeStateFailure(Exception exception) =>
        exception is IOException or InvalidDataException or Java.IO.IOException or Java.Lang.IllegalArgumentException;

    private static async Task<long> HashPendingPrefixAsync(
        ContentResolver resolver,
        global::Android.Net.Uri contentUri,
        IncrementalHash hash,
        long maximumSize,
        CancellationToken cancellationToken)
    {
        await using var input = resolver.OpenInputStream(contentUri)
            ?? throw new IOException("Android Downloads provider did not reopen the partial file.");
        var buffer = ArrayPool<byte>.Shared.Rent(ProtocolConstants.MaxChunkSize);
        long total = 0;
        try
        {
            while (true)
            {
                var read = await input.ReadAsync(buffer.AsMemory(0, ProtocolConstants.MaxChunkSize), cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total = checked(total + read);
                if (total > maximumSize)
                {
                    throw new InvalidDataException("Stored resume data is larger than the offered file.");
                }

                hash.AppendData(buffer, 0, read);
            }

            return total;
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
        ContentResolver resolver,
        AndroidResumeIndex resumeIndex,
        SecureChannel channel,
        ReceiveState state,
        IProgress<TransferProgress>? progress,
        Action<string, bool, string>? transferEnded,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        var success = false;
        var resultMessage = "Transfer failed.";
        var deletePartial = false;

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
                    deletePartial = true;
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
            var finalName = FindAvailableDisplayName(resolver, state.RelativePath, state.FileName);
            // Remove the private URI index before publishing. If publishing then fails,
            // the deterministic MediaStore fallback can rediscover the still-pending row.
            resumeIndex.Remove(state.ResumeKey);
            PublishDownload(resolver, state.ContentUri, finalName);
            state.Published = true;
            success = true;
            resultMessage = state.ResumeOffset > 0
                ? "Transfer resumed, completed, and SHA-256 verified."
                : "Transfer completed and SHA-256 verified.";
            progress?.Report(new TransferProgress(finalName, state.ExpectedSize, state.ExpectedSize, true));
            log?.Invoke($"Сохранено в Загрузки/Genia Link: {finalName}");
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException)
        {
            resultMessage = ex.Message;
            if (!state.StreamClosed)
            {
                state.Stream.Dispose();
                state.StreamClosed = true;
            }

            if (deletePartial)
            {
                TryDelete(resolver, state.ContentUri);
                TryRemoveResumeIndex(resumeIndex, state.ResumeKey, log);
            }

            log?.Invoke($"Incoming transfer rejected safely: {ex.Message}");
        }

        if (!state.EndReported)
        {
            state.EndReported = true;
            transferEnded?.Invoke(state.FileName, success, resultMessage);
        }

        await TransferIo.SendAsync(
            channel,
            TransferProtocol.CreateTransferResult(state.TransferId, success, resultMessage),
            cancellationToken).ConfigureAwait(false);
    }

    private static string BuildDownloadRelativePath(string relativeDirectory)
    {
        var normalized = FileSafety.NormalizeRelativeDirectory(relativeDirectory);
        return normalized.Length == 0
            ? DownloadRootRelativePath
            : DownloadRootRelativePath + normalized + "/";
    }

    private static global::Android.Net.Uri CreatePendingDownload(
        ContentResolver resolver,
        string relativePath,
        string displayName)
    {
        var collection = MediaStore.Downloads.ExternalContentUri
            ?? throw new IOException("Android Downloads collection is unavailable.");
        using var values = new ContentValues();
        values.Put(DisplayNameColumn, displayName);
        values.Put(MimeTypeColumn, "application/octet-stream");
        values.Put(RelativePathColumn, relativePath);
        values.Put(IsPendingColumn, 1);
        return resolver.Insert(collection, values)
            ?? throw new IOException("Android Downloads provider rejected the new file.");
    }

    private static bool IsExpectedPendingDownload(
        ContentResolver resolver,
        global::Android.Net.Uri uri,
        string relativePath,
        string displayName)
    {
        try
        {
            using var cursor = resolver.Query(
                uri,
                [DisplayNameColumn, RelativePathColumn, IsPendingColumn],
                null,
                null,
                null);
            if (cursor is null || !cursor.MoveToFirst())
            {
                return false;
            }

            var storedName = cursor.IsNull(0) ? string.Empty : cursor.GetString(0) ?? string.Empty;
            var storedPath = cursor.IsNull(1) ? string.Empty : cursor.GetString(1) ?? string.Empty;
            var isPending = !cursor.IsNull(2) && cursor.GetInt(2) == 1;
            return isPending &&
                   string.Equals(storedName, displayName, StringComparison.Ordinal) &&
                   MediaStoreRelativePathMatches(storedPath, relativePath);
        }
        catch (Exception ex) when (ex is Java.Lang.SecurityException or Java.Lang.IllegalArgumentException or InvalidOperationException)
        {
            return false;
        }
    }

    private static global::Android.Net.Uri? FindPendingDownload(
        ContentResolver resolver,
        string relativePath,
        string displayName)
    {
        var collection = MediaStore.Downloads.ExternalContentUri
            ?? throw new IOException("Android Downloads collection is unavailable.");

        // MediaStore providers are allowed to normalize RELATIVE_PATH. MagicOS has been
        // observed returning the same path without the trailing slash that was supplied
        // on insert. Query by the deterministic resume name first, then compare normalized
        // paths in managed code so a fresh Wi-Fi reconnect can still find the same .part.
        using var cursor = resolver.Query(
            collection,
            [IdColumn, RelativePathColumn],
            $"{DisplayNameColumn}=? AND {IsPendingColumn}=?",
            [displayName, "1"],
            null);
        if (cursor is null)
        {
            return null;
        }

        while (cursor.MoveToNext())
        {
            var storedPath = cursor.IsNull(1) ? string.Empty : cursor.GetString(1) ?? string.Empty;
            if (!MediaStoreRelativePathMatches(storedPath, relativePath))
            {
                continue;
            }

            return ContentUris.WithAppendedId(collection, cursor.GetLong(0));
        }

        return null;
    }

    private static void PublishDownload(ContentResolver resolver, global::Android.Net.Uri uri, string finalName)
    {
        using var values = new ContentValues();
        values.Put(DisplayNameColumn, finalName);
        values.Put(MimeTypeColumn, GetMimeType(finalName));
        values.Put(IsPendingColumn, 0);
        if (resolver.Update(uri, values, null, null) <= 0)
        {
            throw new IOException("Android Downloads provider did not publish the completed file.");
        }
    }

    private static string FindAvailableDisplayName(ContentResolver resolver, string relativePath, string originalName)
    {
        var collection = MediaStore.Downloads.ExternalContentUri
            ?? throw new IOException("Android Downloads collection is unavailable.");
        if (!DownloadNameExists(resolver, collection, relativePath, originalName))
        {
            return originalName;
        }

        var stem = System.IO.Path.GetFileNameWithoutExtension(originalName);
        var extension = System.IO.Path.GetExtension(originalName);
        for (var index = 1; index <= 9999; index++)
        {
            var candidate = $"{stem} ({index}){extension}";
            if (FileSafety.IsSafeFileName(candidate) && !DownloadNameExists(resolver, collection, relativePath, candidate))
            {
                return candidate;
            }
        }

        throw new IOException("Could not choose a unique Downloads file name.");
    }

    private static bool DownloadNameExists(
        ContentResolver resolver,
        global::Android.Net.Uri collection,
        string relativePath,
        string fileName)
    {
        using var cursor = resolver.Query(
            collection,
            [RelativePathColumn],
            $"{DisplayNameColumn}=? AND {IsPendingColumn}=?",
            [fileName, "0"],
            null);
        if (cursor is null)
        {
            return false;
        }

        while (cursor.MoveToNext())
        {
            var storedPath = cursor.IsNull(0) ? string.Empty : cursor.GetString(0) ?? string.Empty;
            if (MediaStoreRelativePathMatches(storedPath, relativePath))
            {
                return true;
            }
        }

        return false;
    }

    private static bool MediaStoreRelativePathMatches(string left, string right)
    {
        static string Normalize(string value)
        {
            var normalized = value.Trim().Replace('\\', '/').Trim('/');
            while (normalized.Contains("//", StringComparison.Ordinal))
            {
                normalized = normalized.Replace("//", "/", StringComparison.Ordinal);
            }

            return normalized;
        }

        return string.Equals(Normalize(left), Normalize(right), StringComparison.Ordinal);
    }

    private static void CleanupStaleResumeRows(
        ContentResolver resolver,
        AndroidResumeIndex resumeIndex,
        Action<string>? log)
    {
        var cutoffUtc = DateTimeOffset.UtcNow.Subtract(ProtocolConstants.PartialRetention);
        var deleted = 0;

        foreach (var entry in resumeIndex.GetStale(cutoffUtc))
        {
            global::Android.Net.Uri? uri = null;
            try
            {
                uri = global::Android.Net.Uri.Parse(entry.UriString);
                if (uri is not null)
                {
                    TryDelete(resolver, uri);
                }
            }
            catch (Java.Lang.IllegalArgumentException)
            {
            }
            finally
            {
                uri?.Dispose();
            }

            if (TryRemoveResumeIndex(resumeIndex, entry.ResumeKey, log))
            {
                deleted++;
            }
        }

        CleanupLegacyOrphanResumeRows(resolver, resumeIndex, cutoffUtc, log);
        if (deleted > 0)
        {
            log?.Invoke($"Удалено устаревших частичных передач: {deleted}.");
        }
    }

    private static void CleanupLegacyOrphanResumeRows(
        ContentResolver resolver,
        AndroidResumeIndex resumeIndex,
        DateTimeOffset cutoffUtc,
        Action<string>? log)
    {
        try
        {
            var collection = MediaStore.Downloads.ExternalContentUri;
            if (collection is null)
            {
                return;
            }

            var indexedUris = resumeIndex.GetAll()
                .Select(entry => entry.UriString)
                .ToHashSet(StringComparer.Ordinal);
            var cutoffSeconds = cutoffUtc.ToUnixTimeSeconds();
            using var cursor = resolver.Query(
                collection,
                [IdColumn, DateModifiedColumn, DateAddedColumn],
                $"{DisplayNameColumn} LIKE ? AND {IsPendingColumn}=?",
                [".genialink-%.part", "1"],
                null);
            if (cursor is null)
            {
                return;
            }

            while (cursor.MoveToNext())
            {
                var modified = cursor.IsNull(1) ? 0 : cursor.GetLong(1);
                var added = cursor.IsNull(2) ? 0 : cursor.GetLong(2);
                var knownTimestamp = modified > 0 ? modified : added;
                if (knownTimestamp <= 0 || knownTimestamp >= cutoffSeconds)
                {
                    continue;
                }

                using var uri = ContentUris.WithAppendedId(collection, cursor.GetLong(0));
                if (uri is null || indexedUris.Contains(uri.ToString() ?? string.Empty))
                {
                    continue;
                }

                TryDelete(resolver, uri);
            }
        }
        catch (Exception ex) when (ex is Java.Lang.SecurityException or Java.Lang.IllegalArgumentException or InvalidOperationException)
        {
            log?.Invoke("Не удалось выполнить очистку старых неиндексированных частичных передач.");
        }
    }

    private static bool TryRemoveResumeIndex(AndroidResumeIndex resumeIndex, string resumeKey, Action<string>? log)
    {
        try
        {
            return resumeIndex.Remove(resumeKey);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log?.Invoke($"Не удалось обновить индекс докачки: {ex.Message}");
            return false;
        }
    }

    private static void TryTouchResumeIndex(AndroidResumeIndex resumeIndex, string resumeKey, Action<string>? log)
    {
        try
        {
            resumeIndex.Touch(resumeKey);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            log?.Invoke($"Не удалось обновить время состояния докачки: {ex.Message}");
        }
    }

    private static bool HasFreeSpace(string externalStoragePath, long requiredBytes)
    {
        if (requiredBytes <= 0)
        {
            return true;
        }

        try
        {
            using var statFs = new global::Android.OS.StatFs(externalStoragePath);
            return statFs.AvailableBytes >= checked(requiredBytes + ProtocolConstants.FreeSpaceReserveBytes);
        }
        catch (Exception ex) when (ex is Java.Lang.IllegalArgumentException or OverflowException)
        {
            return false;
        }
    }

    private static void TryDelete(ContentResolver resolver, global::Android.Net.Uri uri)
    {
        try
        {
            _ = resolver.Delete(uri, null, null);
        }
        catch (Exception ex) when (ex is Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException or InvalidOperationException)
        {
        }
    }

    private static string GetMimeType(string fileName)
    {
        var extension = System.IO.Path.GetExtension(fileName).TrimStart('.');
        if (string.IsNullOrWhiteSpace(extension))
        {
            return "application/octet-stream";
        }

        try
        {
            return MimeTypeMap.Singleton?.GetMimeTypeFromExtension(extension.ToLowerInvariant())
                ?? "application/octet-stream";
        }
        catch (Java.Lang.IllegalArgumentException)
        {
            return "application/octet-stream";
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

    private sealed class ReceiveState : IAsyncDisposable
    {
        public ReceiveState(
            FileOffer offer,
            string resumeKey,
            string relativePath,
            global::Android.Net.Uri contentUri,
            Stream stream,
            IncrementalHash hash,
            long resumeOffset)
        {
            TransferId = offer.TransferId;
            ResumeKey = resumeKey;
            FileName = offer.FileName;
            ExpectedSize = offer.FileSize;
            ExpectedHash = offer.Sha256.ToArray();
            RelativePath = relativePath;
            ContentUri = contentUri;
            Stream = stream;
            Hash = hash;
            BytesReceived = resumeOffset;
            ResumeOffset = resumeOffset;
        }

        public Guid TransferId { get; }
        public string ResumeKey { get; }
        public string FileName { get; }
        public long ExpectedSize { get; }
        public byte[] ExpectedHash { get; }
        public string RelativePath { get; }
        public global::Android.Net.Uri ContentUri { get; }
        public Stream Stream { get; }
        public IncrementalHash Hash { get; }
        public long BytesReceived { get; set; }
        public long ResumeOffset { get; }
        public bool StreamClosed { get; set; }
        public bool Published { get; set; }
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
            ContentUri.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
