using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using GeniaLink.Core.Identity;

namespace GeniaLink.Core.Network;

public static class IdentityBindingService
{
    public static async Task<TrustedSigningIdentity> BindAsync(
        IPAddress targetAddress,
        int port,
        IDeviceSigningIdentity localIdentity,
        Guid expectedRemoteDeviceId,
        ReadOnlyMemory<byte> trustedSharedKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(targetAddress);
        ArgumentNullException.ThrowIfNull(localIdentity);
        if (!LocalNetworkPolicy.IsAllowedAddress(targetAddress))
        {
            throw new InvalidDataException("Signing-identity binding is restricted to the local network.");
        }

        if (expectedRemoteDeviceId == Guid.Empty)
        {
            throw new ArgumentException("Expected remote device ID must not be empty.", nameof(expectedRemoteDeviceId));
        }

        if (trustedSharedKey.Length != 32)
        {
            throw new ArgumentException("Trusted shared key must contain 32 bytes.", nameof(trustedSharedKey));
        }

        using var tcp = new TcpClient(targetAddress.AddressFamily) { NoDelay = true };
        using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            connectCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
            await tcp.ConnectAsync(targetAddress, port, connectCts.Token).ConfigureAwait(false);
        }

        var stream = tcp.GetStream();
        byte[] sessionKey;
        using (var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            handshakeCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
            sessionKey = await TrustedSessionHandshake.CreateClientSessionKeyAsync(
                stream,
                localIdentity.DeviceId,
                expectedRemoteDeviceId,
                trustedSharedKey,
                handshakeCts.Token).ConfigureAwait(false);
        }

        try
        {
            await using var channel = new SecureChannel(stream, sessionKey, SecureChannelRole.Client);
            using var exchangeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            exchangeCts.CancelAfter(ProtocolConstants.HandshakeTimeout);

            var localMessage = IdentityBindingProtocol.CreateIdentity(localIdentity);
            try
            {
                await channel.SendAsync(localMessage, exchangeCts.Token).ConfigureAwait(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(localMessage);
            }

            var response = await channel.ReceiveAsync(exchangeCts.Token).ConfigureAwait(false);
            try
            {
                var remoteIdentity = IdentityBindingProtocol.ParseIdentity(response);
                if (remoteIdentity.DeviceId != expectedRemoteDeviceId)
                {
                    CryptographicOperations.ZeroMemory(remoteIdentity.SigningPublicKey);
                    throw new AuthenticationException("Authenticated signing identity does not match the selected trusted device.");
                }

                return remoteIdentity;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(response);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sessionKey);
        }
    }

    public static async Task RunServerAsync(
        int port,
        IDeviceSigningIdentity localIdentity,
        Func<Guid, byte[]?> sharedKeyResolver,
        Action<TrustedSigningIdentity, IPAddress> identityBound,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(localIdentity);
        ArgumentNullException.ThrowIfNull(sharedKeyResolver);
        ArgumentNullException.ThrowIfNull(identityBound);

        var listener = new TcpListener(IPAddress.Any, port);
        try
        {
            listener.Start(backlog: 4);
            log?.Invoke($"GNP/1 M2.3/M2.4.2 trusted signing-identity binding listener active on TCP {port}.");
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
                        log?.Invoke("Rejected signing-identity binding connection from a non-local address.");
                        continue;
                    }

                    try
                    {
                        await HandleClientAsync(
                            client,
                            localIdentity,
                            sharedKeyResolver,
                            remoteEndPoint.Address,
                            identityBound,
                            cancellationToken).ConfigureAwait(false);
                    }
                    catch (AuthenticationException ex)
                    {
                        log?.Invoke($"Rejected untrusted signing-identity binding: {ex.Message}");
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        log?.Invoke("Signing-identity binding timed out safely.");
                    }
                    catch (Exception ex) when (ex is IOException or InvalidDataException or SocketException or CryptographicException)
                    {
                        log?.Invoke($"Signing-identity binding ended safely: {ex.Message}");
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
        IDeviceSigningIdentity localIdentity,
        Func<Guid, byte[]?> sharedKeyResolver,
        IPAddress remoteAddress,
        Action<TrustedSigningIdentity, IPAddress> identityBound,
        CancellationToken cancellationToken)
    {
        var stream = client.GetStream();
        ServerHandshakeResult handshake;
        using (var handshakeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            handshakeCts.CancelAfter(ProtocolConstants.HandshakeTimeout);
            handshake = await TrustedSessionHandshake.CreateServerSessionKeyAsync(
                stream,
                localIdentity.DeviceId,
                sharedKeyResolver,
                handshakeCts.Token).ConfigureAwait(false);
        }

        try
        {
            await using var channel = new SecureChannel(stream, handshake.SessionKey, SecureChannelRole.Server);
            using var exchangeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            exchangeCts.CancelAfter(ProtocolConstants.HandshakeTimeout);

            var request = await channel.ReceiveAsync(exchangeCts.Token).ConfigureAwait(false);
            TrustedSigningIdentity remoteIdentity;
            try
            {
                remoteIdentity = IdentityBindingProtocol.ParseIdentity(request);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(request);
            }

            try
            {
                if (remoteIdentity.DeviceId != handshake.RemoteDeviceId)
                {
                    throw new AuthenticationException("Signing identity changed after trusted-session authentication.");
                }

                identityBound(remoteIdentity, remoteAddress);
                var response = IdentityBindingProtocol.CreateIdentity(localIdentity);
                try
                {
                    await channel.SendAsync(response, exchangeCts.Token).ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(response);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(remoteIdentity.SigningPublicKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(handshake.SessionKey);
        }
    }
}
