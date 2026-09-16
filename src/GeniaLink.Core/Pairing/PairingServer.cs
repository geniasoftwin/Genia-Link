using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using GeniaLink.Core.Network;

namespace GeniaLink.Core.Pairing;

public static class PairingServer
{
    public static async Task RunAsync(
        int port,
        PairingPeerInfo local,
        Func<PairingConfirmation, Task<bool>> confirm,
        Action<PairingPeerInfo> paired,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(confirm);
        ArgumentNullException.ThrowIfNull(paired);

        var listener = new TcpListener(IPAddress.Any, port);
        try
        {
            listener.Start(backlog: 4);
            log?.Invoke($"Pairing listener active on TCP {port}.");
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
                        log?.Invoke("Rejected pairing connection from a non-local address.");
                        continue;
                    }

                    try
                    {
                        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                        timeoutCts.CancelAfter(ProtocolConstants.PairingTimeout);
                        var remote = await PairingProtocol.RunServerAsync(client.GetStream(), local, confirm, timeoutCts.Token)
                            .ConfigureAwait(false);
                        paired(remote);
                        log?.Invoke($"Paired with {remote.DeviceName}.");
                    }
                    catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                    {
                        break;
                    }
                    catch (OperationCanceledException)
                    {
                        log?.Invoke("Pairing request timed out.");
                    }
                    catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or CryptographicException or InvalidDataException)
                    {
                        log?.Invoke($"Pairing request rejected safely: {ex.Message}");
                    }
                }
            }
        }
        finally
        {
            listener.Stop();
        }
    }
}
