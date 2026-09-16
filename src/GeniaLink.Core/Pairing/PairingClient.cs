using System.Net;
using System.Net.Sockets;

namespace GeniaLink.Core.Pairing;

public static class PairingClient
{
    public static async Task<PairingPeerInfo> PairAsync(
        IPAddress targetAddress,
        int port,
        PairingPeerInfo local,
        Func<PairingConfirmation, Task<bool>> confirm,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(targetAddress);
        if (!GeniaLink.Core.Network.LocalNetworkPolicy.IsAllowedAddress(targetAddress))
        {
            throw new InvalidOperationException("Genia Link pairing is restricted to local/private IPv4 addresses.");
        }

        using var tcp = new TcpClient(targetAddress.AddressFamily) { NoDelay = true };
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(GeniaLink.Core.Network.ProtocolConstants.PairingTimeout);
        await tcp.ConnectAsync(targetAddress, port, timeoutCts.Token).ConfigureAwait(false);
        return await PairingProtocol.RunClientAsync(tcp.GetStream(), local, confirm, timeoutCts.Token).ConfigureAwait(false);
    }
}
