namespace GeniaLink.Core.Network;

public static class TransferIo
{
    public static async Task SendAsync(
        SecureChannel channel,
        ReadOnlyMemory<byte> message,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(channel);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(ProtocolConstants.TransferIoTimeout);
        await channel.SendAsync(message, timeoutCts.Token).ConfigureAwait(false);
    }

    public static async Task<byte[]> ReceiveAsync(
        SecureChannel channel,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(channel);
        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(ProtocolConstants.IdleTimeout);
        return await channel.ReceiveAsync(timeoutCts.Token).ConfigureAwait(false);
    }
}
