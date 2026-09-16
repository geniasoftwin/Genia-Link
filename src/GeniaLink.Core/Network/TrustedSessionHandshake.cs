using System.IO;
using System.Buffers.Binary;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

namespace GeniaLink.Core.Network;

public sealed record ServerHandshakeResult(Guid RemoteDeviceId, byte[] SessionKey);

public static class TrustedSessionHandshake
{
    private const int NonceSize = 32;
    private const int RequestSize = 4 + 4 + 16 + NonceSize;
    private const int ResponseSize = 4 + 4 + 1 + 16 + NonceSize;
    private static readonly byte[] RequestMagic = "GLT2"u8.ToArray();
    private static readonly byte[] ResponseMagic = "GLR2"u8.ToArray();
    private static readonly byte[] KdfContext = Encoding.ASCII.GetBytes("GENIALINK-TRUSTED-SESSION-V2");

    public static async Task<byte[]> CreateClientSessionKeyAsync(
        Stream stream,
        Guid localDeviceId,
        Guid expectedServerId,
        ReadOnlyMemory<byte> sharedKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ValidateSharedKey(sharedKey);

        var clientNonce = RandomNumberGenerator.GetBytes(NonceSize);
        var request = new byte[RequestSize];
        RequestMagic.CopyTo(request, 0);
        BinaryPrimitives.WriteInt32BigEndian(request.AsSpan(4, 4), ProtocolConstants.Version);
        localDeviceId.TryWriteBytes(request.AsSpan(8, 16));
        clientNonce.CopyTo(request, 24);

        var response = new byte[ResponseSize];
        try
        {
            await stream.WriteAsync(request, cancellationToken).ConfigureAwait(false);
            await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
            await ReadExactlyAsync(stream, response, cancellationToken).ConfigureAwait(false);

            ValidateResponseHeader(response);
            if (response[8] != 1)
            {
                throw new AuthenticationException("The remote device does not trust this Genia Link device.");
            }

            var serverId = new Guid(response.AsSpan(9, 16));
            if (serverId != expectedServerId)
            {
                throw new AuthenticationException("The remote Genia Link identity does not match the selected trusted device.");
            }

            var serverNonce = response.AsSpan(25, NonceSize).ToArray();
            try
            {
                return DeriveSessionKey(sharedKey.Span, localDeviceId, serverId, clientNonce, serverNonce);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(serverNonce);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clientNonce);
            CryptographicOperations.ZeroMemory(request);
            CryptographicOperations.ZeroMemory(response);
        }
    }

    public static async Task<ServerHandshakeResult> CreateServerSessionKeyAsync(
        Stream stream,
        Guid localDeviceId,
        Func<Guid, byte[]?> sharedKeyResolver,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(sharedKeyResolver);

        var request = new byte[RequestSize];
        await ReadExactlyAsync(stream, request, cancellationToken).ConfigureAwait(false);

        byte[]? sharedKey = null;
        var serverNonce = RandomNumberGenerator.GetBytes(NonceSize);
        var response = new byte[ResponseSize];

        try
        {
            ValidateRequestHeader(request);
            var remoteDeviceId = new Guid(request.AsSpan(8, 16));
            var clientNonce = request.AsSpan(24, NonceSize).ToArray();
            try
            {
                sharedKey = sharedKeyResolver(remoteDeviceId);
                var trusted = sharedKey is { Length: 32 };

                ResponseMagic.CopyTo(response, 0);
                BinaryPrimitives.WriteInt32BigEndian(response.AsSpan(4, 4), ProtocolConstants.Version);
                response[8] = trusted ? (byte)1 : (byte)0;
                localDeviceId.TryWriteBytes(response.AsSpan(9, 16));
                serverNonce.CopyTo(response, 25);

                await stream.WriteAsync(response, cancellationToken).ConfigureAwait(false);
                await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

                if (!trusted || sharedKey is null)
                {
                    throw new AuthenticationException("The connecting device is not trusted.");
                }

                var sessionKey = DeriveSessionKey(sharedKey, remoteDeviceId, localDeviceId, clientNonce, serverNonce);
                return new ServerHandshakeResult(remoteDeviceId, sessionKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clientNonce);
            }
        }
        finally
        {
            if (sharedKey is not null)
            {
                CryptographicOperations.ZeroMemory(sharedKey);
            }

            CryptographicOperations.ZeroMemory(serverNonce);
            CryptographicOperations.ZeroMemory(request);
            CryptographicOperations.ZeroMemory(response);
        }
    }

    private static byte[] DeriveSessionKey(
        ReadOnlySpan<byte> sharedKey,
        Guid clientDeviceId,
        Guid serverDeviceId,
        ReadOnlySpan<byte> clientNonce,
        ReadOnlySpan<byte> serverNonce)
    {
        var transcript = new byte[KdfContext.Length + 16 + 16 + NonceSize + NonceSize];
        var offset = 0;
        KdfContext.CopyTo(transcript, offset);
        offset += KdfContext.Length;
        clientDeviceId.TryWriteBytes(transcript.AsSpan(offset, 16));
        offset += 16;
        serverDeviceId.TryWriteBytes(transcript.AsSpan(offset, 16));
        offset += 16;
        clientNonce.CopyTo(transcript.AsSpan(offset, NonceSize));
        offset += NonceSize;
        serverNonce.CopyTo(transcript.AsSpan(offset, NonceSize));

        var keyCopy = sharedKey.ToArray();
        try
        {
            using var hmac = new HMACSHA256(keyCopy);
            return hmac.ComputeHash(transcript);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyCopy);
            CryptographicOperations.ZeroMemory(transcript);
        }
    }

    private static void ValidateRequestHeader(ReadOnlySpan<byte> packet)
    {
        if (packet.Length != RequestSize || !packet[..4].SequenceEqual(RequestMagic))
        {
            throw new AuthenticationException("Invalid trusted-session request.");
        }

        if (BinaryPrimitives.ReadInt32BigEndian(packet.Slice(4, 4)) != ProtocolConstants.Version)
        {
            throw new AuthenticationException("Incompatible Genia Link protocol version.");
        }
    }

    private static void ValidateResponseHeader(ReadOnlySpan<byte> packet)
    {
        if (packet.Length != ResponseSize || !packet[..4].SequenceEqual(ResponseMagic))
        {
            throw new AuthenticationException("Invalid trusted-session response.");
        }

        if (BinaryPrimitives.ReadInt32BigEndian(packet.Slice(4, 4)) != ProtocolConstants.Version)
        {
            throw new AuthenticationException("Incompatible Genia Link protocol version.");
        }
    }

    private static void ValidateSharedKey(ReadOnlyMemory<byte> sharedKey)
    {
        if (sharedKey.Length != 32)
        {
            throw new ArgumentException("Trusted shared key must contain 32 bytes.", nameof(sharedKey));
        }
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[totalRead..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The remote device closed the connection during authentication.");
            }

            totalRead += read;
        }
    }
}
