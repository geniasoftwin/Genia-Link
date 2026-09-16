using System.IO;
using System.Buffers.Binary;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;

namespace GeniaLink.Core.Network;

public enum SecureChannelRole
{
    Client,
    Server
}

public sealed class SecureChannel : IAsyncDisposable
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] AssociatedDataPrefix = Encoding.ASCII.GetBytes("GENIALINK/2/FRAME");
    private static readonly byte[] ClientToServerLabel = Encoding.ASCII.GetBytes("GENIALINK/2/C2S");
    private static readonly byte[] ServerToClientLabel = Encoding.ASCII.GetBytes("GENIALINK/2/S2C");

    private readonly Stream _stream;
    private readonly byte[] _sendKey;
    private readonly byte[] _receiveKey;
    private readonly bool _leaveOpen;
    private ulong _sendSequence;
    private ulong _receiveSequence;
    private bool _disposed;

    public SecureChannel(Stream stream, byte[] sessionKey, SecureChannelRole role, bool leaveOpen = false)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(sessionKey);
        if (sessionKey.Length != 32)
        {
            throw new ArgumentException("Session key must contain 32 bytes.", nameof(sessionKey));
        }

        if (role is not SecureChannelRole.Client and not SecureChannelRole.Server)
        {
            throw new ArgumentOutOfRangeException(nameof(role));
        }

        _stream = stream;
        _leaveOpen = leaveOpen;

        var clientToServerKey = DeriveDirectionalKey(sessionKey, ClientToServerLabel);
        var serverToClientKey = DeriveDirectionalKey(sessionKey, ServerToClientLabel);
        if (role == SecureChannelRole.Client)
        {
            _sendKey = clientToServerKey;
            _receiveKey = serverToClientKey;
        }
        else
        {
            _sendKey = serverToClientKey;
            _receiveKey = clientToServerKey;
        }
    }

    public async Task SendAsync(ReadOnlyMemory<byte> plaintext, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (plaintext.Length > ProtocolConstants.MaxEncryptedFrameSize - NonceSize - TagSize)
        {
            throw new InvalidDataException("Protocol frame is too large.");
        }

        var sequence = GetNextSendSequence();
        var associatedData = CreateAssociatedData(sequence);
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        try
        {
            using (var aes = new AesGcm(_sendKey, TagSize))
            {
                aes.Encrypt(nonce, plaintext.Span, ciphertext, tag, associatedData);
            }

            var frameLength = checked(NonceSize + ciphertext.Length + TagSize);
            var header = new byte[4];
            BinaryPrimitives.WriteInt32BigEndian(header, frameLength);

            await _stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
            await _stream.WriteAsync(nonce, cancellationToken).ConfigureAwait(false);
            await _stream.WriteAsync(ciphertext, cancellationToken).ConfigureAwait(false);
            await _stream.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
            await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(associatedData);
        }
    }

    public async Task<byte[]> ReceiveAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var header = new byte[4];
        await ReadExactlyAsync(_stream, header, cancellationToken).ConfigureAwait(false);
        var frameLength = BinaryPrimitives.ReadInt32BigEndian(header);

        if (frameLength < NonceSize + TagSize || frameLength > ProtocolConstants.MaxEncryptedFrameSize)
        {
            throw new InvalidDataException("Invalid encrypted frame length.");
        }

        var frame = new byte[frameLength];
        await ReadExactlyAsync(_stream, frame, cancellationToken).ConfigureAwait(false);

        var ciphertextLength = frameLength - NonceSize - TagSize;
        var plaintext = new byte[ciphertextLength];
        var sequence = _receiveSequence;
        var associatedData = CreateAssociatedData(sequence);

        try
        {
            using var aes = new AesGcm(_receiveKey, TagSize);
            aes.Decrypt(
                frame.AsSpan(0, NonceSize),
                frame.AsSpan(NonceSize, ciphertextLength),
                frame.AsSpan(NonceSize + ciphertextLength, TagSize),
                plaintext,
                associatedData);

            AdvanceReceiveSequence();
            return plaintext;
        }
        catch (CryptographicException ex)
        {
            CryptographicOperations.ZeroMemory(plaintext);
            throw new AuthenticationException("Encrypted frame authentication or sequence validation failed.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(associatedData);
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        CryptographicOperations.ZeroMemory(_sendKey);
        CryptographicOperations.ZeroMemory(_receiveKey);
        if (!_leaveOpen)
        {
            await _stream.DisposeAsync().ConfigureAwait(false);
        }
    }

    private ulong GetNextSendSequence()
    {
        if (_sendSequence == ulong.MaxValue)
        {
            throw new InvalidOperationException("Secure-channel send sequence was exhausted.");
        }

        return _sendSequence++;
    }

    private void AdvanceReceiveSequence()
    {
        if (_receiveSequence == ulong.MaxValue)
        {
            throw new InvalidOperationException("Secure-channel receive sequence was exhausted.");
        }

        _receiveSequence++;
    }

    private static byte[] CreateAssociatedData(ulong sequence)
    {
        var associatedData = new byte[AssociatedDataPrefix.Length + sizeof(ulong)];
        AssociatedDataPrefix.CopyTo(associatedData, 0);
        BinaryPrimitives.WriteUInt64BigEndian(associatedData.AsSpan(AssociatedDataPrefix.Length), sequence);
        return associatedData;
    }

    private static byte[] DeriveDirectionalKey(byte[] sessionKey, byte[] label)
    {
        var keyCopy = sessionKey.ToArray();
        try
        {
            using var hmac = new HMACSHA256(keyCopy);
            return hmac.ComputeHash(label);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(keyCopy);
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
                throw new EndOfStreamException("The remote device closed the connection.");
            }

            totalRead += read;
        }
    }
}
