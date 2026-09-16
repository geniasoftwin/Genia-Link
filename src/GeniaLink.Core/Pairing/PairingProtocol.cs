using System.IO;
using System.Buffers.Binary;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using GeniaLink.Core.Network;

namespace GeniaLink.Core.Pairing;

public static class PairingProtocol
{
    private const int MaxNameBytes = 160;
    private const int MaxPublicKeyBytes = 256;
    private static readonly byte[] Magic = "GLP2"u8.ToArray();
    private static readonly byte[] SasContext = Encoding.ASCII.GetBytes("GENIALINK-PAIR-SAS-V2");
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static async Task<PairingPeerInfo> RunClientAsync(
        Stream stream,
        PairingPeerInfo local,
        Func<PairingConfirmation, Task<bool>> confirm,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(confirm);
        ValidatePeerInfo(local);

        await WritePeerAsync(stream, local, cancellationToken).ConfigureAwait(false);
        var remote = await ReadPeerAsync(stream, cancellationToken).ConfigureAwait(false);
        await ConfirmBothSidesAsync(stream, local, remote, confirm, cancellationToken).ConfigureAwait(false);
        return remote;
    }

    public static async Task<PairingPeerInfo> RunServerAsync(
        Stream stream,
        PairingPeerInfo local,
        Func<PairingConfirmation, Task<bool>> confirm,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(confirm);
        ValidatePeerInfo(local);

        var remote = await ReadPeerAsync(stream, cancellationToken).ConfigureAwait(false);
        await WritePeerAsync(stream, local, cancellationToken).ConfigureAwait(false);
        await ConfirmBothSidesAsync(stream, local, remote, confirm, cancellationToken).ConfigureAwait(false);
        return remote;
    }

    public static string GetPublicKeyFingerprint(ReadOnlySpan<byte> publicKey)
    {
        var hash = SHA256.HashData(publicKey);
        try
        {
            return Convert.ToHexString(hash.AsSpan(0, 16));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static async Task ConfirmBothSidesAsync(
        Stream stream,
        PairingPeerInfo local,
        PairingPeerInfo remote,
        Func<PairingConfirmation, Task<bool>> confirm,
        CancellationToken cancellationToken)
    {
        if (local.DeviceId == remote.DeviceId)
        {
            throw new AuthenticationException("A device cannot be paired with itself.");
        }

        var code = CreateVerificationCode(local, remote);
        var fingerprint = GetPublicKeyFingerprint(remote.PublicKey);
        var accepted = await confirm(new PairingConfirmation(remote, code, fingerprint)).ConfigureAwait(false);

        var verdict = new[] { accepted ? (byte)1 : (byte)0 };
        await stream.WriteAsync(verdict, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        var remoteVerdict = new byte[1];
        await ReadExactlyAsync(stream, remoteVerdict, cancellationToken).ConfigureAwait(false);
        if (!accepted || remoteVerdict[0] != 1)
        {
            throw new AuthenticationException("Pairing was not confirmed on both devices.");
        }
    }

    private static string CreateVerificationCode(PairingPeerInfo first, PairingPeerInfo second)
    {
        var order = first.DeviceId.CompareTo(second.DeviceId) <= 0
            ? (Left: first, Right: second)
            : (Left: second, Right: first);

        var input = new byte[SasContext.Length + 16 + order.Left.PublicKey.Length + 16 + order.Right.PublicKey.Length];
        var offset = 0;
        SasContext.CopyTo(input, offset);
        offset += SasContext.Length;
        order.Left.DeviceId.TryWriteBytes(input.AsSpan(offset, 16));
        offset += 16;
        order.Left.PublicKey.CopyTo(input, offset);
        offset += order.Left.PublicKey.Length;
        order.Right.DeviceId.TryWriteBytes(input.AsSpan(offset, 16));
        offset += 16;
        order.Right.PublicKey.CopyTo(input, offset);

        var hash = SHA256.HashData(input);
        try
        {
            var value = BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(0, 4)) % 1_000_000;
            return value.ToString("000 000", System.Globalization.CultureInfo.InvariantCulture);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(input);
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static async Task WritePeerAsync(Stream stream, PairingPeerInfo peer, CancellationToken cancellationToken)
    {
        var name = StrictUtf8.GetBytes(peer.DeviceName);
        var packet = new byte[4 + 4 + 16 + 4 + name.Length + 4 + peer.PublicKey.Length];
        var offset = 0;
        Magic.CopyTo(packet, offset);
        offset += 4;
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(offset, 4), ProtocolConstants.Version);
        offset += 4;
        peer.DeviceId.TryWriteBytes(packet.AsSpan(offset, 16));
        offset += 16;
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(offset, 4), name.Length);
        offset += 4;
        name.CopyTo(packet, offset);
        offset += name.Length;
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(offset, 4), peer.PublicKey.Length);
        offset += 4;
        peer.PublicKey.CopyTo(packet, offset);

        await stream.WriteAsync(packet, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task<PairingPeerInfo> ReadPeerAsync(Stream stream, CancellationToken cancellationToken)
    {
        var fixedHeader = new byte[4 + 4 + 16 + 4];
        await ReadExactlyAsync(stream, fixedHeader, cancellationToken).ConfigureAwait(false);
        if (!fixedHeader.AsSpan(0, 4).SequenceEqual(Magic))
        {
            throw new AuthenticationException("Invalid Genia Link pairing request.");
        }

        if (BinaryPrimitives.ReadInt32BigEndian(fixedHeader.AsSpan(4, 4)) != ProtocolConstants.Version)
        {
            throw new AuthenticationException("Incompatible Genia Link pairing version.");
        }

        var deviceId = new Guid(fixedHeader.AsSpan(8, 16));
        var nameLength = BinaryPrimitives.ReadInt32BigEndian(fixedHeader.AsSpan(24, 4));
        if (nameLength is < 1 or > MaxNameBytes)
        {
            throw new InvalidDataException("Invalid pairing device-name length.");
        }

        var nameBytes = new byte[nameLength];
        await ReadExactlyAsync(stream, nameBytes, cancellationToken).ConfigureAwait(false);
        string name;
        try
        {
            name = StrictUtf8.GetString(nameBytes);
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidDataException("Pairing device name is not valid UTF-8.", ex);
        }

        var keyLengthBytes = new byte[4];
        await ReadExactlyAsync(stream, keyLengthBytes, cancellationToken).ConfigureAwait(false);
        var keyLength = BinaryPrimitives.ReadInt32BigEndian(keyLengthBytes);
        if (keyLength is < 32 or > MaxPublicKeyBytes)
        {
            throw new InvalidDataException("Invalid pairing public-key length.");
        }

        if (!IsSafeDeviceName(name, out _))
        {
            throw new InvalidDataException("Pairing device name contains unsafe characters.");
        }

        var publicKey = new byte[keyLength];
        await ReadExactlyAsync(stream, publicKey, cancellationToken).ConfigureAwait(false);
        ValidatePublicKey(publicKey);
        return new PairingPeerInfo(deviceId, name, publicKey);
    }

    private static void ValidatePeerInfo(PairingPeerInfo peer)
    {
        if (peer.DeviceId == Guid.Empty)
        {
            throw new ArgumentException("Pairing device ID cannot be empty.", nameof(peer));
        }

        if (!IsSafeDeviceName(peer.DeviceName, out var nameBytes))
        {
            throw new ArgumentException("Pairing device name is invalid.", nameof(peer));
        }

        if (nameBytes is < 1 or > MaxNameBytes)
        {
            throw new ArgumentException("Pairing device name is outside the allowed size.", nameof(peer));
        }

        ValidatePublicKey(peer.PublicKey);
    }

    public static void ValidatePublicKey(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.Length is < 32 or > MaxPublicKeyBytes)
        {
            throw new InvalidDataException("Pairing public key is outside the allowed size.");
        }

        using var ecdh = ECDiffieHellman.Create();
        ecdh.ImportSubjectPublicKeyInfo(publicKey, out var bytesRead);
        if (bytesRead != publicKey.Length || ecdh.KeySize != 256)
        {
            throw new InvalidDataException("Pairing public key must be an ECDH P-256 key.");
        }

        var parameters = ecdh.ExportParameters(includePrivateParameters: false);
        if (!string.Equals(parameters.Curve.Oid.Value, ECCurve.NamedCurves.nistP256.Oid.Value, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Pairing public key must use the NIST P-256 curve.");
        }
    }

    private static bool IsSafeDeviceName(string? name, out int utf8ByteCount)
    {
        utf8ByteCount = 0;
        if (string.IsNullOrWhiteSpace(name) || name.Any(ch => char.IsControl(ch) || System.Globalization.CharUnicodeInfo.GetUnicodeCategory(ch) == System.Globalization.UnicodeCategory.Format))
        {
            return false;
        }

        utf8ByteCount = StrictUtf8.GetByteCount(name);
        return true;
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[totalRead..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new EndOfStreamException("The remote device closed the pairing connection.");
            }

            totalRead += read;
        }
    }
}
