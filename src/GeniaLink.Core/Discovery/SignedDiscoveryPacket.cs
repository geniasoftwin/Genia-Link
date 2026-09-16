using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Network;

namespace GeniaLink.Core.Discovery;

/// <summary>
/// GNP/1 M2.2 signed discovery envelope.
/// RC4 legacy discovery (GLD2) remains unchanged and is broadcast alongside this packet.
/// </summary>
public static class SignedDiscoveryPacket
{
    private const int MaxNameBytes = 160;
    private const int AgreementFingerprintBytes = 16;
    private const int MaxSigningPublicKeyBytes = 160;
    private static readonly byte[] Magic = "GLS1"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static byte[] Create(DiscoveryAdvertisement advertisement, IDeviceSigningIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(advertisement);
        ArgumentNullException.ThrowIfNull(identity);

        ValidateAdvertisement(advertisement);
        if (identity.DeviceId != advertisement.DeviceId)
        {
            throw new InvalidDataException("Signing identity DeviceId does not match the discovery advertisement.");
        }

        if (!string.Equals(identity.DisplayName, advertisement.DeviceName, StringComparison.Ordinal))
        {
            throw new InvalidDataException("Signing identity display name does not match the discovery advertisement.");
        }

        if (identity.DeviceKind != advertisement.Kind)
        {
            throw new InvalidDataException("Signing identity device kind does not match the discovery advertisement.");
        }

        if (identity.IdentityVersion < 2 || identity.KeyGeneration < 1)
        {
            throw new InvalidDataException("Signing identity metadata is not valid for GNP/1 M2.2 discovery.");
        }

        var nameBytes = StrictUtf8.GetBytes(advertisement.DeviceName);
        var agreementFingerprint = ParseAgreementFingerprint(advertisement.PublicKeyFingerprint);
        var signingPublicKey = identity.ExportSigningPublicKey();
        byte[]? signature = null;
        try
        {
            DeviceSignature.ValidatePublicKey(signingPublicKey);
            if (signingPublicKey.Length > MaxSigningPublicKeyBytes)
            {
                throw new InvalidDataException("Signing public key is too large for discovery.");
            }

            var signedPayloadLength =
                4 + // magic
                4 + // protocol version
                4 + // identity version
                16 + // device id
                4 + // transfer port
                4 + // pairing port
                1 + // device kind
                4 + // key generation
                4 + nameBytes.Length +
                AgreementFingerprintBytes +
                4 + signingPublicKey.Length;

            var signedPayload = new byte[signedPayloadLength];
            var offset = 0;
            Magic.CopyTo(signedPayload, offset);
            offset += 4;
            BinaryPrimitives.WriteInt32BigEndian(signedPayload.AsSpan(offset, 4), ProtocolConstants.Version);
            offset += 4;
            BinaryPrimitives.WriteInt32BigEndian(signedPayload.AsSpan(offset, 4), identity.IdentityVersion);
            offset += 4;
            advertisement.DeviceId.TryWriteBytes(signedPayload.AsSpan(offset, 16));
            offset += 16;
            BinaryPrimitives.WriteInt32BigEndian(signedPayload.AsSpan(offset, 4), advertisement.TransferPort);
            offset += 4;
            BinaryPrimitives.WriteInt32BigEndian(signedPayload.AsSpan(offset, 4), advertisement.PairingPort);
            offset += 4;
            signedPayload[offset++] = (byte)advertisement.Kind;
            BinaryPrimitives.WriteInt32BigEndian(signedPayload.AsSpan(offset, 4), identity.KeyGeneration);
            offset += 4;
            BinaryPrimitives.WriteInt32BigEndian(signedPayload.AsSpan(offset, 4), nameBytes.Length);
            offset += 4;
            nameBytes.CopyTo(signedPayload, offset);
            offset += nameBytes.Length;
            agreementFingerprint.CopyTo(signedPayload, offset);
            offset += agreementFingerprint.Length;
            BinaryPrimitives.WriteInt32BigEndian(signedPayload.AsSpan(offset, 4), signingPublicKey.Length);
            offset += 4;
            signingPublicKey.CopyTo(signedPayload, offset);

            signature = identity.Sign(signedPayload);
            if (signature.Length is < 1 or > DeviceSignature.MaxDerSignatureBytes)
            {
                throw new CryptographicException("Signing identity produced an invalid discovery signature length.");
            }

            var packet = new byte[signedPayload.Length + 4 + signature.Length];
            signedPayload.CopyTo(packet, 0);
            BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(signedPayload.Length, 4), signature.Length);
            signature.CopyTo(packet, signedPayload.Length + 4);
            CryptographicOperations.ZeroMemory(signedPayload);
            return packet;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(agreementFingerprint);
            CryptographicOperations.ZeroMemory(signingPublicKey);
            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    public static SignedDiscoveryAdvertisement ParseAndVerify(ReadOnlySpan<byte> packet)
    {
        const int minimumFixedSize =
            4 + // magic
            4 + // protocol version
            4 + // identity version
            16 + // device id
            4 + // transfer port
            4 + // pairing port
            1 + // kind
            4 + // key generation
            4 + // name length
            AgreementFingerprintBytes +
            4 + // signing key length
            4 + // signature length
            1; // at least one signature byte

        if (packet.Length < minimumFixedSize || !packet[..4].SequenceEqual(Magic))
        {
            throw new InvalidDataException("Invalid signed Genia Link discovery packet.");
        }

        var offset = 4;
        var protocolVersion = ReadInt32(packet, ref offset);
        if (protocolVersion != ProtocolConstants.Version)
        {
            throw new InvalidDataException("Incompatible signed discovery protocol version.");
        }

        var identityVersion = ReadInt32(packet, ref offset);
        if (identityVersion < 2)
        {
            throw new InvalidDataException("Signed discovery identity version is invalid.");
        }

        EnsureRemaining(packet, offset, 16);
        var deviceId = new Guid(packet.Slice(offset, 16));
        offset += 16;
        if (deviceId == Guid.Empty)
        {
            throw new InvalidDataException("Signed discovery device ID cannot be empty.");
        }

        var transferPort = ReadInt32(packet, ref offset);
        var pairingPort = ReadInt32(packet, ref offset);
        ValidatePort(transferPort);
        ValidatePort(pairingPort);

        EnsureRemaining(packet, offset, 1);
        var kind = (DeviceKind)packet[offset++];
        ValidateDeviceKind(kind);

        var keyGeneration = ReadInt32(packet, ref offset);
        if (keyGeneration < 1)
        {
            throw new InvalidDataException("Signed discovery key generation is invalid.");
        }

        var nameLength = ReadInt32(packet, ref offset);
        if (nameLength is < 1 or > MaxNameBytes)
        {
            throw new InvalidDataException("Invalid signed discovery device-name length.");
        }

        EnsureRemaining(packet, offset, nameLength + AgreementFingerprintBytes + 4);
        string deviceName;
        try
        {
            deviceName = StrictUtf8.GetString(packet.Slice(offset, nameLength));
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidDataException("Signed discovery device name is not valid UTF-8.", ex);
        }

        ValidateDeviceName(deviceName);
        offset += nameLength;

        var agreementFingerprint = Convert.ToHexString(packet.Slice(offset, AgreementFingerprintBytes));
        offset += AgreementFingerprintBytes;

        var signingPublicKeyLength = ReadInt32(packet, ref offset);
        if (signingPublicKeyLength is < 1 or > MaxSigningPublicKeyBytes)
        {
            throw new InvalidDataException("Invalid signed discovery public-key length.");
        }

        EnsureRemaining(packet, offset, signingPublicKeyLength + 4 + 1);
        var signingPublicKey = packet.Slice(offset, signingPublicKeyLength).ToArray();
        offset += signingPublicKeyLength;

        var signedPayloadLength = offset;
        var signatureLength = ReadInt32(packet, ref offset);
        if (signatureLength is < 1 or > DeviceSignature.MaxDerSignatureBytes || packet.Length != offset + signatureLength)
        {
            CryptographicOperations.ZeroMemory(signingPublicKey);
            throw new InvalidDataException("Invalid signed discovery signature length.");
        }

        try
        {
            DeviceSignature.ValidatePublicKey(signingPublicKey);
            var signature = packet.Slice(offset, signatureLength);
            if (!DeviceSignature.Verify(signingPublicKey, packet[..signedPayloadLength], signature))
            {
                throw new InvalidDataException("Signed discovery signature verification failed.");
            }

            var signingKeyId = DeviceSignature.GetSigningKeyId(signingPublicKey);
            var advertisement = new DiscoveryAdvertisement(
                deviceId,
                deviceName,
                transferPort,
                pairingPort,
                agreementFingerprint,
                kind);
            return new SignedDiscoveryAdvertisement(
                advertisement,
                identityVersion,
                keyGeneration,
                signingPublicKey,
                signingKeyId);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidDataException("Signed discovery public key is invalid.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingPublicKey);
        }
    }

    public static bool HasSignedMagic(ReadOnlySpan<byte> packet)
    {
        return packet.Length >= Magic.Length && packet[..Magic.Length].SequenceEqual(Magic);
    }

    private static int ReadInt32(ReadOnlySpan<byte> packet, ref int offset)
    {
        EnsureRemaining(packet, offset, 4);
        var value = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(offset, 4));
        offset += 4;
        return value;
    }

    private static void EnsureRemaining(ReadOnlySpan<byte> packet, int offset, int required)
    {
        if (offset < 0 || required < 0 || offset > packet.Length - required)
        {
            throw new InvalidDataException("Signed discovery packet is truncated.");
        }
    }

    private static byte[] ParseAgreementFingerprint(string fingerprintHex)
    {
        byte[] fingerprint;
        try
        {
            fingerprint = Convert.FromHexString(fingerprintHex);
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("Invalid discovery public-key fingerprint.", ex);
        }

        if (fingerprint.Length != AgreementFingerprintBytes)
        {
            CryptographicOperations.ZeroMemory(fingerprint);
            throw new InvalidDataException("Invalid discovery public-key fingerprint length.");
        }

        return fingerprint;
    }

    private static void ValidateAdvertisement(DiscoveryAdvertisement advertisement)
    {
        if (advertisement.DeviceId == Guid.Empty)
        {
            throw new InvalidDataException("Discovery device ID cannot be empty.");
        }

        ValidatePort(advertisement.TransferPort);
        ValidatePort(advertisement.PairingPort);
        ValidateDeviceName(advertisement.DeviceName);
        ValidateDeviceKind(advertisement.Kind);
        var fingerprint = ParseAgreementFingerprint(advertisement.PublicKeyFingerprint);
        CryptographicOperations.ZeroMemory(fingerprint);
    }

    private static void ValidateDeviceName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) ||
            name.Any(ch => char.IsControl(ch) || CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.Format))
        {
            throw new InvalidDataException("Signed discovery device name contains unsafe characters.");
        }

        var byteCount = StrictUtf8.GetByteCount(name);
        if (byteCount is < 1 or > MaxNameBytes)
        {
            throw new InvalidDataException("Signed discovery device name is outside the allowed size.");
        }
    }

    private static void ValidateDeviceKind(DeviceKind deviceKind)
    {
        if (deviceKind is not DeviceKind.Unknown and
            not DeviceKind.WindowsComputer and
            not DeviceKind.AndroidPhone and
            not DeviceKind.AndroidTablet)
        {
            throw new InvalidDataException("Invalid signed discovery device kind.");
        }
    }

    private static void ValidatePort(int port)
    {
        if (port is <= 0 or > IPEndPoint.MaxPort)
        {
            throw new InvalidDataException("Invalid signed discovery TCP port.");
        }
    }
}
