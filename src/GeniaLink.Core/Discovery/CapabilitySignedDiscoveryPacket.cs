using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using GeniaLink.Core.Capabilities;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Network;

namespace GeniaLink.Core.Discovery;

/// <summary>
/// GNP/1 M2.6.2 authenticated capability discovery envelope. GLC1 signs the
/// replay-protected identity assertion together with a monotonic capability revision
/// and the advertised capability bitset. Trust is still decided by the pinned identity registry.
/// </summary>
public static class CapabilitySignedDiscoveryPacket
{
    private const int MaxNameBytes = 160;
    private const int AgreementFingerprintBytes = 16;
    private const int MaxSigningPublicKeyBytes = 160;
    private static readonly byte[] Magic = "GLC1"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static byte[] Create(DiscoveryAdvertisement advertisement, IDeviceSigningIdentity identity, long identityRevision, DeviceCapability capabilities, long capabilityRevision)
    {
        ArgumentNullException.ThrowIfNull(advertisement);
        ArgumentNullException.ThrowIfNull(identity);
        if (identityRevision < 1)
        {
            throw new InvalidDataException("Capability advertisement identity revision must be positive.");
        }

        if (capabilityRevision < 1)
        {
            throw new InvalidDataException("Capability advertisement revision must be positive.");
        }

        capabilities = DeviceCapabilityProfiles.NormalizeSelection(capabilities);
        if (!DeviceCapabilityProfiles.IsValidAdvertisement(capabilities))
        {
            throw new InvalidDataException("Capability advertisement contains an invalid capability set.");
        }

        ValidateAdvertisement(advertisement);
        if (identity.DeviceId != advertisement.DeviceId ||
            !string.Equals(identity.DisplayName, advertisement.DeviceName, StringComparison.Ordinal) ||
            identity.DeviceKind != advertisement.Kind)
        {
            throw new InvalidDataException("Signing identity metadata does not match the capability advertisement.");
        }

        if (identity.IdentityVersion < DeviceIdentityV2.CurrentVersion || identity.KeyGeneration < 1)
        {
            throw new InvalidDataException("Signing identity metadata is not valid for capability advertisement.");
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
                throw new InvalidDataException("Signing public key is too large for capability advertisement.");
            }

            var signedPayloadLength =
                4 + 4 + 4 + 16 + 4 + 4 + 1 + 4 + 8 + 8 + 8 + 4 + nameBytes.Length +
                AgreementFingerprintBytes + 4 + signingPublicKey.Length;
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
            BinaryPrimitives.WriteInt64BigEndian(signedPayload.AsSpan(offset, 8), identityRevision);
            offset += 8;
            BinaryPrimitives.WriteInt64BigEndian(signedPayload.AsSpan(offset, 8), capabilityRevision);
            offset += 8;
            BinaryPrimitives.WriteInt64BigEndian(signedPayload.AsSpan(offset, 8), (long)capabilities);
            offset += 8;
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
                throw new CryptographicException("Signing identity produced an invalid capability advertisement signature length.");
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
        const int minimumFixedSize = 4 + 4 + 4 + 16 + 4 + 4 + 1 + 4 + 8 + 8 + 8 + 4 + AgreementFingerprintBytes + 4 + 4 + 1;
        if (packet.Length < minimumFixedSize || !packet[..4].SequenceEqual(Magic))
        {
            throw new InvalidDataException("Invalid GNP/1 capability advertisement packet.");
        }

        var offset = 4;
        var protocolVersion = ReadInt32(packet, ref offset);
        if (protocolVersion != ProtocolConstants.Version)
        {
            throw new InvalidDataException("Incompatible capability advertisement protocol version.");
        }

        var identityVersion = ReadInt32(packet, ref offset);
        if (identityVersion < DeviceIdentityV2.CurrentVersion)
        {
            throw new InvalidDataException("Capability advertisement identity version is invalid.");
        }

        EnsureRemaining(packet, offset, 16);
        var deviceId = new Guid(packet.Slice(offset, 16));
        offset += 16;
        if (deviceId == Guid.Empty)
        {
            throw new InvalidDataException("Capability advertisement device ID cannot be empty.");
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
            throw new InvalidDataException("Capability advertisement key generation is invalid.");
        }

        var identityRevision = ReadInt64(packet, ref offset);
        if (identityRevision < 1)
        {
            throw new InvalidDataException("Capability advertisement identity revision is invalid.");
        }

        var capabilityRevision = ReadInt64(packet, ref offset);
        if (capabilityRevision < 1)
        {
            throw new InvalidDataException("Capability advertisement revision is invalid.");
        }

        var rawCapabilities = ReadInt64(packet, ref offset);
        var knownCapabilityBits = (long)DeviceCapabilityProfiles.KnownCapabilities;
        if (rawCapabilities <= 0 || (rawCapabilities & ~knownCapabilityBits) != 0)
        {
            throw new InvalidDataException("Capability advertisement contains an unsupported or incomplete capability set.");
        }

        // DeviceCapability currently uses a 32-bit underlying type while GLC1 reserves
        // 64 bits on the wire for forward compatibility. Validate the raw wire value
        // before converting it so malformed/high-bit packets are rejected as protocol
        // errors rather than escaping as OverflowException under checked builds.
        var capabilities = (DeviceCapability)rawCapabilities;
        if (!DeviceCapabilityProfiles.IsValidAdvertisement(capabilities))
        {
            throw new InvalidDataException("Capability advertisement contains an unsupported or incomplete capability set.");
        }

        var nameLength = ReadInt32(packet, ref offset);
        if (nameLength is < 1 or > MaxNameBytes)
        {
            throw new InvalidDataException("Invalid capability advertisement device-name length.");
        }

        EnsureRemaining(packet, offset, nameLength + AgreementFingerprintBytes + 4);
        string deviceName;
        try
        {
            deviceName = StrictUtf8.GetString(packet.Slice(offset, nameLength));
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidDataException("Capability advertisement device name is not valid UTF-8.", ex);
        }

        ValidateDeviceName(deviceName);
        offset += nameLength;
        var agreementFingerprint = Convert.ToHexString(packet.Slice(offset, AgreementFingerprintBytes));
        offset += AgreementFingerprintBytes;

        var signingPublicKeyLength = ReadInt32(packet, ref offset);
        if (signingPublicKeyLength is < 1 or > MaxSigningPublicKeyBytes)
        {
            throw new InvalidDataException("Invalid capability advertisement public-key length.");
        }

        EnsureRemaining(packet, offset, signingPublicKeyLength + 4 + 1);
        var signingPublicKey = packet.Slice(offset, signingPublicKeyLength).ToArray();
        offset += signingPublicKeyLength;
        var signedPayloadLength = offset;
        var signatureLength = ReadInt32(packet, ref offset);
        if (signatureLength is < 1 or > DeviceSignature.MaxDerSignatureBytes || packet.Length != offset + signatureLength)
        {
            CryptographicOperations.ZeroMemory(signingPublicKey);
            throw new InvalidDataException("Invalid capability advertisement signature length.");
        }

        try
        {
            DeviceSignature.ValidatePublicKey(signingPublicKey);
            if (!DeviceSignature.Verify(signingPublicKey, packet[..signedPayloadLength], packet.Slice(offset, signatureLength)))
            {
                throw new InvalidDataException("Capability advertisement signature verification failed.");
            }

            var signingKeyId = DeviceSignature.GetSigningKeyId(signingPublicKey);
            var advertisement = new DiscoveryAdvertisement(deviceId, deviceName, transferPort, pairingPort, agreementFingerprint, kind);
            return new SignedDiscoveryAdvertisement(advertisement, identityVersion, keyGeneration, signingPublicKey, signingKeyId, identityRevision, capabilities, capabilityRevision);
        }
        catch (CryptographicException ex)
        {
            throw new InvalidDataException("Capability advertisement public key is invalid.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingPublicKey);
        }
    }

    public static bool HasMagic(ReadOnlySpan<byte> packet) => packet.Length >= Magic.Length && packet[..Magic.Length].SequenceEqual(Magic);

    private static int ReadInt32(ReadOnlySpan<byte> packet, ref int offset)
    {
        EnsureRemaining(packet, offset, 4);
        var value = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(offset, 4));
        offset += 4;
        return value;
    }

    private static long ReadInt64(ReadOnlySpan<byte> packet, ref int offset)
    {
        EnsureRemaining(packet, offset, 8);
        var value = BinaryPrimitives.ReadInt64BigEndian(packet.Slice(offset, 8));
        offset += 8;
        return value;
    }

    private static void EnsureRemaining(ReadOnlySpan<byte> packet, int offset, int required)
    {
        if (offset < 0 || required < 0 || offset > packet.Length - required)
        {
            throw new InvalidDataException("Capability advertisement packet is truncated.");
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
            throw new InvalidDataException("Capability advertisement device name contains unsafe characters.");
        }

        var byteCount = StrictUtf8.GetByteCount(name);
        if (byteCount is < 1 or > MaxNameBytes)
        {
            throw new InvalidDataException("Capability advertisement device name is outside the allowed size.");
        }
    }

    private static void ValidateDeviceKind(DeviceKind deviceKind)
    {
        if (deviceKind is not DeviceKind.Unknown and not DeviceKind.WindowsComputer and not DeviceKind.AndroidPhone and not DeviceKind.AndroidTablet)
        {
            throw new InvalidDataException("Invalid capability advertisement device kind.");
        }
    }

    private static void ValidatePort(int port)
    {
        if (port is <= 0 or > IPEndPoint.MaxPort)
        {
            throw new InvalidDataException("Invalid capability advertisement TCP port.");
        }
    }
}
