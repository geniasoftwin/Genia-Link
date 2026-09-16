using System.Buffers.Binary;
using System.Security.Cryptography;
using GeniaLink.Core.Identity;

namespace GeniaLink.Core.Network;

public static class IdentityBindingProtocol
{
    private const int MaxSigningPublicKeyBytes = 256;
    private const int LegacyHeaderSize = 4 + 4 + 16 + 4 + 4 + 4;
    private const int RotationHeaderSize = LegacyHeaderSize + 4;
    private const int MaxRotationCertificateBytes = 2048;
    private static readonly byte[] LegacyMagic = "GLI1"u8.ToArray();
    private static readonly byte[] RotationMagic = "GLI2"u8.ToArray();

    public static byte[] CreateIdentity(IDeviceSigningIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var publicKey = identity.ExportSigningPublicKey();
        SigningKeyRotationCertificate[] rotationChain = [];
        try
        {
            DeviceSignature.ValidatePublicKey(publicKey);
            if (publicKey.Length > MaxSigningPublicKeyBytes)
            {
                throw new InvalidDataException("Signing public key is unexpectedly large.");
            }

            if (identity is ISigningKeyRotationSource rotationSource)
            {
                rotationChain = rotationSource.ExportSigningKeyRotationChain() ?? [];
            }

            if (rotationChain.Length == 0)
            {
                var packet = new byte[checked(LegacyHeaderSize + publicKey.Length)];
                LegacyMagic.CopyTo(packet, 0);
                WriteIdentityHeader(packet, identity, publicKey.Length);
                publicKey.CopyTo(packet, LegacyHeaderSize);
                return packet;
            }

            var presentation = new TrustedSigningIdentity(
                identity.DeviceId,
                identity.IdentityVersion,
                identity.KeyGeneration,
                publicKey.ToArray(),
                rotationChain.Select(certificate => certificate.DeepCopy()).ToArray());
            try
            {
                presentation.Validate();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(presentation.SigningPublicKey);
            }

            var serializedCertificates = new byte[rotationChain.Length][];
            try
            {
                var totalCertificateBytes = 0;
                for (var index = 0; index < rotationChain.Length; index++)
                {
                    var serialized = rotationChain[index].Serialize();
                    if (serialized.Length > MaxRotationCertificateBytes)
                    {
                        CryptographicOperations.ZeroMemory(serialized);
                        throw new InvalidDataException("Signing-key rotation certificate is unexpectedly large.");
                    }

                    serializedCertificates[index] = serialized;
                    totalCertificateBytes = checked(totalCertificateBytes + 4 + serialized.Length);
                }

                var packet = new byte[checked(RotationHeaderSize + publicKey.Length + totalCertificateBytes)];
                RotationMagic.CopyTo(packet, 0);
                WriteIdentityHeader(packet, identity, publicKey.Length);
                BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(LegacyHeaderSize, 4), rotationChain.Length);
                publicKey.CopyTo(packet, RotationHeaderSize);
                var offset = RotationHeaderSize + publicKey.Length;
                foreach (var serialized in serializedCertificates)
                {
                    BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(offset, 4), serialized.Length);
                    offset += 4;
                    serialized.CopyTo(packet, offset);
                    offset += serialized.Length;
                }

                return packet;
            }
            finally
            {
                foreach (var serialized in serializedCertificates)
                {
                    if (serialized is not null)
                    {
                        CryptographicOperations.ZeroMemory(serialized);
                    }
                }
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
            ZeroRotationChain(rotationChain);
        }
    }

    public static TrustedSigningIdentity ParseIdentity(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < LegacyHeaderSize)
        {
            throw new InvalidDataException("Invalid GNP/1 signing-identity binding message.");
        }

        if (packet[..4].SequenceEqual(LegacyMagic))
        {
            return ParseLegacyIdentity(packet);
        }

        if (packet[..4].SequenceEqual(RotationMagic))
        {
            return ParseRotationIdentity(packet);
        }

        throw new InvalidDataException("Invalid GNP/1 signing-identity binding message.");
    }

    private static TrustedSigningIdentity ParseLegacyIdentity(ReadOnlySpan<byte> packet)
    {
        var (deviceId, identityVersion, keyGeneration, publicKeyLength) = ParseCommonHeader(packet);
        if (publicKeyLength is <= 0 or > MaxSigningPublicKeyBytes || packet.Length != LegacyHeaderSize + publicKeyLength)
        {
            throw new InvalidDataException("Invalid signing public-key length in identity binding.");
        }

        var publicKey = packet.Slice(LegacyHeaderSize, publicKeyLength).ToArray();
        try
        {
            var identity = new TrustedSigningIdentity(deviceId, identityVersion, keyGeneration, publicKey);
            identity.Validate();
            publicKey = Array.Empty<byte>();
            return identity;
        }
        finally
        {
            if (publicKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }
    }

    private static TrustedSigningIdentity ParseRotationIdentity(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < RotationHeaderSize)
        {
            throw new InvalidDataException("Truncated GNP/1 signing-identity rotation presentation.");
        }

        var (deviceId, identityVersion, keyGeneration, publicKeyLength) = ParseCommonHeader(packet);
        var rotationCount = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(LegacyHeaderSize, 4));
        if (publicKeyLength is <= 0 or > MaxSigningPublicKeyBytes ||
            rotationCount is <= 0 or > SigningKeyRotationCertificate.MaxChainLength ||
            packet.Length < RotationHeaderSize + publicKeyLength)
        {
            throw new InvalidDataException("Invalid signing-key rotation presentation header.");
        }

        var publicKey = packet.Slice(RotationHeaderSize, publicKeyLength).ToArray();
        var certificates = new SigningKeyRotationCertificate[rotationCount];
        try
        {
            var offset = RotationHeaderSize + publicKeyLength;
            for (var index = 0; index < rotationCount; index++)
            {
                if (offset + 4 > packet.Length)
                {
                    throw new InvalidDataException("Truncated signing-key rotation chain.");
                }

                var certificateLength = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(offset, 4));
                offset += 4;
                if (certificateLength is <= 0 or > MaxRotationCertificateBytes || offset + certificateLength > packet.Length)
                {
                    throw new InvalidDataException("Invalid signing-key rotation certificate length.");
                }

                certificates[index] = SigningKeyRotationCertificate.Parse(packet.Slice(offset, certificateLength));
                offset += certificateLength;
            }

            if (offset != packet.Length)
            {
                throw new InvalidDataException("Unexpected trailing data in signing-key rotation presentation.");
            }

            var identity = new TrustedSigningIdentity(deviceId, identityVersion, keyGeneration, publicKey, certificates);
            identity.Validate();
            publicKey = Array.Empty<byte>();
            certificates = [];
            return identity;
        }
        finally
        {
            if (publicKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }

            ZeroRotationChain(certificates);
        }
    }

    private static void WriteIdentityHeader(byte[] packet, IDeviceSigningIdentity identity, int publicKeyLength)
    {
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(4, 4), ProtocolConstants.Version);
        identity.DeviceId.TryWriteBytes(packet.AsSpan(8, 16));
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(24, 4), identity.IdentityVersion);
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(28, 4), identity.KeyGeneration);
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(32, 4), publicKeyLength);
    }

    private static (Guid DeviceId, int IdentityVersion, int KeyGeneration, int PublicKeyLength) ParseCommonHeader(ReadOnlySpan<byte> packet)
    {
        if (BinaryPrimitives.ReadInt32BigEndian(packet.Slice(4, 4)) != ProtocolConstants.Version)
        {
            throw new InvalidDataException("Incompatible Genia Link protocol version in signing-identity binding.");
        }

        return (
            new Guid(packet.Slice(8, 16)),
            BinaryPrimitives.ReadInt32BigEndian(packet.Slice(24, 4)),
            BinaryPrimitives.ReadInt32BigEndian(packet.Slice(28, 4)),
            BinaryPrimitives.ReadInt32BigEndian(packet.Slice(32, 4)));
    }

    private static void ZeroRotationChain(IEnumerable<SigningKeyRotationCertificate> chain)
    {
        foreach (var certificate in chain)
        {
            if (certificate is null)
            {
                continue;
            }

            CryptographicOperations.ZeroMemory(certificate.PreviousSigningPublicKey);
            CryptographicOperations.ZeroMemory(certificate.NewSigningPublicKey);
            CryptographicOperations.ZeroMemory(certificate.PreviousKeySignature);
        }
    }
}
