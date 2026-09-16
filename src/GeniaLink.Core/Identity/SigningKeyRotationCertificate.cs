using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json.Serialization;

namespace GeniaLink.Core.Identity;

/// <summary>
/// GNP/1 M2.4.2 proof that one trusted signing key intentionally delegated trust
/// to the next signing-key generation for the same persistent Device ID.
/// </summary>
public sealed record SigningKeyRotationCertificate(
    Guid DeviceId,
    int IdentityVersion,
    int PreviousKeyGeneration,
    byte[] PreviousSigningPublicKey,
    int NewKeyGeneration,
    byte[] NewSigningPublicKey,
    byte[] PreviousKeySignature)
{
    public const int CertificateVersion = 1;
    public const int MaxChainLength = 32;

    private const int MaxSigningPublicKeyBytes = 256;
    private const int HeaderSize = 4 + 4 + 4 + 16 + 4 + 4 + 4 + 4 + 4;
    private static readonly byte[] Magic = "GLR1"u8.ToArray();

    [JsonIgnore]
    public string PreviousSigningKeyId => DeviceSignature.GetSigningKeyId(PreviousSigningPublicKey);

    [JsonIgnore]
    public string NewSigningKeyId => DeviceSignature.GetSigningKeyId(NewSigningPublicKey);

    public static SigningKeyRotationCertificate Create(
        IDeviceSigningIdentity previousIdentity,
        int newKeyGeneration,
        ReadOnlySpan<byte> newSigningPublicKey)
    {
        ArgumentNullException.ThrowIfNull(previousIdentity);
        if (previousIdentity.KeyGeneration < 1 ||
            previousIdentity.KeyGeneration >= int.MaxValue ||
            newKeyGeneration != previousIdentity.KeyGeneration + 1)
        {
            throw new InvalidDataException("A signing-key rotation certificate must advance exactly one generation.");
        }

        DeviceSignature.ValidatePublicKey(newSigningPublicKey);
        var previousPublicKey = previousIdentity.ExportSigningPublicKey();
        var nextPublicKey = newSigningPublicKey.ToArray();
        byte[]? payload = null;
        byte[]? signature = null;
        try
        {
            var certificate = new SigningKeyRotationCertificate(
                previousIdentity.DeviceId,
                previousIdentity.IdentityVersion,
                previousIdentity.KeyGeneration,
                previousPublicKey,
                newKeyGeneration,
                nextPublicKey,
                Array.Empty<byte>());
            payload = certificate.CreateSigningPayload();
            signature = previousIdentity.Sign(payload);
            if (!DeviceSignature.Verify(previousPublicKey, payload, signature))
            {
                throw new CryptographicException("The previous signing key could not verify its own rotation certificate.");
            }

            previousPublicKey = Array.Empty<byte>();
            nextPublicKey = Array.Empty<byte>();
            var result = certificate with { PreviousKeySignature = signature };
            signature = null;
            result.Validate();
            return result;
        }
        finally
        {
            if (previousPublicKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(previousPublicKey);
            }

            if (nextPublicKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(nextPublicKey);
            }

            if (payload is not null)
            {
                CryptographicOperations.ZeroMemory(payload);
            }

            if (signature is not null)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    public void Validate()
    {
        if (DeviceId == Guid.Empty)
        {
            throw new InvalidDataException("Signing-key rotation Device ID must not be empty.");
        }

        if (IdentityVersion < DeviceIdentityV2.CurrentVersion)
        {
            throw new InvalidDataException("Signing-key rotation identity version is invalid.");
        }

        if (PreviousKeyGeneration < 1 ||
            PreviousKeyGeneration >= int.MaxValue ||
            NewKeyGeneration != PreviousKeyGeneration + 1)
        {
            throw new InvalidDataException("Signing-key rotation generations are not consecutive.");
        }

        if (PreviousSigningPublicKey is null || NewSigningPublicKey is null || PreviousKeySignature is null)
        {
            throw new InvalidDataException("Signing-key rotation certificate is incomplete.");
        }

        if (PreviousSigningPublicKey.Length > MaxSigningPublicKeyBytes || NewSigningPublicKey.Length > MaxSigningPublicKeyBytes)
        {
            throw new InvalidDataException("Signing-key rotation public key is unexpectedly large.");
        }

        DeviceSignature.ValidatePublicKey(PreviousSigningPublicKey);
        DeviceSignature.ValidatePublicKey(NewSigningPublicKey);
        if (PreviousSigningPublicKey.AsSpan().SequenceEqual(NewSigningPublicKey))
        {
            throw new InvalidDataException("Signing-key rotation must replace the signing key.");
        }

        if (PreviousKeySignature.Length is <= 0 or > DeviceSignature.MaxDerSignatureBytes)
        {
            throw new InvalidDataException("Signing-key rotation signature length is invalid.");
        }

        var payload = CreateSigningPayload();
        try
        {
            if (!DeviceSignature.Verify(PreviousSigningPublicKey, payload, PreviousKeySignature))
            {
                throw new CryptographicException("Signing-key rotation certificate signature is invalid.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    public byte[] Serialize()
    {
        Validate();
        var payload = CreateSigningPayload();
        try
        {
            var result = new byte[checked(payload.Length + 4 + PreviousKeySignature.Length)];
            payload.CopyTo(result, 0);
            BinaryPrimitives.WriteInt32BigEndian(result.AsSpan(payload.Length, 4), PreviousKeySignature.Length);
            PreviousKeySignature.CopyTo(result, payload.Length + 4);
            return result;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payload);
        }
    }

    public static SigningKeyRotationCertificate Parse(ReadOnlySpan<byte> packet)
    {
        if (packet.Length < HeaderSize + 4 || !packet[..4].SequenceEqual(Magic))
        {
            throw new InvalidDataException("Invalid GNP/1 signing-key rotation certificate.");
        }

        if (BinaryPrimitives.ReadInt32BigEndian(packet.Slice(4, 4)) != CertificateVersion)
        {
            throw new InvalidDataException("Unsupported signing-key rotation certificate version.");
        }

        if (BinaryPrimitives.ReadInt32BigEndian(packet.Slice(8, 4)) != Network.ProtocolConstants.Version)
        {
            throw new InvalidDataException("Incompatible Genia Link protocol version in signing-key rotation certificate.");
        }

        var deviceId = new Guid(packet.Slice(12, 16));
        var identityVersion = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(28, 4));
        var previousGeneration = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(32, 4));
        var newGeneration = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(36, 4));
        var previousKeyLength = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(40, 4));
        var newKeyLength = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(44, 4));
        if (previousKeyLength is <= 0 or > MaxSigningPublicKeyBytes || newKeyLength is <= 0 or > MaxSigningPublicKeyBytes)
        {
            throw new InvalidDataException("Invalid public-key length in signing-key rotation certificate.");
        }

        var signatureLengthOffset = checked(HeaderSize + previousKeyLength + newKeyLength);
        if (signatureLengthOffset + 4 > packet.Length)
        {
            throw new InvalidDataException("Truncated signing-key rotation certificate.");
        }

        var signatureLength = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(signatureLengthOffset, 4));
        if (signatureLength is <= 0 or > DeviceSignature.MaxDerSignatureBytes || packet.Length != signatureLengthOffset + 4 + signatureLength)
        {
            throw new InvalidDataException("Invalid signature length in signing-key rotation certificate.");
        }

        var previousPublicKey = packet.Slice(HeaderSize, previousKeyLength).ToArray();
        var newPublicKey = packet.Slice(HeaderSize + previousKeyLength, newKeyLength).ToArray();
        var signature = packet.Slice(signatureLengthOffset + 4, signatureLength).ToArray();
        try
        {
            var certificate = new SigningKeyRotationCertificate(
                deviceId,
                identityVersion,
                previousGeneration,
                previousPublicKey,
                newGeneration,
                newPublicKey,
                signature);
            certificate.Validate();
            previousPublicKey = Array.Empty<byte>();
            newPublicKey = Array.Empty<byte>();
            signature = Array.Empty<byte>();
            return certificate;
        }
        finally
        {
            if (previousPublicKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(previousPublicKey);
            }

            if (newPublicKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(newPublicKey);
            }

            if (signature.Length > 0)
            {
                CryptographicOperations.ZeroMemory(signature);
            }
        }
    }

    public SigningKeyRotationCertificate DeepCopy() => new(
        DeviceId,
        IdentityVersion,
        PreviousKeyGeneration,
        PreviousSigningPublicKey.ToArray(),
        NewKeyGeneration,
        NewSigningPublicKey.ToArray(),
        PreviousKeySignature.ToArray());

    private byte[] CreateSigningPayload()
    {
        if (PreviousSigningPublicKey is null || NewSigningPublicKey is null)
        {
            throw new InvalidDataException("Signing-key rotation certificate public keys are missing.");
        }

        if (PreviousSigningPublicKey.Length is <= 0 or > MaxSigningPublicKeyBytes ||
            NewSigningPublicKey.Length is <= 0 or > MaxSigningPublicKeyBytes)
        {
            throw new InvalidDataException("Signing-key rotation public-key length is invalid.");
        }

        var payload = new byte[checked(HeaderSize + PreviousSigningPublicKey.Length + NewSigningPublicKey.Length)];
        Magic.CopyTo(payload, 0);
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(4, 4), CertificateVersion);
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(8, 4), Network.ProtocolConstants.Version);
        DeviceId.TryWriteBytes(payload.AsSpan(12, 16));
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(28, 4), IdentityVersion);
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(32, 4), PreviousKeyGeneration);
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(36, 4), NewKeyGeneration);
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(40, 4), PreviousSigningPublicKey.Length);
        BinaryPrimitives.WriteInt32BigEndian(payload.AsSpan(44, 4), NewSigningPublicKey.Length);
        PreviousSigningPublicKey.CopyTo(payload, HeaderSize);
        NewSigningPublicKey.CopyTo(payload, HeaderSize + PreviousSigningPublicKey.Length);
        return payload;
    }
}
