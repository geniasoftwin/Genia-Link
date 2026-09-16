using System.Security.Cryptography;

namespace GeniaLink.Core.Identity;

/// <summary>
/// Cross-platform signing rules for GNP/1 Device Identity v2.
/// Public keys use SubjectPublicKeyInfo and ECDSA signatures use the RFC 3279 DER sequence format.
/// </summary>
public static class DeviceSignature
{
    public const int P256KeySizeBits = 256;
    public const int Sha256HashSizeBytes = 32;
    public const int MaxDerSignatureBytes = 80;

    public static string GetSigningKeyId(ReadOnlySpan<byte> publicKey)
    {
        ValidatePublicKey(publicKey);
        var hash = SHA256.HashData(publicKey);
        try
        {
            return Convert.ToHexString(hash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    public static void ValidatePublicKey(ReadOnlySpan<byte> publicKey)
    {
        if (publicKey.IsEmpty)
        {
            throw new CryptographicException("Signing public key is empty.");
        }

        var copy = publicKey.ToArray();
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(copy, out var bytesRead);
            if (bytesRead != copy.Length || ecdsa.KeySize != P256KeySizeBits)
            {
                throw new CryptographicException("Signing key is not a valid ECDSA P-256 public key.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(copy);
        }
    }

    public static bool Verify(
        ReadOnlySpan<byte> publicKey,
        ReadOnlySpan<byte> payload,
        ReadOnlySpan<byte> signature)
    {
        if (signature.IsEmpty || signature.Length > MaxDerSignatureBytes)
        {
            return false;
        }

        var publicKeyCopy = publicKey.ToArray();
        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportSubjectPublicKeyInfo(publicKeyCopy, out var bytesRead);
            if (bytesRead != publicKeyCopy.Length || ecdsa.KeySize != P256KeySizeBits)
            {
                return false;
            }

            return ecdsa.VerifyData(
                payload,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }
        catch (CryptographicException)
        {
            return false;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKeyCopy);
        }
    }
}
