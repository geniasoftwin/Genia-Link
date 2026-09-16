using System.Security.Cryptography;

namespace GeniaLink.Core.Identity;

public interface ISigningKeyRotationSource
{
    SigningKeyRotationCertificate[] ExportSigningKeyRotationChain();
}

public static class SigningKeyRotation
{
    public static SigningKeyRotationCertificate[] ValidatePresentation(TrustedSigningIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var chain = identity.RotationChain ?? [];
        if (chain.Length > SigningKeyRotationCertificate.MaxChainLength)
        {
            throw new InvalidDataException("Signing-key rotation chain exceeds its safe limit.");
        }

        if (chain.Length == 0)
        {
            return [];
        }

        for (var index = 0; index < chain.Length; index++)
        {
            var certificate = chain[index] ?? throw new InvalidDataException("Signing-key rotation chain contains an empty certificate.");
            certificate.Validate();
            if (certificate.DeviceId != identity.DeviceId || certificate.IdentityVersion != identity.IdentityVersion)
            {
                throw new InvalidDataException("Signing-key rotation certificate does not belong to the presented identity.");
            }

            if (index > 0)
            {
                var previous = chain[index - 1];
                if (certificate.PreviousKeyGeneration != previous.NewKeyGeneration ||
                    !certificate.PreviousSigningPublicKey.AsSpan().SequenceEqual(previous.NewSigningPublicKey))
                {
                    throw new InvalidDataException("Signing-key rotation chain is not continuous.");
                }
            }
        }

        var last = chain[^1];
        if (last.NewKeyGeneration != identity.KeyGeneration ||
            !last.NewSigningPublicKey.AsSpan().SequenceEqual(identity.SigningPublicKey))
        {
            throw new InvalidDataException("Signing-key rotation chain does not terminate at the presented signing identity.");
        }

        return chain;
    }

    public static void ValidateTrustedTransition(
        Guid deviceId,
        int trustedIdentityVersion,
        int trustedKeyGeneration,
        ReadOnlySpan<byte> trustedSigningPublicKey,
        TrustedSigningIdentity proposedIdentity)
    {
        ArgumentNullException.ThrowIfNull(proposedIdentity);
        DeviceSignature.ValidatePublicKey(trustedSigningPublicKey);
        proposedIdentity.Validate();

        if (deviceId == Guid.Empty || proposedIdentity.DeviceId != deviceId)
        {
            throw new InvalidDataException("Signing-key rotation does not belong to the trusted Device ID.");
        }

        if (trustedIdentityVersion < DeviceIdentityV2.CurrentVersion || trustedKeyGeneration < 1)
        {
            throw new InvalidDataException("Existing trusted signing identity is incomplete for rotation verification.");
        }

        if (proposedIdentity.IdentityVersion != trustedIdentityVersion)
        {
            throw new InvalidDataException("Signing-key rotation changed the identity version unexpectedly.");
        }

        if (proposedIdentity.KeyGeneration <= trustedKeyGeneration)
        {
            throw new InvalidDataException("Signing-key rotation must advance beyond the trusted generation.");
        }

        var chain = ValidatePresentation(proposedIdentity);
        if (chain.Length == 0)
        {
            throw new InvalidDataException("Signing-key replacement requires a continuity certificate signed by the previous trusted key.");
        }

        var trustedKey = trustedSigningPublicKey.ToArray();
        try
        {
            var currentGeneration = trustedKeyGeneration;
            var currentKey = trustedKey;
            var matchedTrustedAnchor = false;
            for (var index = 0; index < chain.Length; index++)
            {
                var certificate = chain[index];
                if (!matchedTrustedAnchor)
                {
                    if (certificate.PreviousKeyGeneration != currentGeneration ||
                        !certificate.PreviousSigningPublicKey.AsSpan().SequenceEqual(currentKey))
                    {
                        continue;
                    }

                    matchedTrustedAnchor = true;
                }

                if (certificate.PreviousKeyGeneration != currentGeneration ||
                    !certificate.PreviousSigningPublicKey.AsSpan().SequenceEqual(currentKey))
                {
                    throw new InvalidDataException("Signing-key rotation chain diverged from the trusted key.");
                }

                currentGeneration = certificate.NewKeyGeneration;
                currentKey = certificate.NewSigningPublicKey;
            }

            if (!matchedTrustedAnchor)
            {
                throw new InvalidDataException("Signing-key rotation chain does not contain the currently trusted signing key.");
            }

            if (currentGeneration != proposedIdentity.KeyGeneration ||
                !currentKey.AsSpan().SequenceEqual(proposedIdentity.SigningPublicKey))
            {
                throw new InvalidDataException("Signing-key rotation chain does not reach the presented signing identity.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(trustedKey);
        }
    }
}
