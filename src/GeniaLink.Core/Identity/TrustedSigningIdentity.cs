namespace GeniaLink.Core.Identity;

public sealed record TrustedSigningIdentity(
    Guid DeviceId,
    int IdentityVersion,
    int KeyGeneration,
    byte[] SigningPublicKey,
    SigningKeyRotationCertificate[]? RotationChain = null)
{
    public string SigningKeyId => DeviceSignature.GetSigningKeyId(SigningPublicKey);

    public void Validate()
    {
        if (DeviceId == Guid.Empty)
        {
            throw new InvalidDataException("Signing identity device ID must not be empty.");
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(IdentityVersion, DeviceIdentityV2.CurrentVersion);
        ArgumentOutOfRangeException.ThrowIfLessThan(KeyGeneration, 1);
        DeviceSignature.ValidatePublicKey(SigningPublicKey);
        _ = SigningKeyRotation.ValidatePresentation(this);
    }
}

public enum SigningIdentityBindingUpdate
{
    Unchanged = 0,
    Bound = 1,
    Rotated = 2
}
