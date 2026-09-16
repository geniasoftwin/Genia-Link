using System.Security.Cryptography;
using GeniaLink.Core.Capabilities;

namespace GeniaLink.Core.Discovery;

/// <summary>
/// Verified GNP/1 M2.2 self-signed discovery advertisement.
/// The signature proves possession of the included signing key and binds that key
/// to the advertised DeviceId/ports/name/kind for this packet. It does not by itself
/// make the peer trusted; trust is still established by pairing/trusted-session state.
/// </summary>
public sealed class SignedDiscoveryAdvertisement
{
    private readonly byte[] _signingPublicKey;

    public SignedDiscoveryAdvertisement(
        DiscoveryAdvertisement advertisement,
        int identityVersion,
        int keyGeneration,
        ReadOnlySpan<byte> signingPublicKey,
        string signingKeyId,
        long identityRevision = 0,
        DeviceCapability capabilities = DeviceCapability.None,
        long capabilityRevision = 0)
    {
        ArgumentNullException.ThrowIfNull(advertisement);
        ArgumentOutOfRangeException.ThrowIfLessThan(identityVersion, 2);
        ArgumentOutOfRangeException.ThrowIfLessThan(keyGeneration, 1);

        if (signingPublicKey.IsEmpty)
        {
            throw new CryptographicException("Signed discovery public key is empty.");
        }

        if (string.IsNullOrWhiteSpace(signingKeyId))
        {
            throw new ArgumentException("Signing key ID must not be empty.", nameof(signingKeyId));
        }

        ArgumentOutOfRangeException.ThrowIfNegative(identityRevision);
        ArgumentOutOfRangeException.ThrowIfNegative(capabilityRevision);
        if (capabilityRevision > 0 && !DeviceCapabilityProfiles.IsValidAdvertisement(capabilities))
        {
            throw new InvalidDataException("Signed capability advertisement contains an invalid capability set.");
        }

        Advertisement = advertisement;
        IdentityVersion = identityVersion;
        KeyGeneration = keyGeneration;
        _signingPublicKey = signingPublicKey.ToArray();
        SigningKeyId = signingKeyId;
        IdentityRevision = identityRevision;
        Capabilities = capabilities;
        CapabilityRevision = capabilityRevision;
    }

    public DiscoveryAdvertisement Advertisement { get; }

    public int IdentityVersion { get; }

    public int KeyGeneration { get; }

    public string SigningKeyId { get; }

    public long IdentityRevision { get; }

    public DeviceCapability Capabilities { get; }

    public long CapabilityRevision { get; }

    public ReadOnlyMemory<byte> SigningPublicKey => _signingPublicKey;
}
