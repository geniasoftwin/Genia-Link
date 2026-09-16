using System.Net;
using GeniaLink.Core.Capabilities;

namespace GeniaLink.Core.Discovery;

public sealed record DiscoveryAdvertisement(
    Guid DeviceId,
    string DeviceName,
    int TransferPort,
    int PairingPort,
    string PublicKeyFingerprint,
    DeviceKind Kind = DeviceKind.Unknown);

public enum DiscoveryIdentityProof
{
    LegacyUnsigned = 0,
    SignedIdentityV2 = 1,
    AuthenticatedTrustedIdentityV2 = 2,
    ReplayProtectedSignedIdentityV2 = 3,
    CapabilitySignedIdentityV2 = 4
}

public sealed record DiscoveredDevice(
    Guid DeviceId,
    string DeviceName,
    IPAddress Address,
    int TransferPort,
    int PairingPort,
    string PublicKeyFingerprint,
    DeviceKind Kind,
    DateTimeOffset LastSeenUtc,
    DiscoveryIdentityProof IdentityProof = DiscoveryIdentityProof.LegacyUnsigned,
    string? SigningKeyId = null,
    int IdentityVersion = 1,
    int SigningKeyGeneration = 0,
    long IdentityRevision = 0,
    DeviceCapability Capabilities = DeviceCapability.None,
    long CapabilityRevision = 0);
