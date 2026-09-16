using GeniaLink.Core.Discovery;

namespace GeniaLink.Core.Identity;

/// <summary>
/// GNP/1 Milestone 2 signing extension for a persistent Genia Link installation identity.
/// The signing private key remains in platform secure storage and is never exported.
/// </summary>
public interface IDeviceSigningIdentity : IDeviceIdentity
{
    int IdentityVersion { get; }

    int KeyGeneration { get; }

    DateTimeOffset CreatedAtUtc { get; }

    DeviceKind DeviceKind { get; }

    string DisplayName { get; }

    string SigningKeyId { get; }

    byte[] ExportSigningPublicKey();

    byte[] Sign(ReadOnlySpan<byte> payload);

    bool VerifySignature(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature);

    DeviceIdentityV2 ToDeviceIdentityV2();
}
