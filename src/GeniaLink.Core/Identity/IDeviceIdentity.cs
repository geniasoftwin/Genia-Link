using GeniaLink.Core.Pairing;

namespace GeniaLink.Core.Identity;

/// <summary>
/// Shared contract for the persistent identity of one installed Genia Link instance.
/// Platform implementations keep private key material in their native secure storage.
/// </summary>
public interface IDeviceIdentity
{
    Guid DeviceId { get; }

    string DeviceName { get; }

    PairingPeerInfo ToPairingPeerInfo();

    string GetPublicKeyFingerprint();

    byte[] DeriveSharedKey(ReadOnlySpan<byte> peerPublicKey);
}
