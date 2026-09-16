namespace GeniaLink.Core.Pairing;

public sealed record PairingPeerInfo(Guid DeviceId, string DeviceName, byte[] PublicKey);

public sealed record PairingConfirmation(PairingPeerInfo Peer, string VerificationCode, string PublicKeyFingerprint);
