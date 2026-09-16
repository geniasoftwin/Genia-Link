using GeniaLink.Core.Discovery;

namespace GeniaLink.Core.Identity;

/// <summary>
/// Public, transport-neutral snapshot of GNP/1 Device Identity v2.
/// It contains no private key material and is not yet part of the RC4 wire protocol.
/// </summary>
public sealed class DeviceIdentityV2
{
    private readonly byte[] _signingPublicKey;

    public DeviceIdentityV2(
        Guid deviceId,
        string displayName,
        DeviceKind deviceKind,
        int keyGeneration,
        DateTimeOffset createdAtUtc,
        ReadOnlySpan<byte> signingPublicKey)
    {
        if (deviceId == Guid.Empty)
        {
            throw new ArgumentException("Device ID must not be empty.", nameof(deviceId));
        }

        if (string.IsNullOrWhiteSpace(displayName))
        {
            throw new ArgumentException("Display name must not be empty.", nameof(displayName));
        }

        if (keyGeneration < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(keyGeneration), "Key generation must be at least 1.");
        }

        if (createdAtUtc == default)
        {
            throw new ArgumentException("Identity creation time must be set.", nameof(createdAtUtc));
        }

        DeviceSignature.ValidatePublicKey(signingPublicKey);

        DeviceId = deviceId;
        DisplayName = displayName;
        DeviceKind = deviceKind;
        KeyGeneration = keyGeneration;
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        _signingPublicKey = signingPublicKey.ToArray();
        SigningKeyId = DeviceSignature.GetSigningKeyId(_signingPublicKey);
    }

    public const int CurrentVersion = 2;

    public int IdentityVersion { get; } = CurrentVersion;

    public Guid DeviceId { get; }

    public string DisplayName { get; }

    public DeviceKind DeviceKind { get; }

    public int KeyGeneration { get; }

    public DateTimeOffset CreatedAtUtc { get; }

    public string SigningKeyId { get; }

    public ReadOnlyMemory<byte> SigningPublicKey => _signingPublicKey;
}
