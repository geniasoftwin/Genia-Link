using System.Collections.Concurrent;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GeniaLink.Core.Capabilities;
using GeniaLink.Core.Pairing;

namespace GeniaLink.Core.Identity;

public enum TrustedIdentityRegistryState
{
    Trusted = 1,
    Changed = 2
}

public enum TrustedIdentityLifecycleState
{
    Active = 1,
    Retired = 2,
    Revoked = 3
}

public enum TrustedIdentityHistoryEventType
{
    Trusted = 1,
    AuthenticatedRename = 2,
    SigningKeyRotated = 3,
    LifecycleChanged = 4,
    PairingTrustReplaced = 5
}

public enum TrustedSigningKeyHistoryState
{
    Retired = 1,
    Revoked = 2
}

public sealed record TrustedSigningKeyHistoryEntry(
    int IdentityVersion,
    int KeyGeneration,
    string SigningKeyId,
    string SigningPublicKeyBase64,
    DateTimeOffset FirstTrustedAtUtc,
    DateTimeOffset LastVerifiedAtUtc,
    TrustedSigningKeyHistoryState State = TrustedSigningKeyHistoryState.Retired);

public sealed record TrustedIdentityHistoryEntry(
    long Sequence,
    DateTimeOffset OccurredAtUtc,
    TrustedIdentityHistoryEventType EventType,
    string? PreviousDeviceName = null,
    string? DeviceName = null,
    TrustedIdentityLifecycleState? PreviousLifecycleState = null,
    TrustedIdentityLifecycleState? LifecycleState = null,
    string? SigningKeyId = null,
    int SigningKeyGeneration = 0,
    long IdentityRevision = 0,
    string? Note = null);

public sealed record TrustedIdentityRegistryEntry(
    Guid DeviceId,
    string DeviceName,
    string PairingKeyId,
    DateTimeOffset FirstTrustedAtUtc,
    DateTimeOffset LastAuthenticatedAtUtc,
    TrustedIdentityRegistryState State = TrustedIdentityRegistryState.Trusted,
    int CurrentSigningIdentityVersion = 0,
    int CurrentSigningKeyGeneration = 0,
    string? CurrentSigningKeyId = null,
    string? CurrentSigningPublicKeyBase64 = null,
    DateTimeOffset? CurrentSigningKeyBoundAtUtc = null,
    DateTimeOffset? CurrentSigningKeyLastVerifiedAtUtc = null,
    TrustedSigningKeyHistoryEntry[]? SigningKeyHistory = null,
    TrustedIdentityLifecycleState LifecycleState = TrustedIdentityLifecycleState.Active,
    DateTimeOffset? LifecycleChangedAtUtc = null,
    string? LifecycleReason = null,
    TrustedIdentityHistoryEntry[]? IdentityHistory = null,
    string? TrustRelationshipId = null,
    long LastAcceptedIdentityRevision = 0,
    DeviceCapability VerifiedCapabilities = DeviceCapability.None,
    long LastAcceptedCapabilityRevision = 0,
    DateTimeOffset? CapabilitiesLastVerifiedAtUtc = null);

public sealed record TrustedSessionAuthorization(
    Guid DeviceId,
    string TrustRelationshipId,
    CancellationToken LifetimeToken);

public sealed record TrustedIdentityRegistryDocument(
    int SchemaVersion,
    DateTimeOffset UpdatedAtUtc,
    TrustedIdentityRegistryEntry[] Identities);

public sealed class TrustedIdentityRegistry
{
    public const int CurrentSchemaVersion = 5;

    private const long MaxStoreBytes = 4 * 1024 * 1024;
    private const int MaxTrustedIdentities = 1024;
    private const int MaxSigningKeyHistoryEntries = 32;
    private const int MaxIdentityHistoryEntries = 128;
    private const int MaxLifecycleReasonBytes = 512;
    private const int MaxDeviceNameBytes = 160;
    private const int Sha256HexLength = 64;
    private const int TrustRelationshipIdHexLength = 32;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };

    private sealed class SharedRegistryState
    {
        public Dictionary<Guid, TrustedIdentityRegistryEntry> Entries { get; } = new();

        public Dictionary<Guid, SessionLifetimeState> SessionLifetimes { get; } = new();

        public object Gate { get; } = new();
    }

    private sealed class SessionLifetimeState(string trustRelationshipId, CancellationTokenSource source)
    {
        public string TrustRelationshipId { get; } = trustRelationshipId;

        public CancellationTokenSource Source { get; } = source;
    }

    private static readonly ConcurrentDictionary<string, SharedRegistryState> SharedStates = new(StringComparer.Ordinal);

    private readonly string _path;
    private readonly string _backupPath;
    private readonly Action<string>? _log;
    private readonly SharedRegistryState _state;

    public TrustedIdentityRegistry(string path, Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        _path = Path.GetFullPath(path);
        _backupPath = _path + ".bak";
        _log = log;
        _state = SharedStates.GetOrAdd(_path, static _ => new SharedRegistryState());

        var directory = Path.GetDirectoryName(_path);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        lock (_state.Gate)
        {
            Load();
        }
    }

    public TrustedIdentityRegistryEntry? Get(Guid deviceId)
    {
        lock (_state.Gate)
        {
            return _state.Entries.TryGetValue(deviceId, out var entry)
                ? CloneEntry(entry)
                : null;
        }
    }

    public TrustedIdentityRegistryEntry[] GetAll()
    {
        lock (_state.Gate)
        {
            return _state.Entries.Values
                .OrderBy(entry => entry.DeviceName, StringComparer.OrdinalIgnoreCase)
                .Select(CloneEntry)
                .ToArray();
        }
    }

    public bool IsActiveTrusted(Guid deviceId)
    {
        lock (_state.Gate)
        {
            return _state.Entries.TryGetValue(deviceId, out var entry) &&
                   entry.State == TrustedIdentityRegistryState.Trusted &&
                   entry.LifecycleState == TrustedIdentityLifecycleState.Active;
        }
    }

    public TrustedSessionAuthorization? GetSessionAuthorization(Guid deviceId)
    {
        ValidateDeviceId(deviceId);
        lock (_state.Gate)
        {
            if (!_state.Entries.TryGetValue(deviceId, out var entry) ||
                entry.State != TrustedIdentityRegistryState.Trusted ||
                entry.LifecycleState != TrustedIdentityLifecycleState.Active)
            {
                return null;
            }

            var trustRelationshipId = entry.TrustRelationshipId;
            if (string.IsNullOrWhiteSpace(trustRelationshipId))
            {
                return null;
            }

            var lifetime = GetOrCreateSessionLifetimeLocked(entry);
            return new TrustedSessionAuthorization(deviceId, trustRelationshipId, lifetime.Source.Token);
        }
    }

    public bool SetLifecycleState(
        Guid deviceId,
        TrustedIdentityLifecycleState lifecycleState,
        DateTimeOffset changedAtUtc,
        string? reason = null)
    {
        ValidateDeviceId(deviceId);
        if (!Enum.IsDefined(lifecycleState))
        {
            throw new InvalidDataException("Trusted identity lifecycle state is invalid.");
        }

        if (changedAtUtc == default)
        {
            throw new InvalidDataException("Trusted identity lifecycle timestamp is missing.");
        }

        ValidateLifecycleReason(reason);
        lock (_state.Gate)
        {
            if (!_state.Entries.TryGetValue(deviceId, out var current))
            {
                throw new InvalidDataException("Trusted identity lifecycle change requires an existing identity.");
            }

            if (current.LifecycleState == lifecycleState)
            {
                return false;
            }

            if (current.LifecycleState == TrustedIdentityLifecycleState.Revoked)
            {
                throw new InvalidDataException("A revoked trusted identity cannot be reactivated or retired. Forget it explicitly before a new SAS pairing.");
            }

            var allowed = (current.LifecycleState, lifecycleState) switch
            {
                (TrustedIdentityLifecycleState.Active, TrustedIdentityLifecycleState.Retired) => true,
                (TrustedIdentityLifecycleState.Active, TrustedIdentityLifecycleState.Revoked) => true,
                (TrustedIdentityLifecycleState.Retired, TrustedIdentityLifecycleState.Active) => true,
                (TrustedIdentityLifecycleState.Retired, TrustedIdentityLifecycleState.Revoked) => true,
                _ => false
            };
            if (!allowed)
            {
                throw new InvalidDataException($"Trusted identity lifecycle transition {current.LifecycleState} -> {lifecycleState} is not allowed.");
            }

            if (lifecycleState == TrustedIdentityLifecycleState.Active && current.State != TrustedIdentityRegistryState.Trusted)
            {
                throw new InvalidDataException("A trusted identity with a changed cryptographic binding cannot be reactivated.");
            }

            var priorChangedAtUtc = current.LifecycleChangedAtUtc ?? current.FirstTrustedAtUtc;
            // Sequence is the ordering authority. A wall-clock correction must never prevent
            // an explicit security action such as Revoke, so clamp rather than reject time rollback.
            var effectiveChangedAtUtc = MaxTimestamp(changedAtUtc, priorChangedAtUtc);

            var updated = current with
            {
                LifecycleState = lifecycleState,
                LifecycleChangedAtUtc = effectiveChangedAtUtc,
                LifecycleReason = string.IsNullOrWhiteSpace(reason) ? null : reason.Trim(),
                IdentityHistory = AppendIdentityHistory(
                    current,
                    effectiveChangedAtUtc,
                    TrustedIdentityHistoryEventType.LifecycleChanged,
                    previousLifecycleState: current.LifecycleState,
                    lifecycleState: lifecycleState,
                    note: string.IsNullOrWhiteSpace(reason) ? null : reason.Trim())
            };

            _state.Entries[deviceId] = updated;
            SaveLockedWithRollback(deviceId, current);
            if (lifecycleState == TrustedIdentityLifecycleState.Revoked)
            {
                InvalidateSessionLifetimeLocked(deviceId);
                _log?.Invoke($"GNP/1 M2.5.2.1 active trusted sessions invalidated for {current.DeviceName} after Revoked.");
            }

            _log?.Invoke($"GNP/1 M2.5.2 trusted identity lifecycle: {current.DeviceName} {current.LifecycleState} -> {lifecycleState} ({deviceId:N}).");
            return true;
        }
    }

    public void SynchronizeTrustedDevice(
        Guid deviceId,
        string deviceName,
        ReadOnlySpan<byte> pairingPublicKey,
        DateTimeOffset pairedAtUtc,
        DateTimeOffset? lastAuthenticatedAtUtc = null,
        TrustedSigningIdentity? legacySigningIdentity = null,
        DateTimeOffset? legacySigningBoundAtUtc = null)
    {
        ValidateDeviceId(deviceId);
        ValidateDeviceName(deviceName);
        PairingProtocol.ValidatePublicKey(pairingPublicKey);
        legacySigningIdentity?.Validate();
        if (legacySigningIdentity is not null && legacySigningIdentity.DeviceId != deviceId)
        {
            throw new InvalidDataException("Legacy signing identity does not belong to the trusted device.");
        }

        var pairingKeyId = GetPairingKeyId(pairingPublicKey);
        var authenticatedAtUtc = MaxTimestamp(pairedAtUtc, lastAuthenticatedAtUtc ?? pairedAtUtc);

        lock (_state.Gate)
        {
            if (!_state.Entries.TryGetValue(deviceId, out var current))
            {
                if (_state.Entries.Count >= MaxTrustedIdentities)
                {
                    throw new InvalidDataException("Trusted Identity Registry reached its safe device limit.");
                }

                var created = new TrustedIdentityRegistryEntry(
                    deviceId,
                    deviceName,
                    pairingKeyId,
                    pairedAtUtc,
                    authenticatedAtUtc,
                    SigningKeyHistory: [],
                    LifecycleState: TrustedIdentityLifecycleState.Active,
                    LifecycleChangedAtUtc: pairedAtUtc,
                    IdentityHistory: CreateInitialIdentityHistory(deviceName, pairedAtUtc),
                    TrustRelationshipId: CreateTrustRelationshipId());
                if (legacySigningIdentity is not null)
                {
                    created = BindFirstSigningIdentity(
                        created,
                        legacySigningIdentity,
                        legacySigningBoundAtUtc ?? pairedAtUtc,
                        legacySigningBoundAtUtc ?? pairedAtUtc);
                }

                _state.Entries[deviceId] = created;
                SaveLockedWithRollback(deviceId, previous: null);
                _log?.Invoke($"GNP/1 M2.4.1 Trusted Identity Registry migrated {deviceName} ({deviceId:N}).");
                return;
            }

            if (!string.Equals(current.PairingKeyId, pairingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                if (current.LifecycleState != TrustedIdentityLifecycleState.Active)
                {
                    throw new InvalidDataException($"Pairing trust replacement was rejected because {current.DeviceName} is {current.LifecycleState}.");
                }

                var replacedAtUtc = authenticatedAtUtc;
                var replaced = new TrustedIdentityRegistryEntry(
                    deviceId,
                    deviceName,
                    pairingKeyId,
                    current.FirstTrustedAtUtc,
                    authenticatedAtUtc,
                    TrustedIdentityRegistryState.Trusted,
                    SigningKeyHistory: [],
                    LifecycleState: TrustedIdentityLifecycleState.Active,
                    LifecycleChangedAtUtc: current.LifecycleChangedAtUtc ?? current.FirstTrustedAtUtc,
                    LifecycleReason: current.LifecycleReason,
                    IdentityHistory: AppendIdentityHistory(
                        current,
                        replacedAtUtc,
                        TrustedIdentityHistoryEventType.PairingTrustReplaced,
                        deviceName: deviceName,
                        note: "Explicit pairing trust anchor replaced; signing-key history reset."),
                    TrustRelationshipId: CreateTrustRelationshipId(),
                    LastAcceptedIdentityRevision: 0);
                if (legacySigningIdentity is not null)
                {
                    replaced = BindFirstSigningIdentity(
                        replaced,
                        legacySigningIdentity,
                        legacySigningBoundAtUtc ?? pairedAtUtc,
                        legacySigningBoundAtUtc ?? pairedAtUtc);
                }

                _state.Entries[deviceId] = replaced;
                SaveLockedWithRollback(deviceId, current);
                InvalidateSessionLifetimeLocked(deviceId);
                _log?.Invoke($"GNP/1 M2.5.2.1 trust relationship replaced for {deviceName}; active sessions and previous resume authorization were invalidated.");
                _log?.Invoke($"GNP/1 M2.4.1 pairing trust anchor changed for {deviceName}; previous signing-key registry history was reset after explicit pairing trust changed.");
                return;
            }

            if (current.LifecycleState != TrustedIdentityLifecycleState.Active)
            {
                // Local startup synchronization must never reactivate, rename, or refresh an
                // administratively retired/revoked identity. Only SetLifecycleState can do that.
                return;
            }

            var updated = current with
            {
                DeviceName = current.LastAcceptedIdentityRevision > 0 ? current.DeviceName : deviceName,
                LastAuthenticatedAtUtc = MaxTimestamp(current.LastAuthenticatedAtUtc, authenticatedAtUtc),
                SigningKeyHistory = current.SigningKeyHistory ?? [],
                IdentityHistory = current.IdentityHistory ?? []
            };

            if (legacySigningIdentity is not null)
            {
                updated = ReconcileLegacySigningIdentity(
                    updated,
                    legacySigningIdentity,
                    legacySigningBoundAtUtc ?? pairedAtUtc);
            }

            if (updated == current)
            {
                return;
            }

            _state.Entries[deviceId] = updated;
            SaveLockedWithRollback(deviceId, current);
        }
    }

    public SigningIdentityBindingUpdate RecordAuthenticatedSigningIdentity(
        Guid deviceId,
        string deviceName,
        ReadOnlySpan<byte> pairingPublicKey,
        TrustedSigningIdentity identity,
        DateTimeOffset verifiedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(identity);
        ValidateDeviceId(deviceId);
        ValidateDeviceName(deviceName);
        PairingProtocol.ValidatePublicKey(pairingPublicKey);
        identity.Validate();
        if (identity.DeviceId != deviceId)
        {
            throw new InvalidDataException("Authenticated signing identity does not belong to the trusted device.");
        }

        var pairingKeyId = GetPairingKeyId(pairingPublicKey);
        lock (_state.Gate)
        {
            if (!_state.Entries.TryGetValue(deviceId, out var current))
            {
                if (_state.Entries.Count >= MaxTrustedIdentities)
                {
                    throw new InvalidDataException("Trusted Identity Registry reached its safe device limit.");
                }

                current = new TrustedIdentityRegistryEntry(
                    deviceId,
                    deviceName,
                    pairingKeyId,
                    verifiedAtUtc,
                    verifiedAtUtc,
                    SigningKeyHistory: [],
                    LifecycleState: TrustedIdentityLifecycleState.Active,
                    LifecycleChangedAtUtc: verifiedAtUtc,
                    IdentityHistory: CreateInitialIdentityHistory(deviceName, verifiedAtUtc));
            }
            else
            {
                if (current.LifecycleState != TrustedIdentityLifecycleState.Active)
                {
                    throw new InvalidDataException($"Authenticated signing identity update was rejected because {current.DeviceName} is {current.LifecycleState}.");
                }

                if (!string.Equals(current.PairingKeyId, pairingKeyId, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidDataException("Trusted Identity Registry pairing-key anchor does not match the authenticated trusted device.");
                }
            }

            var previous = _state.Entries.GetValueOrDefault(deviceId);
            var (updated, result) = ApplyAuthenticatedSigningIdentity(current, deviceName, identity, verifiedAtUtc, allowLocalRecoveryWithoutRotationProof: false);
            _state.Entries[deviceId] = updated;
            SaveLockedWithRollback(deviceId, previous);
            return result;
        }
    }

    public bool RecordAuthenticatedDeviceName(
        Guid deviceId,
        string deviceName,
        ReadOnlySpan<byte> pairingPublicKey,
        int signingIdentityVersion,
        int signingKeyGeneration,
        string signingKeyId,
        long identityRevision,
        DateTimeOffset authenticatedAtUtc)
    {
        ValidateDeviceId(deviceId);
        ValidateDeviceName(deviceName);
        PairingProtocol.ValidatePublicKey(pairingPublicKey);
        if (signingIdentityVersion < DeviceIdentityV2.CurrentVersion)
        {
            throw new InvalidDataException("Authenticated rename requires a Device Identity v2 signing identity.");
        }

        if (signingKeyGeneration < 1)
        {
            throw new InvalidDataException("Authenticated rename signing-key generation is invalid.");
        }

        ValidateSha256Id(signingKeyId, "authenticated rename signing key ID");
        if (identityRevision < 1)
        {
            throw new InvalidDataException("Authenticated identity revision must be positive.");
        }

        if (authenticatedAtUtc == default)
        {
            throw new InvalidDataException("Authenticated rename timestamp is missing.");
        }

        var pairingKeyId = GetPairingKeyId(pairingPublicKey);
        lock (_state.Gate)
        {
            if (!_state.Entries.TryGetValue(deviceId, out var current))
            {
                throw new InvalidDataException("Authenticated rename requires an existing trusted identity.");
            }

            if (current.State != TrustedIdentityRegistryState.Trusted ||
                current.LifecycleState != TrustedIdentityLifecycleState.Active)
            {
                throw new InvalidDataException("Authenticated rename was rejected because the trusted identity is not active and trusted.");
            }

            if (!string.Equals(current.PairingKeyId, pairingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Authenticated rename pairing-key anchor does not match the trusted identity.");
            }

            if (current.CurrentSigningIdentityVersion != signingIdentityVersion ||
                current.CurrentSigningKeyGeneration != signingKeyGeneration ||
                !string.Equals(current.CurrentSigningKeyId, signingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Authenticated rename signing identity does not match the currently trusted signing identity.");
            }

            if (identityRevision < current.LastAcceptedIdentityRevision)
            {
                throw new InvalidDataException("Replay-protected identity revision rollback was rejected.");
            }

            var renamed = !string.Equals(current.DeviceName, deviceName, StringComparison.Ordinal);
            if (identityRevision == current.LastAcceptedIdentityRevision && renamed)
            {
                throw new InvalidDataException("Replay-protected identity revision conflicts with the already accepted device name.");
            }
            var updated = current with
            {
                DeviceName = deviceName,
                LastAuthenticatedAtUtc = MaxTimestamp(current.LastAuthenticatedAtUtc, authenticatedAtUtc),
                CurrentSigningKeyLastVerifiedAtUtc = MaxNullableTimestamp(current.CurrentSigningKeyLastVerifiedAtUtc, authenticatedAtUtc),
                LastAcceptedIdentityRevision = Math.Max(current.LastAcceptedIdentityRevision, identityRevision),
                IdentityHistory = renamed
                    ? AppendIdentityHistory(
                        current,
                        authenticatedAtUtc,
                        TrustedIdentityHistoryEventType.AuthenticatedRename,
                        previousDeviceName: current.DeviceName,
                        deviceName: deviceName,
                        signingKeyId: signingKeyId,
                        signingKeyGeneration: signingKeyGeneration,
                        identityRevision: identityRevision)
                    : current.IdentityHistory ?? []
            };

            if (updated == current)
            {
                return false;
            }

            _state.Entries[deviceId] = updated;
            SaveLockedWithRollback(deviceId, current);
            if (renamed)
            {
                _log?.Invoke($"GNP/1 M2.5.3 authenticated rename recorded at identity revision {identityRevision}: {current.DeviceName} -> {deviceName} ({deviceId:N}).");
            }

            return renamed;
        }
    }

    public bool RecordAuthenticatedCapabilities(
        Guid deviceId,
        ReadOnlySpan<byte> pairingPublicKey,
        int signingIdentityVersion,
        int signingKeyGeneration,
        string signingKeyId,
        DeviceCapability capabilities,
        long capabilityRevision,
        DateTimeOffset authenticatedAtUtc)
    {
        ValidateDeviceId(deviceId);
        PairingProtocol.ValidatePublicKey(pairingPublicKey);
        if (signingIdentityVersion < DeviceIdentityV2.CurrentVersion)
        {
            throw new InvalidDataException("Authenticated capabilities require a Device Identity v2 signing identity.");
        }

        if (signingKeyGeneration < 1)
        {
            throw new InvalidDataException("Authenticated capability signing-key generation is invalid.");
        }

        ValidateSha256Id(signingKeyId, "authenticated capability signing key ID");
        if (!DeviceCapabilityProfiles.IsValidAdvertisement(capabilities))
        {
            throw new InvalidDataException("Authenticated capability set is invalid or unsupported.");
        }

        if (capabilityRevision < 1)
        {
            throw new InvalidDataException("Authenticated capability revision must be positive.");
        }

        if (authenticatedAtUtc == default)
        {
            throw new InvalidDataException("Authenticated capability timestamp is missing.");
        }

        var pairingKeyId = GetPairingKeyId(pairingPublicKey);
        lock (_state.Gate)
        {
            if (!_state.Entries.TryGetValue(deviceId, out var current))
            {
                throw new InvalidDataException("Authenticated capabilities require an existing trusted identity.");
            }

            if (current.State != TrustedIdentityRegistryState.Trusted ||
                current.LifecycleState != TrustedIdentityLifecycleState.Active)
            {
                throw new InvalidDataException("Authenticated capabilities were rejected because the trusted identity is not active and trusted.");
            }

            if (authenticatedAtUtc < current.FirstTrustedAtUtc)
            {
                throw new InvalidDataException("Authenticated capability timestamp predates the trusted relationship.");
            }

            if (!string.Equals(current.PairingKeyId, pairingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Authenticated capability pairing-key anchor does not match the trusted identity.");
            }

            if (current.CurrentSigningIdentityVersion != signingIdentityVersion ||
                current.CurrentSigningKeyGeneration != signingKeyGeneration ||
                !string.Equals(current.CurrentSigningKeyId, signingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Authenticated capability signing identity does not match the currently trusted signing identity.");
            }

            if (capabilityRevision < current.LastAcceptedCapabilityRevision)
            {
                throw new InvalidDataException("Authenticated capability revision rollback was rejected.");
            }

            if (capabilityRevision == current.LastAcceptedCapabilityRevision &&
                current.VerifiedCapabilities != DeviceCapability.None &&
                current.VerifiedCapabilities != capabilities)
            {
                throw new InvalidDataException("Authenticated capability revision conflicts with the already accepted capability set.");
            }

            var changed = current.VerifiedCapabilities != capabilities ||
                          capabilityRevision > current.LastAcceptedCapabilityRevision;
            var updated = current with
            {
                VerifiedCapabilities = capabilities,
                LastAcceptedCapabilityRevision = Math.Max(current.LastAcceptedCapabilityRevision, capabilityRevision),
                CapabilitiesLastVerifiedAtUtc = MaxNullableTimestamp(current.CapabilitiesLastVerifiedAtUtc, authenticatedAtUtc),
                LastAuthenticatedAtUtc = MaxTimestamp(current.LastAuthenticatedAtUtc, authenticatedAtUtc),
                CurrentSigningKeyLastVerifiedAtUtc = MaxNullableTimestamp(current.CurrentSigningKeyLastVerifiedAtUtc, authenticatedAtUtc)
            };

            if (updated == current)
            {
                return false;
            }

            _state.Entries[deviceId] = updated;
            SaveLockedWithRollback(deviceId, current);
            if (changed)
            {
                var profile = DeviceCapabilityProfiles.ResolveProfile(capabilities);
                _log?.Invoke($"GNP/1 M2.6.2 authenticated capabilities accepted for {current.DeviceName}: {capabilities} · profile {profile} · revision {capabilityRevision}.");
            }

            return changed;
        }
    }

    public void MarkAuthenticated(Guid deviceId, DateTimeOffset authenticatedAtUtc)
    {
        lock (_state.Gate)
        {
            if (!_state.Entries.TryGetValue(deviceId, out var current) ||
                current.State != TrustedIdentityRegistryState.Trusted ||
                current.LifecycleState != TrustedIdentityLifecycleState.Active ||
                authenticatedAtUtc <= current.LastAuthenticatedAtUtc)
            {
                return;
            }

            var updated = current with { LastAuthenticatedAtUtc = authenticatedAtUtc };
            _state.Entries[deviceId] = updated;
            SaveLockedWithRollback(deviceId, current);
        }
    }

    public bool Remove(Guid deviceId)
    {
        lock (_state.Gate)
        {
            if (!_state.Entries.Remove(deviceId, out var removed))
            {
                return false;
            }

            try
            {
                SaveLocked();
                InvalidateSessionLifetimeLocked(deviceId);
                if (_state.SessionLifetimes.Remove(deviceId, out var forgottenLifetime))
                {
                    forgottenLifetime.Source.Dispose();
                }

                _log?.Invoke($"GNP/1 M2.5.2.1 trust relationship forgotten for {removed.DeviceName}; active sessions and resume authorization were invalidated.");
                return true;
            }
            catch
            {
                _state.Entries[deviceId] = removed;
                throw;
            }
        }
    }

    public static string GetPairingKeyId(ReadOnlySpan<byte> pairingPublicKey)
    {
        PairingProtocol.ValidatePublicKey(pairingPublicKey);
        return Convert.ToHexString(SHA256.HashData(pairingPublicKey));
    }

    private TrustedIdentityRegistryEntry ReconcileLegacySigningIdentity(
        TrustedIdentityRegistryEntry current,
        TrustedSigningIdentity legacyIdentity,
        DateTimeOffset boundAtUtc)
    {
        if (string.IsNullOrWhiteSpace(current.CurrentSigningKeyId))
        {
            return BindFirstSigningIdentity(current, legacyIdentity, boundAtUtc, boundAtUtc);
        }

        if (string.Equals(current.CurrentSigningKeyId, legacyIdentity.SigningKeyId, StringComparison.OrdinalIgnoreCase))
        {
            if (legacyIdentity.KeyGeneration < current.CurrentSigningKeyGeneration)
            {
                _log?.Invoke($"GNP/1 M2.4.2 registry kept newer signing generation {current.CurrentSigningKeyGeneration} for {current.DeviceName}; legacy snapshot reported generation {legacyIdentity.KeyGeneration}.");
                return current;
            }

            if (legacyIdentity.KeyGeneration > current.CurrentSigningKeyGeneration)
            {
                _log?.Invoke($"GNP/1 M2.4.2 registry rejected a legacy generation increase without a signing-key change for {current.DeviceName}.");
                return current with { State = TrustedIdentityRegistryState.Changed };
            }

            return current with
            {
                CurrentSigningIdentityVersion = legacyIdentity.IdentityVersion,
                CurrentSigningPublicKeyBase64 = Convert.ToBase64String(legacyIdentity.SigningPublicKey),
                CurrentSigningKeyBoundAtUtc = current.CurrentSigningKeyBoundAtUtc ?? boundAtUtc,
                CurrentSigningKeyLastVerifiedAtUtc = MaxNullableTimestamp(current.CurrentSigningKeyLastVerifiedAtUtc, boundAtUtc)
            };
        }

        if (legacyIdentity.KeyGeneration > current.CurrentSigningKeyGeneration)
        {
            var (reconciled, _) = ApplyAuthenticatedSigningIdentity(current, current.DeviceName, legacyIdentity, boundAtUtc, allowLocalRecoveryWithoutRotationProof: true);
            _log?.Invoke($"GNP/1 M2.4.1 registry reconciled a newer authenticated M2.3 signing generation for {current.DeviceName} after local registry recovery.");
            return reconciled;
        }

        _log?.Invoke($"GNP/1 M2.4.1 registry detected a legacy signing-key snapshot conflict for {current.DeviceName}; existing registry identity was preserved until a fresh authenticated M2.3 binding verifies the change.");
        return current with { State = TrustedIdentityRegistryState.Changed };
    }

    private static TrustedIdentityRegistryEntry BindFirstSigningIdentity(
        TrustedIdentityRegistryEntry current,
        TrustedSigningIdentity identity,
        DateTimeOffset boundAtUtc,
        DateTimeOffset verifiedAtUtc)
    {
        return current with
        {
            State = TrustedIdentityRegistryState.Trusted,
            CurrentSigningIdentityVersion = identity.IdentityVersion,
            CurrentSigningKeyGeneration = identity.KeyGeneration,
            CurrentSigningKeyId = identity.SigningKeyId,
            CurrentSigningPublicKeyBase64 = Convert.ToBase64String(identity.SigningPublicKey),
            CurrentSigningKeyBoundAtUtc = boundAtUtc,
            CurrentSigningKeyLastVerifiedAtUtc = verifiedAtUtc,
            SigningKeyHistory = current.SigningKeyHistory ?? []
        };
    }

    private static (TrustedIdentityRegistryEntry Updated, SigningIdentityBindingUpdate Result) ApplyAuthenticatedSigningIdentity(
        TrustedIdentityRegistryEntry current,
        string deviceName,
        TrustedSigningIdentity identity,
        DateTimeOffset verifiedAtUtc,
        bool allowLocalRecoveryWithoutRotationProof)
    {
        var signingKeyId = identity.SigningKeyId;
        var signingPublicKeyBase64 = Convert.ToBase64String(identity.SigningPublicKey);
        if (string.IsNullOrWhiteSpace(current.CurrentSigningKeyId))
        {
            var renamedHistory = string.Equals(current.DeviceName, deviceName, StringComparison.Ordinal)
                ? current.IdentityHistory ?? []
                : AppendIdentityHistory(
                    current,
                    verifiedAtUtc,
                    TrustedIdentityHistoryEventType.AuthenticatedRename,
                    previousDeviceName: current.DeviceName,
                    deviceName: deviceName,
                    signingKeyId: signingKeyId,
                    signingKeyGeneration: identity.KeyGeneration);
            var bound = BindFirstSigningIdentity(current, identity, verifiedAtUtc, verifiedAtUtc) with
            {
                DeviceName = deviceName,
                LastAuthenticatedAtUtc = MaxTimestamp(current.LastAuthenticatedAtUtc, verifiedAtUtc),
                IdentityHistory = renamedHistory
            };
            return (bound, SigningIdentityBindingUpdate.Bound);
        }

        if (string.Equals(current.CurrentSigningKeyId, signingKeyId, StringComparison.OrdinalIgnoreCase))
        {
            if (identity.KeyGeneration < current.CurrentSigningKeyGeneration)
            {
                throw new InvalidDataException("Trusted Identity Registry rejected a signing-key generation rollback.");
            }

            if (identity.KeyGeneration > current.CurrentSigningKeyGeneration)
            {
                throw new InvalidDataException("Trusted Identity Registry rejected a generation increase without a signing-key change.");
            }

            var identityHistory = string.Equals(current.DeviceName, deviceName, StringComparison.Ordinal)
                ? current.IdentityHistory ?? []
                : AppendIdentityHistory(
                    current,
                    verifiedAtUtc,
                    TrustedIdentityHistoryEventType.AuthenticatedRename,
                    previousDeviceName: current.DeviceName,
                    deviceName: deviceName,
                    signingKeyId: signingKeyId,
                    signingKeyGeneration: identity.KeyGeneration);
            var unchanged = current with
            {
                DeviceName = deviceName,
                State = TrustedIdentityRegistryState.Trusted,
                LastAuthenticatedAtUtc = MaxTimestamp(current.LastAuthenticatedAtUtc, verifiedAtUtc),
                CurrentSigningIdentityVersion = identity.IdentityVersion,
                CurrentSigningKeyGeneration = identity.KeyGeneration,
                CurrentSigningPublicKeyBase64 = signingPublicKeyBase64,
                CurrentSigningKeyBoundAtUtc = current.CurrentSigningKeyBoundAtUtc ?? verifiedAtUtc,
                CurrentSigningKeyLastVerifiedAtUtc = MaxNullableTimestamp(current.CurrentSigningKeyLastVerifiedAtUtc, verifiedAtUtc),
                SigningKeyHistory = current.SigningKeyHistory ?? [],
                IdentityHistory = identityHistory
            };
            return (unchanged, SigningIdentityBindingUpdate.Unchanged);
        }

        if (identity.KeyGeneration <= current.CurrentSigningKeyGeneration)
        {
            throw new InvalidDataException("Trusted Identity Registry requires a higher signing-key generation for replacement.");
        }

        var previousSigningKeyId = current.CurrentSigningKeyId;
        var previousSigningPublicKeyBase64 = current.CurrentSigningPublicKeyBase64;
        if (string.IsNullOrWhiteSpace(previousSigningKeyId) ||
            string.IsNullOrWhiteSpace(previousSigningPublicKeyBase64) ||
            current.CurrentSigningKeyBoundAtUtc is null ||
            current.CurrentSigningKeyLastVerifiedAtUtc is null ||
            current.CurrentSigningIdentityVersion < DeviceIdentityV2.CurrentVersion ||
            current.CurrentSigningKeyGeneration < 1)
        {
            throw new InvalidDataException("Trusted Identity Registry current signing identity is incomplete and cannot be rotated safely.");
        }

        if (!allowLocalRecoveryWithoutRotationProof)
        {
            var previousSigningPublicKey = Convert.FromBase64String(previousSigningPublicKeyBase64);
            try
            {
                SigningKeyRotation.ValidateTrustedTransition(
                    current.DeviceId,
                    current.CurrentSigningIdentityVersion,
                    current.CurrentSigningKeyGeneration,
                    previousSigningPublicKey,
                    identity);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(previousSigningPublicKey);
            }
        }

        var history = (current.SigningKeyHistory ?? []).ToList();
        history.Add(new TrustedSigningKeyHistoryEntry(
            current.CurrentSigningIdentityVersion,
            current.CurrentSigningKeyGeneration,
            previousSigningKeyId,
            previousSigningPublicKeyBase64,
            current.CurrentSigningKeyBoundAtUtc.Value,
            current.CurrentSigningKeyLastVerifiedAtUtc.Value));
        if (history.Count > MaxSigningKeyHistoryEntries)
        {
            history.RemoveRange(0, history.Count - MaxSigningKeyHistoryEntries);
        }

        var identityHistoryForRotation = current.IdentityHistory ?? [];
        if (!string.Equals(current.DeviceName, deviceName, StringComparison.Ordinal))
        {
            identityHistoryForRotation = AppendIdentityHistory(
                current,
                verifiedAtUtc,
                TrustedIdentityHistoryEventType.AuthenticatedRename,
                previousDeviceName: current.DeviceName,
                deviceName: deviceName,
                signingKeyId: signingKeyId,
                signingKeyGeneration: identity.KeyGeneration);
        }

        var historyCarrier = current with { IdentityHistory = identityHistoryForRotation };
        identityHistoryForRotation = AppendIdentityHistory(
            historyCarrier,
            verifiedAtUtc,
            TrustedIdentityHistoryEventType.SigningKeyRotated,
            deviceName: deviceName,
            signingKeyId: signingKeyId,
            signingKeyGeneration: identity.KeyGeneration,
            note: $"Previous signing key: {previousSigningKeyId} generation {current.CurrentSigningKeyGeneration}.");

        var rotated = current with
        {
            DeviceName = deviceName,
            State = TrustedIdentityRegistryState.Trusted,
            LastAuthenticatedAtUtc = MaxTimestamp(current.LastAuthenticatedAtUtc, verifiedAtUtc),
            CurrentSigningIdentityVersion = identity.IdentityVersion,
            CurrentSigningKeyGeneration = identity.KeyGeneration,
            CurrentSigningKeyId = signingKeyId,
            CurrentSigningPublicKeyBase64 = signingPublicKeyBase64,
            CurrentSigningKeyBoundAtUtc = verifiedAtUtc,
            CurrentSigningKeyLastVerifiedAtUtc = verifiedAtUtc,
            SigningKeyHistory = history.ToArray(),
            IdentityHistory = identityHistoryForRotation,
            // Capability state was authenticated by the previous signing key. A continuity-
            // proven key rotation preserves device trust, but the new key must advertise
            // capabilities again before they are considered current authenticated state.
            VerifiedCapabilities = DeviceCapability.None,
            LastAcceptedCapabilityRevision = 0,
            CapabilitiesLastVerifiedAtUtc = null
        };
        return (rotated, SigningIdentityBindingUpdate.Rotated);
    }

    private void Load()
    {
        if (TryLoadFromPath(_path, out var primaryError))
        {
            return;
        }

        if (primaryError is not null)
        {
            _log?.Invoke($"GNP/1 M2.4.1 Trusted Identity Registry primary file could not be loaded: {primaryError.Message}");
        }

        if (!TryLoadFromPath(_backupPath, out var backupError))
        {
            if (backupError is not null)
            {
                _log?.Invoke($"GNP/1 M2.4.1 Trusted Identity Registry backup could not be loaded: {backupError.Message}");
            }

            _state.Entries.Clear();
            return;
        }

        _log?.Invoke("GNP/1 M2.4.1 Trusted Identity Registry recovered from local backup.");
        try
        {
            File.Copy(_backupPath, _path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _log?.Invoke($"GNP/1 M2.4.1 Trusted Identity Registry recovery could not rewrite the primary file: {ex.Message}");
        }
    }

    private bool TryLoadFromPath(string path, out Exception? error)
    {
        error = null;
        if (!File.Exists(path))
        {
            return false;
        }

        try
        {
            if (new FileInfo(path).Length > MaxStoreBytes)
            {
                throw new InvalidDataException("Trusted Identity Registry is unexpectedly large.");
            }

            var json = File.ReadAllText(path, StrictUtf8);
            var document = JsonSerializer.Deserialize<TrustedIdentityRegistryDocument>(json)
                ?? throw new InvalidDataException("Trusted Identity Registry document is empty.");
            if (document.SchemaVersion is < 1 or > CurrentSchemaVersion)
            {
                throw new InvalidDataException($"Unsupported Trusted Identity Registry schema version {document.SchemaVersion}.");
            }

            var identities = document.Identities ?? throw new InvalidDataException("Trusted Identity Registry identity list is missing.");
            if (identities.Length > MaxTrustedIdentities)
            {
                throw new InvalidDataException("Trusted Identity Registry exceeds its safe device limit.");
            }

            var loaded = new Dictionary<Guid, TrustedIdentityRegistryEntry>();
            foreach (var entry in identities)
            {
                var normalized = ValidateAndNormalizeEntry(entry, document.SchemaVersion);
                if (!loaded.TryAdd(normalized.DeviceId, normalized))
                {
                    throw new InvalidDataException("Trusted Identity Registry contains a duplicate Device ID.");
                }
            }

            lock (_state.Gate)
            {
                _state.Entries.Clear();
                foreach (var pair in loaded)
                {
                    _state.Entries.Add(pair.Key, pair.Value);
                }
            }

            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or DecoderFallbackException or EncoderFallbackException or FormatException or CryptographicException)
        {
            error = ex;
            return false;
        }
    }

    private static TrustedIdentityRegistryEntry ValidateAndNormalizeEntry(TrustedIdentityRegistryEntry entry, int schemaVersion)
    {
        ValidateDeviceId(entry.DeviceId);
        ValidateDeviceName(entry.DeviceName);
        ValidateSha256Id(entry.PairingKeyId, "pairing key ID");

        var bindingState = entry.State;
        var lifecycleState = entry.LifecycleState;
        if (schemaVersion == 1)
        {
            // Schema v1 used RegistryState.Revoked=3 before lifecycle state was split out.
            if ((int)bindingState == 3)
            {
                bindingState = TrustedIdentityRegistryState.Trusted;
                lifecycleState = TrustedIdentityLifecycleState.Revoked;
            }
            else if ((int)lifecycleState == 0)
            {
                lifecycleState = TrustedIdentityLifecycleState.Active;
            }
        }

        if (!Enum.IsDefined(bindingState))
        {
            throw new InvalidDataException("Trusted Identity Registry contains an invalid cryptographic binding state.");
        }

        if (!Enum.IsDefined(lifecycleState))
        {
            throw new InvalidDataException("Trusted Identity Registry contains an invalid lifecycle state.");
        }

        if (entry.FirstTrustedAtUtc == default ||
            entry.LastAuthenticatedAtUtc == default ||
            entry.LastAuthenticatedAtUtc < entry.FirstTrustedAtUtc)
        {
            throw new InvalidDataException("Trusted Identity Registry timestamps are incomplete or inconsistent.");
        }

        var lifecycleChangedAtUtc = entry.LifecycleChangedAtUtc ?? entry.FirstTrustedAtUtc;
        if (lifecycleChangedAtUtc < entry.FirstTrustedAtUtc)
        {
            throw new InvalidDataException("Trusted Identity Registry lifecycle timestamp predates initial trust.");
        }

        ValidateLifecycleReason(entry.LifecycleReason);

        var trustRelationshipId = entry.TrustRelationshipId;
        if (schemaVersion < 3 || string.IsNullOrWhiteSpace(trustRelationshipId))
        {
            trustRelationshipId = CreateMigratedTrustRelationshipId(entry);
        }

        ValidateTrustRelationshipId(trustRelationshipId);

        var lastAcceptedIdentityRevision = schemaVersion < 4 ? 0 : entry.LastAcceptedIdentityRevision;
        if (lastAcceptedIdentityRevision < 0)
        {
            throw new InvalidDataException("Trusted Identity Registry last accepted identity revision is invalid.");
        }

        var verifiedCapabilities = schemaVersion < 5 ? DeviceCapability.None : entry.VerifiedCapabilities;
        var lastAcceptedCapabilityRevision = schemaVersion < 5 ? 0 : entry.LastAcceptedCapabilityRevision;
        var capabilitiesLastVerifiedAtUtc = schemaVersion < 5 ? null : entry.CapabilitiesLastVerifiedAtUtc;
        if (lastAcceptedCapabilityRevision < 0)
        {
            throw new InvalidDataException("Trusted Identity Registry last accepted capability revision is invalid.");
        }

        if (lastAcceptedCapabilityRevision == 0)
        {
            verifiedCapabilities = DeviceCapability.None;
            capabilitiesLastVerifiedAtUtc = null;
        }
        else
        {
            if (!DeviceCapabilityProfiles.IsValidAdvertisement(verifiedCapabilities) || capabilitiesLastVerifiedAtUtc is null)
            {
                throw new InvalidDataException("Trusted Identity Registry authenticated capability state is incomplete or invalid.");
            }

            if (capabilitiesLastVerifiedAtUtc.Value < entry.FirstTrustedAtUtc)
            {
                throw new InvalidDataException("Trusted Identity Registry capability verification timestamp predates initial trust.");
            }
        }

        var signingHistory = entry.SigningKeyHistory ?? [];
        if (signingHistory.Length > MaxSigningKeyHistoryEntries)
        {
            throw new InvalidDataException("Trusted Identity Registry signing-key history exceeds its safe limit.");
        }

        var hasAnyCurrentSigningData = entry.CurrentSigningIdentityVersion != 0 ||
                                       entry.CurrentSigningKeyGeneration != 0 ||
                                       !string.IsNullOrWhiteSpace(entry.CurrentSigningKeyId) ||
                                       !string.IsNullOrWhiteSpace(entry.CurrentSigningPublicKeyBase64) ||
                                       entry.CurrentSigningKeyBoundAtUtc is not null ||
                                       entry.CurrentSigningKeyLastVerifiedAtUtc is not null;
        if (hasAnyCurrentSigningData)
        {
            ValidateSigningIdentityFields(
                entry.CurrentSigningIdentityVersion,
                entry.CurrentSigningKeyGeneration,
                entry.CurrentSigningKeyId,
                entry.CurrentSigningPublicKeyBase64,
                entry.CurrentSigningKeyBoundAtUtc,
                entry.CurrentSigningKeyLastVerifiedAtUtc);
        }

        foreach (var historyEntry in signingHistory)
        {
            if (!Enum.IsDefined(historyEntry.State))
            {
                throw new InvalidDataException("Trusted Identity Registry contains an invalid signing-key history state.");
            }

            ValidateSigningIdentityFields(
                historyEntry.IdentityVersion,
                historyEntry.KeyGeneration,
                historyEntry.SigningKeyId,
                historyEntry.SigningPublicKeyBase64,
                historyEntry.FirstTrustedAtUtc,
                historyEntry.LastVerifiedAtUtc);
        }

        var identityHistory = entry.IdentityHistory ?? [];
        if (schemaVersion == 1 && identityHistory.Length == 0)
        {
            identityHistory = CreateInitialIdentityHistory(entry.DeviceName, entry.FirstTrustedAtUtc);
        }

        if (identityHistory.Length > MaxIdentityHistoryEntries)
        {
            throw new InvalidDataException("Trusted Identity Registry identity history exceeds its safe limit.");
        }

        long previousSequence = 0;
        foreach (var historyEntry in identityHistory)
        {
            if (historyEntry.Sequence <= previousSequence || historyEntry.OccurredAtUtc == default)
            {
                throw new InvalidDataException("Trusted Identity Registry identity history sequence is invalid.");
            }

            if (!Enum.IsDefined(historyEntry.EventType))
            {
                throw new InvalidDataException("Trusted Identity Registry contains an invalid identity history event type.");
            }

            if (historyEntry.PreviousDeviceName is not null)
            {
                ValidateDeviceName(historyEntry.PreviousDeviceName);
            }

            if (historyEntry.DeviceName is not null)
            {
                ValidateDeviceName(historyEntry.DeviceName);
            }

            if (historyEntry.PreviousLifecycleState is not null && !Enum.IsDefined(historyEntry.PreviousLifecycleState.Value))
            {
                throw new InvalidDataException("Trusted Identity Registry history contains an invalid previous lifecycle state.");
            }

            if (historyEntry.LifecycleState is not null && !Enum.IsDefined(historyEntry.LifecycleState.Value))
            {
                throw new InvalidDataException("Trusted Identity Registry history contains an invalid lifecycle state.");
            }

            if (historyEntry.SigningKeyId is not null)
            {
                ValidateSha256Id(historyEntry.SigningKeyId, "identity history signing key ID");
                if (historyEntry.SigningKeyGeneration < 1)
                {
                    throw new InvalidDataException("Trusted Identity Registry history signing-key generation is invalid.");
                }
            }
            else if (historyEntry.SigningKeyGeneration != 0)
            {
                throw new InvalidDataException("Trusted Identity Registry history signing-key generation has no key ID.");
            }

            if (historyEntry.IdentityRevision < 0)
            {
                throw new InvalidDataException("Trusted Identity Registry history identity revision is invalid.");
            }

            ValidateLifecycleReason(historyEntry.Note);
            previousSequence = historyEntry.Sequence;
        }

        return entry with
        {
            State = bindingState,
            LifecycleState = lifecycleState,
            LifecycleChangedAtUtc = lifecycleChangedAtUtc,
            LifecycleReason = string.IsNullOrWhiteSpace(entry.LifecycleReason) ? null : entry.LifecycleReason.Trim(),
            SigningKeyHistory = signingHistory,
            IdentityHistory = identityHistory,
            TrustRelationshipId = trustRelationshipId,
            LastAcceptedIdentityRevision = lastAcceptedIdentityRevision,
            VerifiedCapabilities = verifiedCapabilities,
            LastAcceptedCapabilityRevision = lastAcceptedCapabilityRevision,
            CapabilitiesLastVerifiedAtUtc = capabilitiesLastVerifiedAtUtc
        };
    }

    private static void ValidateSigningIdentityFields(
        int identityVersion,
        int keyGeneration,
        string? signingKeyId,
        string? signingPublicKeyBase64,
        DateTimeOffset? firstTrustedAtUtc,
        DateTimeOffset? lastVerifiedAtUtc)
    {
        if (identityVersion < DeviceIdentityV2.CurrentVersion ||
            keyGeneration < 1 ||
            string.IsNullOrWhiteSpace(signingKeyId) ||
            string.IsNullOrWhiteSpace(signingPublicKeyBase64) ||
            firstTrustedAtUtc is null ||
            lastVerifiedAtUtc is null)
        {
            throw new InvalidDataException("Trusted Identity Registry signing identity is incomplete.");
        }

        if (lastVerifiedAtUtc.Value < firstTrustedAtUtc.Value)
        {
            throw new InvalidDataException("Trusted Identity Registry signing-key timestamps are inconsistent.");
        }

        ValidateSha256Id(signingKeyId, "signing key ID");
        var signingPublicKey = Convert.FromBase64String(signingPublicKeyBase64);
        try
        {
            DeviceSignature.ValidatePublicKey(signingPublicKey);
            var derivedKeyId = DeviceSignature.GetSigningKeyId(signingPublicKey);
            if (!string.Equals(derivedKeyId, signingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Trusted Identity Registry signing-key fingerprint does not match its public key.");
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(signingPublicKey);
        }
    }

    private void SaveLockedWithRollback(Guid deviceId, TrustedIdentityRegistryEntry? previous)
    {
        try
        {
            SaveLocked();
        }
        catch
        {
            if (previous is null)
            {
                _state.Entries.Remove(deviceId);
            }
            else
            {
                _state.Entries[deviceId] = previous;
            }

            throw;
        }
    }

    private void SaveLocked()
    {
        var document = new TrustedIdentityRegistryDocument(
            CurrentSchemaVersion,
            DateTimeOffset.UtcNow,
            _state.Entries.Values.OrderBy(entry => entry.DeviceName, StringComparer.OrdinalIgnoreCase).ToArray());
        var json = JsonSerializer.Serialize(document, IndentedJsonOptions);
        if (StrictUtf8.GetByteCount(json) > MaxStoreBytes)
        {
            throw new InvalidDataException("Trusted Identity Registry unexpectedly exceeds the safe size limit.");
        }

        var tempPath = _path + ".tmp";
        try
        {
            File.WriteAllText(tempPath, json, StrictUtf8);
            if (File.Exists(_path))
            {
                File.Copy(_path, _backupPath, overwrite: true);
            }

            File.Move(tempPath, _path, overwrite: true);
        }
        finally
        {
            try
            {
                if (File.Exists(tempPath))
                {
                    File.Delete(tempPath);
                }
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static TrustedIdentityRegistryEntry CloneEntry(TrustedIdentityRegistryEntry entry) =>
        entry with
        {
            SigningKeyHistory = (entry.SigningKeyHistory ?? []).ToArray(),
            IdentityHistory = (entry.IdentityHistory ?? []).ToArray()
        };

    private static TrustedIdentityHistoryEntry[] CreateInitialIdentityHistory(string deviceName, DateTimeOffset trustedAtUtc) =>
    [
        new TrustedIdentityHistoryEntry(
            1,
            trustedAtUtc,
            TrustedIdentityHistoryEventType.Trusted,
            DeviceName: deviceName,
            LifecycleState: TrustedIdentityLifecycleState.Active,
            Note: "Initial trusted pairing.")
    ];

    private static TrustedIdentityHistoryEntry[] AppendIdentityHistory(
        TrustedIdentityRegistryEntry current,
        DateTimeOffset occurredAtUtc,
        TrustedIdentityHistoryEventType eventType,
        string? previousDeviceName = null,
        string? deviceName = null,
        TrustedIdentityLifecycleState? previousLifecycleState = null,
        TrustedIdentityLifecycleState? lifecycleState = null,
        string? signingKeyId = null,
        int signingKeyGeneration = 0,
        long identityRevision = 0,
        string? note = null)
    {
        var history = (current.IdentityHistory ?? []).ToList();
        var nextSequence = history.Count == 0 ? 1 : checked(history[^1].Sequence + 1);
        history.Add(new TrustedIdentityHistoryEntry(
            nextSequence,
            occurredAtUtc,
            eventType,
            previousDeviceName,
            deviceName,
            previousLifecycleState,
            lifecycleState,
            signingKeyId,
            signingKeyGeneration,
            identityRevision,
            note));
        if (history.Count > MaxIdentityHistoryEntries)
        {
            history.RemoveRange(0, history.Count - MaxIdentityHistoryEntries);
        }

        return history.ToArray();
    }

    private SessionLifetimeState GetOrCreateSessionLifetimeLocked(TrustedIdentityRegistryEntry entry)
    {
        var trustRelationshipId = entry.TrustRelationshipId;
        if (string.IsNullOrWhiteSpace(trustRelationshipId))
        {
            throw new InvalidDataException("Trusted identity trust relationship ID is missing.");
        }

        if (_state.SessionLifetimes.TryGetValue(entry.DeviceId, out var existing))
        {
            if (string.Equals(existing.TrustRelationshipId, trustRelationshipId, StringComparison.Ordinal))
            {
                return existing;
            }

            try
            {
                existing.Source.Cancel();
            }
            finally
            {
                existing.Source.Dispose();
            }
        }

        var created = new SessionLifetimeState(trustRelationshipId, new CancellationTokenSource());
        _state.SessionLifetimes[entry.DeviceId] = created;
        return created;
    }

    private void InvalidateSessionLifetimeLocked(Guid deviceId)
    {
        if (!_state.SessionLifetimes.TryGetValue(deviceId, out var lifetime))
        {
            return;
        }

        lifetime.Source.Cancel();
    }

    private static string CreateTrustRelationshipId() => Guid.NewGuid().ToString("N");

    private static string CreateMigratedTrustRelationshipId(TrustedIdentityRegistryEntry entry)
    {
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hasher.AppendData(entry.DeviceId.ToByteArray());
        hasher.AppendData(Encoding.ASCII.GetBytes(entry.PairingKeyId.ToUpperInvariant()));
        hasher.AppendData(Encoding.ASCII.GetBytes(entry.FirstTrustedAtUtc.UtcDateTime.Ticks.ToString(CultureInfo.InvariantCulture)));
        var digest = hasher.GetHashAndReset();
        try
        {
            return Convert.ToHexString(digest.AsSpan(0, 16)).ToLowerInvariant();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(digest);
        }
    }

    private static void ValidateTrustRelationshipId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) ||
            value.Length != TrustRelationshipIdHexLength ||
            value.Any(ch => !Uri.IsHexDigit(ch)))
        {
            throw new InvalidDataException("Trusted Identity Registry trust relationship ID is invalid.");
        }
    }

    private static void ValidateDeviceId(Guid deviceId)
    {
        if (deviceId == Guid.Empty)
        {
            throw new InvalidDataException("Trusted Identity Registry Device ID must not be empty.");
        }
    }

    private static void ValidateDeviceName(string? deviceName)
    {
        if (string.IsNullOrWhiteSpace(deviceName) ||
            StrictUtf8.GetByteCount(deviceName) > MaxDeviceNameBytes ||
            deviceName.Any(ch => char.IsControl(ch) || CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.Format))
        {
            throw new InvalidDataException("Trusted Identity Registry device name is invalid.");
        }
    }

    private static void ValidateSha256Id(string? value, string fieldName)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length != Sha256HexLength || value.Any(ch => !Uri.IsHexDigit(ch)))
        {
            throw new InvalidDataException($"Trusted Identity Registry {fieldName} is invalid.");
        }
    }

    private static void ValidateLifecycleReason(string? value)
    {
        if (value is null)
        {
            return;
        }

        if (StrictUtf8.GetByteCount(value) > MaxLifecycleReasonBytes ||
            value.Any(ch => char.IsControl(ch) || CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.Format))
        {
            throw new InvalidDataException("Trusted Identity Registry lifecycle/history note is invalid.");
        }
    }

    private static DateTimeOffset MaxTimestamp(DateTimeOffset first, DateTimeOffset second) => first >= second ? first : second;

    private static DateTimeOffset MaxNullableTimestamp(DateTimeOffset? first, DateTimeOffset second) =>
        first is not null && first.Value >= second ? first.Value : second;
}
