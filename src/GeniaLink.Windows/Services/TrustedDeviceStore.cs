using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GeniaLink.Core.Capabilities;
using GeniaLink.Core.Discovery;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Network;
using GeniaLink.Core.Pairing;

namespace GeniaLink.Windows.Services;

internal sealed record TrustedDevice(
    Guid DeviceId,
    string DeviceName,
    string PublicKeyBase64,
    DateTimeOffset PairedAtUtc,
    DeviceKind Kind = DeviceKind.Unknown,
    string? LastVerifiedAddress = null,
    int LastVerifiedTransferPort = 0,
    int LastVerifiedPairingPort = 0,
    DateTimeOffset? EndpointVerifiedAtUtc = null,
    int SigningIdentityVersion = 0,
    int SigningKeyGeneration = 0,
    string? SigningKeyId = null,
    string? SigningPublicKeyBase64 = null,
    DateTimeOffset? SigningKeyBoundAtUtc = null)
{
    public byte[] GetPublicKey() => Convert.FromBase64String(PublicKeyBase64);

    public byte[]? GetSigningPublicKey() =>
        string.IsNullOrWhiteSpace(SigningPublicKeyBase64) ? null : Convert.FromBase64String(SigningPublicKeyBase64);

    public IPAddress? GetLastVerifiedAddress() =>
        !string.IsNullOrWhiteSpace(LastVerifiedAddress) && IPAddress.TryParse(LastVerifiedAddress, out var address)
            ? address
            : null;
}

internal sealed class TrustedDeviceStore
{
    private const long MaxStoreBytes = 1024 * 1024;
    private const int MaxTrustedDevices = 1024;
    private const int MaxDeviceNameBytes = 160;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };
    private readonly string _path;
    private readonly TrustedIdentityRegistry _identityRegistry;
    private readonly Action<string>? _log;
    private readonly Dictionary<Guid, TrustedDevice> _devices = new();
    private readonly object _gate = new();

    public TrustedDeviceStore(string appDataDirectory, Action<string>? log)
    {
        Directory.CreateDirectory(appDataDirectory);
        _path = Path.Combine(appDataDirectory, "trusted-devices.json");
        _log = log;
        _identityRegistry = new TrustedIdentityRegistry(Path.Combine(appDataDirectory, "trusted-identities.json"), log);
        var trustedDeviceDatabaseLoaded = Load(log);
        MigrateTrustedIdentityRegistry(trustedDeviceDatabaseLoaded);
    }

    public TrustedDevice? Get(Guid deviceId)
    {
        lock (_gate)
        {
            return _devices.TryGetValue(deviceId, out var device) && _identityRegistry.IsActiveTrusted(deviceId)
                ? device
                : null;
        }
    }

    public TrustedDevice? GetAny(Guid deviceId)
    {
        lock (_gate)
        {
            return _devices.GetValueOrDefault(deviceId);
        }
    }

    public TrustedDevice[] GetAll()
    {
        lock (_gate)
        {
            return _devices.Values
                .Where(device => _identityRegistry.IsActiveTrusted(device.DeviceId))
                .OrderBy(device => device.DeviceName, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();
        }
    }

    public TrustedDevice[] GetAllIncludingInactive()
    {
        lock (_gate)
        {
            return _devices.Values
                .OrderBy(device => device.DeviceName, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();
        }
    }

    public TrustedIdentityLifecycleState? GetLifecycleState(Guid deviceId) =>
        _identityRegistry.Get(deviceId)?.LifecycleState;

    public TrustedIdentityRegistryEntry? GetIdentityRegistryEntry(Guid deviceId) =>
        _identityRegistry.Get(deviceId);

    public TrustedIdentityRegistryEntry[] GetIdentityRegistryEntries() =>
        _identityRegistry.GetAll();

    public TrustedSessionAuthorization? GetSessionAuthorization(Guid deviceId) =>
        _identityRegistry.GetSessionAuthorization(deviceId);

    public bool IsKnownInactive(Guid deviceId)
    {
        var entry = _identityRegistry.Get(deviceId);
        return entry is not null && entry.LifecycleState != TrustedIdentityLifecycleState.Active;
    }

    public bool SetLifecycleState(Guid deviceId, TrustedIdentityLifecycleState lifecycleState, string? reason = null)
    {
        lock (_gate)
        {
            _devices.TryGetValue(deviceId, out var current);
            var changed = _identityRegistry.SetLifecycleState(deviceId, lifecycleState, DateTimeOffset.UtcNow, reason);
            if (!changed || lifecycleState == TrustedIdentityLifecycleState.Active || current is null)
            {
                return changed;
            }

            if (lifecycleState == TrustedIdentityLifecycleState.Revoked)
            {
                // Revocation is terminal for this record. Remove the compatibility trust
                // record as defense in depth so an older build that does not understand
                // schema-v3 lifecycle cannot silently reuse the former ECDH trust anchor.
                _devices.Remove(deviceId);
                try
                {
                    SaveLocked();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or EncoderFallbackException)
                {
                    _devices[deviceId] = current;
                    _log?.Invoke($"GNP/1 M2.5.2 identity is securely Revoked in the registry, but its compatibility trusted-device record could not be removed: {ex.Message}");
                }

                return true;
            }

            // Do not retain a routable endpoint for an administratively inactive identity.
            // The registry is authoritative; if this compatibility-store write fails, access
            // still fails closed because Get/GetAll require Active + Trusted in the registry.
            var updated = current with
            {
                LastVerifiedAddress = null,
                LastVerifiedTransferPort = 0,
                LastVerifiedPairingPort = 0,
                EndpointVerifiedAtUtc = null
            };
            _devices[deviceId] = updated;
            try
            {
                SaveLocked();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or EncoderFallbackException)
            {
                _devices[deviceId] = current;
                _log?.Invoke($"GNP/1 M2.5.2 lifecycle changed securely for {current.DeviceName}, but the compatibility trusted-device endpoint could not be cleared: {ex.Message}");
            }

            return true;
        }
    }

    public void Upsert(PairingPeerInfo peer, DeviceKind deviceKind = DeviceKind.Unknown)
    {
        ArgumentNullException.ThrowIfNull(peer);
        PairingProtocol.ValidatePublicKey(peer.PublicKey);
        ValidateDeviceName(peer.DeviceName);
        ValidateDeviceKind(deviceKind);

        var existingRegistryEntry = _identityRegistry.Get(peer.DeviceId);
        if (existingRegistryEntry is not null && existingRegistryEntry.LifecycleState != TrustedIdentityLifecycleState.Active)
        {
            throw new InvalidDataException($"Pairing was rejected because {existingRegistryEntry.DeviceName} is {existingRegistryEntry.LifecycleState}. Reactivate a retired identity or forget a revoked identity before pairing again.");
        }

        lock (_gate)
        {
            var hadPrevious = _devices.TryGetValue(peer.DeviceId, out var previous);
            if (!hadPrevious && _devices.Count >= MaxTrustedDevices)
            {
                throw new InvalidDataException("Trusted-device database reached its safe device limit.");
            }

            var publicKeyBase64 = Convert.ToBase64String(peer.PublicKey);
            var sameIdentity = previous is not null &&
                               string.Equals(previous.PublicKeyBase64, publicKeyBase64, StringComparison.Ordinal);
            var storedKind = deviceKind != DeviceKind.Unknown
                ? deviceKind
                : previous?.Kind ?? DeviceKind.Unknown;

            var record = new TrustedDevice(
                peer.DeviceId,
                peer.DeviceName,
                publicKeyBase64,
                DateTimeOffset.UtcNow,
                storedKind,
                sameIdentity ? previous?.LastVerifiedAddress : null,
                sameIdentity ? previous?.LastVerifiedTransferPort ?? 0 : 0,
                sameIdentity ? previous?.LastVerifiedPairingPort ?? 0 : 0,
                sameIdentity ? previous?.EndpointVerifiedAtUtc : null,
                sameIdentity ? previous?.SigningIdentityVersion ?? 0 : 0,
                sameIdentity ? previous?.SigningKeyGeneration ?? 0 : 0,
                sameIdentity ? previous?.SigningKeyId : null,
                sameIdentity ? previous?.SigningPublicKeyBase64 : null,
                sameIdentity ? previous?.SigningKeyBoundAtUtc : null);

            _devices[record.DeviceId] = record;
            try
            {
                SaveLocked();
            }
            catch
            {
                if (hadPrevious && previous is not null)
                {
                    _devices[record.DeviceId] = previous;
                }
                else
                {
                    _devices.Remove(record.DeviceId);
                }

                throw;
            }

            TrySynchronizeIdentityRegistry(record);
        }
    }

    public void UpdateDeviceKind(Guid deviceId, DeviceKind deviceKind)
    {
        ValidateDeviceKind(deviceKind);
        if (deviceKind == DeviceKind.Unknown)
        {
            return;
        }

        lock (_gate)
        {
            if (!_devices.TryGetValue(deviceId, out var current) || current.Kind == deviceKind)
            {
                return;
            }

            _devices[deviceId] = current with { Kind = deviceKind };
            try
            {
                SaveLocked();
            }
            catch
            {
                _devices[deviceId] = current;
                throw;
            }
        }
    }

    public bool TryApplyAuthenticatedSignedDiscovery(DiscoveredDevice device)
    {
        ArgumentNullException.ThrowIfNull(device);
        var capabilityProof = device.IdentityProof == DiscoveryIdentityProof.CapabilitySignedIdentityV2;
        var replayProtected = device.IdentityProof == DiscoveryIdentityProof.ReplayProtectedSignedIdentityV2 || capabilityProof;
        if ((device.IdentityProof != DiscoveryIdentityProof.SignedIdentityV2 &&
             device.IdentityProof != DiscoveryIdentityProof.ReplayProtectedSignedIdentityV2 &&
             !capabilityProof) ||
            string.IsNullOrWhiteSpace(device.SigningKeyId) ||
            device.IdentityVersion < DeviceIdentityV2.CurrentVersion ||
            device.SigningKeyGeneration < 1 ||
            (replayProtected && device.IdentityRevision < 1) ||
            (capabilityProof && (device.CapabilityRevision < 1 || !DeviceCapabilityProfiles.IsValidAdvertisement(device.Capabilities))))
        {
            return false;
        }

        ValidateDeviceName(device.DeviceName);
        lock (_gate)
        {
            if (!_devices.TryGetValue(device.DeviceId, out var current) ||
                current.SigningIdentityVersion != device.IdentityVersion ||
                current.SigningKeyGeneration != device.SigningKeyGeneration ||
                !string.Equals(current.SigningKeyId, device.SigningKeyId, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            byte[]? pairingPublicKey = null;
            try
            {
                pairingPublicKey = current.GetPublicKey();
                var trustedFingerprint = PairingProtocol.GetPublicKeyFingerprint(pairingPublicKey);
                if (!string.Equals(trustedFingerprint, device.PublicKeyFingerprint, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                var sameName = string.Equals(current.DeviceName, device.DeviceName, StringComparison.Ordinal);
                var registryEntry = _identityRegistry.Get(device.DeviceId);
                if (registryEntry is null ||
                    registryEntry.State != TrustedIdentityRegistryState.Trusted ||
                    registryEntry.LifecycleState != TrustedIdentityLifecycleState.Active ||
                    !string.Equals(registryEntry.PairingKeyId, TrustedIdentityRegistry.GetPairingKeyId(pairingPublicKey), StringComparison.OrdinalIgnoreCase) ||
                    registryEntry.CurrentSigningIdentityVersion != device.IdentityVersion ||
                    registryEntry.CurrentSigningKeyGeneration != device.SigningKeyGeneration ||
                    !string.Equals(registryEntry.CurrentSigningKeyId, device.SigningKeyId, StringComparison.OrdinalIgnoreCase) ||
                    (replayProtected && device.IdentityRevision < registryEntry.LastAcceptedIdentityRevision) ||
                    (replayProtected && device.IdentityRevision == registryEntry.LastAcceptedIdentityRevision && !sameName) ||
                    (capabilityProof && device.CapabilityRevision < registryEntry.LastAcceptedCapabilityRevision) ||
                    (capabilityProof && device.CapabilityRevision == registryEntry.LastAcceptedCapabilityRevision &&
                     registryEntry.VerifiedCapabilities != DeviceCapability.None &&
                     registryEntry.VerifiedCapabilities != device.Capabilities))
                {
                    return false;
                }

                if (!replayProtected)
                {
                    // GLS1 remains useful for compatibility and endpoint authentication, but
                    // M2.5.3 never lets an unordered legacy packet mutate the trusted name.
                    return sameName;
                }

                var authenticatedAtUtc = DateTimeOffset.UtcNow;
                try
                {
                    _ = _identityRegistry.RecordAuthenticatedDeviceName(
                        device.DeviceId,
                        device.DeviceName,
                        pairingPublicKey,
                        device.IdentityVersion,
                        device.SigningKeyGeneration,
                        device.SigningKeyId,
                        device.IdentityRevision,
                        authenticatedAtUtc);

                    if (capabilityProof)
                    {
                        _ = _identityRegistry.RecordAuthenticatedCapabilities(
                            device.DeviceId,
                            pairingPublicKey,
                            device.IdentityVersion,
                            device.SigningKeyGeneration,
                            device.SigningKeyId,
                            device.Capabilities,
                            device.CapabilityRevision,
                            authenticatedAtUtc);
                    }
                }
                catch (InvalidDataException)
                {
                    // A stale/lower revision or a conflicting assertion at the same revision
                    // is expected hostile/replayed input and must not mutate compatibility state.
                    return false;
                }

                if (sameName)
                {
                    return true;
                }

                var previousName = current.DeviceName;
                var updated = current with { DeviceName = device.DeviceName };
                _devices[device.DeviceId] = updated;
                try
                {
                    SaveLocked();
                }
                catch
                {
                    _devices[device.DeviceId] = current;
                    throw;
                }

                _log?.Invoke($"GNP/1 M2.5.3 replay-protected authenticated rename accepted: {previousName} -> {device.DeviceName} ({device.DeviceId:N}, revision {device.IdentityRevision}); Device ID and trust anchors were preserved.");
                return true;
            }
            finally
            {
                if (pairingPublicKey is not null)
                {
                    CryptographicOperations.ZeroMemory(pairingPublicKey);
                }
            }
        }
    }

    public void UpdateVerifiedEndpoint(
        Guid deviceId,
        IPAddress address,
        int transferPort,
        int pairingPort,
        DeviceKind deviceKind = DeviceKind.Unknown)
    {
        ArgumentNullException.ThrowIfNull(address);
        ValidateEndpoint(address, transferPort, pairingPort);
        ValidateDeviceKind(deviceKind);

        lock (_gate)
        {
            if (!_devices.TryGetValue(deviceId, out var current) || !_identityRegistry.IsActiveTrusted(deviceId))
            {
                return;
            }

            var verifiedAtUtc = DateTimeOffset.UtcNow;
            var updated = current with
            {
                LastVerifiedAddress = address.ToString(),
                LastVerifiedTransferPort = transferPort,
                LastVerifiedPairingPort = pairingPort,
                EndpointVerifiedAtUtc = verifiedAtUtc,
                Kind = deviceKind != DeviceKind.Unknown ? deviceKind : current.Kind
            };

            _devices[deviceId] = updated;
            try
            {
                SaveLocked();
            }
            catch
            {
                _devices[deviceId] = current;
                throw;
            }

            TryMarkRegistryAuthenticated(deviceId, verifiedAtUtc);
        }
    }

    public SigningIdentityBindingUpdate UpdateSigningIdentity(TrustedSigningIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        identity.Validate();

        lock (_gate)
        {
            if (!_devices.TryGetValue(identity.DeviceId, out var current) || !_identityRegistry.IsActiveTrusted(identity.DeviceId))
            {
                throw new InvalidDataException("Cannot bind a signing identity to an inactive or untrusted device.");
            }

            var signingKeyId = identity.SigningKeyId;
            var signingPublicKeyBase64 = Convert.ToBase64String(identity.SigningPublicKey);
            SigningIdentityBindingUpdate result;
            if (string.IsNullOrWhiteSpace(current.SigningKeyId))
            {
                result = SigningIdentityBindingUpdate.Bound;
            }
            else if (string.Equals(current.SigningKeyId, signingKeyId, StringComparison.OrdinalIgnoreCase))
            {
                if (identity.KeyGeneration < current.SigningKeyGeneration)
                {
                    throw new InvalidDataException("Trusted signing-key generation rollback was rejected.");
                }

                if (identity.KeyGeneration > current.SigningKeyGeneration)
                {
                    throw new InvalidDataException("Trusted signing-key generation cannot increase without changing the signing key.");
                }

                result = SigningIdentityBindingUpdate.Unchanged;
            }
            else
            {
                if (identity.KeyGeneration <= current.SigningKeyGeneration)
                {
                    throw new InvalidDataException("Trusted signing-key replacement requires a higher key generation.");
                }

                var currentSigningPublicKey = current.GetSigningPublicKey()
                    ?? throw new InvalidDataException("Current trusted signing public key is missing.");
                try
                {
                    SigningKeyRotation.ValidateTrustedTransition(
                        current.DeviceId,
                        current.SigningIdentityVersion,
                        current.SigningKeyGeneration,
                        currentSigningPublicKey,
                        identity);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(currentSigningPublicKey);
                }

                result = SigningIdentityBindingUpdate.Rotated;
            }

            var verifiedAtUtc = DateTimeOffset.UtcNow;
            var updated = current with
            {
                SigningIdentityVersion = identity.IdentityVersion,
                SigningKeyGeneration = identity.KeyGeneration,
                SigningKeyId = signingKeyId,
                SigningPublicKeyBase64 = signingPublicKeyBase64,
                SigningKeyBoundAtUtc = result == SigningIdentityBindingUpdate.Unchanged
                    ? current.SigningKeyBoundAtUtc ?? verifiedAtUtc
                    : verifiedAtUtc
            };

            if (updated == current)
            {
                TryRecordSigningIdentityRegistry(current, identity, verifiedAtUtc, result);
                return result;
            }

            _devices[identity.DeviceId] = updated;
            try
            {
                SaveLocked();
            }
            catch
            {
                _devices[identity.DeviceId] = current;
                throw;
            }

            TryRecordSigningIdentityRegistry(updated, identity, verifiedAtUtc, result);
            return result;
        }
    }

    public bool Remove(Guid deviceId)
    {
        lock (_gate)
        {
            var hadRegistryRecord = _identityRegistry.Get(deviceId) is not null;
            var removedCompatibilityRecord = _devices.Remove(deviceId, out var removed);
            if (removedCompatibilityRecord)
            {
                try
                {
                    SaveLocked();
                }
                catch
                {
                    if (removed is not null)
                    {
                        _devices[deviceId] = removed;
                    }

                    throw;
                }
            }

            // Registry-only records are intentionally preserved after compatibility-store
            // recovery. "Forget" must therefore also be able to remove such a record,
            // otherwise a terminal Revoked identity could become impossible to clear.
            var removedRegistryRecord = TryRemoveIdentityRegistry(deviceId);
            if (hadRegistryRecord && !removedRegistryRecord)
            {
                return false;
            }

            return removedCompatibilityRecord || removedRegistryRecord;
        }
    }


    private void MigrateTrustedIdentityRegistry(bool trustedDeviceDatabaseLoaded)
    {
        foreach (var device in _devices.Values)
        {
            TrySynchronizeIdentityRegistry(device);
        }

        if (trustedDeviceDatabaseLoaded)
        {
            var trustedDeviceIds = _devices.Keys.ToHashSet();
            var orphaned = _identityRegistry.GetAll().Count(entry => !trustedDeviceIds.Contains(entry.DeviceId));
            if (orphaned > 0)
            {
                _log?.Invoke($"GNP/1 M2.5.2 preserved {orphaned} registry-only identity record(s) instead of deleting lifecycle/revocation history automatically.");
            }
        }

        var replayProtectedNamesRestored = 0;
        foreach (var registryEntry in _identityRegistry.GetAll())
        {
            if (registryEntry.LastAcceptedIdentityRevision > 0 &&
                _devices.TryGetValue(registryEntry.DeviceId, out var compatibilityDevice) &&
                !string.Equals(compatibilityDevice.DeviceName, registryEntry.DeviceName, StringComparison.Ordinal))
            {
                _devices[registryEntry.DeviceId] = compatibilityDevice with { DeviceName = registryEntry.DeviceName };
                replayProtectedNamesRestored++;
            }
        }

        if (replayProtectedNamesRestored > 0)
        {
            SaveLocked();
            _log?.Invoke($"GNP/1 M2.5.3 restored {replayProtectedNamesRestored} replay-protected device name(s) from the Trusted Identity Registry.");
        }

        var registryEntries = _identityRegistry.GetAll();
        var active = registryEntries.Count(entry => entry.LifecycleState == TrustedIdentityLifecycleState.Active);
        var retired = registryEntries.Count(entry => entry.LifecycleState == TrustedIdentityLifecycleState.Retired);
        var revoked = registryEntries.Count(entry => entry.LifecycleState == TrustedIdentityLifecycleState.Revoked);
        _log?.Invoke($"GNP/1 M2.5.3 Trusted Identity Registry active: {registryEntries.Length} record(s) · Active {active} · Retired {retired} · Revoked {revoked}.");
    }

    private void TrySynchronizeIdentityRegistry(TrustedDevice device)
    {
        byte[]? pairingPublicKey = null;
        byte[]? signingPublicKey = null;
        try
        {
            pairingPublicKey = device.GetPublicKey();
            TrustedSigningIdentity? signingIdentity = null;
            if (device.SigningIdentityVersion >= DeviceIdentityV2.CurrentVersion &&
                device.SigningKeyGeneration >= 1 &&
                !string.IsNullOrWhiteSpace(device.SigningKeyId) &&
                !string.IsNullOrWhiteSpace(device.SigningPublicKeyBase64) &&
                device.SigningKeyBoundAtUtc is not null)
            {
                signingPublicKey = device.GetSigningPublicKey();
                if (signingPublicKey is not null)
                {
                    signingIdentity = new TrustedSigningIdentity(
                        device.DeviceId,
                        device.SigningIdentityVersion,
                        device.SigningKeyGeneration,
                        signingPublicKey);
                }
            }

            _identityRegistry.SynchronizeTrustedDevice(
                device.DeviceId,
                device.DeviceName,
                pairingPublicKey,
                device.PairedAtUtc,
                device.EndpointVerifiedAtUtc,
                signingIdentity,
                device.SigningKeyBoundAtUtc);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or FormatException or CryptographicException or EncoderFallbackException)
        {
            _log?.Invoke($"GNP/1 M2.4.1 Trusted Identity Registry synchronization failed for {device.DeviceName}; existing M2.3 trust was kept: {ex.Message}");
        }
        finally
        {
            if (signingPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(signingPublicKey);
            }

            if (pairingPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(pairingPublicKey);
            }
        }
    }

    private void TryRecordSigningIdentityRegistry(
        TrustedDevice device,
        TrustedSigningIdentity identity,
        DateTimeOffset verifiedAtUtc,
        SigningIdentityBindingUpdate expectedUpdate)
    {
        byte[]? pairingPublicKey = null;
        try
        {
            pairingPublicKey = device.GetPublicKey();
            var registryUpdate = _identityRegistry.RecordAuthenticatedSigningIdentity(
                device.DeviceId,
                device.DeviceName,
                pairingPublicKey,
                identity,
                verifiedAtUtc);
            if (registryUpdate != expectedUpdate)
            {
                _log?.Invoke($"GNP/1 M2.4.1 registry update classification differed for {device.DeviceName}: M2.4.2={expectedUpdate}, registry={registryUpdate}.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or FormatException or CryptographicException or EncoderFallbackException)
        {
            _log?.Invoke($"GNP/1 M2.4.1 signing identity could not be written to the registry for {device.DeviceName}; existing M2.3 trust was kept: {ex.Message}");
        }
        finally
        {
            if (pairingPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(pairingPublicKey);
            }
        }
    }

    private void TryMarkRegistryAuthenticated(Guid deviceId, DateTimeOffset authenticatedAtUtc)
    {
        try
        {
            _identityRegistry.MarkAuthenticated(deviceId, authenticatedAtUtc);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or EncoderFallbackException)
        {
            _log?.Invoke($"GNP/1 M2.4.1 trusted-session timestamp could not be written to the registry for {deviceId:N}: {ex.Message}");
        }
    }

    private bool TryRemoveIdentityRegistry(Guid deviceId)
    {
        try
        {
            return _identityRegistry.Remove(deviceId);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or EncoderFallbackException)
        {
            _log?.Invoke($"GNP/1 M2.4.1 registry record could not be removed for {deviceId:N}: {ex.Message}");
            return false;
        }
    }

    private bool Load(Action<string>? log)
    {
        if (!File.Exists(_path))
        {
            return true;
        }

        try
        {
            if (new FileInfo(_path).Length > MaxStoreBytes)
            {
                throw new InvalidDataException("Trusted-device database is unexpectedly large.");
            }

            var json = File.ReadAllText(_path);
            var records = JsonSerializer.Deserialize<List<TrustedDevice>>(json) ?? [];
            foreach (var record in records.Take(MaxTrustedDevices))
            {
                if (record.DeviceId == Guid.Empty)
                {
                    continue;
                }

                try
                {
                    ValidateDeviceName(record.DeviceName);
                    ValidateDeviceKind(record.Kind);
                }
                catch (InvalidDataException)
                {
                    continue;
                }

                byte[]? publicKey = null;
                try
                {
                    publicKey = record.GetPublicKey();
                    PairingProtocol.ValidatePublicKey(publicKey);
                    var normalizedSigning = NormalizeStoredSigningIdentity(record, log);
                    _devices[record.DeviceId] = NormalizeStoredEndpoint(normalizedSigning, log);
                }
                catch (Exception ex) when (ex is FormatException or CryptographicException or InvalidDataException)
                {
                    log?.Invoke($"Ignored invalid trusted-device record: {ex.Message}");
                }
                finally
                {
                    if (publicKey is not null)
                    {
                        CryptographicOperations.ZeroMemory(publicKey);
                    }
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or EncoderFallbackException)
        {
            log?.Invoke($"Trusted-device database could not be loaded: {ex.Message}");
            return false;
        }

        return true;
    }

    private static TrustedDevice NormalizeStoredSigningIdentity(TrustedDevice record, Action<string>? log)
    {
        var hasAnySigningData = record.SigningIdentityVersion != 0 ||
                                record.SigningKeyGeneration != 0 ||
                                !string.IsNullOrWhiteSpace(record.SigningKeyId) ||
                                !string.IsNullOrWhiteSpace(record.SigningPublicKeyBase64) ||
                                record.SigningKeyBoundAtUtc is not null;
        if (!hasAnySigningData)
        {
            return record;
        }

        byte[]? signingPublicKey = null;
        try
        {
            if (record.SigningIdentityVersion < DeviceIdentityV2.CurrentVersion ||
                record.SigningKeyGeneration < 1 ||
                string.IsNullOrWhiteSpace(record.SigningKeyId) ||
                string.IsNullOrWhiteSpace(record.SigningPublicKeyBase64) ||
                record.SigningKeyBoundAtUtc is null)
            {
                throw new InvalidDataException("Stored signing-identity binding is incomplete.");
            }

            signingPublicKey = record.GetSigningPublicKey();
            if (signingPublicKey is null)
            {
                throw new InvalidDataException("Stored signing public key is missing.");
            }

            DeviceSignature.ValidatePublicKey(signingPublicKey);
            var derivedKeyId = DeviceSignature.GetSigningKeyId(signingPublicKey);
            if (!string.Equals(derivedKeyId, record.SigningKeyId, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("Stored signing-key fingerprint does not match its public key.");
            }

            return record;
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or InvalidDataException)
        {
            log?.Invoke($"Ignored invalid signing-identity binding for trusted device {record.DeviceName}: {ex.Message}");
            return record with
            {
                SigningIdentityVersion = 0,
                SigningKeyGeneration = 0,
                SigningKeyId = null,
                SigningPublicKeyBase64 = null,
                SigningKeyBoundAtUtc = null
            };
        }
        finally
        {
            if (signingPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(signingPublicKey);
            }
        }
    }

    private static TrustedDevice NormalizeStoredEndpoint(TrustedDevice record, Action<string>? log)
    {
        var hasAnyEndpointData = !string.IsNullOrWhiteSpace(record.LastVerifiedAddress) ||
                                 record.LastVerifiedTransferPort != 0 ||
                                 record.LastVerifiedPairingPort != 0 ||
                                 record.EndpointVerifiedAtUtc is not null;
        if (!hasAnyEndpointData)
        {
            return record;
        }

        var address = record.GetLastVerifiedAddress();
        if (address is not null)
        {
            try
            {
                ValidateEndpoint(address, record.LastVerifiedTransferPort, record.LastVerifiedPairingPort);
                if (record.EndpointVerifiedAtUtc is not null)
                {
                    return record;
                }
            }
            catch (InvalidDataException)
            {
            }
        }

        log?.Invoke($"Ignored invalid persisted endpoint for trusted device {record.DeviceName}; cryptographic trust was kept.");
        return record with
        {
            LastVerifiedAddress = null,
            LastVerifiedTransferPort = 0,
            LastVerifiedPairingPort = 0,
            EndpointVerifiedAtUtc = null
        };
    }

    private void SaveLocked()
    {
        var json = JsonSerializer.Serialize(
            _devices.Values.OrderBy(device => device.DeviceName, StringComparer.OrdinalIgnoreCase),
            IndentedJsonOptions);
        if (StrictUtf8.GetByteCount(json) > MaxStoreBytes)
        {
            throw new InvalidDataException("Trusted-device database unexpectedly exceeds the safe size limit.");
        }

        var tempPath = _path + ".tmp";
        try
        {
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _path, overwrite: true);
        }
        finally
        {
            TryDeleteTempFile(tempPath);
        }
    }

    private static void ValidateDeviceName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) ||
            StrictUtf8.GetByteCount(name) > MaxDeviceNameBytes ||
            name.Any(ch => char.IsControl(ch) || CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.Format))
        {
            throw new InvalidDataException("Trusted device name is invalid.");
        }
    }

    private static void ValidateDeviceKind(DeviceKind deviceKind)
    {
        if (deviceKind is not DeviceKind.Unknown and
            not DeviceKind.WindowsComputer and
            not DeviceKind.AndroidPhone and
            not DeviceKind.AndroidTablet)
        {
            throw new InvalidDataException("Trusted device kind is invalid.");
        }
    }

    private static void ValidateEndpoint(IPAddress address, int transferPort, int pairingPort)
    {
        if (!LocalNetworkPolicy.IsAllowedAddress(address) ||
            transferPort is < 1 or > 65535 ||
            pairingPort is < 1 or > 65535)
        {
            throw new InvalidDataException("Trusted-device endpoint is not a valid local Genia Link endpoint.");
        }
    }

    private static void TryDeleteTempFile(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
