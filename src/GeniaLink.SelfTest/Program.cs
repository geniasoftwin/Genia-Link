using System.IO;
using System.Net;
using System.Threading.Channels;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GeniaLink.Core.Capabilities;
using GeniaLink.Core.Discovery;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Network;
using GeniaLink.Core.Pairing;
using GeniaLink.Core.Security;
using GeniaLink.Core.Transfers;

namespace GeniaLink.SelfTest;

internal static class Program
{
    private static int _failures;

    private static async Task<int> Main()
    {
        Test("Unsafe file names are rejected", TestUnsafeNames);
        Test("Destination stays inside root", TestDestinationPath);
        Test("Protocol v3 offer/resume round-trip", TestProtocolRoundTrip);
        Test("Protected Genia Link folder control messages round-trip", TestRemoteFolderProtocolRoundTrip);
        Test("Remote browser derives folder navigation safely", TestRemoteBrowserIndex);
        Test("Relative transfer paths reject traversal", TestRelativePathSafety);
        Test("Remote Genia Link file paths reject traversal", TestRemoteFilePathSafety);
        Test("Resume keys are deterministic and trust-scoped", TestResumeKeyDeterminism);
        Test("Folder selection preserves safe relative structure", TestTransferSelection);
        Test("Discovery packet round-trip", TestDiscoveryRoundTrip);
        Test("GNP/1 M2.2 signed discovery round-trip verifies", TestSignedDiscoveryRoundTrip);
        Test("GNP/1 M2.2 signed discovery detects tampering", TestSignedDiscoveryTamperDetection);
        Test("GNP/1 M2.5.3 replay-protected signed discovery round-trip verifies", TestReplayProtectedSignedDiscoveryRoundTrip);
        Test("GNP/1 M2.5.3 replay-protected signed discovery detects tampering", TestReplayProtectedSignedDiscoveryTamperDetection);
        Test("GNP/1 M2.6.2 signed capability advertisement round-trip verifies", TestCapabilitySignedDiscoveryRoundTrip);
        Test("GNP/1 M2.6.2 signed capability advertisement detects tampering", TestCapabilitySignedDiscoveryTamperDetection);
        Test("GNP/1 M2.6.2 capability advertisement rejects unknown high bits safely", TestCapabilitySignedDiscoveryRejectsUnknownHighBits);
        Test("GNP/1 M2.5.3 local identity assertion revision advances deterministically", TestIdentityAssertionRevisionStore);
        Test("GNP/1 M2.6.2 local capability assertion revision advances deterministically", TestCapabilityAssertionRevisionStore);
        Test("GNP/1 M2.6.2 role profiles resolve automatically from capabilities", TestDeviceCapabilityProfiles);
        Test("GNP/1 M2.3/M2.4.2 signing-identity binding payload round-trip", TestIdentityBindingProtocolRoundTrip);
        Test("GNP/1 M2.4.2 trusted signing-key rotation chain verifies", TestSigningKeyRotation);
        Test("GNP/1 M2.4.2/M2.5 Trusted Identity Registry continuity, lifecycle and session revocation", TestTrustedIdentityRegistry);
        Test("Device identity contract preserves the installation ID", TestDeviceIdentityContract);
        Test("Device Identity v2 ECDSA signing verifies and detects tampering", TestDeviceIdentityV2Signing);
        Test("Device Identity v2 signing key ID is deterministic", TestDeviceIdentityV2KeyId);
        Test("Local-only network policy rejects public IPs", TestLocalNetworkPolicy);
        Test("Transfer timeouts stay bounded", TestTransferTimeoutPolicy);
        Test("Android raw ECDH + SHA-256 matches .NET DeriveKeyFromHash", TestAndroidCompatibleEcdhKdf);
        await TestAsync("Remote preview stays bounded and rejects binary text", TestRemotePreviewPolicyAsync);
        await TestAsync("Pairing protocol produces matching verification code", TestPairingProtocolAsync);
        await TestAsync("Trusted handshake derives the same session key", TestTrustedHandshakeAsync);
        await TestAsync("Encrypted channel round-trip", TestEncryptedRoundTripAsync);
        await TestAsync("Encrypted channel detects tampering", TestTamperDetectionAsync);
        await TestAsync("Encrypted channel rejects replayed frames", TestReplayDetectionAsync);

        Console.WriteLine();
        Console.WriteLine(_failures == 0
            ? "SELF-TEST PASSED: all security/integrity checks succeeded."
            : $"SELF-TEST FAILED: {_failures} check(s) failed.");
        return _failures == 0 ? 0 : 1;
    }

    private static void TestDeviceCapabilityProfiles()
    {
        var client = DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Client);
        Assert(client.HasFlag(DeviceCapability.TrustedDiscovery), "Client must include Trusted Discovery.");
        Assert(client.HasFlag(DeviceCapability.TrustedTransport), "Client must include Trusted Transport.");
        Assert(client.HasFlag(DeviceCapability.FileTransfer), "Client preset should include File Transfer.");

        var server = DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Server);
        Assert(server.HasFlag(DeviceCapability.BackgroundAvailability), "Server must include Background Availability.");
        Assert(server.HasFlag(DeviceCapability.NetworkEvents), "Server preset should include Network Events.");
        Assert(server.HasFlag(DeviceCapability.Sync), "Server preset should include Sync.");

        var relayNormalized = DeviceCapabilityProfiles.Normalize(DeviceRoleProfile.Relay, DeviceCapability.None);
        Assert(relayNormalized.HasFlag(DeviceCapability.TrustedDiscovery), "Relay normalization must restore core discovery.");
        Assert(relayNormalized.HasFlag(DeviceCapability.TrustedTransport), "Relay normalization must restore core transport.");
        Assert(relayNormalized.HasFlag(DeviceCapability.BackgroundAvailability), "Relay must require Background Availability.");
        Assert(relayNormalized.HasFlag(DeviceCapability.Relay), "Relay role must require Relay capability.");

        var unknown = (DeviceCapability)(1 << 30);
        var customNormalized = DeviceCapabilityProfiles.Normalize(DeviceRoleProfile.Custom, unknown);
        Assert((customNormalized & unknown) == DeviceCapability.None, "Unknown capability bits must be stripped.");
        Assert(customNormalized.HasFlag(DeviceCapability.TrustedDiscovery), "Custom profile must retain core discovery.");
        Assert(customNormalized.HasFlag(DeviceCapability.TrustedTransport), "Custom profile must retain core transport.");

        Assert(DeviceCapabilityProfiles.ResolveProfile(client) == DeviceRoleProfile.Client, "Exact Client capability set must resolve to Client.");
        Assert(DeviceCapabilityProfiles.ResolveProfile(server) == DeviceRoleProfile.Server, "Exact Server capability set must resolve to Server.");
        Assert(DeviceCapabilityProfiles.ResolveProfile(DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Relay)) == DeviceRoleProfile.Relay, "Exact Relay capability set must resolve to Relay.");
        Assert(DeviceCapabilityProfiles.ResolveProfile(DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Backup)) == DeviceRoleProfile.Backup, "Exact Backup capability set must resolve to Backup.");
        var customSet = client | DeviceCapability.Messaging;
        Assert(DeviceCapabilityProfiles.ResolveProfile(customSet) == DeviceRoleProfile.Custom, "A non-preset capability combination must resolve to Custom.");
        Assert(!DeviceCapabilityProfiles.IsValidAdvertisement(DeviceCapability.FileTransfer), "Capability advertisement without trusted core requirements must be rejected.");
    }

    private static void TestIdentityBindingProtocolRoundTrip()
    {
        using var identity = new SelfTestSigningIdentity(
            Guid.Parse("80e0a2aa-3b41-49b6-86a7-0041a0acba99"),
            "GENIA-M23-TEST",
            DeviceKind.WindowsComputer);
        var packet = IdentityBindingProtocol.CreateIdentity(identity);
        TrustedSigningIdentity? parsed = null;
        try
        {
            parsed = IdentityBindingProtocol.ParseIdentity(packet);
            Assert(parsed.DeviceId == identity.DeviceId, "Identity binding device ID mismatch.");
            Assert(parsed.IdentityVersion == identity.IdentityVersion, "Identity binding version mismatch.");
            Assert(parsed.KeyGeneration == identity.KeyGeneration, "Identity binding key generation mismatch.");
            Assert(parsed.SigningKeyId == identity.SigningKeyId, "Identity binding signing key mismatch.");

            var malformed = packet.ToArray();
            System.Buffers.Binary.BinaryPrimitives.WriteInt32BigEndian(malformed.AsSpan(32, 4), int.MaxValue);
            var rejected = false;
            try
            {
                _ = IdentityBindingProtocol.ParseIdentity(malformed);
            }
            catch (InvalidDataException)
            {
                rejected = true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(malformed);
            }

            Assert(rejected, "Identity binding must reject an invalid public-key length.");
        }
        finally
        {
            if (parsed is not null)
            {
                CryptographicOperations.ZeroMemory(parsed.SigningPublicKey);
            }

            CryptographicOperations.ZeroMemory(packet);
        }
    }

    private static void TestSigningKeyRotation()
    {
        var deviceId = Guid.Parse("2cf9a60a-60a5-4d55-a266-2fe5da2bf86a");
        using var generation1 = new SelfTestSigningIdentity(deviceId, "GENIA-M242-TEST", DeviceKind.WindowsComputer);
        using var generation2 = generation1.Rotate();
        using var generation3 = generation2.Rotate();
        var trustedPublicKey = generation1.ExportSigningPublicKey();
        TrustedSigningIdentity? proposed = null;
        TrustedSigningIdentity? parsed = null;
        byte[]? packet = null;
        try
        {
            proposed = generation3.ToTrustedSigningIdentity();
            SigningKeyRotation.ValidateTrustedTransition(
                deviceId,
                DeviceIdentityV2.CurrentVersion,
                1,
                trustedPublicKey,
                proposed);
            Assert(proposed.RotationChain is { Length: 2 }, "A peer that missed one generation must receive the complete 1->2->3 continuity chain.");

            packet = IdentityBindingProtocol.CreateIdentity(generation3);
            Assert(packet.AsSpan(0, 4).SequenceEqual("GLI2"u8), "A rotated identity must use the M2.4.2 rotation-aware binding envelope.");
            parsed = IdentityBindingProtocol.ParseIdentity(packet);
            Assert(parsed.KeyGeneration == 3, "Rotation-aware identity binding must preserve the current generation.");
            Assert(parsed.RotationChain is { Length: 2 }, "Rotation-aware identity binding must preserve the certificate chain.");
            SigningKeyRotation.ValidateTrustedTransition(
                deviceId,
                DeviceIdentityV2.CurrentVersion,
                1,
                trustedPublicKey,
                parsed);

            using var unprovenKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var unprovenPublicKey = unprovenKey.ExportSubjectPublicKeyInfo();
            try
            {
                var unproven = new TrustedSigningIdentity(
                    deviceId,
                    DeviceIdentityV2.CurrentVersion,
                    2,
                    unprovenPublicKey);
                var rejected = false;
                try
                {
                    SigningKeyRotation.ValidateTrustedTransition(
                        deviceId,
                        DeviceIdentityV2.CurrentVersion,
                        1,
                        trustedPublicKey,
                        unproven);
                }
                catch (InvalidDataException)
                {
                    rejected = true;
                }

                Assert(rejected, "A higher signing-key generation without the previous-key continuity certificate must be rejected.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(unprovenPublicKey);
            }

            var tamperedChain = generation3.ExportSigningKeyRotationChain();
            try
            {
                tamperedChain[0].PreviousKeySignature[^1] ^= 0x01;
                var tamperedPublicKey = generation3.ExportSigningPublicKey();
                try
                {
                    var tampered = new TrustedSigningIdentity(
                        deviceId,
                        DeviceIdentityV2.CurrentVersion,
                        3,
                        tamperedPublicKey,
                        tamperedChain);
                    var rejected = false;
                    try
                    {
                        tampered.Validate();
                    }
                    catch (CryptographicException)
                    {
                        rejected = true;
                    }

                    Assert(rejected, "Tampering with a rotation certificate signature must invalidate the whole presentation.");
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(tamperedPublicKey);
                }
            }
            finally
            {
                foreach (var certificate in tamperedChain)
                {
                    CryptographicOperations.ZeroMemory(certificate.PreviousSigningPublicKey);
                    CryptographicOperations.ZeroMemory(certificate.NewSigningPublicKey);
                    CryptographicOperations.ZeroMemory(certificate.PreviousKeySignature);
                }
            }
        }
        finally
        {
            if (packet is not null)
            {
                CryptographicOperations.ZeroMemory(packet);
            }

            if (parsed is not null)
            {
                ZeroTrustedSigningIdentity(parsed);
            }

            if (proposed is not null)
            {
                ZeroTrustedSigningIdentity(proposed);
            }

            CryptographicOperations.ZeroMemory(trustedPublicKey);
        }
    }

    private static void TestTrustedIdentityRegistry()
    {
        var root = Path.Combine(Path.GetTempPath(), "GeniaLinkRegistrySelfTest", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "trusted-identities.json");
        var deviceId = Guid.Parse("4c07a1e2-d917-4ad5-bbad-dcf0f65e2c51");
        var pairedAtUtc = new DateTimeOffset(2026, 9, 1, 10, 0, 0, TimeSpan.Zero);
        var firstVerifiedAtUtc = pairedAtUtc.AddMinutes(1);
        byte[]? pairingPublicKey = null;
        byte[]? rotatedPairingPublicKey = null;
        TrustedSigningIdentity? identity1 = null;
        TrustedSigningIdentity? identity2 = null;
        try
        {
            using var pairingKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            using var rotatedPairingKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            using var generation1 = new SelfTestSigningIdentity(deviceId, "GENIA-M242-TEST", DeviceKind.WindowsComputer);
            using var generation2 = generation1.Rotate();
            pairingPublicKey = pairingKey.ExportSubjectPublicKeyInfo();
            rotatedPairingPublicKey = rotatedPairingKey.ExportSubjectPublicKeyInfo();
            identity1 = generation1.ToTrustedSigningIdentity();

            var legacyV1Path = Path.Combine(root, "trusted-identities-v1.json");
            var legacyV1Json = JsonSerializer.Serialize(new
            {
                SchemaVersion = 1,
                UpdatedAtUtc = firstVerifiedAtUtc,
                Identities = new[]
                {
                    new
                    {
                        DeviceId = deviceId,
                        DeviceName = "GENIA-M242-TEST",
                        PairingKeyId = TrustedIdentityRegistry.GetPairingKeyId(pairingPublicKey),
                        FirstTrustedAtUtc = pairedAtUtc,
                        LastAuthenticatedAtUtc = firstVerifiedAtUtc,
                        State = 1,
                        CurrentSigningIdentityVersion = DeviceIdentityV2.CurrentVersion,
                        CurrentSigningKeyGeneration = 1,
                        CurrentSigningKeyId = identity1.SigningKeyId,
                        CurrentSigningPublicKeyBase64 = Convert.ToBase64String(identity1.SigningPublicKey),
                        CurrentSigningKeyBoundAtUtc = firstVerifiedAtUtc,
                        CurrentSigningKeyLastVerifiedAtUtc = firstVerifiedAtUtc,
                        SigningKeyHistory = Array.Empty<object>()
                    }
                }
            });
            File.WriteAllText(legacyV1Path, legacyV1Json);
            var migratedV1Registry = new TrustedIdentityRegistry(legacyV1Path);
            var migratedV1 = migratedV1Registry.Get(deviceId) ?? throw new InvalidDataException("Schema-v1 registry migration record is missing.");
            Assert(migratedV1.LifecycleState == TrustedIdentityLifecycleState.Active, "Schema-v1 trusted identity must migrate to Active lifecycle without repeat pairing.");
            Assert(migratedV1.CurrentSigningKeyId == identity1.SigningKeyId, "Schema-v1 migration must preserve the pinned signing key.");
            Assert((migratedV1.IdentityHistory ?? []).Any(entry => entry.EventType == TrustedIdentityHistoryEventType.Trusted), "Schema-v1 migration must seed bounded identity history.");
            Assert(migratedV1.VerifiedCapabilities == DeviceCapability.None && migratedV1.LastAcceptedCapabilityRevision == 0, "Pre-M2.6.2 registry migration must start with no authenticated capability assertion.");

            var legacyRevokedPath = Path.Combine(root, "trusted-identities-v1-revoked.json");
            var legacyRevokedJson = legacyV1Json.Replace("\"State\":1", "\"State\":3", StringComparison.Ordinal);
            File.WriteAllText(legacyRevokedPath, legacyRevokedJson);
            var migratedRevokedRegistry = new TrustedIdentityRegistry(legacyRevokedPath);
            var migratedRevoked = migratedRevokedRegistry.Get(deviceId) ?? throw new InvalidDataException("Schema-v1 revoked registry migration record is missing.");
            Assert(migratedRevoked.LifecycleState == TrustedIdentityLifecycleState.Revoked, "Legacy RegistryState.Revoked must migrate to terminal lifecycle Revoked.");
            Assert(!migratedRevokedRegistry.IsActiveTrusted(deviceId), "Migrated legacy revocation must remain fail-closed.");

            var registry = new TrustedIdentityRegistry(path);
            registry.SynchronizeTrustedDevice(
                deviceId,
                "GENIA-M242-TEST",
                pairingPublicKey,
                pairedAtUtc,
                firstVerifiedAtUtc,
                identity1,
                firstVerifiedAtUtc);

            var migrated = registry.Get(deviceId) ?? throw new InvalidDataException("Migrated registry record is missing.");
            Assert(migrated.DeviceId == deviceId, "Registry migration must preserve Device ID.");
            Assert(migrated.PairingKeyId == TrustedIdentityRegistry.GetPairingKeyId(pairingPublicKey), "Registry migration must pin the paired ECDH public key.");
            Assert(migrated.CurrentSigningKeyId == identity1.SigningKeyId, "Registry migration must import the authenticated M2.3 signing key.");
            Assert(migrated.CurrentSigningKeyGeneration == 1, "Registry migration must preserve signing-key generation.");
            Assert(File.Exists(path), "Registry migration must persist trusted-identities.json.");

            var reloaded = new TrustedIdentityRegistry(path);
            var persisted = reloaded.Get(deviceId) ?? throw new InvalidDataException("Reloaded registry record is missing.");
            Assert(persisted.CurrentSigningKeyId == identity1.SigningKeyId, "Registry signing identity must survive restart.");
            Assert(persisted.SigningKeyHistory is { Length: 0 }, "Initial signing identity must not create false history.");
            Assert(persisted.LifecycleState == TrustedIdentityLifecycleState.Active, "Migrated trusted identity must start Active.");
            Assert(reloaded.IsActiveTrusted(deviceId), "Active trusted identity must be usable.");
            Assert(persisted.IdentityHistory is { Length: >= 1 }, "M2.5.2 registry must retain identity history.");
            Assert(!string.IsNullOrWhiteSpace(persisted.TrustRelationshipId) && persisted.TrustRelationshipId.Length == 32, "M2.5.2.1 registry must assign a trust relationship ID.");
            var initialTrustRelationshipId = persisted.TrustRelationshipId;
            var initialAuthorization = reloaded.GetSessionAuthorization(deviceId)
                ?? throw new InvalidDataException("Active identity is missing session authorization.");
            Assert(initialAuthorization.TrustRelationshipId == initialTrustRelationshipId, "Session authorization must bind to the current trust relationship.");
            Assert(!initialAuthorization.LifetimeToken.IsCancellationRequested, "Active trust session lifetime must start valid.");

            var renameAtUtc = firstVerifiedAtUtc.AddSeconds(5);
            var renamed = reloaded.RecordAuthenticatedDeviceName(
                deviceId,
                "GENIABOOK",
                pairingPublicKey,
                DeviceIdentityV2.CurrentVersion,
                1,
                identity1.SigningKeyId,
                10,
                renameAtUtc);
            Assert(renamed, "M2.5 authenticated rename must report a persisted name change.");

            var afterRename = reloaded.Get(deviceId) ?? throw new InvalidDataException("Renamed registry record is missing.");
            Assert(afterRename.DeviceName == "GENIABOOK", "Authenticated rename must persist the new device name.");
            Assert(afterRename.DeviceId == persisted.DeviceId, "Authenticated rename must preserve Device ID.");
            Assert(afterRename.PairingKeyId == persisted.PairingKeyId, "Authenticated rename must preserve the pairing trust anchor.");
            Assert(afterRename.CurrentSigningKeyId == persisted.CurrentSigningKeyId, "Authenticated rename must preserve the signing key ID.");
            Assert(afterRename.CurrentSigningKeyGeneration == persisted.CurrentSigningKeyGeneration, "Authenticated rename must preserve signing-key generation.");
            Assert(afterRename.FirstTrustedAtUtc == persisted.FirstTrustedAtUtc, "Authenticated rename must preserve the original trust timestamp.");
            Assert(afterRename.SigningKeyHistory is { Length: 0 }, "Authenticated rename must not create signing-key history.");
            Assert(afterRename.TrustRelationshipId == initialTrustRelationshipId, "Authenticated rename must preserve the trust relationship ID.");
            Assert(afterRename.LastAcceptedIdentityRevision == 10, "Replay-protected rename must persist the accepted identity revision.");
            Assert((afterRename.IdentityHistory ?? []).Any(entry =>
                entry.EventType == TrustedIdentityHistoryEventType.AuthenticatedRename &&
                entry.PreviousDeviceName == "GENIA-M242-TEST" &&
                entry.DeviceName == "GENIABOOK" &&
                entry.IdentityRevision == 10), "Authenticated rename must append identity history with its signed identity revision.");

            var replayRollbackRejected = false;
            try
            {
                _ = reloaded.RecordAuthenticatedDeviceName(
                    deviceId,
                    "GENIA-M242-TEST",
                    pairingPublicKey,
                    DeviceIdentityV2.CurrentVersion,
                    1,
                    identity1.SigningKeyId,
                    9,
                    renameAtUtc.AddMilliseconds(100));
            }
            catch (InvalidDataException)
            {
                replayRollbackRejected = true;
            }

            Assert(replayRollbackRejected, "A lower signed identity revision must not replay an old device name.");

            var sameRevisionConflictRejected = false;
            try
            {
                _ = reloaded.RecordAuthenticatedDeviceName(
                    deviceId,
                    "CONFLICTING-NAME",
                    pairingPublicKey,
                    DeviceIdentityV2.CurrentVersion,
                    1,
                    identity1.SigningKeyId,
                    10,
                    renameAtUtc.AddMilliseconds(200));
            }
            catch (InvalidDataException)
            {
                sameRevisionConflictRejected = true;
            }

            Assert(sameRevisionConflictRejected, "A conflicting name at an already accepted identity revision must be rejected.");
            Assert((reloaded.Get(deviceId) ?? throw new InvalidDataException("Registry record disappeared after replay rejection.")).DeviceName == "GENIABOOK", "Replay rejection must preserve the newest trusted name.");

            var wrongRenamePairingAnchorRejected = false;
            try
            {
                _ = reloaded.RecordAuthenticatedDeviceName(
                    deviceId,
                    "ATTACKER-NAME",
                    rotatedPairingPublicKey,
                    DeviceIdentityV2.CurrentVersion,
                    1,
                    identity1.SigningKeyId,
                    11,
                    renameAtUtc.AddMilliseconds(500));
            }
            catch (InvalidDataException)
            {
                wrongRenamePairingAnchorRejected = true;
            }

            Assert(wrongRenamePairingAnchorRejected, "Authenticated rename must reject a mismatched pairing trust anchor.");

            var wrongRenameKeyRejected = false;
            try
            {
                _ = reloaded.RecordAuthenticatedDeviceName(
                    deviceId,
                    "ATTACKER-NAME",
                    pairingPublicKey,
                    DeviceIdentityV2.CurrentVersion,
                    1,
                    new string('0', 64),
                    11,
                    renameAtUtc.AddSeconds(1));
            }
            catch (InvalidDataException)
            {
                wrongRenameKeyRejected = true;
            }

            Assert(wrongRenameKeyRejected, "Authenticated rename must reject a name signed by a non-trusted signing identity.");
            Assert((reloaded.Get(deviceId) ?? throw new InvalidDataException("Registry record disappeared after rejected rename.")).DeviceName == "GENIABOOK", "Rejected rename must not change the trusted name.");

            var clientCapabilities = DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Client);
            var capabilitiesAtUtc = renameAtUtc.AddSeconds(2);
            Assert(reloaded.RecordAuthenticatedCapabilities(
                deviceId,
                pairingPublicKey,
                DeviceIdentityV2.CurrentVersion,
                1,
                identity1.SigningKeyId,
                clientCapabilities,
                100,
                capabilitiesAtUtc), "M2.6.2 authenticated capability state must be persisted for a trusted signing identity.");
            var afterCapabilities = reloaded.Get(deviceId) ?? throw new InvalidDataException("Capability registry record is missing.");
            Assert(afterCapabilities.VerifiedCapabilities == clientCapabilities, "Trusted registry must retain authenticated capabilities.");
            Assert(afterCapabilities.LastAcceptedCapabilityRevision == 100, "Trusted registry must retain the accepted capability revision.");
            Assert(afterCapabilities.CapabilitiesLastVerifiedAtUtc is not null, "Trusted registry must retain capability verification time.");

            var capabilityRollbackRejected = false;
            try
            {
                _ = reloaded.RecordAuthenticatedCapabilities(
                    deviceId,
                    pairingPublicKey,
                    DeviceIdentityV2.CurrentVersion,
                    1,
                    identity1.SigningKeyId,
                    clientCapabilities,
                    99,
                    capabilitiesAtUtc.AddMilliseconds(100));
            }
            catch (InvalidDataException)
            {
                capabilityRollbackRejected = true;
            }

            Assert(capabilityRollbackRejected, "A lower authenticated capability revision must be rejected as replay.");

            var capabilityConflictRejected = false;
            try
            {
                _ = reloaded.RecordAuthenticatedCapabilities(
                    deviceId,
                    pairingPublicKey,
                    DeviceIdentityV2.CurrentVersion,
                    1,
                    identity1.SigningKeyId,
                    DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Server),
                    100,
                    capabilitiesAtUtc.AddMilliseconds(200));
            }
            catch (InvalidDataException)
            {
                capabilityConflictRejected = true;
            }

            Assert(capabilityConflictRejected, "A different capability set at the same authenticated revision must be rejected.");

            var wrongCapabilityKeyRejected = false;
            try
            {
                _ = reloaded.RecordAuthenticatedCapabilities(
                    deviceId,
                    pairingPublicKey,
                    DeviceIdentityV2.CurrentVersion,
                    1,
                    new string('0', 64),
                    clientCapabilities,
                    101,
                    capabilitiesAtUtc.AddMilliseconds(300));
            }
            catch (InvalidDataException)
            {
                wrongCapabilityKeyRejected = true;
            }

            Assert(wrongCapabilityKeyRejected, "Authenticated capabilities must reject a non-trusted signing identity.");

            var sameKeyInflationRejected = false;
            try
            {
                var inflated = new TrustedSigningIdentity(
                    deviceId,
                    DeviceIdentityV2.CurrentVersion,
                    2,
                    identity1.SigningPublicKey);
                _ = reloaded.RecordAuthenticatedSigningIdentity(
                    deviceId,
                    "GENIABOOK",
                    pairingPublicKey,
                    inflated,
                    firstVerifiedAtUtc.AddSeconds(10));
            }
            catch (InvalidDataException)
            {
                sameKeyInflationRejected = true;
            }

            Assert(sameKeyInflationRejected, "Registry must reject a generation increase that reuses the same signing key.");

            var sharedTimestamp = firstVerifiedAtUtc.AddSeconds(30);
            registry.MarkAuthenticated(deviceId, sharedTimestamp);
            var sharedView = reloaded.Get(deviceId) ?? throw new InvalidDataException("Shared registry view is missing.");
            Assert(sharedView.LastAuthenticatedAtUtc == sharedTimestamp, "Registry instances for one app-data path must share in-process state.");

            identity2 = generation2.ToTrustedSigningIdentity();
            var rotated = reloaded.RecordAuthenticatedSigningIdentity(
                deviceId,
                "GENIABOOK",
                pairingPublicKey,
                identity2,
                firstVerifiedAtUtc.AddMinutes(1));
            Assert(rotated == SigningIdentityBindingUpdate.Rotated, "A higher signing generation with valid continuity proof must be recorded as rotation.");

            var afterRotation = reloaded.Get(deviceId) ?? throw new InvalidDataException("Rotated registry record is missing.");
            Assert(afterRotation.CurrentSigningKeyId == identity2.SigningKeyId, "Registry rotation must promote the continuity-proven signing key.");
            Assert(afterRotation.CurrentSigningKeyGeneration == 2, "Registry rotation must promote the higher generation.");
            Assert(afterRotation.VerifiedCapabilities == DeviceCapability.None && afterRotation.LastAcceptedCapabilityRevision == 0, "Signing-key rotation must clear capability state until the new key authenticates it again.");
            var rotationHistory = afterRotation.SigningKeyHistory ?? [];
            Assert(rotationHistory.Length == 1, "Registry rotation must retain exactly one retired signing key in history.");
            Assert(rotationHistory[0].SigningKeyId == identity1.SigningKeyId, "Registry history must retain the previous trusted signing key.");
            Assert((afterRotation.IdentityHistory ?? []).Any(entry =>
                entry.EventType == TrustedIdentityHistoryEventType.SigningKeyRotated &&
                entry.SigningKeyId == identity2.SigningKeyId &&
                entry.SigningKeyGeneration == 2), "Signing-key rotation must append identity history.");

            var rollbackRejected = false;
            try
            {
                _ = reloaded.RecordAuthenticatedSigningIdentity(
                    deviceId,
                    "GENIABOOK",
                    pairingPublicKey,
                    identity1,
                    firstVerifiedAtUtc.AddMinutes(1).AddSeconds(10));
            }
            catch (InvalidDataException)
            {
                rollbackRejected = true;
            }

            Assert(rollbackRejected, "Registry must reject rollback to a retired signing key generation.");

            using var unprovenSigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var unprovenPublicKey = unprovenSigningKey.ExportSubjectPublicKeyInfo();
            try
            {
                var unprovenIdentity = new TrustedSigningIdentity(deviceId, DeviceIdentityV2.CurrentVersion, 3, unprovenPublicKey);
                var unprovenRejected = false;
                try
                {
                    _ = reloaded.RecordAuthenticatedSigningIdentity(
                        deviceId,
                        "GENIABOOK",
                        pairingPublicKey,
                        unprovenIdentity,
                        firstVerifiedAtUtc.AddMinutes(2));
                }
                catch (InvalidDataException)
                {
                    unprovenRejected = true;
                }

                Assert(unprovenRejected, "Registry must reject a newer signing key that lacks previous-key continuity proof.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(unprovenPublicKey);
            }

            var retiredAtUtc = firstVerifiedAtUtc.AddMinutes(2).AddSeconds(10);
            Assert(reloaded.SetLifecycleState(deviceId, TrustedIdentityLifecycleState.Retired, retiredAtUtc, "Self-test retirement."), "Active identity must transition to Retired.");
            var retiredRecord = reloaded.Get(deviceId) ?? throw new InvalidDataException("Retired registry record is missing.");
            Assert(retiredRecord.LifecycleState == TrustedIdentityLifecycleState.Retired, "Retired state must persist in the registry.");
            Assert(!reloaded.IsActiveTrusted(deviceId), "Retired identity must not be usable as active trust.");
            Assert(reloaded.GetSessionAuthorization(deviceId) is null, "Retired identity must not authorize a new trusted session.");
            Assert(!initialAuthorization.LifetimeToken.IsCancellationRequested, "Retiring an identity must not forcibly cancel a session that was already authenticated.");

            var retiredRenameRejected = false;
            try
            {
                _ = reloaded.RecordAuthenticatedDeviceName(
                    deviceId,
                    "SHOULD-NOT-RENAME",
                    pairingPublicKey,
                    DeviceIdentityV2.CurrentVersion,
                    2,
                    identity2.SigningKeyId,
                    12,
                    retiredAtUtc.AddSeconds(1));
            }
            catch (InvalidDataException)
            {
                retiredRenameRejected = true;
            }

            Assert(retiredRenameRejected, "Retired identity must reject authenticated rename propagation.");
            reloaded.SynchronizeTrustedDevice(
                deviceId,
                "STALE-LOCAL-NAME",
                pairingPublicKey,
                retiredAtUtc.AddSeconds(2),
                retiredAtUtc.AddSeconds(2),
                identity2,
                retiredAtUtc.AddSeconds(2));
            var stillRetired = reloaded.Get(deviceId) ?? throw new InvalidDataException("Retired registry record disappeared after synchronization.");
            Assert(stillRetired.LifecycleState == TrustedIdentityLifecycleState.Retired, "Startup synchronization must not reactivate Retired identity.");
            Assert(stillRetired.DeviceName == "GENIABOOK", "Startup synchronization must not rename a Retired identity.");

            var reactivatedAtUtc = retiredAtUtc.AddSeconds(10);
            Assert(reloaded.SetLifecycleState(deviceId, TrustedIdentityLifecycleState.Active, reactivatedAtUtc, "Self-test reactivation."), "Retired identity must support explicit reactivation.");
            Assert(reloaded.IsActiveTrusted(deviceId), "Explicitly reactivated identity must become usable again.");
            var reactivatedAuthorization = reloaded.GetSessionAuthorization(deviceId)
                ?? throw new InvalidDataException("Reactivated identity is missing session authorization.");
            Assert(reactivatedAuthorization.TrustRelationshipId == initialTrustRelationshipId, "Retired -> Active must preserve the same trust relationship.");
            Assert(!reactivatedAuthorization.LifetimeToken.IsCancellationRequested, "Retired -> Active must preserve a valid session lifetime.");
            var lifecycleHistory = (reloaded.Get(deviceId) ?? throw new InvalidDataException("Reactivated identity is missing.")).IdentityHistory ?? [];
            Assert(lifecycleHistory.Count(entry => entry.EventType == TrustedIdentityHistoryEventType.LifecycleChanged) >= 2, "Retire/reactivate transitions must be retained in identity history.");

            reloaded.MarkAuthenticated(deviceId, firstVerifiedAtUtc.AddMinutes(3));
            Assert(File.Exists(path + ".bak"), "Registry atomic updates must retain a backup file.");
            File.WriteAllText(path, "{corrupted-registry");
            var recovered = new TrustedIdentityRegistry(path);
            var recoveredRecord = recovered.Get(deviceId) ?? throw new InvalidDataException("Registry backup recovery did not restore the trusted identity.");
            Assert(recoveredRecord.CurrentSigningKeyId == identity2.SigningKeyId, "Registry backup recovery must restore the last complete signing identity.");
            Assert(recoveredRecord.SigningKeyHistory is { Length: 1 }, "Registry backup recovery must preserve signing-key history.");

            var preReplacementAuthorization = recovered.GetSessionAuthorization(deviceId)
                ?? throw new InvalidDataException("Recovered identity is missing session authorization before pairing replacement.");
            recovered.SynchronizeTrustedDevice(
                deviceId,
                "GENIABOOK",
                rotatedPairingPublicKey,
                firstVerifiedAtUtc.AddMinutes(4));
            var rebound = recovered.Get(deviceId) ?? throw new InvalidDataException("Re-paired registry record is missing.");
            Assert(rebound.PairingKeyId == TrustedIdentityRegistry.GetPairingKeyId(rotatedPairingPublicKey), "Explicit pairing trust change must replace the registry pairing anchor.");
            Assert(string.IsNullOrWhiteSpace(rebound.CurrentSigningKeyId), "Changing the paired ECDH trust anchor must clear the previous signing binding.");
            Assert(rebound.SigningKeyHistory is { Length: 0 }, "Changing the paired ECDH trust anchor must clear previous signing-key history.");
            Assert(rebound.VerifiedCapabilities == DeviceCapability.None && rebound.LastAcceptedCapabilityRevision == 0, "Changing the paired ECDH trust anchor must clear authenticated capability state.");
            Assert((rebound.IdentityHistory ?? []).Any(entry => entry.EventType == TrustedIdentityHistoryEventType.PairingTrustReplaced), "Pairing trust replacement must be retained in identity history.");
            Assert(rebound.TrustRelationshipId != initialTrustRelationshipId, "Pairing trust replacement must create a new trust relationship ID.");
            Assert(preReplacementAuthorization.LifetimeToken.IsCancellationRequested, "Pairing trust replacement must cancel sessions authorized by the prior trust relationship.");
            var reboundAuthorization = recovered.GetSessionAuthorization(deviceId)
                ?? throw new InvalidDataException("Re-paired identity is missing fresh session authorization.");
            Assert(reboundAuthorization.TrustRelationshipId == rebound.TrustRelationshipId, "Fresh session authorization must use the replacement trust relationship ID.");
            Assert(!reboundAuthorization.LifetimeToken.IsCancellationRequested, "Replacement trust relationship must have a fresh valid session lifetime.");

            var revokedAtUtc = firstVerifiedAtUtc.AddMinutes(5);
            Assert(recovered.SetLifecycleState(deviceId, TrustedIdentityLifecycleState.Revoked, revokedAtUtc, "Self-test revocation."), "Active identity must support explicit revocation.");
            Assert(!recovered.IsActiveTrusted(deviceId), "Revoked identity must fail closed for trusted use.");
            Assert(reboundAuthorization.LifetimeToken.IsCancellationRequested, "Revocation must immediately cancel active session authorization.");
            Assert(recovered.GetSessionAuthorization(deviceId) is null, "Revoked identity must not authorize any new session.");

            var revokedReactivationRejected = false;
            try
            {
                _ = recovered.SetLifecycleState(deviceId, TrustedIdentityLifecycleState.Active, revokedAtUtc.AddSeconds(1), "Should fail.");
            }
            catch (InvalidDataException)
            {
                revokedReactivationRejected = true;
            }

            Assert(revokedReactivationRejected, "Revoked identity must be terminal until explicit forget/new SAS pairing.");

            var revokedPairingReplacementRejected = false;
            try
            {
                recovered.SynchronizeTrustedDevice(
                    deviceId,
                    "REVOKED-REPAIR",
                    pairingPublicKey,
                    revokedAtUtc.AddSeconds(2));
            }
            catch (InvalidDataException)
            {
                revokedPairingReplacementRejected = true;
            }

            Assert(revokedPairingReplacementRejected, "Revoked identity must reject pairing-anchor replacement without explicit forget.");
            var revokedRecord = recovered.Get(deviceId) ?? throw new InvalidDataException("Revoked registry record is missing.");
            Assert(revokedRecord.LifecycleState == TrustedIdentityLifecycleState.Revoked, "Revocation must persist in the registry.");
            Assert((revokedRecord.IdentityHistory ?? []).Any(entry =>
                entry.EventType == TrustedIdentityHistoryEventType.LifecycleChanged &&
                entry.LifecycleState == TrustedIdentityLifecycleState.Revoked), "Revocation must be retained in identity history.");
            var revokedTrustRelationshipId = revokedRecord.TrustRelationshipId;
            Assert(recovered.Remove(deviceId), "Explicit Forget must remove the revoked trust relationship.");
            recovered.SynchronizeTrustedDevice(
                deviceId,
                "GENIABOOK",
                rotatedPairingPublicKey,
                revokedAtUtc.AddMinutes(1));
            var repairedAfterForget = recovered.Get(deviceId) ?? throw new InvalidDataException("Fresh pairing after Forget is missing.");
            Assert(repairedAfterForget.LifecycleState == TrustedIdentityLifecycleState.Active, "Fresh SAS pairing after Forget must create an Active identity.");
            Assert(repairedAfterForget.TrustRelationshipId != revokedTrustRelationshipId, "Fresh SAS pairing after Forget must not inherit the revoked trust relationship ID.");
        }
        finally
        {
            if (identity2 is not null)
            {
                ZeroTrustedSigningIdentity(identity2);
            }

            if (identity1 is not null)
            {
                ZeroTrustedSigningIdentity(identity1);
            }

            if (rotatedPairingPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(rotatedPairingPublicKey);
            }

            if (pairingPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(pairingPublicKey);
            }

            Directory.Delete(root, recursive: true);
        }
    }

    private static void TestDeviceIdentityContract()
    {
        var expectedId = Guid.Parse("7f1ea2a7-e7d5-4ad6-a08a-b9d22eea9f01");
#pragma warning disable CA1859 // Intentional interface-typed variable validates the shared GNP/1 M1 identity contract.
        IDeviceIdentity identity = new SelfTestDeviceIdentity(expectedId, "GENIA-TEST");
#pragma warning restore CA1859

        Assert(identity.DeviceId == expectedId, "Device identity must expose the persistent installation ID unchanged.");
        Assert(identity.DeviceId != Guid.Empty, "Device identity must never expose an empty installation ID.");
        Assert(identity.DeviceName == "GENIA-TEST", "Device identity must expose the current safe device name.");

        var peer = identity.ToPairingPeerInfo();
        Assert(peer.DeviceId == identity.DeviceId, "Pairing identity must use the same DeviceId as the local identity contract.");
        Assert(peer.DeviceName == identity.DeviceName, "Pairing identity must use the same device name as the local identity contract.");
    }

    private static void TestDeviceIdentityV2Signing()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        var payload = "GNP/1-M2-self-test"u8.ToArray();
        var tampered = payload.ToArray();
        tampered[^1] ^= 0x01;
        var signature = ecdsa.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);

        try
        {
            Assert(DeviceSignature.Verify(publicKey, payload, signature), "A valid ECDSA P-256 signature must verify.");
            Assert(!DeviceSignature.Verify(publicKey, tampered, signature), "Changing one payload byte must invalidate the signature.");

            var identity = new DeviceIdentityV2(
                Guid.Parse("f238184f-7038-4a8c-86fb-d3635707c326"),
                "GENIA-M2-TEST",
                DeviceKind.WindowsComputer,
                1,
                new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero),
                publicKey);
            Assert(identity.IdentityVersion == 2, "Device Identity v2 must report version 2.");
            Assert(identity.KeyGeneration == 1, "Initial signing key generation must be 1.");
            Assert(identity.SigningKeyId == DeviceSignature.GetSigningKeyId(publicKey), "Identity snapshot must bind SigningKeyId to the public signing key.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
            CryptographicOperations.ZeroMemory(payload);
            CryptographicOperations.ZeroMemory(tampered);
            CryptographicOperations.ZeroMemory(signature);
        }
    }

    private static void TestDeviceIdentityV2KeyId()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        try
        {
            var first = DeviceSignature.GetSigningKeyId(publicKey);
            var second = DeviceSignature.GetSigningKeyId(publicKey);
            Assert(first == second, "SigningKeyId must be stable for the same public key.");
            Assert(first.Length == DeviceSignature.Sha256HashSizeBytes * 2, "SigningKeyId must be a full SHA-256 hexadecimal fingerprint.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static void TestUnsafeNames()
    {
        var unsafeNames = new[]
        {
            "../evil.txt", "..\\evil.txt", "C:\\evil.txt", "/tmp/evil.txt", "CON", "NUL.txt",
            "CON.foo.bar", "LPT1.data.bin", "bad:name.txt", "report\u202Etxt.exe", ".", ".."
        };

        foreach (var value in unsafeNames)
        {
            Assert(!FileSafety.IsSafeFileName(value), $"Must reject unsafe name: {value}");
        }

        Assert(FileSafety.IsSafeFileName("photo 2026.jpg"), "A normal file name should be accepted.");
    }

    private static void TestDestinationPath()
    {
        var root = Path.Combine(Path.GetTempPath(), "GeniaLinkSelfTest", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            var path = FileSafety.GetUniqueDestinationPath(root, "safe.txt");
            var expectedPrefix = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root)) + Path.DirectorySeparatorChar;
            Assert(path.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase), "Destination must remain inside root.");
            var hash = SHA256.HashData("part-test"u8.ToArray());
            try
            {
                var part = FileSafety.GetResumePartPath(root, "Folder", "safe.txt", 123, hash);
                Assert(Path.GetFileName(part).Length < 64, "Resume part-file name should remain safely below filesystem component limits.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void TestProtocolRoundTrip()
    {
        var id = Guid.NewGuid();
        var hash = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray();
        var original = new FileOffer(id, "demo.bin", "Photos/2026", 123456, hash);
        var parsed = TransferProtocol.ParseFileOffer(TransferProtocol.CreateFileOffer(original));
        Assert(parsed.TransferId == id, "Transfer ID mismatch.");
        Assert(parsed.FileName == original.FileName, "File name mismatch.");
        Assert(parsed.RelativeDirectory == original.RelativeDirectory, "Relative directory mismatch.");
        Assert(parsed.FileSize == original.FileSize, "File size mismatch.");
        Assert(parsed.Sha256.SequenceEqual(hash), "Hash mismatch.");

        var accepted = TransferProtocol.ParseFileAccept(TransferProtocol.CreateFileAccept(id, 98765));
        Assert(accepted.TransferId == id, "Resume accept transfer ID mismatch.");
        Assert(accepted.ResumeOffset == 98765, "Resume offset mismatch.");

        var chunk = TransferProtocol.ParseFileChunk(TransferProtocol.CreateFileChunk(id, 4096, [1, 2, 3, 4]));
        Assert(chunk.TransferId == id && chunk.Offset == 4096, "Chunk offset round-trip mismatch.");
        Assert(chunk.Data.SequenceEqual(new byte[] { 1, 2, 3, 4 }), "Chunk data mismatch.");

        var deviceId = Guid.NewGuid();
        var hello = TransferProtocol.ParseHello(
            TransferProtocol.CreateHello(deviceId, "TEST-PC"),
            MessageType.Hello);
        Assert(hello.Version == ProtocolConstants.Version, "Hello version mismatch.");
        Assert(hello.DeviceId == deviceId, "Hello device ID mismatch.");
        Assert(hello.DeviceName == "TEST-PC", "Hello device name mismatch.");
    }

    private static void TestRemoteFolderProtocolRoundTrip()
    {
        TransferProtocol.ParseBrowseRequest(TransferProtocol.CreateBrowseRequest());
        var listCount = TransferProtocol.ParseBrowseListStart(TransferProtocol.CreateBrowseListStart(2));
        Assert(listCount == 2, "Remote browse file count mismatch.");

        var original = new GeniaLink.Core.Models.RemoteFileEntry("Camera/one.jpg", 12345, 1_700_000_000);
        var parsed = TransferProtocol.ParseBrowseEntry(TransferProtocol.CreateBrowseEntry(original));
        Assert(parsed == original, "Remote browse entry mismatch.");
        TransferProtocol.ParseBrowseListEnd(TransferProtocol.CreateBrowseListEnd());

        var request = TransferProtocol.ParseDownloadRequestStart(TransferProtocol.CreateDownloadRequestStart(2, ProtocolConstants.Port));
        Assert(request.Count == 2, "Remote download count mismatch.");
        Assert(request.ReturnTransferPort == ProtocolConstants.Port, "Remote download return port mismatch.");
        var item = TransferProtocol.ParseDownloadRequestItem(TransferProtocol.CreateDownloadRequestItem("Camera/one.jpg"));
        Assert(item == "Camera/one.jpg", "Remote download path mismatch.");
        TransferProtocol.ParseDownloadRequestCommit(TransferProtocol.CreateDownloadRequestCommit());
        Assert(TransferProtocol.ParseDownloadRequestAccepted(TransferProtocol.CreateDownloadRequestAccepted(2)) == 2, "Remote download acceptance mismatch.");
        Assert(
            TransferProtocol.ParseDownloadRequestRejected(TransferProtocol.CreateDownloadRequestRejected("No file")) == "No file",
            "Remote download rejection mismatch.");

        var previewPath = TransferProtocol.ParsePreviewRequest(TransferProtocol.CreatePreviewRequest("Camera/one.jpg"));
        Assert(previewPath == "Camera/one.jpg", "Remote preview path mismatch.");
        var previewOriginal = new GeniaLink.Core.Models.RemoteFilePreview(
            "Notes/readme.txt",
            GeniaLink.Core.Models.RemotePreviewKind.TextUtf8,
            "text/plain; charset=utf-8",
            "hello"u8.ToArray(),
            string.Empty);
        var previewParsed = TransferProtocol.ParsePreviewResponse(TransferProtocol.CreatePreviewResponse(previewOriginal));
        Assert(previewParsed.RelativePath == previewOriginal.RelativePath, "Remote preview response path mismatch.");
        Assert(previewParsed.Kind == previewOriginal.Kind, "Remote preview kind mismatch.");
        Assert(previewParsed.Data.SequenceEqual(previewOriginal.Data), "Remote preview payload mismatch.");
    }

    private static void TestRemoteBrowserIndex()
    {
        var files = new GeniaLink.Core.Models.RemoteFileEntry[]
        {
            new("root.txt", 10, 100),
            new("Movies/one.mp4", 1000, 200),
            new("Movies/Sub/two.mkv", 2000, 300),
            new("Photos/a.jpg", 100, 150)
        };

        var root = RemoteBrowserIndex.BuildDirectory(files, string.Empty);
        Assert(root.Count(entry => entry.IsDirectory) == 2, "Root browser should expose two derived folders.");
        Assert(root.Any(entry => entry.IsDirectory && entry.Name == "Movies" && entry.DescendantFileCount == 2), "Movies aggregate mismatch.");
        Assert(root.Any(entry => !entry.IsDirectory && entry.Name == "root.txt"), "Root file missing from browser index.");

        var movies = RemoteBrowserIndex.BuildDirectory(files, "Movies");
        Assert(movies.Any(entry => entry.IsDirectory && entry.Name == "Sub"), "Nested folder missing from browser index.");
        Assert(movies.Any(entry => !entry.IsDirectory && entry.Name == "one.mp4"), "Immediate nested file missing from browser index.");
        Assert(RemoteBrowserIndex.GetParentDirectory("Movies/Sub") == "Movies", "Remote browser parent path mismatch.");
    }

    private static async Task TestRemotePreviewPolicyAsync()
    {
        var textBytes = Enumerable.Repeat((byte)'A', ProtocolConstants.MaxTextPreviewBytes + 1024).ToArray();
        await using (var input = new MemoryStream(textBytes, writable: false))
        {
            var preview = await RemotePreviewPolicy.CreateTextPreviewAsync(input, "Notes/test.txt", CancellationToken.None);
            Assert(preview.Kind == GeniaLink.Core.Models.RemotePreviewKind.TextUtf8, "Text preview kind mismatch.");
            Assert(preview.Data.Length <= ProtocolConstants.MaxPreviewBytes, "Text preview exceeded the global preview limit.");
            Assert(Encoding.UTF8.GetString(preview.Data).Contains("64 КБ", StringComparison.Ordinal), "Truncated preview marker is missing.");
        }

        await using (var binary = new MemoryStream(new byte[] { 0, 1, 2, 3, 4 }, writable: false))
        {
            var preview = await RemotePreviewPolicy.CreateTextPreviewAsync(binary, "Notes/fake.txt", CancellationToken.None);
            Assert(preview.Kind == GeniaLink.Core.Models.RemotePreviewKind.None, "Binary-looking text must not be rendered as text preview.");
            Assert(preview.Data.Length == 0, "Unavailable preview must not expose binary bytes.");
        }
    }

    private static void TestRemoteFilePathSafety()
    {
        Assert(FileSafety.IsSafeRelativeFilePath("one.txt"), "Root Genia Link file should be allowed.");
        Assert(FileSafety.IsSafeRelativeFilePath("Photos/2026/one.jpg"), "Nested Genia Link file should be allowed.");
        Assert(!FileSafety.IsSafeRelativeFilePath("../secret.txt"), "Remote parent traversal must be rejected.");
        Assert(!FileSafety.IsSafeRelativeFilePath("Photos/../../secret.txt"), "Embedded remote traversal must be rejected.");
        Assert(!FileSafety.IsSafeRelativeFilePath("/absolute.txt"), "Absolute remote paths must be rejected.");
        Assert(!FileSafety.IsSafeRelativeFilePath("Photos\\secret.txt"), "Backslash remote paths must be rejected on the wire.");

        var root = Path.Combine(Path.GetTempPath(), "GeniaLinkRemoteFolderTest", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path.Combine(root, "Photos"));
        var expected = Path.Combine(root, "Photos", "one.txt");
        File.WriteAllText(expected, "one");
        try
        {
            var resolved = FileSafety.ResolveSharedFilePath(root, "Photos/one.txt");
            Assert(string.Equals(Path.GetFullPath(expected), resolved, StringComparison.OrdinalIgnoreCase), "Remote shared file must resolve inside Genia Link root.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void TestRelativePathSafety()
    {
        Assert(FileSafety.IsSafeRelativeDirectory(string.Empty), "Empty relative directory should be allowed.");
        Assert(FileSafety.IsSafeRelativeDirectory("Photos/2026/August"), "Normal relative path should be allowed.");
        Assert(!FileSafety.IsSafeRelativeDirectory("../escape"), "Parent traversal must be rejected.");
        Assert(!FileSafety.IsSafeRelativeDirectory("Photos/../escape"), "Embedded traversal must be rejected.");
        Assert(!FileSafety.IsSafeRelativeDirectory("/absolute"), "Absolute-looking path must be rejected.");
        Assert(!FileSafety.IsSafeRelativeDirectory("Photos\\escape"), "Backslash path must be rejected on the wire.");
    }

    private static void TestResumeKeyDeterminism()
    {
        var hash = SHA256.HashData("resume-test"u8.ToArray());
        try
        {
            var first = FileSafety.CreateResumeKey("Folder/Sub", "demo.bin", 1234, hash);
            var second = FileSafety.CreateResumeKey("Folder/Sub", "demo.bin", 1234, hash);
            var different = FileSafety.CreateResumeKey("Folder/Sub", "demo2.bin", 1234, hash);
            Assert(first == second, "Resume key must be deterministic.");
            Assert(first != different, "Different files should not share a resume key.");
            Assert(first.Length == 32, "Resume key should use a compact 128-bit hex prefix.");

            var senderA = Guid.Parse("11111111-1111-4111-8111-111111111111");
            var senderB = Guid.Parse("22222222-2222-4222-8222-222222222222");
            const string relationshipA = "00112233445566778899aabbccddeeff";
            const string relationshipB = "ffeeddccbbaa99887766554433221100";
            var scopedA1 = FileSafety.CreateResumeKey("Folder/Sub", "demo.bin", 1234, hash, senderA, relationshipA);
            var scopedA2 = FileSafety.CreateResumeKey("Folder/Sub", "demo.bin", 1234, hash, senderA, relationshipA);
            var scopedDifferentDevice = FileSafety.CreateResumeKey("Folder/Sub", "demo.bin", 1234, hash, senderB, relationshipA);
            var scopedDifferentTrust = FileSafety.CreateResumeKey("Folder/Sub", "demo.bin", 1234, hash, senderA, relationshipB);
            Assert(scopedA1 == scopedA2, "Trust-scoped resume key must remain deterministic inside one trust relationship.");
            Assert(scopedA1 != scopedDifferentDevice, "Two trusted devices must never share a resume namespace for the same file.");
            Assert(scopedA1 != scopedDifferentTrust, "A new trust relationship must invalidate the previous resume namespace.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(hash);
        }
    }

    private static void TestCapabilityAssertionRevisionStore()
    {
        var root = Path.Combine(Path.GetTempPath(), "GeniaLinkCapabilityRevisionSelfTest", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "capability-assertion-revision.json");
        var deviceId = Guid.Parse("5555fc57-b454-462d-bae1-9f2b3545daa1");
        try
        {
            using var identity = new SelfTestSigningIdentity(deviceId, "CAP-REVISION", DeviceKind.WindowsComputer);
            var client = DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Client);
            var first = CapabilityAssertionRevisionStore.LoadOrAdvance(path, identity, client);
            var unchanged = CapabilityAssertionRevisionStore.LoadOrAdvance(path, identity, client);
            Assert(first == unchanged, "Unchanged capability assertion must keep its revision.");

            var custom = client | DeviceCapability.Messaging;
            var advanced = CapabilityAssertionRevisionStore.LoadOrAdvance(path, identity, custom);
            Assert(advanced == first + 1, "Changed capability set must advance capability revision exactly once.");
            var persisted = CapabilityAssertionRevisionStore.LoadOrAdvance(path, identity, custom);
            Assert(persisted == advanced, "Persisted capability revision must survive reload without advancing.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void TestTransferSelection()
    {
        var root = Path.Combine(Path.GetTempPath(), "GeniaLinkSelectionTest", Guid.NewGuid().ToString("N"));
        var folder = Path.Combine(root, "Camera");
        var nested = Path.Combine(folder, "2026");
        Directory.CreateDirectory(nested);
        var first = Path.Combine(folder, "one.txt");
        var second = Path.Combine(nested, "two.bin");
        File.WriteAllText(first, "one");
        File.WriteAllBytes(second, [1, 2, 3]);

        try
        {
            var selected = TransferSelection.Expand([folder]);
            Assert(selected.Count == 2, "Folder selection should enumerate both files.");
            var firstSource = selected.Single(item => Path.GetFileName(item.FullPath) == "one.txt");
            var secondSource = selected.Single(item => Path.GetFileName(item.FullPath) == "two.bin");
            Assert(firstSource.RelativeDirectory == "Camera", "Top-level folder name must be preserved.");
            Assert(secondSource.RelativeDirectory == "Camera/2026", "Nested folder structure must be preserved.");
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private static void TestDiscoveryRoundTrip()
    {
        var original = new DiscoveryAdvertisement(
            Guid.NewGuid(),
            "TEST-PC",
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            "00112233445566778899AABBCCDDEEFF",
            DeviceKind.WindowsComputer);
        var packet = DiscoveryPacket.Create(original);
        var parsed = DiscoveryPacket.Parse(packet);
        Assert(parsed == original, "Discovery advertisement mismatch.");
        Assert(parsed.Kind == DeviceKind.WindowsComputer, "Discovery device kind mismatch.");

        var legacyPacket = packet[..^1];
        var legacyParsed = DiscoveryPacket.Parse(legacyPacket);
        Assert(legacyParsed.Kind == DeviceKind.Unknown, "Legacy discovery packet should remain compatible and report unknown device kind.");
    }

    private static void TestSignedDiscoveryRoundTrip()
    {
        var deviceId = Guid.Parse("9505780d-1b2a-4bb4-98a7-bb9a85269527");
        using var identity = new SelfTestSigningIdentity(deviceId, "GNP-M2-TEST", DeviceKind.WindowsComputer);
        var advertisement = new DiscoveryAdvertisement(
            deviceId,
            identity.DeviceName,
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            "00112233445566778899AABBCCDDEEFF",
            identity.DeviceKind);

        var packet = SignedDiscoveryPacket.Create(advertisement, identity);
        try
        {
            var parsed = SignedDiscoveryPacket.ParseAndVerify(packet);
            Assert(parsed.Advertisement == advertisement, "Signed discovery advertisement mismatch.");
            Assert(parsed.IdentityVersion == DeviceIdentityV2.CurrentVersion, "Signed discovery identity version mismatch.");
            Assert(parsed.KeyGeneration == identity.KeyGeneration, "Signed discovery key generation mismatch.");
            Assert(parsed.SigningKeyId == identity.SigningKeyId, "Signed discovery signing key ID mismatch.");
            Assert(parsed.SigningPublicKey.Length > 0, "Signed discovery must carry the public signing key.");
            Assert(SignedDiscoveryPacket.HasSignedMagic(packet), "Signed discovery packet must be distinguishable from legacy GLD2 discovery.");

            var legacyRejected = false;
            try
            {
                _ = DiscoveryPacket.Parse(packet);
            }
            catch (InvalidDataException)
            {
                legacyRejected = true;
            }

            Assert(legacyRejected, "Legacy GLD2 parser must ignore/reject the separate M2.2 signed discovery envelope.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packet);
        }
    }

    private static void TestSignedDiscoveryTamperDetection()
    {
        var deviceId = Guid.Parse("29b1314a-cb8c-4df0-a839-891c11e9350e");
        using var identity = new SelfTestSigningIdentity(deviceId, "GNP-M2-TAMPER", DeviceKind.AndroidPhone);
        var advertisement = new DiscoveryAdvertisement(
            deviceId,
            identity.DeviceName,
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            "FFEEDDCCBBAA99887766554433221100",
            identity.DeviceKind);
        var packet = SignedDiscoveryPacket.Create(advertisement, identity);
        var tampered = packet.ToArray();
        try
        {
            // Offset 12 begins the DeviceId in GLS1. Changing one signed byte must
            // make the packet unverifiable even if the rest of the structure is valid.
            tampered[12] ^= 0x01;
            var rejected = false;
            try
            {
                _ = SignedDiscoveryPacket.ParseAndVerify(tampered);
            }
            catch (InvalidDataException)
            {
                rejected = true;
            }

            Assert(rejected, "Changing one byte of a signed discovery packet must be rejected.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packet);
            CryptographicOperations.ZeroMemory(tampered);
        }
    }

    private static void TestReplayProtectedSignedDiscoveryRoundTrip()
    {
        var deviceId = Guid.Parse("df099c4f-a136-4e83-88cf-236b41710a7d");
        using var identity = new SelfTestSigningIdentity(deviceId, "GNP-M253-TEST", DeviceKind.WindowsComputer);
        var advertisement = new DiscoveryAdvertisement(
            deviceId,
            identity.DeviceName,
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            "0123456789ABCDEFFEDCBA9876543210",
            identity.DeviceKind);
        const long revision = 42;
        var packet = ReplayProtectedSignedDiscoveryPacket.Create(advertisement, identity, revision);
        try
        {
            var parsed = ReplayProtectedSignedDiscoveryPacket.ParseAndVerify(packet);
            Assert(parsed.Advertisement == advertisement, "GLS2 discovery advertisement mismatch.");
            Assert(parsed.IdentityRevision == revision, "GLS2 must preserve the signed identity revision.");
            Assert(parsed.SigningKeyId == identity.SigningKeyId, "GLS2 signing key ID mismatch.");
            Assert(ReplayProtectedSignedDiscoveryPacket.HasMagic(packet), "GLS2 packet must expose replay-protected magic.");
            Assert(!SignedDiscoveryPacket.HasSignedMagic(packet), "GLS2 must remain distinguishable from GLS1 compatibility discovery.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packet);
        }
    }

    private static void TestReplayProtectedSignedDiscoveryTamperDetection()
    {
        var deviceId = Guid.Parse("339c6451-8351-401d-9045-224ee8b99188");
        using var identity = new SelfTestSigningIdentity(deviceId, "GNP-M253-TAMPER", DeviceKind.AndroidPhone);
        var advertisement = new DiscoveryAdvertisement(
            deviceId,
            identity.DeviceName,
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            "11223344556677889900AABBCCDDEEFF",
            identity.DeviceKind);
        var packet = ReplayProtectedSignedDiscoveryPacket.Create(advertisement, identity, 77);
        var tampered = packet.ToArray();
        try
        {
            // GLS2 identity revision starts after magic/version/identity/device/ports/kind/generation.
            tampered[45] ^= 0x01;
            var rejected = false;
            try
            {
                _ = ReplayProtectedSignedDiscoveryPacket.ParseAndVerify(tampered);
            }
            catch (InvalidDataException)
            {
                rejected = true;
            }

            Assert(rejected, "Changing the signed GLS2 identity revision must invalidate the packet.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packet);
            CryptographicOperations.ZeroMemory(tampered);
        }
    }

    private static void TestCapabilitySignedDiscoveryRoundTrip()
    {
        var deviceId = Guid.Parse("5ec2ead6-b8bb-40a2-a31a-7f21e4e2c6ce");
        using var identity = new SelfTestSigningIdentity(deviceId, "GNP-M262-TEST", DeviceKind.WindowsComputer);
        var advertisement = new DiscoveryAdvertisement(
            deviceId,
            identity.DeviceName,
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            "AABBCCDDEEFF00112233445566778899",
            identity.DeviceKind);
        const long identityRevision = 123;
        const long capabilityRevision = 456;
        var capabilities = DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Server);
        var packet = CapabilitySignedDiscoveryPacket.Create(advertisement, identity, identityRevision, capabilities, capabilityRevision);
        try
        {
            var parsed = CapabilitySignedDiscoveryPacket.ParseAndVerify(packet);
            Assert(parsed.Advertisement == advertisement, "GLC1 discovery advertisement mismatch.");
            Assert(parsed.IdentityRevision == identityRevision, "GLC1 must preserve the signed identity revision.");
            Assert(parsed.CapabilityRevision == capabilityRevision, "GLC1 must preserve the signed capability revision.");
            Assert(parsed.Capabilities == capabilities, "GLC1 must preserve the signed capability set.");
            Assert(parsed.SigningKeyId == identity.SigningKeyId, "GLC1 signing key ID mismatch.");
            Assert(CapabilitySignedDiscoveryPacket.HasMagic(packet), "GLC1 packet must expose capability magic.");
            Assert(!ReplayProtectedSignedDiscoveryPacket.HasMagic(packet), "GLC1 must remain distinguishable from GLS2 compatibility discovery.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packet);
        }
    }

    private static void TestCapabilitySignedDiscoveryTamperDetection()
    {
        var deviceId = Guid.Parse("6685192c-9f75-487b-a547-a61b96cd48d3");
        using var identity = new SelfTestSigningIdentity(deviceId, "GNP-M262-TAMPER", DeviceKind.AndroidPhone);
        var advertisement = new DiscoveryAdvertisement(
            deviceId,
            identity.DeviceName,
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            "99887766554433221100FFEEDDCCBBAA",
            identity.DeviceKind);
        var capabilities = DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Client);
        var packet = CapabilitySignedDiscoveryPacket.Create(advertisement, identity, 55, capabilities, 66);
        var tampered = packet.ToArray();
        try
        {
            // GLC1 capability bitset occupies bytes 57..64 in big-endian order.
            // Toggle a currently-known capability in the low byte so the modified
            // set remains structurally valid and rejection must come from signature
            // verification, not from capability-range validation.
            tampered[64] ^= (byte)DeviceCapability.BackgroundAvailability;
            var rejected = false;
            try
            {
                _ = CapabilitySignedDiscoveryPacket.ParseAndVerify(tampered);
            }
            catch (InvalidDataException)
            {
                rejected = true;
            }

            Assert(rejected, "Changing signed GLC1 capabilities must invalidate the packet.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packet);
            CryptographicOperations.ZeroMemory(tampered);
        }
    }

    private static void TestCapabilitySignedDiscoveryRejectsUnknownHighBits()
    {
        var deviceId = Guid.Parse("04ec06bb-137f-4dda-b247-241af9b726c2");
        using var identity = new SelfTestSigningIdentity(deviceId, "GNP-M262-HIGHBITS", DeviceKind.AndroidPhone);
        var advertisement = new DiscoveryAdvertisement(
            deviceId,
            identity.DeviceName,
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            "102030405060708090A0B0C0D0E0F001",
            identity.DeviceKind);
        var capabilities = DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Client);
        var packet = CapabilitySignedDiscoveryPacket.Create(advertisement, identity, 77, capabilities, 88);
        var malformed = packet.ToArray();
        try
        {
            // Set an unknown high bit in the reserved 64-bit wire field. A hostile
            // packet must be rejected as InvalidDataException even when checked
            // arithmetic is enabled; OverflowException must never escape the parser.
            malformed[57] ^= 0x01;
            var rejected = false;
            try
            {
                _ = CapabilitySignedDiscoveryPacket.ParseAndVerify(malformed);
            }
            catch (InvalidDataException)
            {
                rejected = true;
            }

            Assert(rejected, "Unknown high GLC1 capability bits must be rejected as invalid protocol data.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packet);
            CryptographicOperations.ZeroMemory(malformed);
        }
    }

    private static void TestIdentityAssertionRevisionStore()
    {
        var root = Path.Combine(Path.GetTempPath(), "GeniaLinkIdentityRevisionSelfTest", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        var path = Path.Combine(root, "identity-assertion-revision.json");
        var deviceId = Guid.Parse("8773b474-c3e8-4664-ac54-d7c682db980e");
        try
        {
            using var identity1 = new SelfTestSigningIdentity(deviceId, "REVISION-A", DeviceKind.WindowsComputer);
            var revision1 = IdentityAssertionRevisionStore.LoadOrAdvance(path, identity1);
            var revision1Again = IdentityAssertionRevisionStore.LoadOrAdvance(path, identity1);
            Assert(revision1Again == revision1, "Unchanged public identity assertion must keep the same revision across reloads.");

            using var identity2 = new SelfTestSigningIdentity(deviceId, "REVISION-B", DeviceKind.WindowsComputer);
            var revision2 = IdentityAssertionRevisionStore.LoadOrAdvance(path, identity2);
            Assert(revision2 == checked(revision1 + 1), "Changed public identity assertion must advance the persisted revision exactly once.");
            var revision2Again = IdentityAssertionRevisionStore.LoadOrAdvance(path, identity2);
            Assert(revision2Again == revision2, "Persisted changed assertion must not increment repeatedly without another change.");
        }
        finally
        {
            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch (IOException)
            {
            }
            catch (UnauthorizedAccessException)
            {
            }
        }
    }

    private static void TestLocalNetworkPolicy()
    {
        Assert(LocalNetworkPolicy.IsAllowedAddress(IPAddress.Loopback), "Loopback must be allowed.");
        Assert(LocalNetworkPolicy.IsAllowedAddress(IPAddress.Parse("192.168.10.25")), "RFC1918 192.168/16 must be allowed.");
        Assert(LocalNetworkPolicy.IsAllowedAddress(IPAddress.Parse("10.20.30.40")), "RFC1918 10/8 must be allowed.");
        Assert(LocalNetworkPolicy.IsAllowedAddress(IPAddress.Parse("172.16.0.1")), "RFC1918 172.16/12 must be allowed.");
        Assert(LocalNetworkPolicy.IsAllowedAddress(IPAddress.Parse("100.64.0.1")), "Shared local carrier range must be allowed.");
        Assert(!LocalNetworkPolicy.IsAllowedAddress(IPAddress.Parse("8.8.8.8")), "Public IPv4 must be rejected.");
        Assert(!LocalNetworkPolicy.IsAllowedAddress(IPAddress.Parse("1.1.1.1")), "Public IPv4 must be rejected.");
        Assert(!LocalNetworkPolicy.IsAllowedAddress(IPAddress.IPv6Loopback), "v0.2 discovery/transport is IPv4-only.");
    }

    private static void TestTransferTimeoutPolicy()
    {
        Assert(ProtocolConstants.IdleTimeout >= TimeSpan.FromSeconds(5), "Idle timeout must not be unrealistically short.");
        Assert(ProtocolConstants.IdleTimeout <= TimeSpan.FromSeconds(60), "Idle timeout must remain bounded after a broken connection.");
        Assert(ProtocolConstants.TransferIoTimeout >= TimeSpan.FromSeconds(5), "Transfer I/O timeout must not be unrealistically short.");
        Assert(ProtocolConstants.TransferIoTimeout <= TimeSpan.FromSeconds(60), "Transfer I/O timeout must remain bounded after a broken connection.");
    }

    private static void TestAndroidCompatibleEcdhKdf()
    {
        using var left = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var right = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var dotNetDerived = left.DeriveKeyFromHash(right.PublicKey, HashAlgorithmName.SHA256);
        var rawSecret = left.DeriveRawSecretAgreement(right.PublicKey);
        var androidStyle = SHA256.HashData(rawSecret);

        try
        {
            Assert(
                CryptographicOperations.FixedTimeEquals(dotNetDerived, androidStyle),
                "Android ECDH compatibility KDF must equal SHA-256(raw ECDH secret).");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dotNetDerived);
            CryptographicOperations.ZeroMemory(rawSecret);
            CryptographicOperations.ZeroMemory(androidStyle);
        }
    }

    private static async Task TestPairingProtocolAsync()
    {
        using var leftKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        using var rightKey = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
        var left = new PairingPeerInfo(Guid.NewGuid(), "LEFT", leftKey.ExportSubjectPublicKeyInfo());
        var right = new PairingPeerInfo(Guid.NewGuid(), "RIGHT", rightKey.ExportSubjectPublicKeyInfo());
        var (clientStream, serverStream) = InMemoryDuplexStream.CreatePair();
        await using var clientSide = clientStream;
        await using var serverSide = serverStream;
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        string? serverCode = null;
        string? clientCode = null;

        var serverTask = PairingProtocol.RunServerAsync(
            serverSide,
            right,
            confirmation =>
            {
                serverCode = confirmation.VerificationCode;
                return Task.FromResult(true);
            },
            timeoutCts.Token);

        var remote = await PairingProtocol.RunClientAsync(
            clientSide,
            left,
            confirmation =>
            {
                clientCode = confirmation.VerificationCode;
                return Task.FromResult(true);
            },
            timeoutCts.Token);
        var serverRemote = await serverTask;

        Assert(remote.DeviceId == right.DeviceId, "Pairing client received wrong peer ID.");
        Assert(serverRemote.DeviceId == left.DeviceId, "Pairing server received wrong peer ID.");
        Assert(!string.IsNullOrWhiteSpace(clientCode) && clientCode == serverCode, "Pairing verification codes must match.");
    }

    private static async Task TestTrustedHandshakeAsync()
    {
        var clientId = Guid.NewGuid();
        var serverId = Guid.NewGuid();
        var sharedKey = RandomNumberGenerator.GetBytes(32);
        var (clientStream, serverStream) = InMemoryDuplexStream.CreatePair();
        await using var clientSide = clientStream;
        await using var serverSide = serverStream;
        using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

        try
        {
            var serverTask = TrustedSessionHandshake.CreateServerSessionKeyAsync(
                serverSide,
                serverId,
                id => id == clientId ? sharedKey.ToArray() : null,
                timeoutCts.Token);

            var clientSessionKey = await TrustedSessionHandshake.CreateClientSessionKeyAsync(
                clientSide,
                clientId,
                serverId,
                sharedKey,
                timeoutCts.Token);
            var serverResult = await serverTask;

            try
            {
                Assert(serverResult.RemoteDeviceId == clientId, "Trusted handshake remote ID mismatch.");
                Assert(CryptographicOperations.FixedTimeEquals(clientSessionKey, serverResult.SessionKey), "Trusted handshake session keys differ.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(clientSessionKey);
                CryptographicOperations.ZeroMemory(serverResult.SessionKey);
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(sharedKey);
        }
    }

    private static async Task TestEncryptedRoundTripAsync()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            await using var stream = new MemoryStream();
            await using (var writer = new SecureChannel(stream, key, SecureChannelRole.Client, leaveOpen: true))
            {
                await writer.SendAsync("hello secure world"u8.ToArray(), CancellationToken.None);
            }

            stream.Position = 0;
            await using var reader = new SecureChannel(stream, key, SecureChannelRole.Server, leaveOpen: true);
            var result = await reader.ReceiveAsync(CancellationToken.None);
            Assert(result.SequenceEqual("hello secure world"u8.ToArray()), "Decrypted payload mismatch.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static async Task TestTamperDetectionAsync()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            await using var stream = new MemoryStream();
            await using (var writer = new SecureChannel(stream, key, SecureChannelRole.Client, leaveOpen: true))
            {
                await writer.SendAsync("do not tamper"u8.ToArray(), CancellationToken.None);
            }

            var bytes = stream.ToArray();
            bytes[4 + 12] ^= 0x40;
            await using var tampered = new MemoryStream(bytes);
            await using var reader = new SecureChannel(tampered, key, SecureChannelRole.Server, leaveOpen: true);
            var detected = false;
            try
            {
                _ = await reader.ReceiveAsync(CancellationToken.None);
            }
            catch (AuthenticationException)
            {
                detected = true;
            }

            Assert(detected, "Tampered encrypted data must be rejected.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static async Task TestReplayDetectionAsync()
    {
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            await using var source = new MemoryStream();
            await using (var writer = new SecureChannel(source, key, SecureChannelRole.Client, leaveOpen: true))
            {
                await writer.SendAsync("first"u8.ToArray(), CancellationToken.None);
                await writer.SendAsync("second"u8.ToArray(), CancellationToken.None);
            }

            var bytes = source.ToArray();
            var firstFrameLength = System.Buffers.Binary.BinaryPrimitives.ReadInt32BigEndian(bytes.AsSpan(0, 4));
            var firstFrameTotal = checked(4 + firstFrameLength);
            var replayed = new byte[firstFrameTotal * 2];
            bytes.AsSpan(0, firstFrameTotal).CopyTo(replayed);
            bytes.AsSpan(0, firstFrameTotal).CopyTo(replayed.AsSpan(firstFrameTotal));

            await using var stream = new MemoryStream(replayed);
            await using var reader = new SecureChannel(stream, key, SecureChannelRole.Server, leaveOpen: true);
            var first = await reader.ReceiveAsync(CancellationToken.None);
            Assert(first.SequenceEqual("first"u8.ToArray()), "First replay test frame did not decrypt.");

            var detected = false;
            try
            {
                _ = await reader.ReceiveAsync(CancellationToken.None);
            }
            catch (AuthenticationException)
            {
                detected = true;
            }

            Assert(detected, "A duplicated encrypted frame must be rejected by sequence binding.");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private sealed class SelfTestSigningIdentity : IDeviceSigningIdentity, ISigningKeyRotationSource, IDisposable
    {
        private readonly ECDsa _ecdsa;
        private readonly SigningKeyRotationCertificate[] _rotationChain;
        private bool _disposed;

        public SelfTestSigningIdentity(Guid deviceId, string deviceName, DeviceKind deviceKind)
            : this(
                deviceId,
                deviceName,
                deviceKind,
                1,
                new DateTimeOffset(2026, 9, 1, 0, 0, 0, TimeSpan.Zero),
                ECDsa.Create(ECCurve.NamedCurves.nistP256),
                [])
        {
        }

        private SelfTestSigningIdentity(
            Guid deviceId,
            string deviceName,
            DeviceKind deviceKind,
            int keyGeneration,
            DateTimeOffset createdAtUtc,
            ECDsa ecdsa,
            SigningKeyRotationCertificate[] rotationChain)
        {
            DeviceId = deviceId;
            DeviceName = deviceName;
            DeviceKind = deviceKind;
            KeyGeneration = keyGeneration;
            CreatedAtUtc = createdAtUtc;
            _ecdsa = ecdsa;
            _rotationChain = rotationChain.Select(certificate => certificate.DeepCopy()).ToArray();
            var publicKey = ExportSigningPublicKey();
            try
            {
                SigningKeyId = DeviceSignature.GetSigningKeyId(publicKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }

        public Guid DeviceId { get; }

        public string DeviceName { get; }

        public int IdentityVersion { get; } = DeviceIdentityV2.CurrentVersion;

        public int KeyGeneration { get; }

        public DateTimeOffset CreatedAtUtc { get; }

        public DeviceKind DeviceKind { get; }

        public string DisplayName => DeviceName;

        public string SigningKeyId { get; }

        public byte[] ExportSigningPublicKey()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _ecdsa.ExportSubjectPublicKeyInfo();
        }

        public byte[] Sign(ReadOnlySpan<byte> payload)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return _ecdsa.SignData(
                payload,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.Rfc3279DerSequence);
        }

        public bool VerifySignature(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
        {
            var publicKey = ExportSigningPublicKey();
            try
            {
                return DeviceSignature.Verify(publicKey, payload, signature);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }

        public SigningKeyRotationCertificate[] ExportSigningKeyRotationChain() =>
            _rotationChain.Select(certificate => certificate.DeepCopy()).ToArray();

        public SelfTestSigningIdentity Rotate()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            var nextEcdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var nextPublicKey = nextEcdsa.ExportSubjectPublicKeyInfo();
            try
            {
                var nextGeneration = checked(KeyGeneration + 1);
                var certificate = SigningKeyRotationCertificate.Create(this, nextGeneration, nextPublicKey);
                var chain = ExportSigningKeyRotationChain().ToList();
                chain.Add(certificate);
                return new SelfTestSigningIdentity(
                    DeviceId,
                    DeviceName,
                    DeviceKind,
                    nextGeneration,
                    CreatedAtUtc.AddMinutes(1),
                    nextEcdsa,
                    chain.ToArray());
            }
            catch
            {
                nextEcdsa.Dispose();
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(nextPublicKey);
            }
        }

        public TrustedSigningIdentity ToTrustedSigningIdentity()
        {
            var publicKey = ExportSigningPublicKey();
            try
            {
                var identity = new TrustedSigningIdentity(
                    DeviceId,
                    IdentityVersion,
                    KeyGeneration,
                    publicKey,
                    ExportSigningKeyRotationChain());
                identity.Validate();
                publicKey = Array.Empty<byte>();
                return identity;
            }
            finally
            {
                if (publicKey.Length > 0)
                {
                    CryptographicOperations.ZeroMemory(publicKey);
                }
            }
        }

        public DeviceIdentityV2 ToDeviceIdentityV2()
        {
            var publicKey = ExportSigningPublicKey();
            try
            {
                return new DeviceIdentityV2(DeviceId, DisplayName, DeviceKind, KeyGeneration, CreatedAtUtc, publicKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }

        public PairingPeerInfo ToPairingPeerInfo() => new(DeviceId, DeviceName, ExportSigningPublicKey());

        public string GetPublicKeyFingerprint() => "00112233445566778899AABBCCDDEEFF";

        public byte[] DeriveSharedKey(ReadOnlySpan<byte> peerPublicKey) => SHA256.HashData(peerPublicKey);

        public void Dispose()
        {
            if (!_disposed)
            {
                _ecdsa.Dispose();
                _disposed = true;
            }

            GC.SuppressFinalize(this);
        }
    }

    private sealed class SelfTestDeviceIdentity(Guid deviceId, string deviceName) : IDeviceIdentity
    {
        public Guid DeviceId { get; } = deviceId;

        public string DeviceName { get; } = deviceName;

        public PairingPeerInfo ToPairingPeerInfo() => new(DeviceId, DeviceName, [1]);

        public string GetPublicKeyFingerprint() => "SELFTEST";

        public byte[] DeriveSharedKey(ReadOnlySpan<byte> peerPublicKey) => SHA256.HashData(peerPublicKey);
    }

    private static void ZeroTrustedSigningIdentity(TrustedSigningIdentity identity)
    {
        CryptographicOperations.ZeroMemory(identity.SigningPublicKey);
        foreach (var certificate in identity.RotationChain ?? [])
        {
            CryptographicOperations.ZeroMemory(certificate.PreviousSigningPublicKey);
            CryptographicOperations.ZeroMemory(certificate.NewSigningPublicKey);
            CryptographicOperations.ZeroMemory(certificate.PreviousKeySignature);
        }
    }

    private static void Test(string name, Action action)
    {
        try
        {
            action();
            Console.WriteLine($"[PASS] {name}");
        }
        catch (Exception ex)
        {
            _failures++;
            Console.WriteLine($"[FAIL] {name}: {ex.Message}");
        }
    }

    private static async Task TestAsync(string name, Func<Task> action)
    {
        try
        {
            await action();
            Console.WriteLine($"[PASS] {name}");
        }
        catch (Exception ex)
        {
            _failures++;
            Console.WriteLine($"[FAIL] {name}: {ex.Message}");
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }
}

internal sealed class InMemoryDuplexStream : Stream
{
    private readonly Channel<byte[]> _incoming;
    private readonly Channel<byte[]> _outgoing;
    private byte[]? _currentReadBuffer;
    private int _currentReadOffset;
    private bool _disposed;

    private InMemoryDuplexStream(Channel<byte[]> incoming, Channel<byte[]> outgoing)
    {
        _incoming = incoming;
        _outgoing = outgoing;
    }

    public override bool CanRead => !_disposed;

    public override bool CanSeek => false;

    public override bool CanWrite => !_disposed;

    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public static (InMemoryDuplexStream Left, InMemoryDuplexStream Right) CreatePair()
    {
        var leftToRight = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
            AllowSynchronousContinuations = false
        });
        var rightToLeft = Channel.CreateUnbounded<byte[]>(new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = true,
            AllowSynchronousContinuations = false
        });

        return (
            new InMemoryDuplexStream(rightToLeft, leftToRight),
            new InMemoryDuplexStream(leftToRight, rightToLeft));
    }

    public override void Flush()
    {
        ThrowIfDisposed();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public override int Read(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("Synchronous reads are not used by Genia Link self-tests.");

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (buffer.Length == 0)
        {
            return 0;
        }

        while (true)
        {
            if (_currentReadBuffer is not null && _currentReadOffset < _currentReadBuffer.Length)
            {
                var available = _currentReadBuffer.Length - _currentReadOffset;
                var count = Math.Min(buffer.Length, available);
                _currentReadBuffer.AsMemory(_currentReadOffset, count).CopyTo(buffer);
                _currentReadOffset += count;
                if (_currentReadOffset == _currentReadBuffer.Length)
                {
                    CryptographicOperations.ZeroMemory(_currentReadBuffer);
                    _currentReadBuffer = null;
                    _currentReadOffset = 0;
                }

                return count;
            }

            if (!await _incoming.Reader.WaitToReadAsync(cancellationToken))
            {
                return 0;
            }

            if (_incoming.Reader.TryRead(out var nextBuffer))
            {
                _currentReadBuffer = nextBuffer;
                _currentReadOffset = 0;
            }
        }
    }

    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

    public override void SetLength(long value) => throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException("Synchronous writes are not used by Genia Link self-tests.");

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfDisposed();
        if (buffer.Length == 0)
        {
            return;
        }

        var copy = buffer.ToArray();
        try
        {
            await _outgoing.Writer.WriteAsync(copy, cancellationToken);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(copy);
            throw;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (!_disposed)
        {
            _disposed = true;
            if (disposing)
            {
                _outgoing.Writer.TryComplete();
                if (_currentReadBuffer is not null)
                {
                    CryptographicOperations.ZeroMemory(_currentReadBuffer);
                    _currentReadBuffer = null;
                }

                while (_incoming.Reader.TryRead(out var pendingBuffer))
                {
                    CryptographicOperations.ZeroMemory(pendingBuffer);
                }
            }
        }

        base.Dispose(disposing);
    }

    private void ThrowIfDisposed()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
    }
}
