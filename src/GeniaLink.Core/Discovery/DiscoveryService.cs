using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using GeniaLink.Core.Capabilities;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Network;

namespace GeniaLink.Core.Discovery;

public static class DiscoveryService
{
    private const int MaxSignedPeerCacheEntries = 256;

    public static Task RunAsync(
        DiscoveryAdvertisement localAdvertisement,
        Action<DiscoveredDevice> deviceSeen,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        return RunAsync(localAdvertisement, null, 0, DeviceCapability.None, 0, deviceSeen, log, cancellationToken);
    }

    public static Task RunAsync(
        DiscoveryAdvertisement localAdvertisement,
        IDeviceSigningIdentity? signingIdentity,
        Action<DiscoveredDevice> deviceSeen,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        return RunAsync(localAdvertisement, signingIdentity, 0, DeviceCapability.None, 0, deviceSeen, log, cancellationToken);
    }

    public static Task RunAsync(
        DiscoveryAdvertisement localAdvertisement,
        IDeviceSigningIdentity? signingIdentity,
        long identityRevision,
        Action<DiscoveredDevice> deviceSeen,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        return RunAsync(localAdvertisement, signingIdentity, identityRevision, DeviceCapability.None, 0, deviceSeen, log, cancellationToken);
    }

    public static async Task RunAsync(
        DiscoveryAdvertisement localAdvertisement,
        IDeviceSigningIdentity? signingIdentity,
        long identityRevision,
        DeviceCapability capabilities,
        long capabilityRevision,
        Action<DiscoveredDevice> deviceSeen,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(localAdvertisement);
        ArgumentNullException.ThrowIfNull(deviceSeen);
        ArgumentOutOfRangeException.ThrowIfNegative(identityRevision);
        ArgumentOutOfRangeException.ThrowIfNegative(capabilityRevision);

        using var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, ProtocolConstants.DiscoveryPort));
        udp.EnableBroadcast = true;

        var legacyPacket = DiscoveryPacket.Create(localAdvertisement);
        byte[]? signedPacket = null;
        byte[]? replayProtectedPacket = null;
        byte[]? capabilityPacket = null;
        if (signingIdentity is not null)
        {
            try
            {
                signedPacket = SignedDiscoveryPacket.Create(localAdvertisement, signingIdentity);
                if (identityRevision > 0)
                {
                    replayProtectedPacket = ReplayProtectedSignedDiscoveryPacket.Create(localAdvertisement, signingIdentity, identityRevision);
                }
            }
            catch (Exception ex) when (ex is InvalidDataException or CryptographicException)
            {
                log?.Invoke($"GNP/1 signed discovery is unavailable; legacy GLD2 discovery remains active: {ex.Message}");
                signedPacket = null;
                replayProtectedPacket = null;
            }

            if (replayProtectedPacket is not null && capabilityRevision > 0)
            {
                try
                {
                    var normalizedCapabilities = DeviceCapabilityProfiles.NormalizeSelection(capabilities);
                    capabilityPacket = CapabilitySignedDiscoveryPacket.Create(
                        localAdvertisement,
                        signingIdentity,
                        identityRevision,
                        normalizedCapabilities,
                        capabilityRevision);
                    capabilities = normalizedCapabilities;
                }
                catch (Exception ex) when (ex is InvalidDataException or CryptographicException)
                {
                    // M2.6.2 is additive. A local capability-state problem must never
                    // disable the older signed identity advertisements used for compatibility.
                    log?.Invoke($"GNP/1 M2.6.2 capability advertisement is unavailable; GLS2/GLS1 compatibility discovery remains active: {ex.Message}");
                    capabilityPacket = null;
                }
            }
        }

        var broadcast = new IPEndPoint(IPAddress.Broadcast, ProtocolConstants.DiscoveryPort);
        if (capabilityPacket is not null)
        {
            log?.Invoke($"Local discovery active on UDP {ProtocolConstants.DiscoveryPort} with GNP/1 M2.6.2 signed capability advertisements (identity revision {identityRevision}, capability revision {capabilityRevision}, capabilities {capabilities}).");
        }
        else if (replayProtectedPacket is not null)
        {
            log?.Invoke($"Local discovery active on UDP {ProtocolConstants.DiscoveryPort} with GNP/1 M2.5.3 replay-protected signed identity advertisements (revision {identityRevision}).");
        }
        else
        {
            log?.Invoke(signedPacket is null
                ? $"Local discovery active on UDP {ProtocolConstants.DiscoveryPort}."
                : $"Local discovery active on UDP {ProtocolConstants.DiscoveryPort} with GNP/1 M2.2 signed identity advertisements.");
        }

        var receiveTask = ReceiveLoopAsync(udp, localAdvertisement.DeviceId, deviceSeen, log, cancellationToken);
        var announceTask = AnnounceLoopAsync(udp, legacyPacket, signedPacket, replayProtectedPacket, capabilityPacket, broadcast, cancellationToken);
        await Task.WhenAll(receiveTask, announceTask).ConfigureAwait(false);
    }

    private static async Task AnnounceLoopAsync(
        UdpClient udp,
        byte[] legacyPacket,
        byte[]? signedPacket,
        byte[]? replayProtectedPacket,
        byte[]? capabilityPacket,
        IPEndPoint broadcast,
        CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            // Newest proof first. M2.6.2 peers prefer GLC1, M2.5.3 peers still
            // understand GLS2, M2.2 peers understand GLS1, and older peers keep GLD2.
            if (capabilityPacket is not null)
            {
                await udp.SendAsync(capabilityPacket, broadcast, cancellationToken).ConfigureAwait(false);
            }

            if (replayProtectedPacket is not null)
            {
                await udp.SendAsync(replayProtectedPacket, broadcast, cancellationToken).ConfigureAwait(false);
            }

            if (signedPacket is not null)
            {
                await udp.SendAsync(signedPacket, broadcast, cancellationToken).ConfigureAwait(false);
            }

            await udp.SendAsync(legacyPacket, broadcast, cancellationToken).ConfigureAwait(false);
            await Task.Delay(ProtocolConstants.DiscoveryInterval, cancellationToken).ConfigureAwait(false);
        }
    }

    private static async Task ReceiveLoopAsync(
        UdpClient udp,
        Guid localDeviceId,
        Action<DiscoveredDevice> deviceSeen,
        Action<string>? log,
        CancellationToken cancellationToken)
    {
        var recentlySigned = new Dictionary<Guid, DateTimeOffset>();
        var recentlyReplayProtected = new Dictionary<Guid, DateTimeOffset>();
        var recentlyCapability = new Dictionary<Guid, DateTimeOffset>();
        var verifiedSigningKeys = new Dictionary<Guid, string>();
        var verifiedSignedPackets = new Dictionary<string, SignedDiscoveryAdvertisement>(StringComparer.Ordinal);

        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await udp.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                return;
            }

            try
            {
                if (result.RemoteEndPoint.Address.AddressFamily != AddressFamily.InterNetwork ||
                    !LocalNetworkPolicy.IsAllowedAddress(result.RemoteEndPoint.Address))
                {
                    continue;
                }

                if (CapabilitySignedDiscoveryPacket.HasMagic(result.Buffer))
                {
                    var signed = ParseCachedSignedPacket(result.Buffer, verifiedSignedPackets);
                    var advertisement = signed.Advertisement;
                    if (advertisement.DeviceId == localDeviceId)
                    {
                        continue;
                    }

                    var now = DateTimeOffset.UtcNow;
                    RemoveExpiredSignedEntries(recentlySigned, now);
                    RemoveExpiredSignedEntries(recentlyReplayProtected, now);
                    RemoveExpiredSignedEntries(recentlyCapability, now);
                    RememberSeen(recentlySigned, advertisement.DeviceId, now);
                    RememberSeen(recentlyReplayProtected, advertisement.DeviceId, now);
                    RememberSeen(recentlyCapability, advertisement.DeviceId, now);
                    LogVerifiedSigningIdentity(verifiedSigningKeys, signed, log, SignedDiscoveryKind.Capability);

                    deviceSeen(new DiscoveredDevice(
                        advertisement.DeviceId,
                        advertisement.DeviceName,
                        result.RemoteEndPoint.Address,
                        advertisement.TransferPort,
                        advertisement.PairingPort,
                        advertisement.PublicKeyFingerprint,
                        advertisement.Kind,
                        now,
                        DiscoveryIdentityProof.CapabilitySignedIdentityV2,
                        signed.SigningKeyId,
                        signed.IdentityVersion,
                        signed.KeyGeneration,
                        signed.IdentityRevision,
                        signed.Capabilities,
                        signed.CapabilityRevision));
                    continue;
                }

                if (ReplayProtectedSignedDiscoveryPacket.HasMagic(result.Buffer))
                {
                    var signed = ParseCachedSignedPacket(result.Buffer, verifiedSignedPackets);
                    var advertisement = signed.Advertisement;
                    if (advertisement.DeviceId == localDeviceId)
                    {
                        continue;
                    }

                    var now = DateTimeOffset.UtcNow;
                    RemoveExpiredSignedEntries(recentlySigned, now);
                    RemoveExpiredSignedEntries(recentlyReplayProtected, now);
                    RemoveExpiredSignedEntries(recentlyCapability, now);
                    if (recentlyCapability.TryGetValue(advertisement.DeviceId, out var capabilitySeenUtc) &&
                        now - capabilitySeenUtc <= ProtocolConstants.DiscoveryExpiry)
                    {
                        // Never downgrade a M2.6.2 peer to the compatibility GLS2 packet
                        // that it broadcasts immediately after GLC1.
                        continue;
                    }

                    RememberSeen(recentlySigned, advertisement.DeviceId, now);
                    RememberSeen(recentlyReplayProtected, advertisement.DeviceId, now);
                    LogVerifiedSigningIdentity(verifiedSigningKeys, signed, log, SignedDiscoveryKind.ReplayProtected);

                    deviceSeen(new DiscoveredDevice(
                        advertisement.DeviceId,
                        advertisement.DeviceName,
                        result.RemoteEndPoint.Address,
                        advertisement.TransferPort,
                        advertisement.PairingPort,
                        advertisement.PublicKeyFingerprint,
                        advertisement.Kind,
                        now,
                        DiscoveryIdentityProof.ReplayProtectedSignedIdentityV2,
                        signed.SigningKeyId,
                        signed.IdentityVersion,
                        signed.KeyGeneration,
                        signed.IdentityRevision));
                    continue;
                }

                if (SignedDiscoveryPacket.HasSignedMagic(result.Buffer))
                {
                    var signed = ParseCachedSignedPacket(result.Buffer, verifiedSignedPackets);
                    var advertisement = signed.Advertisement;
                    if (advertisement.DeviceId == localDeviceId)
                    {
                        continue;
                    }

                    var now = DateTimeOffset.UtcNow;
                    RemoveExpiredSignedEntries(recentlySigned, now);
                    RemoveExpiredSignedEntries(recentlyReplayProtected, now);
                    RemoveExpiredSignedEntries(recentlyCapability, now);
                    // Never downgrade a peer from GLS2 to GLS1; GLC1 is stronger still.
                    if ((recentlyCapability.TryGetValue(advertisement.DeviceId, out var capabilitySeenUtc) &&
                         now - capabilitySeenUtc <= ProtocolConstants.DiscoveryExpiry) ||
                        (recentlyReplayProtected.TryGetValue(advertisement.DeviceId, out var protectedSeenUtc) &&
                         now - protectedSeenUtc <= ProtocolConstants.DiscoveryExpiry))
                    {
                        continue;
                    }

                    RememberSeen(recentlySigned, advertisement.DeviceId, now);
                    LogVerifiedSigningIdentity(verifiedSigningKeys, signed, log, SignedDiscoveryKind.Signed);

                    deviceSeen(new DiscoveredDevice(
                        advertisement.DeviceId,
                        advertisement.DeviceName,
                        result.RemoteEndPoint.Address,
                        advertisement.TransferPort,
                        advertisement.PairingPort,
                        advertisement.PublicKeyFingerprint,
                        advertisement.Kind,
                        now,
                        DiscoveryIdentityProof.SignedIdentityV2,
                        signed.SigningKeyId,
                        signed.IdentityVersion,
                        signed.KeyGeneration));
                    continue;
                }

                var legacyAdvertisement = DiscoveryPacket.Parse(result.Buffer);
                if (legacyAdvertisement.DeviceId == localDeviceId)
                {
                    continue;
                }

                var legacyNow = DateTimeOffset.UtcNow;
                RemoveExpiredSignedEntries(recentlySigned, legacyNow);
                if (recentlySigned.TryGetValue(legacyAdvertisement.DeviceId, out var signedSeenUtc) &&
                    legacyNow - signedSeenUtc <= ProtocolConstants.DiscoveryExpiry)
                {
                    continue;
                }

                deviceSeen(new DiscoveredDevice(
                    legacyAdvertisement.DeviceId,
                    legacyAdvertisement.DeviceName,
                    result.RemoteEndPoint.Address,
                    legacyAdvertisement.TransferPort,
                    legacyAdvertisement.PairingPort,
                    legacyAdvertisement.PublicKeyFingerprint,
                    legacyAdvertisement.Kind,
                    legacyNow));
            }
            catch (InvalidDataException)
            {
                // LAN discovery input is untrusted. Malformed or unverifiable packets
                // are ignored; trust-sensitive capability state is applied later only
                // after matching the pinned pairing + signing identity.
            }
        }
    }

    private static SignedDiscoveryAdvertisement ParseCachedSignedPacket(
        byte[] packet,
        Dictionary<string, SignedDiscoveryAdvertisement> cache)
    {
        var packetHashBytes = SHA256.HashData(packet);
        try
        {
            var packetHash = Convert.ToHexString(packetHashBytes);
            if (cache.TryGetValue(packetHash, out var cached))
            {
                return cached;
            }

            SignedDiscoveryAdvertisement parsed;
            if (CapabilitySignedDiscoveryPacket.HasMagic(packet))
            {
                parsed = CapabilitySignedDiscoveryPacket.ParseAndVerify(packet);
            }
            else if (ReplayProtectedSignedDiscoveryPacket.HasMagic(packet))
            {
                parsed = ReplayProtectedSignedDiscoveryPacket.ParseAndVerify(packet);
            }
            else
            {
                parsed = SignedDiscoveryPacket.ParseAndVerify(packet);
            }

            if (cache.Count < MaxSignedPeerCacheEntries)
            {
                cache[packetHash] = parsed;
            }

            return parsed;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(packetHashBytes);
        }
    }

    private static void RememberSeen(Dictionary<Guid, DateTimeOffset> entries, Guid deviceId, DateTimeOffset now)
    {
        if (entries.ContainsKey(deviceId) || entries.Count < MaxSignedPeerCacheEntries)
        {
            entries[deviceId] = now;
        }
    }

    private static void LogVerifiedSigningIdentity(
        Dictionary<Guid, string> verifiedSigningKeys,
        SignedDiscoveryAdvertisement signed,
        Action<string>? log,
        SignedDiscoveryKind kind)
    {
        var advertisement = signed.Advertisement;
        if (verifiedSigningKeys.TryGetValue(advertisement.DeviceId, out var previousSigningKeyId))
        {
            if (!string.Equals(previousSigningKeyId, signed.SigningKeyId, StringComparison.OrdinalIgnoreCase))
            {
                verifiedSigningKeys[advertisement.DeviceId] = signed.SigningKeyId;
                log?.Invoke($"GNP/1 M2.2 signing key changed in discovery for {advertisement.DeviceName}: {previousSigningKeyId} -> {signed.SigningKeyId}.");
            }

            return;
        }

        if (verifiedSigningKeys.Count >= MaxSignedPeerCacheEntries)
        {
            return;
        }

        verifiedSigningKeys[advertisement.DeviceId] = signed.SigningKeyId;
        log?.Invoke(kind switch
        {
            SignedDiscoveryKind.Capability =>
                $"GNP/1 M2.6.2 signed capability advertisement verified for {advertisement.DeviceName}: {signed.SigningKeyId} (generation {signed.KeyGeneration}, identity revision {signed.IdentityRevision}, capability revision {signed.CapabilityRevision}, capabilities {signed.Capabilities}). Trust not yet implied.",
            SignedDiscoveryKind.ReplayProtected =>
                $"GNP/1 M2.5.3 replay-protected signed discovery verified for {advertisement.DeviceName}: {signed.SigningKeyId} (generation {signed.KeyGeneration}, revision {signed.IdentityRevision}).",
            _ =>
                $"GNP/1 M2.2 signed discovery verified for {advertisement.DeviceName}: {signed.SigningKeyId} (generation {signed.KeyGeneration})."
        });
    }

    private static void RemoveExpiredSignedEntries(Dictionary<Guid, DateTimeOffset> entries, DateTimeOffset now)
    {
        if (entries.Count == 0)
        {
            return;
        }

        foreach (var deviceId in entries
                     .Where(item => now - item.Value > ProtocolConstants.DiscoveryExpiry)
                     .Select(item => item.Key)
                     .ToArray())
        {
            entries.Remove(deviceId);
        }
    }

    private enum SignedDiscoveryKind
    {
        Signed,
        ReplayProtected,
        Capability
    }
}
