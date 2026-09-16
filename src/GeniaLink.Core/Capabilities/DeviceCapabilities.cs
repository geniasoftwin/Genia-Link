namespace GeniaLink.Core.Capabilities;

public enum DeviceRoleProfile
{
    Client = 0,
    Server = 1,
    Relay = 2,
    Backup = 3,
    Custom = 4
}

[Flags]
public enum DeviceCapability
{
    None = 0,
    TrustedDiscovery = 1 << 0,
    TrustedTransport = 1 << 1,
    FileTransfer = 1 << 2,
    SharedResources = 1 << 3,
    BackgroundAvailability = 1 << 4,
    NetworkEvents = 1 << 5,
    Sync = 1 << 6,
    Relay = 1 << 7,
    Backup = 1 << 8,
    PrinterGateway = 1 << 9,
    Messaging = 1 << 10
}

public static class DeviceCapabilityProfiles
{
    public const DeviceCapability CoreRequirements =
        DeviceCapability.TrustedDiscovery |
        DeviceCapability.TrustedTransport;

    public const DeviceCapability KnownCapabilities =
        DeviceCapability.TrustedDiscovery |
        DeviceCapability.TrustedTransport |
        DeviceCapability.FileTransfer |
        DeviceCapability.SharedResources |
        DeviceCapability.BackgroundAvailability |
        DeviceCapability.NetworkEvents |
        DeviceCapability.Sync |
        DeviceCapability.Relay |
        DeviceCapability.Backup |
        DeviceCapability.PrinterGateway |
        DeviceCapability.Messaging;

    public static DeviceRoleProfile NormalizeRole(DeviceRoleProfile role) => role switch
    {
        DeviceRoleProfile.Client => DeviceRoleProfile.Client,
        DeviceRoleProfile.Server => DeviceRoleProfile.Server,
        DeviceRoleProfile.Relay => DeviceRoleProfile.Relay,
        DeviceRoleProfile.Backup => DeviceRoleProfile.Backup,
        DeviceRoleProfile.Custom => DeviceRoleProfile.Custom,
        _ => DeviceRoleProfile.Client
    };

    public static DeviceCapability GetRequired(DeviceRoleProfile role) => NormalizeRole(role) switch
    {
        DeviceRoleProfile.Client => CoreRequirements,
        DeviceRoleProfile.Server => CoreRequirements | DeviceCapability.BackgroundAvailability,
        DeviceRoleProfile.Relay => CoreRequirements | DeviceCapability.BackgroundAvailability | DeviceCapability.Relay,
        DeviceRoleProfile.Backup => CoreRequirements | DeviceCapability.BackgroundAvailability | DeviceCapability.Backup,
        DeviceRoleProfile.Custom => CoreRequirements,
        _ => CoreRequirements
    };

    public static DeviceCapability GetPreset(DeviceRoleProfile role) => NormalizeRole(role) switch
    {
        DeviceRoleProfile.Client =>
            CoreRequirements |
            DeviceCapability.FileTransfer |
            DeviceCapability.SharedResources,
        DeviceRoleProfile.Server =>
            CoreRequirements |
            DeviceCapability.FileTransfer |
            DeviceCapability.SharedResources |
            DeviceCapability.BackgroundAvailability |
            DeviceCapability.NetworkEvents |
            DeviceCapability.Sync,
        DeviceRoleProfile.Relay =>
            CoreRequirements |
            DeviceCapability.BackgroundAvailability |
            DeviceCapability.Relay,
        DeviceRoleProfile.Backup =>
            CoreRequirements |
            DeviceCapability.FileTransfer |
            DeviceCapability.BackgroundAvailability |
            DeviceCapability.Sync |
            DeviceCapability.Backup,
        DeviceRoleProfile.Custom => CoreRequirements | DeviceCapability.FileTransfer,
        _ => CoreRequirements | DeviceCapability.FileTransfer
    };

    /// <summary>
    /// Normalizes a capability set independently from a UI role. M2.6.2 makes the
    /// capability set authoritative and derives the user-facing role from it.
    /// </summary>
    public static DeviceCapability NormalizeSelection(DeviceCapability selected) =>
        (selected & KnownCapabilities) | CoreRequirements;

    public static DeviceCapability Normalize(DeviceRoleProfile role, DeviceCapability selected) =>
        (selected & KnownCapabilities) | GetRequired(role);

    public static DeviceRoleProfile ResolveProfile(DeviceCapability capabilities)
    {
        var normalized = NormalizeSelection(capabilities);
        if (normalized == GetPreset(DeviceRoleProfile.Client))
        {
            return DeviceRoleProfile.Client;
        }

        if (normalized == GetPreset(DeviceRoleProfile.Server))
        {
            return DeviceRoleProfile.Server;
        }

        if (normalized == GetPreset(DeviceRoleProfile.Relay))
        {
            return DeviceRoleProfile.Relay;
        }

        if (normalized == GetPreset(DeviceRoleProfile.Backup))
        {
            return DeviceRoleProfile.Backup;
        }

        return DeviceRoleProfile.Custom;
    }

    public static bool IsKnownSet(DeviceCapability capabilities) =>
        (capabilities & ~KnownCapabilities) == DeviceCapability.None;

    public static bool IsValidAdvertisement(DeviceCapability capabilities) =>
        capabilities != DeviceCapability.None &&
        IsKnownSet(capabilities) &&
        (capabilities & CoreRequirements) == CoreRequirements;

    public static bool IsRequired(DeviceRoleProfile role, DeviceCapability capability) =>
        (GetRequired(role) & capability) == capability;
}
