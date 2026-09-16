using System.Text;
using System.Text.Json;
using GeniaLink.Core.Identity;

namespace GeniaLink.Core.Capabilities;

/// <summary>
/// Persists a monotonically increasing revision for the local capability assertion.
/// A dedicated revision is required because capabilities may change without an
/// identity rename/key-generation change, while replayed older advertisements must
/// never roll the trusted peer back to a previous capability set.
/// </summary>
public static class CapabilityAssertionRevisionStore
{
    private const int CurrentSchemaVersion = 1;
    private const long MaxStoreBytes = 64 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };
    private static readonly object Gate = new();

    public static long LoadOrAdvance(
        string path,
        IDeviceSigningIdentity identity,
        DeviceCapability capabilities,
        Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.DeviceId == Guid.Empty || identity.KeyGeneration < 1 || string.IsNullOrWhiteSpace(identity.SigningKeyId))
        {
            throw new InvalidDataException("Capability revision requires a complete signing identity.");
        }

        var normalizedCapabilities = DeviceCapabilityProfiles.NormalizeSelection(capabilities);
        if (!DeviceCapabilityProfiles.IsValidAdvertisement(normalizedCapabilities))
        {
            throw new InvalidDataException("Capability revision requires a valid GNP/1 capability set.");
        }

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory))
        {
            Directory.CreateDirectory(directory);
        }

        lock (Gate)
        {
            var previous = TryLoad(fullPath, log) ?? TryLoad(fullPath + ".bak", log);
            if (previous is not null && previous.DeviceId == identity.DeviceId)
            {
                ValidateRevision(previous.Revision);
                if (Matches(previous, identity, normalizedCapabilities))
                {
                    return previous.Revision;
                }

                var nextRevision = checked(previous.Revision + 1);
                Save(fullPath, CreateDocument(identity, normalizedCapabilities, nextRevision));
                log?.Invoke($"GNP/1 M2.6.2 local capability revision advanced: {previous.Revision} -> {nextRevision} ({normalizedCapabilities}).");
                return nextRevision;
            }

            var recoveryBaseline = Math.Max(1L, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            Save(fullPath, CreateDocument(identity, normalizedCapabilities, recoveryBaseline));
            log?.Invoke($"GNP/1 M2.6.2 local capability revision initialized at {recoveryBaseline} ({normalizedCapabilities}).");
            return recoveryBaseline;
        }
    }

    private static CapabilityAssertionRevisionDocument? TryLoad(string path, Action<string>? log)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            if (new FileInfo(path).Length > MaxStoreBytes)
            {
                throw new InvalidDataException("Capability assertion revision store is unexpectedly large.");
            }

            var json = File.ReadAllText(path, StrictUtf8);
            var document = JsonSerializer.Deserialize<CapabilityAssertionRevisionDocument>(json)
                ?? throw new InvalidDataException("Capability assertion revision store is empty.");
            if (document.SchemaVersion != CurrentSchemaVersion || document.DeviceId == Guid.Empty)
            {
                throw new InvalidDataException("Capability assertion revision store schema or Device ID is invalid.");
            }

            ValidateRevision(document.Revision);
            if (document.KeyGeneration < 1 || string.IsNullOrWhiteSpace(document.SigningKeyId))
            {
                throw new InvalidDataException("Capability assertion revision store contains invalid signing metadata.");
            }

            var capabilities = (DeviceCapability)document.Capabilities;
            if (!DeviceCapabilityProfiles.IsValidAdvertisement(capabilities))
            {
                throw new InvalidDataException("Capability assertion revision store contains an invalid capability set.");
            }

            return document;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or DecoderFallbackException or EncoderFallbackException)
        {
            log?.Invoke($"GNP/1 M2.6.2 capability revision store could not be loaded from {Path.GetFileName(path)}: {ex.Message}");
            return null;
        }
    }

    private static bool Matches(
        CapabilityAssertionRevisionDocument previous,
        IDeviceSigningIdentity identity,
        DeviceCapability capabilities) =>
        previous.KeyGeneration == identity.KeyGeneration &&
        string.Equals(previous.SigningKeyId, identity.SigningKeyId, StringComparison.OrdinalIgnoreCase) &&
        previous.Capabilities == (long)capabilities;

    private static CapabilityAssertionRevisionDocument CreateDocument(
        IDeviceSigningIdentity identity,
        DeviceCapability capabilities,
        long revision) =>
        new(
            CurrentSchemaVersion,
            identity.DeviceId,
            revision,
            identity.KeyGeneration,
            identity.SigningKeyId,
            (long)capabilities,
            DateTimeOffset.UtcNow);

    private static void Save(string path, CapabilityAssertionRevisionDocument document)
    {
        var json = JsonSerializer.Serialize(document, IndentedJsonOptions);
        if (StrictUtf8.GetByteCount(json) > MaxStoreBytes)
        {
            throw new InvalidDataException("Capability assertion revision store exceeds its safe size limit.");
        }

        var tempPath = path + ".tmp";
        try
        {
            File.WriteAllText(tempPath, json, StrictUtf8);
            if (File.Exists(path))
            {
                File.Copy(path, path + ".bak", overwrite: true);
            }

            File.Move(tempPath, path, overwrite: true);
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

    private static void ValidateRevision(long revision)
    {
        if (revision < 1)
        {
            throw new InvalidDataException("Capability assertion revision must be positive.");
        }
    }

    private sealed record CapabilityAssertionRevisionDocument(
        int SchemaVersion,
        Guid DeviceId,
        long Revision,
        int KeyGeneration,
        string SigningKeyId,
        long Capabilities,
        DateTimeOffset UpdatedAtUtc);
}
