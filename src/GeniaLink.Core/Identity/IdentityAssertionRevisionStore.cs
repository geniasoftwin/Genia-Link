using System.Text;
using System.Text.Json;
using GeniaLink.Core.Discovery;

namespace GeniaLink.Core.Identity;

/// <summary>
/// Persists a monotonically increasing local revision for the public identity assertion
/// carried by replay-protected discovery. The revision advances whenever a field signed
/// into the assertion changes (name, kind, signing generation or signing key ID).
/// </summary>
public static class IdentityAssertionRevisionStore
{
    private const int CurrentSchemaVersion = 1;
    private const long MaxStoreBytes = 64 * 1024;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };
    private static readonly object Gate = new();

    public static long LoadOrAdvance(string path, IDeviceSigningIdentity identity, Action<string>? log = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(identity);
        if (identity.DeviceId == Guid.Empty || identity.KeyGeneration < 1 || string.IsNullOrWhiteSpace(identity.SigningKeyId))
        {
            throw new InvalidDataException("Replay-protected identity revision requires a complete signing identity.");
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
                if (Matches(previous, identity))
                {
                    return previous.Revision;
                }

                var nextRevision = checked(previous.Revision + 1);
                Save(fullPath, CreateDocument(identity, nextRevision));
                log?.Invoke($"GNP/1 M2.5.3 local identity assertion revision advanced: {previous.Revision} -> {nextRevision}.");
                return nextRevision;
            }

            // A time-based baseline makes recovery from a lost/corrupt revision file overwhelmingly
            // likely to advance beyond any previously issued small counter while remaining monotonic
            // for subsequent changes because the persisted value is incremented from then on.
            var recoveryBaseline = Math.Max(1L, DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            Save(fullPath, CreateDocument(identity, recoveryBaseline));
            log?.Invoke($"GNP/1 M2.5.3 local identity assertion revision initialized at {recoveryBaseline}.");
            return recoveryBaseline;
        }
    }

    private static IdentityAssertionRevisionDocument? TryLoad(string path, Action<string>? log)
    {
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            if (new FileInfo(path).Length > MaxStoreBytes)
            {
                throw new InvalidDataException("Identity assertion revision store is unexpectedly large.");
            }

            var json = File.ReadAllText(path, StrictUtf8);
            var document = JsonSerializer.Deserialize<IdentityAssertionRevisionDocument>(json)
                ?? throw new InvalidDataException("Identity assertion revision store is empty.");
            if (document.SchemaVersion != CurrentSchemaVersion || document.DeviceId == Guid.Empty)
            {
                throw new InvalidDataException("Identity assertion revision store schema or Device ID is invalid.");
            }

            ValidateRevision(document.Revision);
            ValidateDisplayName(document.DisplayName);
            if (!Enum.IsDefined(document.DeviceKind) || document.KeyGeneration < 1 || string.IsNullOrWhiteSpace(document.SigningKeyId))
            {
                throw new InvalidDataException("Identity assertion revision store contains invalid identity metadata.");
            }

            return document;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or DecoderFallbackException or EncoderFallbackException)
        {
            log?.Invoke($"GNP/1 M2.5.3 identity assertion revision store could not be loaded from {Path.GetFileName(path)}: {ex.Message}");
            return null;
        }
    }

    private static bool Matches(IdentityAssertionRevisionDocument previous, IDeviceSigningIdentity identity) =>
        string.Equals(previous.DisplayName, identity.DisplayName, StringComparison.Ordinal) &&
        previous.DeviceKind == identity.DeviceKind &&
        previous.KeyGeneration == identity.KeyGeneration &&
        string.Equals(previous.SigningKeyId, identity.SigningKeyId, StringComparison.OrdinalIgnoreCase);

    private static IdentityAssertionRevisionDocument CreateDocument(IDeviceSigningIdentity identity, long revision) =>
        new(
            CurrentSchemaVersion,
            identity.DeviceId,
            revision,
            identity.DisplayName,
            identity.DeviceKind,
            identity.KeyGeneration,
            identity.SigningKeyId,
            DateTimeOffset.UtcNow);

    private static void Save(string path, IdentityAssertionRevisionDocument document)
    {
        var json = JsonSerializer.Serialize(document, IndentedJsonOptions);
        if (StrictUtf8.GetByteCount(json) > MaxStoreBytes)
        {
            throw new InvalidDataException("Identity assertion revision store exceeds its safe size limit.");
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
            throw new InvalidDataException("Identity assertion revision must be positive.");
        }
    }

    private static void ValidateDisplayName(string? displayName)
    {
        if (string.IsNullOrWhiteSpace(displayName) || StrictUtf8.GetByteCount(displayName) > 160 || displayName.Any(char.IsControl))
        {
            throw new InvalidDataException("Identity assertion revision display name is invalid.");
        }
    }

    private sealed record IdentityAssertionRevisionDocument(
        int SchemaVersion,
        Guid DeviceId,
        long Revision,
        string DisplayName,
        DeviceKind DeviceKind,
        int KeyGeneration,
        string SigningKeyId,
        DateTimeOffset UpdatedAtUtc);
}
