using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using GeniaLink.Core.Network;

namespace GeniaLink.Android.Services;

internal sealed record AndroidResumeEntry(
    string ResumeKey,
    string UriString,
    string RelativePath,
    string PartialName,
    long FileSize,
    string Sha256Base64,
    DateTimeOffset UpdatedAtUtc);

internal sealed class AndroidResumeIndex
{
    private const long MaxStoreBytes = 256 * 1024;
    private const int MaxEntries = 64;
    private const int MaxUriCharacters = 4096;
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };
    private readonly string _path;
    private readonly Dictionary<string, AndroidResumeEntry> _entries = new(StringComparer.Ordinal);
    private readonly object _gate = new();

    public AndroidResumeIndex(global::Android.Content.Context context, Action<string>? log)
    {
        ArgumentNullException.ThrowIfNull(context);
        var filesDirectory = context.FilesDir?.AbsolutePath
            ?? throw new IOException("Android app files directory is unavailable.");
        Directory.CreateDirectory(filesDirectory);
        _path = Path.Combine(filesDirectory, "resume-index.json");
        Load(log);
    }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    public AndroidResumeEntry? GetMatching(
        string resumeKey,
        string relativePath,
        string partialName,
        long fileSize,
        ReadOnlySpan<byte> sha256)
    {
        var expectedHash = Convert.ToBase64String(sha256);
        lock (_gate)
        {
            if (!_entries.TryGetValue(resumeKey, out var entry))
            {
                return null;
            }

            return entry.FileSize == fileSize &&
                   string.Equals(entry.RelativePath, relativePath, StringComparison.Ordinal) &&
                   string.Equals(entry.PartialName, partialName, StringComparison.Ordinal) &&
                   string.Equals(entry.Sha256Base64, expectedHash, StringComparison.Ordinal)
                ? entry
                : null;
        }
    }

    public void Upsert(
        string resumeKey,
        global::Android.Net.Uri uri,
        string relativePath,
        string partialName,
        long fileSize,
        ReadOnlySpan<byte> sha256)
    {
        ArgumentNullException.ThrowIfNull(uri);
        var uriString = uri.ToString();
        if (string.IsNullOrWhiteSpace(uriString) || uriString.Length > MaxUriCharacters)
        {
            throw new InvalidDataException("Android resume URI is invalid.");
        }

        var entry = new AndroidResumeEntry(
            resumeKey,
            uriString,
            relativePath,
            partialName,
            fileSize,
            Convert.ToBase64String(sha256),
            DateTimeOffset.UtcNow);

        lock (_gate)
        {
            if (!_entries.ContainsKey(resumeKey) && _entries.Count >= MaxEntries)
            {
                throw new InvalidDataException("Android resume index reached its safe entry limit.");
            }

            var hadPrevious = _entries.TryGetValue(resumeKey, out var previous);
            _entries[resumeKey] = entry;
            try
            {
                SaveLocked();
            }
            catch
            {
                if (hadPrevious && previous is not null)
                {
                    _entries[resumeKey] = previous;
                }
                else
                {
                    _entries.Remove(resumeKey);
                }

                throw;
            }
        }
    }

    public void Touch(string resumeKey)
    {
        lock (_gate)
        {
            if (!_entries.TryGetValue(resumeKey, out var entry))
            {
                return;
            }

            var previous = entry;
            _entries[resumeKey] = entry with { UpdatedAtUtc = DateTimeOffset.UtcNow };
            try
            {
                SaveLocked();
            }
            catch
            {
                _entries[resumeKey] = previous;
                throw;
            }
        }
    }

    public bool Remove(string resumeKey)
    {
        lock (_gate)
        {
            if (!_entries.Remove(resumeKey, out var removed))
            {
                return false;
            }

            try
            {
                SaveLocked();
                return true;
            }
            catch
            {
                _entries[resumeKey] = removed;
                throw;
            }
        }
    }

    public AndroidResumeEntry[] GetStale(DateTimeOffset cutoffUtc)
    {
        lock (_gate)
        {
            return _entries.Values
                .Where(entry => entry.UpdatedAtUtc < cutoffUtc)
                .ToArray();
        }
    }

    public AndroidResumeEntry[] GetAll()
    {
        lock (_gate)
        {
            return _entries.Values.ToArray();
        }
    }

    private void Load(Action<string>? log)
    {
        if (!File.Exists(_path))
        {
            return;
        }

        try
        {
            if (new FileInfo(_path).Length > MaxStoreBytes)
            {
                throw new InvalidDataException("Android resume index is unexpectedly large.");
            }

            var json = File.ReadAllText(_path);
            var records = JsonSerializer.Deserialize<List<AndroidResumeEntry>>(json) ?? [];
            foreach (var record in records.Take(MaxEntries))
            {
                if (!IsValidRecord(record))
                {
                    continue;
                }

                _entries[record.ResumeKey] = record;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            log?.Invoke($"Android resume index could not be loaded: {ex.Message}");
        }
    }

    private static bool IsValidRecord(AndroidResumeEntry? record)
    {
        if (record is null ||
            string.IsNullOrWhiteSpace(record.ResumeKey) ||
            string.IsNullOrWhiteSpace(record.UriString) ||
            string.IsNullOrWhiteSpace(record.RelativePath) ||
            string.IsNullOrWhiteSpace(record.PartialName) ||
            string.IsNullOrWhiteSpace(record.Sha256Base64) ||
            record.ResumeKey.Length != 32 ||
            record.ResumeKey.Any(ch => !global::System.Uri.IsHexDigit(ch)) ||
            record.UriString.Length is < 10 or > MaxUriCharacters ||
            !record.UriString.StartsWith("content://", StringComparison.Ordinal) ||
            record.FileSize < 0 || record.FileSize > ProtocolConstants.MaxFileSize ||
            !record.PartialName.Equals($".genialink-{record.ResumeKey}.part", StringComparison.Ordinal) ||
            !record.RelativePath.StartsWith("Download/Genia Link/", StringComparison.Ordinal) ||
            record.RelativePath.Split('/', StringSplitOptions.RemoveEmptyEntries).Any(segment => segment is "." or ".."))
        {
            return false;
        }

        byte[]? hash = null;
        try
        {
            hash = Convert.FromBase64String(record.Sha256Base64);
            return hash.Length == 32;
        }
        catch (FormatException)
        {
            return false;
        }
        finally
        {
            if (hash is not null)
            {
                CryptographicOperations.ZeroMemory(hash);
            }
        }
    }

    private void SaveLocked()
    {
        var json = JsonSerializer.Serialize(
            _entries.Values.OrderBy(entry => entry.ResumeKey, StringComparer.Ordinal),
            IndentedJsonOptions);
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
