using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace GeniaLink.Core.Security;

public static class FileSafety
{
    private static readonly HashSet<string> ReservedWindowsNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    };

    public static bool IsSafeFileName(string? fileName) => IsSafePathSegment(fileName);

    public static bool IsSafePathSegment(string? segment)
    {
        if (string.IsNullOrWhiteSpace(segment) || segment.Length > 240)
        {
            return false;
        }

        if (!string.Equals(segment, Path.GetFileName(segment), StringComparison.Ordinal))
        {
            return false;
        }

        if (segment is "." or "..")
        {
            return false;
        }

        if (segment.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            segment.Contains('/') || segment.Contains('\\') || segment.Contains(':') ||
            segment.Any(ch => char.IsControl(ch) || CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.Format))
        {
            return false;
        }

        if (segment.EndsWith(' ') || segment.EndsWith('.'))
        {
            return false;
        }

        var deviceStem = segment.Split('.', 2)[0];
        return !ReservedWindowsNames.Contains(deviceStem);
    }

    public static bool IsSafeRelativeDirectory(string? relativeDirectory)
    {
        if (string.IsNullOrEmpty(relativeDirectory))
        {
            return true;
        }

        if (relativeDirectory.Length > Network.ProtocolConstants.MaxRelativeDirectoryCharacters ||
            relativeDirectory.StartsWith('/') ||
            relativeDirectory.EndsWith('/') ||
            relativeDirectory.Contains('\\') ||
            relativeDirectory.Contains("//", StringComparison.Ordinal) ||
            relativeDirectory.Contains(':'))
        {
            return false;
        }

        var segments = relativeDirectory.Split('/', StringSplitOptions.None);
        return segments.Length <= Network.ProtocolConstants.MaxRelativeDirectoryDepth &&
               segments.All(IsSafePathSegment);
    }

    public static string NormalizeRelativeDirectory(string? relativeDirectory)
    {
        if (string.IsNullOrWhiteSpace(relativeDirectory))
        {
            return string.Empty;
        }

        var normalized = relativeDirectory.Replace('\\', '/').Trim('/');
        if (!IsSafeRelativeDirectory(normalized))
        {
            throw new InvalidDataException("Unsafe relative directory.");
        }

        return normalized;
    }

    public static bool IsSafeRelativeFilePath(string? relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath) ||
            relativePath.Length > Network.ProtocolConstants.MaxRelativeDirectoryCharacters + 241 ||
            relativePath.StartsWith('/') ||
            relativePath.EndsWith('/') ||
            relativePath.Contains('\\') ||
            relativePath.Contains("//", StringComparison.Ordinal) ||
            relativePath.Contains(':'))
        {
            return false;
        }

        var separator = relativePath.LastIndexOf('/');
        if (separator < 0)
        {
            return IsSafeFileName(relativePath);
        }

        var directory = relativePath[..separator];
        var fileName = relativePath[(separator + 1)..];
        return IsSafeRelativeDirectory(directory) && IsSafeFileName(fileName);
    }

    public static string NormalizeRelativeFilePath(string? relativePath)
    {
        if (string.IsNullOrWhiteSpace(relativePath))
        {
            throw new InvalidDataException("Remote file path is empty.");
        }

        var normalized = relativePath.Replace('\\', '/').Trim('/');
        if (!IsSafeRelativeFilePath(normalized))
        {
            throw new InvalidDataException("Unsafe remote file path.");
        }

        return normalized;
    }

    public static string ResolveSharedFilePath(string rootDirectory, string relativePath)
    {
        var normalized = NormalizeRelativeFilePath(relativePath);
        var root = Path.GetFullPath(rootDirectory);
        if (!Directory.Exists(root))
        {
            throw new DirectoryNotFoundException("Genia Link folder does not exist.");
        }

        EnsureDirectoryIsNotReparsePoint(root);
        var current = root;
        var segments = normalized.Split('/');
        for (var index = 0; index < segments.Length - 1; index++)
        {
            current = EnsureInsideRoot(root, Path.Combine(current, segments[index]));
            if (!Directory.Exists(current))
            {
                throw new FileNotFoundException("Requested Genia Link folder entry no longer exists.");
            }

            EnsureDirectoryIsNotReparsePoint(current);
        }

        var filePath = EnsureInsideRoot(root, Path.Combine(current, segments[^1]));
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("Requested Genia Link file no longer exists.", filePath);
        }

        var attributes = File.GetAttributes(filePath);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Shared Genia Link files must not be symbolic links or reparse points.");
        }

        return filePath;
    }

    public static string GetUniqueDestinationPath(string rootDirectory, string fileName) =>
        GetUniqueDestinationPath(rootDirectory, string.Empty, fileName);

    public static string GetUniqueDestinationPath(string rootDirectory, string relativeDirectory, string fileName)
    {
        if (!IsSafeFileName(fileName))
        {
            throw new InvalidDataException("Unsafe file name.");
        }

        var normalizedDirectory = NormalizeRelativeDirectory(relativeDirectory);
        var root = Path.GetFullPath(rootDirectory);
        Directory.CreateDirectory(root);
        EnsureDirectoryIsNotReparsePoint(root);

        var destinationDirectory = root;
        if (normalizedDirectory.Length > 0)
        {
            foreach (var segment in normalizedDirectory.Split('/'))
            {
                destinationDirectory = EnsureInsideRoot(root, Path.Combine(destinationDirectory, segment));
                if (Directory.Exists(destinationDirectory))
                {
                    EnsureDirectoryIsNotReparsePoint(destinationDirectory);
                }
                else
                {
                    Directory.CreateDirectory(destinationDirectory);
                    EnsureDirectoryIsNotReparsePoint(destinationDirectory);
                }
            }
        }

        var candidate = EnsureInsideRoot(root, Path.Combine(destinationDirectory, fileName));
        if (!File.Exists(candidate) && !Directory.Exists(candidate))
        {
            return candidate;
        }

        var stem = Path.GetFileNameWithoutExtension(fileName);
        var extension = Path.GetExtension(fileName);
        for (var i = 1; i <= 9999; i++)
        {
            candidate = EnsureInsideRoot(root, Path.Combine(destinationDirectory, $"{stem} ({i}){extension}"));
            if (!File.Exists(candidate) && !Directory.Exists(candidate))
            {
                return candidate;
            }
        }

        throw new IOException("Could not choose a unique destination file name.");
    }

    public static string GetResumePartPath(
        string rootDirectory,
        string relativeDirectory,
        string fileName,
        long fileSize,
        ReadOnlySpan<byte> sha256)
    {
        if (sha256.Length != 32 || fileSize < 0)
        {
            throw new InvalidDataException("Invalid resumable-transfer metadata.");
        }

        var normalizedDirectory = NormalizeRelativeDirectory(relativeDirectory);
        if (!IsSafeFileName(fileName))
        {
            throw new InvalidDataException("Unsafe file name.");
        }

        var root = Path.GetFullPath(rootDirectory);
        Directory.CreateDirectory(root);
        EnsureDirectoryIsNotReparsePoint(root);
        var resumeDirectory = EnsureInsideRoot(root, Path.Combine(root, ".genialink-resume"));
        Directory.CreateDirectory(resumeDirectory);
        EnsureDirectoryIsNotReparsePoint(resumeDirectory);

        var key = CreateResumeKey(normalizedDirectory, fileName, fileSize, sha256);
        return EnsureInsideRoot(root, Path.Combine(resumeDirectory, $"{key}.part"));
    }

    public static string GetResumePartPath(
        string rootDirectory,
        string relativeDirectory,
        string fileName,
        long fileSize,
        ReadOnlySpan<byte> sha256,
        Guid remoteDeviceId,
        string trustRelationshipId)
    {
        if (remoteDeviceId == Guid.Empty || !IsValidTrustRelationshipId(trustRelationshipId))
        {
            throw new InvalidDataException("Invalid trusted resume authorization context.");
        }

        if (sha256.Length != 32 || fileSize < 0)
        {
            throw new InvalidDataException("Invalid resumable-transfer metadata.");
        }

        var normalizedDirectory = NormalizeRelativeDirectory(relativeDirectory);
        if (!IsSafeFileName(fileName))
        {
            throw new InvalidDataException("Unsafe file name.");
        }

        var root = Path.GetFullPath(rootDirectory);
        Directory.CreateDirectory(root);
        EnsureDirectoryIsNotReparsePoint(root);
        var resumeDirectory = EnsureInsideRoot(root, Path.Combine(root, ".genialink-resume"));
        Directory.CreateDirectory(resumeDirectory);
        EnsureDirectoryIsNotReparsePoint(resumeDirectory);

        var key = CreateResumeKey(normalizedDirectory, fileName, fileSize, sha256, remoteDeviceId, trustRelationshipId);
        return EnsureInsideRoot(root, Path.Combine(resumeDirectory, $"{key}.part"));
    }

    public static string CreateResumeKey(
        string relativeDirectory,
        string fileName,
        long fileSize,
        ReadOnlySpan<byte> sha256,
        Guid remoteDeviceId,
        string trustRelationshipId)
    {
        if (remoteDeviceId == Guid.Empty ||
            !IsValidTrustRelationshipId(trustRelationshipId) ||
            sha256.Length != 32 ||
            fileSize < 0 ||
            !IsSafeFileName(fileName))
        {
            throw new InvalidDataException("Invalid trusted resumable-transfer metadata.");
        }

        var normalizedDirectory = NormalizeRelativeDirectory(relativeDirectory);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hasher.AppendData(Encoding.ASCII.GetBytes("GNP1-M2.5.2.1-TRUST-RESUME"));
        hasher.AppendData([0]);
        hasher.AppendData(remoteDeviceId.ToByteArray());
        hasher.AppendData([0]);
        hasher.AppendData(Encoding.ASCII.GetBytes(trustRelationshipId.ToLowerInvariant()));
        hasher.AppendData([0]);
        hasher.AppendData(sha256);
        Span<byte> sizeBytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(sizeBytes, fileSize);
        hasher.AppendData(sizeBytes);
        hasher.AppendData(Encoding.UTF8.GetBytes(normalizedDirectory));
        hasher.AppendData([0]);
        hasher.AppendData(Encoding.UTF8.GetBytes(fileName));
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

    public static string CreateResumeKey(
        string relativeDirectory,
        string fileName,
        long fileSize,
        ReadOnlySpan<byte> sha256)
    {
        if (sha256.Length != 32 || fileSize < 0 || !IsSafeFileName(fileName))
        {
            throw new InvalidDataException("Invalid resumable-transfer metadata.");
        }

        var normalizedDirectory = NormalizeRelativeDirectory(relativeDirectory);
        using var hasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hasher.AppendData(sha256);
        Span<byte> sizeBytes = stackalloc byte[sizeof(long)];
        BinaryPrimitives.WriteInt64BigEndian(sizeBytes, fileSize);
        hasher.AppendData(sizeBytes);
        hasher.AppendData(Encoding.UTF8.GetBytes(normalizedDirectory));
        hasher.AppendData([0]);
        hasher.AppendData(Encoding.UTF8.GetBytes(fileName));
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

    public static void CleanupStaleResumeParts(string rootDirectory, DateTimeOffset cutoffUtc)
    {
        try
        {
            var root = Path.GetFullPath(rootDirectory);
            if (Directory.Exists(root))
            {
                EnsureDirectoryIsNotReparsePoint(root);
            }

            var resumeDirectory = EnsureInsideRoot(root, Path.Combine(root, ".genialink-resume"));
            if (!Directory.Exists(resumeDirectory))
            {
                return;
            }

            EnsureDirectoryIsNotReparsePoint(resumeDirectory);
            foreach (var path in Directory.EnumerateFiles(resumeDirectory, "*.part", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    if (File.GetLastWriteTimeUtc(path) < cutoffUtc.UtcDateTime)
                    {
                        File.Delete(path);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
        }
    }

    private static bool IsValidTrustRelationshipId(string? value) =>
        !string.IsNullOrWhiteSpace(value) &&
        value.Length == 32 &&
        value.All(Uri.IsHexDigit);

    private static void EnsureDirectoryIsNotReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Receive directories must not be symbolic links or junctions.");
        }
    }

    private static string EnsureInsideRoot(string root, string candidate)
    {
        var fullRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        var fullCandidate = Path.GetFullPath(candidate);
        var prefix = fullRoot + Path.DirectorySeparatorChar;

        if (!fullCandidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Resolved path escapes the destination directory.");
        }

        return fullCandidate;
    }
}
