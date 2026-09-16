using GeniaLink.Core.Models;
using GeniaLink.Core.Security;

namespace GeniaLink.Core.Transfers;

public static class RemoteBrowserIndex
{
    public static RemoteBrowserEntry[] BuildDirectory(
        IReadOnlyList<RemoteFileEntry> files,
        string? currentDirectory)
    {
        ArgumentNullException.ThrowIfNull(files);
        var normalizedDirectory = FileSafety.NormalizeRelativeDirectory(currentDirectory);
        var prefix = normalizedDirectory.Length == 0 ? string.Empty : normalizedDirectory + "/";
        var immediateFiles = new List<RemoteBrowserEntry>();
        var directories = new Dictionary<string, DirectoryAggregate>(StringComparer.Ordinal);

        foreach (var file in files)
        {
            if (!FileSafety.IsSafeRelativeFilePath(file.RelativePath) ||
                file.FileSize < 0 ||
                !file.RelativePath.StartsWith(prefix, StringComparison.Ordinal))
            {
                continue;
            }

            var remainder = file.RelativePath[prefix.Length..];
            var separator = remainder.IndexOf('/');
            if (separator < 0)
            {
                immediateFiles.Add(new RemoteBrowserEntry(
                    false,
                    remainder,
                    file.RelativePath,
                    file.FileSize,
                    file.ModifiedUnixTimeSeconds,
                    1,
                    file.FileSize));
                continue;
            }

            var directoryName = remainder[..separator];
            if (!FileSafety.IsSafePathSegment(directoryName))
            {
                continue;
            }

            var directoryPath = prefix + directoryName;
            if (!directories.TryGetValue(directoryPath, out var aggregate))
            {
                aggregate = new DirectoryAggregate(directoryName, directoryPath);
                directories.Add(directoryPath, aggregate);
            }

            aggregate.FileCount++;
            aggregate.TotalBytes = checked(aggregate.TotalBytes + file.FileSize);
            aggregate.ModifiedUnixTimeSeconds = Math.Max(aggregate.ModifiedUnixTimeSeconds, file.ModifiedUnixTimeSeconds);
        }

        return directories.Values
            .Select(item => new RemoteBrowserEntry(
                true,
                item.Name,
                item.RelativePath,
                0,
                item.ModifiedUnixTimeSeconds,
                item.FileCount,
                item.TotalBytes))
            .Concat(immediateFiles)
            .ToArray();
    }

    public static string GetParentDirectory(string? currentDirectory)
    {
        var normalized = FileSafety.NormalizeRelativeDirectory(currentDirectory);
        var separator = normalized.LastIndexOf('/');
        return separator < 0 ? string.Empty : normalized[..separator];
    }

    private sealed class DirectoryAggregate(string name, string relativePath)
    {
        public string Name { get; } = name;
        public string RelativePath { get; } = relativePath;
        public int FileCount { get; set; }
        public long TotalBytes { get; set; }
        public long ModifiedUnixTimeSeconds { get; set; }
    }
}
