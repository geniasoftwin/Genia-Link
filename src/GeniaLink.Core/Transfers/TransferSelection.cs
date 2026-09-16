using System.IO;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Security;

namespace GeniaLink.Core.Transfers;

public static class TransferSelection
{
    public static IReadOnlyList<TransferFileSource> Expand(IEnumerable<string> selectedPaths)
    {
        ArgumentNullException.ThrowIfNull(selectedPaths);
        var result = new List<TransferFileSource>();
        var seenFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var sourcePath in selectedPaths)
        {
            if (string.IsNullOrWhiteSpace(sourcePath))
            {
                continue;
            }

            var fullPath = Path.GetFullPath(sourcePath);
            if (File.Exists(fullPath))
            {
                AddFile(result, seenFiles, fullPath, string.Empty);
                continue;
            }

            if (!Directory.Exists(fullPath))
            {
                continue;
            }

            EnsureNotReparsePoint(fullPath);
            var rootName = Path.GetFileName(Path.TrimEndingDirectorySeparator(fullPath));
            if (!FileSafety.IsSafePathSegment(rootName))
            {
                throw new InvalidDataException($"Unsafe folder name: {rootName}");
            }

            EnumerateDirectory(result, seenFiles, fullPath, rootName, depth: 1);
        }

        if (result.Count == 0)
        {
            throw new InvalidDataException("No transferable files were selected.");
        }

        return result;
    }

    private static void EnumerateDirectory(
        List<TransferFileSource> result,
        HashSet<string> seenFiles,
        string directory,
        string relativeDirectory,
        int depth)
    {
        if (depth > ProtocolConstants.MaxRelativeDirectoryDepth)
        {
            throw new InvalidDataException("Folder tree is deeper than the Genia Link safety limit.");
        }

        foreach (var file in Directory.EnumerateFiles(directory).OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            EnsureNotReparsePoint(file);
            AddFile(result, seenFiles, file, relativeDirectory);
        }

        foreach (var child in Directory.EnumerateDirectories(directory).OrderBy(path => path, StringComparer.OrdinalIgnoreCase))
        {
            EnsureNotReparsePoint(child);
            var childName = Path.GetFileName(Path.TrimEndingDirectorySeparator(child));
            if (!FileSafety.IsSafePathSegment(childName))
            {
                throw new InvalidDataException($"Unsafe folder name: {childName}");
            }

            var nextRelative = FileSafety.NormalizeRelativeDirectory(relativeDirectory + "/" + childName);
            EnumerateDirectory(result, seenFiles, child, nextRelative, depth + 1);
        }
    }

    private static void AddFile(
        List<TransferFileSource> result,
        HashSet<string> seenFiles,
        string path,
        string relativeDirectory)
    {
        if (result.Count >= ProtocolConstants.MaxBatchFiles)
        {
            throw new InvalidDataException($"A single transfer is limited to {ProtocolConstants.MaxBatchFiles:N0} files.");
        }

        var fullPath = Path.GetFullPath(path);
        EnsureNotReparsePoint(fullPath);
        var name = Path.GetFileName(fullPath);
        if (!FileSafety.IsSafeFileName(name))
        {
            throw new InvalidDataException($"Unsafe file name: {name}");
        }

        if (seenFiles.Add(fullPath))
        {
            result.Add(new TransferFileSource(fullPath, FileSafety.NormalizeRelativeDirectory(relativeDirectory)));
        }
    }

    private static void EnsureNotReparsePoint(string path)
    {
        var attributes = File.GetAttributes(path);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException($"Symbolic links and junctions are not followed: {Path.GetFileName(path)}");
        }
    }
}
