namespace GeniaLink.Core.Models;

public sealed record RemoteBrowserEntry(
    bool IsDirectory,
    string Name,
    string RelativePath,
    long FileSize,
    long ModifiedUnixTimeSeconds,
    int DescendantFileCount,
    long DescendantBytes);
