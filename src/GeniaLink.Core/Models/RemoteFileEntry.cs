namespace GeniaLink.Core.Models;

public sealed record RemoteFileEntry(
    string RelativePath,
    long FileSize,
    long ModifiedUnixTimeSeconds)
{
    public string FileName => RelativePath.Split('/').LastOrDefault() ?? RelativePath;

    public string RelativeDirectory
    {
        get
        {
            var separator = RelativePath.LastIndexOf('/');
            return separator <= 0 ? string.Empty : RelativePath[..separator];
        }
    }
}
