namespace GeniaLink.Core.Models;

public enum RemotePreviewKind : byte
{
    None = 0,
    ImageJpeg = 1,
    TextUtf8 = 2
}

public sealed record RemoteFilePreview(
    string RelativePath,
    RemotePreviewKind Kind,
    string MediaType,
    byte[] Data,
    string Message);
