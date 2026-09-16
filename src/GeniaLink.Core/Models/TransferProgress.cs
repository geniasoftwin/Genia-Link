namespace GeniaLink.Core.Models;

public sealed record TransferProgress(
    string FileName,
    long BytesTransferred,
    long TotalBytes,
    bool IsReceiving)
{
    public double Percentage => TotalBytes <= 0 ? 0 : Math.Clamp(BytesTransferred * 100d / TotalBytes, 0, 100);
}
