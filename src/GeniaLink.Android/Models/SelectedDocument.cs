namespace GeniaLink.Android.Models;

internal sealed record SelectedDocument(
    string UriString,
    string DisplayName,
    long? ReportedSize,
    string RelativeDirectory = "")
{
    public global::Android.Net.Uri GetUri() =>
        global::Android.Net.Uri.Parse(UriString)
        ?? throw new InvalidDataException("Selected document URI is invalid.");
}
