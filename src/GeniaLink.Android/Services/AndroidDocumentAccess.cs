using System.Globalization;
using Android.Content;
using GeniaLink.Android.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Security;

namespace GeniaLink.Android.Services;

internal static class AndroidDocumentAccess
{
    private const int MaxDisplayNameCharacters = 240;

    public static SelectedDocument Describe(ContentResolver resolver, global::Android.Net.Uri uri)
    {
        ArgumentNullException.ThrowIfNull(resolver);
        ArgumentNullException.ThrowIfNull(uri);

        string? displayName = null;
        long? size = null;

        using (var cursor = resolver.Query(uri, ["_display_name", "_size"], null, null, null))
        {
            if (cursor?.MoveToFirst() == true)
            {
                var nameIndex = cursor.GetColumnIndex("_display_name");
                if (nameIndex >= 0 && !cursor.IsNull(nameIndex))
                {
                    displayName = cursor.GetString(nameIndex);
                }

                var sizeIndex = cursor.GetColumnIndex("_size");
                if (sizeIndex >= 0 && !cursor.IsNull(sizeIndex))
                {
                    var reported = cursor.GetLong(sizeIndex);
                    if (reported >= 0)
                    {
                        size = reported;
                    }
                }
            }
        }

        displayName = CreateSafeTransferName(displayName);
        if (size is > ProtocolConstants.MaxFileSize)
        {
            throw new InvalidDataException($"Файл слишком большой для Genia Link: {displayName}");
        }

        var uriString = uri.ToString();
        if (string.IsNullOrWhiteSpace(uriString))
        {
            throw new InvalidDataException("Android document URI is empty.");
        }

        return new SelectedDocument(uriString, displayName, size);
    }

    public static string CreateSafeTransferName(string? sourceName)
    {
        var raw = string.IsNullOrWhiteSpace(sourceName) ? "GeniaLink-file" : sourceName.Trim();
        var cleaned = new string(raw
            .Where(ch => !char.IsControl(ch) && CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.Format)
            .Select(ch => ch is '/' or '\\' or ':' ? '_' : ch)
            .Take(MaxDisplayNameCharacters)
            .ToArray())
            .Trim()
            .TrimEnd('.', ' ');

        if (FileSafety.IsSafeFileName(cleaned))
        {
            return cleaned;
        }

        var extension = string.Empty;
        try
        {
            extension = Path.GetExtension(cleaned);
            if (extension.Length > 16 || extension.Any(ch => !char.IsLetterOrDigit(ch) && ch != '.'))
            {
                extension = string.Empty;
            }
        }
        catch (ArgumentException)
        {
            extension = string.Empty;
        }

        var fallback = $"GeniaLink-file-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}{extension}";
        if (!FileSafety.IsSafeFileName(fallback))
        {
            fallback = "GeniaLink-file.bin";
        }

        return fallback;
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes.ToString(CultureInfo.CurrentCulture)} Б";
        }

        var value = bytes / 1024d;
        if (value < 1024)
        {
            return $"{value:F1} КБ";
        }

        value /= 1024d;
        if (value < 1024)
        {
            return $"{value:F1} МБ";
        }

        value /= 1024d;
        return $"{value:F2} ГБ";
    }
}
