using System.Buffers;
using System.Text;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;

namespace GeniaLink.Core.Transfers;

public static class RemotePreviewPolicy
{
    private static readonly HashSet<string> ImageExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".bmp", ".gif"
    };

    private static readonly HashSet<string> TextExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".txt", ".log", ".md", ".json", ".xml", ".csv", ".ini", ".cfg",
        ".yaml", ".yml", ".cs", ".xaml", ".ps1", ".bat", ".cmd"
    };

    public static bool IsImagePath(string relativePath) => ImageExtensions.Contains(Path.GetExtension(relativePath));

    public static bool IsTextPath(string relativePath) => TextExtensions.Contains(Path.GetExtension(relativePath));

    public static async Task<RemoteFilePreview> CreateTextPreviewAsync(
        Stream input,
        string relativePath,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        var buffer = ArrayPool<byte>.Shared.Rent(ProtocolConstants.MaxTextPreviewBytes + 1);
        try
        {
            var total = 0;
            while (total < ProtocolConstants.MaxTextPreviewBytes + 1)
            {
                var read = await input.ReadAsync(
                    buffer.AsMemory(total, ProtocolConstants.MaxTextPreviewBytes + 1 - total),
                    cancellationToken).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }

                total += read;
            }

            var visibleLength = Math.Min(total, ProtocolConstants.MaxTextPreviewBytes);
            var span = buffer.AsSpan(0, visibleLength);
            if (LooksBinary(span))
            {
                return Unavailable(relativePath, "Файл похож на бинарный; текстовый предпросмотр отключён.");
            }

            var text = Encoding.UTF8.GetString(span);
            if (total > ProtocolConstants.MaxTextPreviewBytes)
            {
                text += Environment.NewLine + Environment.NewLine + "… предпросмотр ограничен первыми 64 КБ …";
            }

            var data = Encoding.UTF8.GetBytes(text);
            return new RemoteFilePreview(relativePath, RemotePreviewKind.TextUtf8, "text/plain; charset=utf-8", data, string.Empty);
        }
        finally
        {
            Array.Clear(buffer, 0, Math.Min(buffer.Length, ProtocolConstants.MaxTextPreviewBytes + 1));
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public static RemoteFilePreview CreateImagePreview(string relativePath, byte[] jpegData)
    {
        ArgumentNullException.ThrowIfNull(jpegData);
        if (jpegData.Length == 0 || jpegData.Length > ProtocolConstants.MaxPreviewBytes)
        {
            return Unavailable(relativePath, "Не удалось подготовить безопасную миниатюру изображения.");
        }

        return new RemoteFilePreview(relativePath, RemotePreviewKind.ImageJpeg, "image/jpeg", jpegData, string.Empty);
    }

    public static RemoteFilePreview Unavailable(string relativePath, string message) =>
        new(relativePath, RemotePreviewKind.None, string.Empty, [], message);

    private static bool LooksBinary(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
        {
            return false;
        }

        var suspicious = 0;
        foreach (var value in data)
        {
            if (value == 0)
            {
                return true;
            }

            if (value < 0x09 || value is > 0x0D and < 0x20)
            {
                suspicious++;
            }
        }

        return suspicious > Math.Max(8, data.Length / 20);
    }
}
