using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using GeniaLink.Core.Network;

namespace GeniaLink.Windows.Services;

internal static class WindowsPreviewProvider
{
    public static Task<byte[]?> CreateJpegThumbnailAsync(string fullPath, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fullPath);
        return Task.Run(() => CreateJpegThumbnail(fullPath, cancellationToken), cancellationToken);
    }

    private static byte[]? CreateJpegThumbnail(string fullPath, CancellationToken cancellationToken)
    {
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            using var input = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            var decoder = BitmapDecoder.Create(input, BitmapCreateOptions.PreservePixelFormat, BitmapCacheOption.OnLoad);
            if (decoder.Frames.Count == 0)
            {
                return null;
            }

            BitmapSource source = decoder.Frames[0];
            source.Freeze();
            foreach (var maxDimension in new[] { 1024d, 768d, 512d })
            {
                cancellationToken.ThrowIfCancellationRequested();
                var scaled = Scale(source, maxDimension);
                foreach (var quality in new[] { 82, 68, 54 })
                {
                    var encoded = EncodeJpeg(scaled, quality);
                    if (encoded.Length <= ProtocolConstants.MaxPreviewBytes)
                    {
                        return encoded;
                    }
                }
            }

            return null;
        }
        catch (Exception ex) when (ex is IOException or FormatException or NotSupportedException or ArgumentException or InvalidOperationException)
        {
            return null;
        }
    }

    private static BitmapSource Scale(BitmapSource source, double maxDimension)
    {
        var largest = Math.Max(source.PixelWidth, source.PixelHeight);
        if (largest <= maxDimension)
        {
            return source;
        }

        var scale = maxDimension / largest;
        var transformed = new TransformedBitmap(source, new ScaleTransform(scale, scale));
        transformed.Freeze();
        return transformed;
    }

    private static byte[] EncodeJpeg(BitmapSource source, int quality)
    {
        var encoder = new JpegBitmapEncoder { QualityLevel = quality };
        encoder.Frames.Add(BitmapFrame.Create(source));
        using var output = new MemoryStream();
        encoder.Save(output);
        return output.ToArray();
    }
}
