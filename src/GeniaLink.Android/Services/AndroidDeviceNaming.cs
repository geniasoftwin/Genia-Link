using System.Globalization;
using System.Text;
using GeniaLink.Core.Discovery;

namespace GeniaLink.Android.Services;

internal static class AndroidDeviceNaming
{
    private const int MaxNameBytes = 160;
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static string GetSafeDeviceName()
    {
        var model = global::Android.OS.Build.Model;
        var manufacturer = global::Android.OS.Build.Manufacturer;
        var candidates = new[]
        {
            $"{manufacturer} {model}",
            model,
            "Android device"
        };

        foreach (var candidate in candidates)
        {
            var sanitized = Sanitize(candidate);
            if (!string.IsNullOrWhiteSpace(sanitized) && StrictUtf8.GetByteCount(sanitized) <= MaxNameBytes)
            {
                return sanitized;
            }
        }

        return "Android device";
    }

    public static DeviceKind GetDeviceKind(global::Android.Content.Context context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var smallestWidthDp = context.Resources?.Configuration?.SmallestScreenWidthDp ?? 0;
        return smallestWidthDp >= 600 ? DeviceKind.AndroidTablet : DeviceKind.AndroidPhone;
    }

    private static string Sanitize(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        var chars = value
            .Where(ch => !char.IsControl(ch) && CharUnicodeInfo.GetUnicodeCategory(ch) != UnicodeCategory.Format)
            .ToArray();
        return new string(chars).Trim();
    }
}
