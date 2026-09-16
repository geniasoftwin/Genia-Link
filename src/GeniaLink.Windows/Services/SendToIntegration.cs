using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;

namespace GeniaLink.Windows.Services;

internal static class SendToIntegration
{
    private const string ShortcutPrefix = "Genia Link - ";

    public static int InstallOrRefresh(string executablePath, IEnumerable<TrustedDevice> devices)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentNullException.ThrowIfNull(devices);
        var fullExecutablePath = Path.GetFullPath(executablePath);
        if (!File.Exists(fullExecutablePath))
        {
            throw new FileNotFoundException("Genia Link executable was not found.", fullExecutablePath);
        }

        var sendToDirectory = Environment.GetFolderPath(Environment.SpecialFolder.SendTo);
        if (string.IsNullOrWhiteSpace(sendToDirectory))
        {
            throw new IOException("Windows SendTo folder is unavailable.");
        }

        Directory.CreateDirectory(sendToDirectory);
        RemoveExisting(sendToDirectory);

        var shellType = Type.GetTypeFromProgID("WScript.Shell")
            ?? throw new PlatformNotSupportedException("Windows Script Host is unavailable.");
        object? shell = null;
        var created = 0;
        var usedShortcutNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            shell = Activator.CreateInstance(shellType)
                ?? throw new PlatformNotSupportedException("Windows Script Host could not be started.");
            foreach (var device in devices)
            {
                var safeName = SanitizeShortcutName(device.DeviceName);
                var uniqueName = MakeUniqueShortcutName(safeName, device.DeviceId, usedShortcutNames);
                var shortcutPath = Path.Combine(sendToDirectory, $"{ShortcutPrefix}{uniqueName}.lnk");
                dynamic shortcut = shellType.InvokeMember(
                    "CreateShortcut",
                    System.Reflection.BindingFlags.InvokeMethod,
                    binder: null,
                    target: shell,
                    args: [shortcutPath],
                    culture: CultureInfo.InvariantCulture)!;
                try
                {
                    shortcut.TargetPath = fullExecutablePath;
                    shortcut.Arguments = $"--send-to {device.DeviceId:D}";
                    shortcut.WorkingDirectory = Path.GetDirectoryName(fullExecutablePath) ?? string.Empty;
                    shortcut.IconLocation = fullExecutablePath + ",0";
                    shortcut.Description = $"Отправить через Genia Link на {device.DeviceName}";
                    shortcut.Save();
                    created++;
                }
                finally
                {
                    if (Marshal.IsComObject(shortcut))
                    {
                        Marshal.FinalReleaseComObject(shortcut);
                    }
                }
            }
        }
        finally
        {
            if (shell is not null && Marshal.IsComObject(shell))
            {
                Marshal.FinalReleaseComObject(shell);
            }
        }

        return created;
    }

    public static int Remove()
    {
        var sendToDirectory = Environment.GetFolderPath(Environment.SpecialFolder.SendTo);
        return string.IsNullOrWhiteSpace(sendToDirectory) ? 0 : RemoveExisting(sendToDirectory);
    }

    private static int RemoveExisting(string sendToDirectory)
    {
        var removed = 0;
        foreach (var path in Directory.EnumerateFiles(sendToDirectory, ShortcutPrefix + "*.lnk", SearchOption.TopDirectoryOnly))
        {
            try
            {
                File.Delete(path);
                removed++;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
            }
        }

        return removed;
    }

    private static string MakeUniqueShortcutName(string safeName, Guid deviceId, HashSet<string> usedNames)
    {
        if (usedNames.Add(safeName))
        {
            return safeName;
        }

        var shortId = deviceId.ToString("N")[..8];
        var withId = $"{safeName} ({shortId})";
        if (usedNames.Add(withId))
        {
            return withId;
        }

        var fullId = $"{safeName} ({deviceId:D})";
        usedNames.Add(fullId);
        return fullId;
    }

    private static string SanitizeShortcutName(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(value
            .Where(ch => !char.IsControl(ch) && Array.IndexOf(invalid, ch) < 0)
            .Take(80)
            .ToArray())
            .Trim()
            .TrimEnd('.', ' ');
        return string.IsNullOrWhiteSpace(cleaned) ? "Устройство" : cleaned;
    }
}
