using Microsoft.Win32;

namespace GeniaLink.Windows.Services;

internal static class StartupIntegration
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "Genia Link";

    public static void SetEnabled(bool enabled, string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);

        using var runKey = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true)
            ?? throw new InvalidOperationException("Could not open the current-user Windows startup registry key.");

        if (!enabled)
        {
            runKey.DeleteValue(ValueName, throwOnMissingValue: false);
            return;
        }

        var command = $"\"{executablePath}\" --startup";
        runKey.SetValue(ValueName, command, RegistryValueKind.String);
    }
}
