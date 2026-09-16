using System.IO;
using System.Text.Json;
using GeniaLink.Core.Capabilities;

namespace GeniaLink.Windows.Services;

internal sealed record AppSettings(
    bool StartWithWindows = false,
    bool StartMinimized = true,
    bool EnableSendToIntegration = true,
    bool ShowNotifications = true,
    string? ReceiveFolder = null,
    DeviceRoleProfile DeviceRole = DeviceRoleProfile.Client,
    DeviceCapability Capabilities = DeviceCapability.TrustedDiscovery | DeviceCapability.TrustedTransport | DeviceCapability.FileTransfer | DeviceCapability.SharedResources);

internal sealed class AppSettingsStore
{
    private const long MaxSettingsBytes = 64 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly string _path;

    public AppSettingsStore(string appDataDirectory, Action<string>? log)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appDataDirectory);
        Directory.CreateDirectory(appDataDirectory);
        _path = Path.Combine(appDataDirectory, "settings.json");
        Current = Normalize(Load(log), log);
    }

    public AppSettings Current { get; private set; }

    public void Save(AppSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var normalized = Normalize(settings, log: null);
        var json = JsonSerializer.Serialize(normalized, JsonOptions);
        if (System.Text.Encoding.UTF8.GetByteCount(json) > MaxSettingsBytes)
        {
            throw new InvalidDataException("Genia Link settings unexpectedly exceed the safe size limit.");
        }

        var tempPath = _path + ".tmp";
        try
        {
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _path, overwrite: true);
            Current = normalized;
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static AppSettings Normalize(AppSettings settings, Action<string>? log)
    {
        var savedRole = DeviceCapabilityProfiles.NormalizeRole(settings.DeviceRole);
        var normalizedCapabilities = settings.Capabilities == DeviceCapability.None
            ? DeviceCapabilityProfiles.GetPreset(savedRole)
            : DeviceCapabilityProfiles.NormalizeSelection(settings.Capabilities);
        var resolvedRole = DeviceCapabilityProfiles.ResolveProfile(normalizedCapabilities);

        string receiveFolder;
        try
        {
            receiveFolder = ReceiveFolderPolicy.Normalize(settings.ReceiveFolder);
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidDataException or NotSupportedException or PathTooLongException)
        {
            log?.Invoke($"Invalid saved receive folder was ignored; default Downloads folder is used: {ex.Message}");
            receiveFolder = ReceiveFolderPolicy.GetDefaultReceiveFolder();
        }

        return settings with
        {
            ReceiveFolder = receiveFolder,
            DeviceRole = resolvedRole,
            Capabilities = normalizedCapabilities
        };
    }

    private AppSettings Load(Action<string>? log)
    {
        if (!File.Exists(_path))
        {
            return new AppSettings();
        }

        try
        {
            if (new FileInfo(_path).Length > MaxSettingsBytes)
            {
                throw new InvalidDataException("Genia Link settings file is unexpectedly large.");
            }

            var json = File.ReadAllText(_path);
            return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException)
        {
            log?.Invoke($"Settings could not be loaded; safe defaults are used: {ex.Message}");
            return new AppSettings();
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            File.Delete(path);
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }
}
