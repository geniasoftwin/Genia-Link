using GeniaLink.Core.Discovery;

namespace GeniaLink.Android.Models;

internal sealed record DeviceListItem(
    DiscoveredDevice Device,
    bool IsRecentlySeen,
    bool IsTrusted,
    bool IdentityMatches)
{
    public string Status => IsTrusted
        ? IdentityMatches
            ? IsRecentlySeen ? "доверенное" : "спит / нет свежего discovery"
            : "ключ изменился"
        : "не сопряжено";

    public string DeviceKindText => Device.Kind switch
    {
        DeviceKind.WindowsComputer => "Windows · компьютер",
        DeviceKind.AndroidPhone => "Android · телефон",
        DeviceKind.AndroidTablet => "Android · планшет",
        _ => "устройство"
    };

    public string DeviceIcon => Device.Kind switch
    {
        DeviceKind.WindowsComputer => "🖥",
        DeviceKind.AndroidPhone => "📱",
        DeviceKind.AndroidTablet => "▭",
        _ => "●"
    };

    public override string ToString() =>
        $"{DeviceIcon}  {Device.DeviceName}\n{DeviceKindText} · {Device.Address} · {Status}";
}
