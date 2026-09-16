using System.Net;
using GeniaLink.Core.Discovery;

namespace GeniaLink.Windows.Models;

internal sealed record DeviceListItem(
    Guid DeviceId,
    string DeviceName,
    IPAddress Address,
    int TransferPort,
    int PairingPort,
    string PublicKeyFingerprint,
    DeviceKind Kind,
    bool IsRecentlySeen,
    bool IsTrusted,
    bool IdentityMatches)
{
    public string Status => IsTrusted
        ? IdentityMatches
            ? IsRecentlySeen ? "Доверенное · доступно" : "Доверенное · спит / нет свежего discovery"
            : "ВНИМАНИЕ: идентификатор ключа изменился"
        : "Новое устройство";

    public string DisplayName => $"{DeviceIcon}  {DeviceName}";

    public string DetailText => $"{DeviceKindText} · {CompactStatus}";

    public string CompactStatus => IsTrusted
        ? IdentityMatches
            ? IsRecentlySeen ? "Доступен" : "Спит"
            : "Ключ изменился"
        : "Новое устройство";

    public string GroupName => Kind switch
    {
        DeviceKind.WindowsComputer => "Компьютеры",
        DeviceKind.AndroidPhone or DeviceKind.AndroidTablet => "Мобильные устройства",
        _ => "Другие устройства"
    };

    public string DeviceKindText => Kind switch
    {
        DeviceKind.WindowsComputer => "Windows",
        DeviceKind.AndroidPhone => "Android · телефон",
        DeviceKind.AndroidTablet => "Android · планшет",
        _ => "Тип не определён"
    };

    public string DeviceIcon => Kind switch
    {
        DeviceKind.WindowsComputer => "🖥",
        DeviceKind.AndroidPhone => "📱",
        DeviceKind.AndroidTablet => "▭",
        _ => "●"
    };
}
