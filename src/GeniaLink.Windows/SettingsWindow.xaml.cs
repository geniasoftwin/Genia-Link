using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using GeniaLink.Core.Capabilities;
using GeniaLink.Core.Discovery;
using GeniaLink.Core.Identity;
using GeniaLink.Windows.Services;
using Forms = System.Windows.Forms;

namespace GeniaLink.Windows;

internal sealed record TrustedDeviceSettingsItem(
    Guid DeviceId,
    string DeviceName,
    DeviceKind Kind,
    string Status,
    TrustedIdentityLifecycleState LifecycleState,
    DateTimeOffset PairedAtUtc,
    string Fingerprint)
{
    public string DeviceKindText => Kind switch
    {
        DeviceKind.WindowsComputer => "Windows",
        DeviceKind.AndroidPhone => "Android · телефон",
        DeviceKind.AndroidTablet => "Android · планшет",
        _ => "Не определён"
    };

    public string LifecycleText => LifecycleState switch
    {
        TrustedIdentityLifecycleState.Active => "Active",
        TrustedIdentityLifecycleState.Retired => "Retired",
        TrustedIdentityLifecycleState.Revoked => "Revoked",
        _ => "Unknown"
    };

    public string PairedAtText => PairedAtUtc.ToLocalTime().ToString("g", CultureInfo.CurrentCulture);
}

public partial class SettingsWindow : Window
{
    private readonly ObservableCollection<TrustedDeviceSettingsItem> _devices;
    private readonly Func<int> _refreshSendTo;
    private readonly Func<int> _removeSendTo;
    private readonly Func<Guid, bool> _forgetDevice;
    private readonly Func<Guid, TrustedIdentityLifecycleState, bool> _setLifecycleState;
    private readonly string _localFingerprint;
    private readonly int _localSigningGeneration;
    private readonly string _localSigningKeyId;
    private readonly Action _requestSigningKeyRotation;
    private bool _initializingCapabilities = true;
    private bool _synchronizingCapabilityProfile;

    internal SettingsWindow(
        Window owner,
        AppSettings settings,
        IEnumerable<TrustedDeviceSettingsItem> devices,
        Func<int> refreshSendTo,
        Func<int> removeSendTo,
        Func<Guid, bool> forgetDevice,
        Func<Guid, TrustedIdentityLifecycleState, bool> setLifecycleState,
        string localFingerprint,
        int localSigningGeneration,
        string localSigningKeyId,
        Action requestSigningKeyRotation)
    {
        InitializeComponent();
        Owner = owner;
        ArgumentNullException.ThrowIfNull(settings);
        ArgumentNullException.ThrowIfNull(devices);
        _refreshSendTo = refreshSendTo ?? throw new ArgumentNullException(nameof(refreshSendTo));
        _removeSendTo = removeSendTo ?? throw new ArgumentNullException(nameof(removeSendTo));
        _forgetDevice = forgetDevice ?? throw new ArgumentNullException(nameof(forgetDevice));
        _setLifecycleState = setLifecycleState ?? throw new ArgumentNullException(nameof(setLifecycleState));
        _localFingerprint = localFingerprint ?? string.Empty;
        _localSigningGeneration = localSigningGeneration;
        _localSigningKeyId = localSigningKeyId ?? string.Empty;
        _requestSigningKeyRotation = requestSigningKeyRotation ?? throw new ArgumentNullException(nameof(requestSigningKeyRotation));

        StartWithWindowsCheckBox.IsChecked = settings.StartWithWindows;
        StartMinimizedCheckBox.IsChecked = settings.StartMinimized;
        EnableSendToCheckBox.IsChecked = settings.EnableSendToIntegration;
        ShowNotificationsCheckBox.IsChecked = settings.ShowNotifications;
        ReceiveFolderTextBox.Text = settings.ReceiveFolder ?? ReceiveFolderPolicy.GetDefaultReceiveFolder();
        var initialCapabilities = DeviceCapabilityProfiles.NormalizeSelection(settings.Capabilities);
        SelectDeviceRole(DeviceCapabilityProfiles.ResolveProfile(initialCapabilities));
        SetCapabilitySelection(initialCapabilities);
        UpdateCapabilityRequirements();
        _initializingCapabilities = false;
        LocalFingerprintTextBox.Text = _localFingerprint;
        SigningIdentityTextBlock.Text = $"Generation {_localSigningGeneration} · {_localSigningKeyId}";

        _devices = new ObservableCollection<TrustedDeviceSettingsItem>(devices);
        TrustedDevicesDataGrid.ItemsSource = _devices;
        UpdateLifecycleButtons();
    }

    internal AppSettings? ResultSettings { get; private set; }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        var capabilities = DeviceCapabilityProfiles.NormalizeSelection(ReadCapabilitySelection());
        var role = DeviceCapabilityProfiles.ResolveProfile(capabilities);
        ResultSettings = new AppSettings(
            StartWithWindowsCheckBox.IsChecked == true,
            StartMinimizedCheckBox.IsChecked == true,
            EnableSendToCheckBox.IsChecked == true,
            ShowNotificationsCheckBox.IsChecked == true,
            ReceiveFolderTextBox.Text,
            role,
            capabilities);
        DialogResult = true;
    }

    private void DeviceRoleComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_initializingCapabilities || _synchronizingCapabilityProfile)
        {
            return;
        }

        var role = GetSelectedDeviceRole();
        _synchronizingCapabilityProfile = true;
        try
        {
            if (role != DeviceRoleProfile.Custom)
            {
                SetCapabilitySelection(DeviceCapabilityProfiles.GetPreset(role));
            }

            if (role is DeviceRoleProfile.Server or DeviceRoleProfile.Relay or DeviceRoleProfile.Backup)
            {
                StartWithWindowsCheckBox.IsChecked = true;
                StartMinimizedCheckBox.IsChecked = true;
            }

            UpdateCapabilityRequirements();
        }
        finally
        {
            _synchronizingCapabilityProfile = false;
        }
    }

    private void CapabilityCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        if (_initializingCapabilities || _synchronizingCapabilityProfile)
        {
            return;
        }

        var capabilities = DeviceCapabilityProfiles.NormalizeSelection(ReadCapabilitySelection());
        var resolvedRole = DeviceCapabilityProfiles.ResolveProfile(capabilities);
        _synchronizingCapabilityProfile = true;
        try
        {
            SetCapabilitySelection(capabilities);
            SelectDeviceRole(resolvedRole);
            UpdateCapabilityRequirements();
        }
        finally
        {
            _synchronizingCapabilityProfile = false;
        }
    }

    private DeviceRoleProfile GetSelectedDeviceRole()
    {
        if (DeviceRoleComboBox.SelectedItem is ComboBoxItem item &&
            item.Tag is string value &&
            Enum.TryParse<DeviceRoleProfile>(value, ignoreCase: false, out var role))
        {
            return DeviceCapabilityProfiles.NormalizeRole(role);
        }

        return DeviceRoleProfile.Client;
    }

    private void SelectDeviceRole(DeviceRoleProfile role)
    {
        var normalized = DeviceCapabilityProfiles.NormalizeRole(role);
        foreach (var entry in DeviceRoleComboBox.Items.OfType<ComboBoxItem>())
        {
            if (entry.Tag is string value && string.Equals(value, normalized.ToString(), StringComparison.Ordinal))
            {
                DeviceRoleComboBox.SelectedItem = entry;
                return;
            }
        }

        DeviceRoleComboBox.SelectedIndex = 0;
    }

    private DeviceCapability ReadCapabilitySelection()
    {
        var result = DeviceCapability.None;
        AddIfChecked(TrustedDiscoveryCapabilityCheckBox, DeviceCapability.TrustedDiscovery, ref result);
        AddIfChecked(TrustedTransportCapabilityCheckBox, DeviceCapability.TrustedTransport, ref result);
        AddIfChecked(FileTransferCapabilityCheckBox, DeviceCapability.FileTransfer, ref result);
        AddIfChecked(SharedResourcesCapabilityCheckBox, DeviceCapability.SharedResources, ref result);
        AddIfChecked(BackgroundAvailabilityCapabilityCheckBox, DeviceCapability.BackgroundAvailability, ref result);
        AddIfChecked(NetworkEventsCapabilityCheckBox, DeviceCapability.NetworkEvents, ref result);
        AddIfChecked(SyncCapabilityCheckBox, DeviceCapability.Sync, ref result);
        AddIfChecked(RelayCapabilityCheckBox, DeviceCapability.Relay, ref result);
        AddIfChecked(BackupCapabilityCheckBox, DeviceCapability.Backup, ref result);
        AddIfChecked(PrinterGatewayCapabilityCheckBox, DeviceCapability.PrinterGateway, ref result);
        AddIfChecked(MessagingCapabilityCheckBox, DeviceCapability.Messaging, ref result);
        return result;
    }

    private static void AddIfChecked(System.Windows.Controls.CheckBox checkBox, DeviceCapability capability, ref DeviceCapability result)
    {
        if (checkBox.IsChecked == true)
        {
            result |= capability;
        }
    }

    private void SetCapabilitySelection(DeviceCapability capabilities)
    {
        TrustedDiscoveryCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.TrustedDiscovery);
        TrustedTransportCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.TrustedTransport);
        FileTransferCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.FileTransfer);
        SharedResourcesCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.SharedResources);
        BackgroundAvailabilityCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.BackgroundAvailability);
        NetworkEventsCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.NetworkEvents);
        SyncCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.Sync);
        RelayCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.Relay);
        BackupCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.Backup);
        PrinterGatewayCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.PrinterGateway);
        MessagingCapabilityCheckBox.IsChecked = capabilities.HasFlag(DeviceCapability.Messaging);
    }

    private void UpdateCapabilityRequirements()
    {
        var role = GetSelectedDeviceRole();
        ApplyRequirement(TrustedDiscoveryCapabilityCheckBox, role, DeviceCapability.TrustedDiscovery);
        ApplyRequirement(TrustedTransportCapabilityCheckBox, role, DeviceCapability.TrustedTransport);
        ApplyRequirement(FileTransferCapabilityCheckBox, role, DeviceCapability.FileTransfer);
        ApplyRequirement(SharedResourcesCapabilityCheckBox, role, DeviceCapability.SharedResources);
        ApplyRequirement(BackgroundAvailabilityCapabilityCheckBox, role, DeviceCapability.BackgroundAvailability);
        ApplyRequirement(NetworkEventsCapabilityCheckBox, role, DeviceCapability.NetworkEvents);
        ApplyRequirement(SyncCapabilityCheckBox, role, DeviceCapability.Sync);
        ApplyRequirement(RelayCapabilityCheckBox, role, DeviceCapability.Relay);
        ApplyRequirement(BackupCapabilityCheckBox, role, DeviceCapability.Backup);
        ApplyRequirement(PrinterGatewayCapabilityCheckBox, role, DeviceCapability.PrinterGateway);
        ApplyRequirement(MessagingCapabilityCheckBox, role, DeviceCapability.Messaging);

        RoleCapabilityExplanationTextBlock.Text = role switch
        {
            DeviceRoleProfile.Client => "Client: базовый trusted node. Discovery и Trusted Transport обязательны; File Transfer и Shared Resources включены профилем, но их можно отключить.",
            DeviceRoleProfile.Server => "Server: постоянный инфраструктурный узел. Background Availability обязательна. Network Events и Genia Sync пока сохраняются как M2.6 capability-профиль; их сетевые сервисы будут включены отдельными следующими checkpoint-ами.",
            DeviceRoleProfile.Relay => "Relay: профиль требует Background Availability и Relay. В M2.6.2 конфигурация сохраняется и аутентифицированно публикуется; сам relay-routing ещё не активируется.",
            DeviceRoleProfile.Backup => "Backup: профиль требует Background Availability и Backup. Sync рекомендуется профилем; backup-протокол будет отдельным сервисным checkpoint-ом.",
            DeviceRoleProfile.Custom => "Пользовательский: набор не совпадает с готовым профилем. Можно свободно менять необязательные функции; Trusted Discovery и Trusted Transport остаются обязательным ядром Genia Network.",
            _ => "Trusted Discovery и Trusted Transport являются обязательным ядром Genia Network."
        };
    }

    private static void ApplyRequirement(System.Windows.Controls.CheckBox checkBox, DeviceRoleProfile role, DeviceCapability capability)
    {
        var required = DeviceCapabilityProfiles.IsRequired(role, capability);
        if (required)
        {
            checkBox.IsChecked = true;
        }

        checkBox.IsEnabled = !required;
    }

    private void ChooseReceiveFolderButton_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.FolderBrowserDialog
        {
            Description = "Выберите локальную папку для входящих файлов Genia Link",
            SelectedPath = ReceiveFolderTextBox.Text,
            ShowNewFolderButton = true,
            UseDescriptionForTitle = true
        };

        if (dialog.ShowDialog() == Forms.DialogResult.OK && !string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            ReceiveFolderTextBox.Text = dialog.SelectedPath;
        }
    }

    private void DefaultReceiveFolderButton_Click(object sender, RoutedEventArgs e)
    {
        ReceiveFolderTextBox.Text = ReceiveFolderPolicy.GetDefaultReceiveFolder();
    }

    private void RefreshSendToButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var count = _refreshSendTo();
            System.Windows.MessageBox.Show(
                this,
                count == 0
                    ? "Сейчас нет онлайн-доверенных устройств."
                    : $"Доступных ярлыков Genia Link: {count}.",
                "Genia Link",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or PlatformNotSupportedException or System.Reflection.TargetInvocationException)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void RemoveSendToButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var removed = _removeSendTo();
            System.Windows.MessageBox.Show(
                this,
                $"Удалено ярлыков Genia Link: {removed}.",
                "Genia Link",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void TrustedDevicesDataGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e) =>
        UpdateLifecycleButtons();

    private void RetireReactivateButton_Click(object sender, RoutedEventArgs e)
    {
        if (TrustedDevicesDataGrid.SelectedItem is not TrustedDeviceSettingsItem selected ||
            selected.LifecycleState == TrustedIdentityLifecycleState.Revoked)
        {
            return;
        }

        var target = selected.LifecycleState == TrustedIdentityLifecycleState.Retired
            ? TrustedIdentityLifecycleState.Active
            : TrustedIdentityLifecycleState.Retired;
        if (target == TrustedIdentityLifecycleState.Retired)
        {
            var answer = System.Windows.MessageBox.Show(
                this,
                $"Перевести {selected.DeviceName} в Retired?\n\nУстройство перестанет участвовать в trusted discovery и передачах, но identity, ключи и история сохранятся. Позже его можно вернуть в Active без нового сопряжения.",
                "Genia Link · Retire device",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);
            if (answer != MessageBoxResult.Yes)
            {
                return;
            }
        }

        ApplyLifecycleChange(selected, target);
    }

    private void RevokeButton_Click(object sender, RoutedEventArgs e)
    {
        if (TrustedDevicesDataGrid.SelectedItem is not TrustedDeviceSettingsItem selected ||
            selected.LifecycleState == TrustedIdentityLifecycleState.Revoked)
        {
            return;
        }

        var answer = System.Windows.MessageBox.Show(
            this,
            $"ОТОЗВАТЬ доверие к {selected.DeviceName}?\n\nRevoked — терминальное состояние: signed discovery, rename, key rotation и trusted-подключения от этой identity будут блокироваться. Активные передачи будут немедленно остановлены, а прежняя докачка не перейдёт в новое доверие. Для нового доверия запись нужно сначала явно забыть, затем выполнить новое SAS-сопряжение.",
            "Genia Link · Revoke trust",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        ApplyLifecycleChange(selected, TrustedIdentityLifecycleState.Revoked);
    }

    private void ApplyLifecycleChange(TrustedDeviceSettingsItem selected, TrustedIdentityLifecycleState target)
    {
        try
        {
            if (!_setLifecycleState(selected.DeviceId, target))
            {
                return;
            }

            var index = _devices.IndexOf(selected);
            if (index >= 0)
            {
                var status = target switch
                {
                    TrustedIdentityLifecycleState.Active => "Ожидает discovery",
                    TrustedIdentityLifecycleState.Retired => "Не участвует",
                    TrustedIdentityLifecycleState.Revoked => "Заблокировано",
                    _ => selected.Status
                };
                var updated = selected with { LifecycleState = target, Status = status };
                _devices[index] = updated;
                TrustedDevicesDataGrid.SelectedItem = updated;
            }

            UpdateLifecycleButtons();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void UpdateLifecycleButtons()
    {
        if (TrustedDevicesDataGrid?.SelectedItem is not TrustedDeviceSettingsItem selected)
        {
            if (RetireReactivateButton is not null)
            {
                RetireReactivateButton.IsEnabled = false;
            }

            if (RevokeButton is not null)
            {
                RevokeButton.IsEnabled = false;
            }

            return;
        }

        var revoked = selected.LifecycleState == TrustedIdentityLifecycleState.Revoked;
        RetireReactivateButton.Content = selected.LifecycleState == TrustedIdentityLifecycleState.Retired
            ? "Вернуть в Active"
            : "Перевести в Retired";
        RetireReactivateButton.IsEnabled = !revoked;
        RevokeButton.IsEnabled = !revoked;
    }

    private void ForgetSelectedButton_Click(object sender, RoutedEventArgs e)
    {
        if (TrustedDevicesDataGrid.SelectedItem is not TrustedDeviceSettingsItem selected)
        {
            return;
        }

        var answer = System.Windows.MessageBox.Show(
            this,
            $"Удалить доверие к {selected.DeviceName}?\nДля следующей передачи потребуется новое безопасное сопряжение.",
            "Genia Link",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            if (_forgetDevice(selected.DeviceId))
            {
                _devices.Remove(selected);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void RotateSigningKeyButton_Click(object sender, RoutedEventArgs e)
    {
        var answer = System.Windows.MessageBox.Show(
            this,
            "Запланировать безопасную смену signing key?\n\nПри следующем запуске Genia Link старый signing key подпишет новый. Device ID, ECDH-ключ и существующие сопряжения не меняются. Устройства должны быть обновлены до GNP/1 M2.4.2, чтобы принять новый ключ без повторного сопряжения.",
            "Genia Link · Trusted Key Rotation",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);

        if (answer != MessageBoxResult.Yes)
        {
            return;
        }

        try
        {
            _requestSigningKeyRotation();
            System.Windows.MessageBox.Show(
                this,
                "Смена signing key запланирована. Полностью закройте Genia Link и запустите его снова. При следующем чистом запуске generation увеличится на 1, а переход будет подписан текущим ключом.",
                "Genia Link",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or CryptographicException)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void CopyInfoButton_Click(object sender, RoutedEventArgs e)
    {
        var text =
            $"Genia Link v0.3.1 RC4{Environment.NewLine}" +
            $"Protocol v3{Environment.NewLine}" +
            $"Fingerprint: {_localFingerprint}{Environment.NewLine}" +
            "Local-only: no cloud, telemetry, analytics, or external API.";
        System.Windows.Clipboard.SetText(text);
    }
}
