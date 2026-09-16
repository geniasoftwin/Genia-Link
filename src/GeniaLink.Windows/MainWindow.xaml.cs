using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using GeniaLink.Core.Capabilities;
using GeniaLink.Core.Discovery;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Pairing;
using GeniaLink.Core.Transfers;
using GeniaLink.Windows.Models;
using GeniaLink.Windows.Services;
using Microsoft.Win32;
using Forms = System.Windows.Forms;
using Drawing = System.Drawing;

namespace GeniaLink.Windows;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "WPF window lifetime disposes the tray icon in OnClosed and explicit application exit.")]
public partial class MainWindow : Window
{
    private readonly string _appDataDirectory;
    private readonly LocalIdentity _identity;
    private readonly TrustedDeviceStore _trustedDevices;
    private readonly AppSettingsStore _settingsStore;
    private AppSettings _settings;
    private readonly Dictionary<Guid, DiscoveredDevice> _discovered = new();
    private readonly HashSet<Guid> _staleDevices = new();
    private readonly HashSet<Guid> _identityBindingInFlight = new();
    private readonly Dictionary<Guid, DateTimeOffset> _identityBindingRetryAfter = new();
    private readonly ObservableCollection<DeviceListItem> _deviceItems = new();
    private readonly Progress<TransferProgress> _progress;
    private readonly Stopwatch _progressStopwatch = new();

    private Action? _cancelServices;
    private Task? _servicesTask;
    private Action? _cancelSend;
    private bool _isReceiving;
    private bool _isBrowsing;
    private TransferFileSource[] _selectedSources = Array.Empty<TransferFileSource>();
    private string _progressFileName = string.Empty;
    private Forms.NotifyIcon? _trayIcon;
    private Drawing.Icon? _trayIconImage;
    private string? _sendToOnlineSignature;
    private bool _minimizeNoticeShown;
    private readonly Queue<ExternalSendRequest> _externalSendQueue = new();
    private bool _externalQueueRunning;

    public MainWindow()
    {
        InitializeComponent();
        _progress = new Progress<TransferProgress>(UpdateProgress);
        _appDataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Genia Link");

        _identity = LocalIdentity.LoadOrCreate(_appDataDirectory, AppendLog);
        _trustedDevices = new TrustedDeviceStore(_appDataDirectory, AppendLog);
        _settingsStore = new AppSettingsStore(_appDataDirectory, AppendLog);
        _settings = _settingsStore.Current;

        DevicesListBox.ItemsSource = _deviceItems;
        var deviceView = CollectionViewSource.GetDefaultView(_deviceItems);
        deviceView.GroupDescriptions.Add(new PropertyGroupDescription(nameof(DeviceListItem.GroupName)));
        LocalDeviceNameTextBlock.Text = _identity.DeviceName;
        FingerprintTextBlock.Text = FormatFingerprint(_identity.GetPublicKeyFingerprint());
        LocalIpTextBlock.Text = GetLocalIPv4Addresses();
        ReceiveFolderTextBlock.Text = GetReceiveFolder();
        InitializeTrayIcon();
        TryApplyStartupIntegration();
        RestorePersistedTrustedEndpoints();
        TryRefreshSendToForOnlineDevices();
        AppendLog("Genia Link v0.3.1 RC4 started. Internet/cloud services are not used.");
        AppendLog($"Local Device ID: {_identity.DeviceId:D}");
        AppendLog($"GNP/1 M2 Signing Key ID: {_identity.SigningKeyId} (generation {_identity.KeyGeneration})");
        AppendLog($"GNP/1 M2.6 local role profile: {_settings.DeviceRole} · capabilities: {_settings.Capabilities}.");
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        if (_servicesTask is not null)
        {
            return;
        }

        var servicesCts = new CancellationTokenSource();
        _cancelServices = servicesCts.Cancel;
        _servicesTask = RunLocalServicesAsync(servicesCts);
        await _servicesTask;
    }

    private async Task RunLocalServicesAsync(CancellationTokenSource servicesCts)
    {
        using (servicesCts)
        {
            try
            {
                Directory.CreateDirectory(GetReceiveFolder());
                var localPeer = _identity.ToPairingPeerInfo();
                var advertisement = new DiscoveryAdvertisement(
                    _identity.DeviceId,
                    _identity.DeviceName,
                    ProtocolConstants.Port,
                    ProtocolConstants.PairingPort,
                    PairingProtocol.GetPublicKeyFingerprint(localPeer.PublicKey),
                    DeviceKind.WindowsComputer);

                ServiceStatusTextBlock.Text = "Локальная сеть активна";
                AppendLog("Starting local receiver, discovery, and pairing services...");

                var transferTask = FileTransferServer.RunAsync(
                    ProtocolConstants.Port,
                    _identity.DeviceId,
                    ResolveSharedKey,
                    _trustedDevices.GetSessionAuthorization,
                    GetReceiveFolder(),
                    _progress,
                    (fileName, size) => { _ = Dispatcher.InvokeAsync(() => OnIncomingTransferStarted(fileName, size)); },
                    (fileName, success, message) => { _ = Dispatcher.InvokeAsync(() => OnIncomingTransferEnded(fileName, success, message)); },
                    (deviceId, address) => { _ = Dispatcher.InvokeAsync(() => OnAuthenticatedPeerSeen(deviceId, address)); },
                    Services.WindowsPreviewProvider.CreateJpegThumbnailAsync,
                    message => { _ = Dispatcher.InvokeAsync(() => AppendLog(message)); },
                    servicesCts.Token);

                var pairingTask = PairingServer.RunAsync(
                    ProtocolConstants.PairingPort,
                    localPeer,
                    ConfirmPairingAsync,
                    peer => Dispatcher.Invoke(() => SaveTrustedPeer(peer)),
                    message => { _ = Dispatcher.InvokeAsync(() => AppendLog(message)); },
                    servicesCts.Token);

                var identityBindingTask = IdentityBindingService.RunServerAsync(
                    ProtocolConstants.IdentityBindingPort,
                    _identity,
                    ResolveSharedKey,
                    (identity, address) => OnTrustedSigningIdentityBound(identity, address, "incoming authenticated binding"),
                    message => { _ = Dispatcher.InvokeAsync(() => AppendLog(message)); },
                    servicesCts.Token);

                var identityRevision = IdentityAssertionRevisionStore.LoadOrAdvance(
                    Path.Combine(_appDataDirectory, "identity-assertion-revision.json"),
                    _identity,
                    message => { _ = Dispatcher.InvokeAsync(() => AppendLog(message)); });
                var capabilityRevision = CapabilityAssertionRevisionStore.LoadOrAdvance(
                    Path.Combine(_appDataDirectory, "capability-assertion-revision.json"),
                    _identity,
                    _settings.Capabilities,
                    message => { _ = Dispatcher.InvokeAsync(() => AppendLog(message)); });
                var discoveryTask = DiscoveryService.RunAsync(
                    advertisement,
                    _identity,
                    identityRevision,
                    _settings.Capabilities,
                    capabilityRevision,
                    device => { _ = Dispatcher.InvokeAsync(() => OnDeviceSeen(device)); },
                    message => { _ = Dispatcher.InvokeAsync(() => AppendLog(message)); },
                    servicesCts.Token);

                var cleanupTask = CleanupDiscoveredDevicesAsync(servicesCts.Token);
                var tasks = new[] { transferTask, pairingTask, identityBindingTask, discoveryTask, cleanupTask };
                var firstCompleted = await Task.WhenAny(tasks);
                if (!servicesCts.IsCancellationRequested && firstCompleted.IsCompleted)
                {
                    servicesCts.Cancel();
                }

                await Task.WhenAll(tasks);
            }
            catch (OperationCanceledException) when (servicesCts.IsCancellationRequested)
            {
            }
            catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or CryptographicException or InvalidDataException)
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    ServiceStatusTextBlock.Text = "Ошибка локальной службы";
                    AppendLog($"Local service stopped safely: {ex.Message}");
                });
            }
            finally
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    _cancelServices = null;
                    ServiceStatusTextBlock.Text = "Локальные службы остановлены";
                });
            }
        }
    }

    private async Task CleanupDiscoveredDevicesAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken);
            await Dispatcher.InvokeAsync(() =>
            {
                var cutoff = DateTimeOffset.UtcNow - ProtocolConstants.DiscoveryExpiry;
                var expired = _discovered
                    .Where(pair => pair.Value.LastSeenUtc < cutoff)
                    .Select(pair => pair.Key)
                    .ToArray();

                var changed = false;
                foreach (var deviceId in expired)
                {
                    if (_trustedDevices.Get(deviceId) is not null)
                    {
                        changed |= _staleDevices.Add(deviceId);
                    }
                    else
                    {
                        changed |= _discovered.Remove(deviceId);
                        _staleDevices.Remove(deviceId);
                    }
                }

                if (changed)
                {
                    RefreshDeviceList();
                }
            });
        }
    }

    private byte[]? ResolveSharedKey(Guid remoteDeviceId)
    {
        var trusted = _trustedDevices.Get(remoteDeviceId);
        if (trusted is null)
        {
            return null;
        }

        byte[] publicKey;
        try
        {
            publicKey = trusted.GetPublicKey();
        }
        catch (FormatException)
        {
            return null;
        }

        try
        {
            return _identity.DeriveSharedKey(publicKey);
        }
        catch (CryptographicException)
        {
            return null;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private void OnDeviceSeen(DiscoveredDevice device)
    {
        if (_trustedDevices.IsKnownInactive(device.DeviceId))
        {
            _discovered.Remove(device.DeviceId);
            _staleDevices.Remove(device.DeviceId);
            RefreshDeviceList();
            return;
        }

        device = PromoteKnownAuthenticatedSignedDiscovery(device);
        _discovered[device.DeviceId] = device;
        _staleDevices.Remove(device.DeviceId);
        if (device.Kind != DeviceKind.Unknown && _trustedDevices.Get(device.DeviceId) is not null)
        {
            try
            {
                _trustedDevices.UpdateDeviceKind(device.DeviceId, device.Kind);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
            {
                AppendLog($"Trusted device type could not be updated: {ex.Message}");
            }
        }

        TryStartSigningIdentityBinding(device);
        RefreshDeviceList();
    }

    private DiscoveredDevice PromoteKnownAuthenticatedSignedDiscovery(DiscoveredDevice device)
    {
        if (device.IdentityProof != DiscoveryIdentityProof.SignedIdentityV2 &&
            device.IdentityProof != DiscoveryIdentityProof.ReplayProtectedSignedIdentityV2 &&
            device.IdentityProof != DiscoveryIdentityProof.CapabilitySignedIdentityV2)
        {
            return device;
        }

        try
        {
            if (!_trustedDevices.TryApplyAuthenticatedSignedDiscovery(device))
            {
                return device;
            }

            return device with { IdentityProof = DiscoveryIdentityProof.AuthenticatedTrustedIdentityV2 };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or CryptographicException or FormatException)
        {
            AppendLog($"GNP/1 M2.6.2 authenticated discovery state could not be persisted for {device.DeviceName}; existing trust was kept: {ex.Message}");
            return device;
        }
    }

    private void TryStartSigningIdentityBinding(DiscoveredDevice device)
    {
        if ((device.IdentityProof != DiscoveryIdentityProof.SignedIdentityV2 &&
             device.IdentityProof != DiscoveryIdentityProof.ReplayProtectedSignedIdentityV2 &&
             device.IdentityProof != DiscoveryIdentityProof.CapabilitySignedIdentityV2) ||
            string.IsNullOrWhiteSpace(device.SigningKeyId) ||
            device.IdentityVersion < DeviceIdentityV2.CurrentVersion ||
            device.SigningKeyGeneration < 1)
        {
            return;
        }

        var trusted = _trustedDevices.Get(device.DeviceId);
        if (trusted is null)
        {
            return;
        }

        if (string.Equals(trusted.SigningKeyId, device.SigningKeyId, StringComparison.OrdinalIgnoreCase) &&
            trusted.SigningKeyGeneration >= device.SigningKeyGeneration)
        {
            return;
        }

        var now = DateTimeOffset.UtcNow;
        if (_identityBindingInFlight.Contains(device.DeviceId) ||
            (_identityBindingRetryAfter.TryGetValue(device.DeviceId, out var retryAfter) && retryAfter > now))
        {
            return;
        }

        _identityBindingInFlight.Add(device.DeviceId);
        _identityBindingRetryAfter[device.DeviceId] = now + TimeSpan.FromMinutes(1);
        _ = BindTrustedSigningIdentityAsync(device);
    }

    private async Task BindTrustedSigningIdentityAsync(DiscoveredDevice discovered)
    {
        byte[]? trustedPublicKey = null;
        byte[]? sharedKey = null;
        TrustedSigningIdentity? remoteIdentity = null;
        try
        {
            var trusted = _trustedDevices.Get(discovered.DeviceId);
            if (trusted is null)
            {
                return;
            }

            trustedPublicKey = trusted.GetPublicKey();
            sharedKey = _identity.DeriveSharedKey(trustedPublicKey);
            using var timeoutCts = new CancellationTokenSource(ProtocolConstants.HandshakeTimeout + TimeSpan.FromSeconds(5));
            remoteIdentity = await IdentityBindingService.BindAsync(
                discovered.Address,
                ProtocolConstants.IdentityBindingPort,
                _identity,
                discovered.DeviceId,
                sharedKey,
                timeoutCts.Token);

            var update = _trustedDevices.UpdateSigningIdentity(remoteIdentity);
            var action = update switch
            {
                SigningIdentityBindingUpdate.Bound => "bound",
                SigningIdentityBindingUpdate.Rotated => "rotated",
                _ => "verified"
            };
            var milestone = update == SigningIdentityBindingUpdate.Rotated ? "M2.4.2" : "M2.3";
            PromoteAuthenticatedSigningIdentityToDiscovered(remoteIdentity, discovered.Address);
            AppendLog($"GNP/1 {milestone} trusted signing identity {action} for {trusted.DeviceName}: {remoteIdentity.SigningKeyId} (generation {remoteIdentity.KeyGeneration}).");
            if (!string.Equals(discovered.SigningKeyId, remoteIdentity.SigningKeyId, StringComparison.OrdinalIgnoreCase))
            {
                AppendLog($"Signed discovery key differed from the authenticated binding for {trusted.DeviceName}; discovery proof was not trusted for key replacement.");
            }

            RefreshDeviceList();
        }
        catch (OperationCanceledException)
        {
            AppendLog($"GNP/1 M2.3 signing-identity binding timed out for {discovered.DeviceName}; existing trust was kept.");
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or CryptographicException or InvalidDataException or ArgumentException)
        {
            AppendLog($"GNP/1 M2.3 signing-identity binding unavailable for {discovered.DeviceName}; existing trust was kept: {ex.Message}");
        }
        finally
        {
            if (remoteIdentity is not null)
            {
                CryptographicOperations.ZeroMemory(remoteIdentity.SigningPublicKey);
            }

            if (sharedKey is not null)
            {
                CryptographicOperations.ZeroMemory(sharedKey);
            }

            if (trustedPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(trustedPublicKey);
            }

            _identityBindingInFlight.Remove(discovered.DeviceId);
        }
    }

    private void OnTrustedSigningIdentityBound(TrustedSigningIdentity identity, IPAddress address, string source)
    {
        try
        {
            var trusted = _trustedDevices.Get(identity.DeviceId);
            if (trusted is null)
            {
                return;
            }

            var update = _trustedDevices.UpdateSigningIdentity(identity);
            var signingKeyId = identity.SigningKeyId;
            var keyGeneration = identity.KeyGeneration;
            _ = Dispatcher.InvokeAsync(() =>
            {
                var action = update switch
                {
                    SigningIdentityBindingUpdate.Bound => "bound",
                    SigningIdentityBindingUpdate.Rotated => "rotated",
                    _ => "verified"
                };
                var milestone = update == SigningIdentityBindingUpdate.Rotated ? "M2.4.2" : "M2.3";
                PromoteAuthenticatedSigningIdentityToDiscovered(identity, address);
                AppendLog($"GNP/1 {milestone} trusted signing identity {action} for {trusted.DeviceName} after {source}: {signingKeyId} (generation {keyGeneration}, {address}).");
                RefreshDeviceList();
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or InvalidDataException or ArgumentException)
        {
            _ = Dispatcher.InvokeAsync(() => AppendLog($"Authenticated signing identity could not be persisted: {ex.Message}"));
        }
    }

    private void PromoteAuthenticatedSigningIdentityToDiscovered(TrustedSigningIdentity identity, IPAddress address)
    {
        var trusted = _trustedDevices.Get(identity.DeviceId);
        var trustedFingerprint = trusted is null ? null : GetTrustedFingerprint(trusted);
        if (trusted is null || trustedFingerprint is null || !_discovered.TryGetValue(identity.DeviceId, out var current))
        {
            return;
        }

        // A successful M2.3 exchange is already authenticated by the pre-existing ECDH trust.
        // Promote only a discovery record whose agreement-key fingerprint still matches that
        // trusted identity; never use binding to hide a genuine ECDH identity mismatch.
        if (!string.Equals(current.PublicKeyFingerprint, trustedFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        current = PromoteKnownAuthenticatedSignedDiscovery(current);

        _discovered[identity.DeviceId] = current with
        {
            Address = address,
            LastSeenUtc = DateTimeOffset.UtcNow,
            IdentityProof = DiscoveryIdentityProof.AuthenticatedTrustedIdentityV2,
            SigningKeyId = identity.SigningKeyId,
            IdentityVersion = identity.IdentityVersion,
            SigningKeyGeneration = identity.KeyGeneration
        };
        _staleDevices.Remove(identity.DeviceId);
    }

    private void RefreshDeviceList()
    {
        var selectedId = (DevicesListBox.SelectedItem as DeviceListItem)?.DeviceId;
        var items = _discovered.Values
            .OrderBy(device => device.Kind is DeviceKind.WindowsComputer ? 0 : device.Kind is DeviceKind.AndroidPhone or DeviceKind.AndroidTablet ? 1 : 2)
            .ThenBy(device => device.DeviceName, StringComparer.CurrentCultureIgnoreCase)
            .Select(CreateDeviceListItem)
            .ToArray();

        _deviceItems.Clear();
        foreach (var item in items)
        {
            _deviceItems.Add(item);
        }

        DeviceCountTextBlock.Text = items.Length == 0 ? "не найдено" : items.Length.ToString(System.Globalization.CultureInfo.CurrentCulture);
        if (selectedId is not null)
        {
            DevicesListBox.SelectedItem = _deviceItems.FirstOrDefault(item => item.DeviceId == selectedId.Value);
        }

        UpdateSelectedDeviceUi();
        TryRefreshSendToForOnlineDevices();
    }

    private DeviceListItem CreateDeviceListItem(DiscoveredDevice device)
    {
        var trusted = _trustedDevices.GetAny(device.DeviceId);
        var registryEntry = _trustedDevices.GetIdentityRegistryEntry(device.DeviceId);
        var cryptographicBindingTrusted = registryEntry?.State == TrustedIdentityRegistryState.Trusted;
        var trustedFingerprint = trusted is null ? null : GetTrustedFingerprint(trusted);
        var agreementIdentityMatches = trusted is null ||
                                       (trustedFingerprint is not null &&
                                        string.Equals(trustedFingerprint, device.PublicKeyFingerprint, StringComparison.OrdinalIgnoreCase));
        // A compatibility GLD2 packet carries no signing key, so it cannot prove that a
        // previously bound signing identity changed. Treat only an explicit signed/authenticated
        // mismatch as a signing-key conflict; the trusted ECDH handshake still gates transfers.
        var signingIdentityMatches = trusted is null ||
                                     string.IsNullOrWhiteSpace(trusted.SigningKeyId) ||
                                     _staleDevices.Contains(device.DeviceId) ||
                                     device.IdentityProof == DiscoveryIdentityProof.LegacyUnsigned ||
                                     ((device.IdentityProof is DiscoveryIdentityProof.SignedIdentityV2 or DiscoveryIdentityProof.ReplayProtectedSignedIdentityV2 or DiscoveryIdentityProof.AuthenticatedTrustedIdentityV2) &&
                                      !string.IsNullOrWhiteSpace(device.SigningKeyId) &&
                                      string.Equals(trusted.SigningKeyId, device.SigningKeyId, StringComparison.OrdinalIgnoreCase));
        var identityMatches = agreementIdentityMatches && signingIdentityMatches &&
                              (trusted is null || cryptographicBindingTrusted);

        return new DeviceListItem(
            device.DeviceId,
            device.DeviceName,
            device.Address,
            device.TransferPort,
            device.PairingPort,
            device.PublicKeyFingerprint,
            device.Kind,
            !_staleDevices.Contains(device.DeviceId),
            trusted is not null,
            identityMatches);
    }

    private static string? GetTrustedFingerprint(TrustedDevice trusted)
    {
        try
        {
            var publicKey = trusted.GetPublicKey();
            try
            {
                return PairingProtocol.GetPublicKeyFingerprint(publicKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }
        catch (FormatException)
        {
            return null;
        }
    }

    private void RestorePersistedTrustedEndpoints()
    {
        var restored = 0;
        foreach (var trusted in _trustedDevices.GetAll())
        {
            var address = trusted.GetLastVerifiedAddress();
            var fingerprint = GetTrustedFingerprint(trusted);
            if (address is null ||
                fingerprint is null ||
                trusted.LastVerifiedTransferPort is < 1 or > 65535 ||
                trusted.LastVerifiedPairingPort is < 1 or > 65535 ||
                trusted.EndpointVerifiedAtUtc is null)
            {
                continue;
            }

            _discovered[trusted.DeviceId] = new DiscoveredDevice(
                trusted.DeviceId,
                trusted.DeviceName,
                address,
                trusted.LastVerifiedTransferPort,
                trusted.LastVerifiedPairingPort,
                fingerprint,
                trusted.Kind,
                trusted.EndpointVerifiedAtUtc.Value,
                string.IsNullOrWhiteSpace(trusted.SigningKeyId)
                    ? DiscoveryIdentityProof.LegacyUnsigned
                    : DiscoveryIdentityProof.AuthenticatedTrustedIdentityV2,
                trusted.SigningKeyId,
                trusted.SigningIdentityVersion > 0 ? trusted.SigningIdentityVersion : 1,
                trusted.SigningKeyGeneration);
            _staleDevices.Add(trusted.DeviceId);
            restored++;
        }

        if (restored > 0)
        {
            AppendLog($"Restored {restored} trusted sleeping endpoint(s) from authenticated history.");
            RefreshDeviceList();
        }
    }

    private void TryPersistVerifiedEndpoint(DeviceListItem device, string source)
    {
        try
        {
            _trustedDevices.UpdateVerifiedEndpoint(
                device.DeviceId,
                device.Address,
                device.TransferPort,
                device.PairingPort,
                device.Kind);
            AppendLog($"Remembered authenticated LAN endpoint for {device.DeviceName} after {source}.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AppendLog($"Authenticated endpoint could not be persisted: {ex.Message}");
        }
    }

    private void OnAuthenticatedPeerSeen(Guid deviceId, IPAddress address)
    {
        var trusted = _trustedDevices.Get(deviceId);
        if (trusted is null)
        {
            return;
        }

        var kind = _discovered.TryGetValue(deviceId, out var current)
            ? current.Kind
            : trusted.Kind;
        try
        {
            _trustedDevices.UpdateVerifiedEndpoint(
                deviceId,
                address,
                ProtocolConstants.Port,
                ProtocolConstants.PairingPort,
                kind);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AppendLog($"Authenticated incoming endpoint could not be persisted: {ex.Message}");
            return;
        }

        var refreshed = _trustedDevices.Get(deviceId);
        var fingerprint = refreshed is null ? null : GetTrustedFingerprint(refreshed);
        if (refreshed is null || fingerprint is null)
        {
            return;
        }

        _discovered[deviceId] = new DiscoveredDevice(
            deviceId,
            refreshed.DeviceName,
            address,
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            fingerprint,
            refreshed.Kind,
            DateTimeOffset.UtcNow,
            string.IsNullOrWhiteSpace(refreshed.SigningKeyId)
                ? DiscoveryIdentityProof.LegacyUnsigned
                : DiscoveryIdentityProof.AuthenticatedTrustedIdentityV2,
            refreshed.SigningKeyId,
            refreshed.SigningIdentityVersion > 0 ? refreshed.SigningIdentityVersion : 1,
            refreshed.SigningKeyGeneration);
        _staleDevices.Remove(deviceId);
        AppendLog($"Authenticated incoming connection refreshed the saved endpoint for {refreshed.DeviceName}.");
        RefreshDeviceList();
    }

    private void DevicesListBox_SelectionChanged(object sender, SelectionChangedEventArgs e) => UpdateSelectedDeviceUi();

    private void UpdateSelectedDeviceUi()
    {
        if (DevicesListBox.SelectedItem is not DeviceListItem selected)
        {
            SelectedDeviceTextBlock.Text = "Выберите устройство слева";
            PairButton.IsEnabled = false;
            PairButton.Visibility = Visibility.Collapsed;
            ForgetButton.IsEnabled = false;
            ForgetSelectedMenuItem.IsEnabled = false;
            SendButton.IsEnabled = false;
            BrowseRemoteButton.IsEnabled = false;
            return;
        }

        var compactStatus = selected.IsTrusted
            ? selected.IdentityMatches
                ? selected.IsRecentlySeen ? "Доступен" : "Спит"
                : "Ключ изменился"
            : "Новое устройство";
        SelectedDeviceTextBlock.Text = $"{selected.DeviceName} · {compactStatus}";

        var pairingRequired = !selected.IsTrusted || !selected.IdentityMatches;
        PairButton.Content = selected.IsTrusted && !selected.IdentityMatches ? "Сопрячь заново" : "Сопрячь";
        PairButton.IsEnabled = !_isReceiving && !_isBrowsing && _cancelSend is null && pairingRequired;
        PairButton.Visibility = pairingRequired ? Visibility.Visible : Visibility.Collapsed;

        ForgetButton.IsEnabled = !_isReceiving && !_isBrowsing && _cancelSend is null && selected.IsTrusted;
        ForgetSelectedMenuItem.IsEnabled = ForgetButton.IsEnabled;
        SendButton.IsEnabled = !_isReceiving && !_isBrowsing && selected.IsTrusted && selected.IdentityMatches && _selectedSources.Length > 0 && _cancelSend is null;
        BrowseRemoteButton.IsEnabled = !_isReceiving && !_isBrowsing && _cancelSend is null && selected.IsTrusted && selected.IdentityMatches;
    }

    private async void BrowseRemoteButton_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesListBox.SelectedItem is not DeviceListItem selected ||
            !selected.IsTrusted ||
            !selected.IdentityMatches ||
            _isReceiving ||
            _isBrowsing ||
            _cancelSend is not null)
        {
            return;
        }

        var trusted = _trustedDevices.Get(selected.DeviceId);
        if (trusted is null)
        {
            RefreshDeviceList();
            return;
        }

        byte[] peerPublicKey;
        try
        {
            peerPublicKey = trusted.GetPublicKey();
        }
        catch (FormatException ex)
        {
            AppendLog($"Stored trusted key is invalid: {ex.Message}");
            return;
        }

        var sharedKey = Array.Empty<byte>();
        _isBrowsing = true;
        UpdateSelectedDeviceUi();
        try
        {
            sharedKey = _identity.DeriveSharedKey(peerPublicKey);
            AppendLog($"Reading protected Genia Link folder on {selected.DeviceName} ({selected.Address})...");
            var files = await RemoteFolderClient.ListFilesAsync(
                selected.Address,
                selected.TransferPort,
                _identity.DeviceId,
                _identity.DeviceName,
                selected.DeviceId,
                sharedKey,
                CancellationToken.None);

            TryPersistVerifiedEndpoint(selected, "authenticated Genia Link folder browse");
            AppendLog($"Remote Genia Link folder on {selected.DeviceName}: {files.Count} file(s).");
            using var browser = new RemoteFilesWindow(
                selected.DeviceName,
                files,
                async cancellationToken =>
                {
                    var refreshed = await RemoteFolderClient.ListFilesAsync(
                        selected.Address,
                        selected.TransferPort,
                        _identity.DeviceId,
                        _identity.DeviceName,
                        selected.DeviceId,
                        sharedKey,
                        cancellationToken);
                    TryPersistVerifiedEndpoint(selected, "authenticated Genia Link folder refresh");
                    return refreshed;
                },
                async (relativePath, cancellationToken) =>
                {
                    var preview = await RemoteFolderClient.GetPreviewAsync(
                        selected.Address,
                        selected.TransferPort,
                        _identity.DeviceId,
                        _identity.DeviceName,
                        selected.DeviceId,
                        sharedKey,
                        relativePath,
                        cancellationToken);
                    TryPersistVerifiedEndpoint(selected, "authenticated Genia Link file preview");
                    return preview;
                })
            {
                Owner = this
            };
            if (browser.ShowDialog() != true)
            {
                return;
            }

            var requested = browser.SelectedRelativePaths;
            if (requested.Count == 0)
            {
                return;
            }

            AppendLog($"Requesting {requested.Count} file(s) from {selected.DeviceName}; incoming files will use the local Genia Link folder.");
            await RemoteFolderClient.RequestDownloadAsync(
                selected.Address,
                selected.TransferPort,
                ProtocolConstants.Port,
                _identity.DeviceId,
                _identity.DeviceName,
                selected.DeviceId,
                sharedKey,
                requested,
                CancellationToken.None);
            TryPersistVerifiedEndpoint(selected, "authenticated remote download request");
            ProgressTextBlock.Text = $"Запрошено файлов: {requested.Count}";
            AppendLog("Remote device accepted the protected download request; files will arrive through the normal verified transfer receiver.");
        }
        catch (OperationCanceledException)
        {
            AppendLog("Remote Genia Link folder request timed out safely.");
            ProgressTextBlock.Text = "Тайм-аут просмотра";
        }
        catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or InvalidDataException or AuthenticationException or CryptographicException or InvalidOperationException)
        {
            AppendLog($"Remote Genia Link folder request failed safely: {ex.Message}");
            ProgressTextBlock.Text = "Ошибка просмотра файлов";
            System.Windows.MessageBox.Show(this, ex.Message, "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            if (sharedKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(sharedKey);
            }

            CryptographicOperations.ZeroMemory(peerPublicKey);
            _isBrowsing = false;
            UpdateSelectedDeviceUi();
        }
    }

    private async void PairButton_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesListBox.SelectedItem is not DeviceListItem selected)
        {
            return;
        }

        PairButton.IsEnabled = false;
        try
        {
            AppendLog($"Pairing with {selected.DeviceName} at {selected.Address}...");
            var localPeer = _identity.ToPairingPeerInfo();
            var remote = await PairingClient.PairAsync(
                selected.Address,
                selected.PairingPort,
                localPeer,
                confirmation => ConfirmSelectedPairingAsync(selected, confirmation),
                CancellationToken.None);

            try
            {
                if (remote.DeviceId != selected.DeviceId)
                {
                    throw new AuthenticationException("Discovered device ID changed during pairing.");
                }

                SaveTrustedPeer(remote);
                TryPersistVerifiedEndpoint(selected, "successful pairing");
                AppendLog($"Trusted pairing completed with {remote.DeviceName}.");
            }
            finally
            {
                CryptographicOperations.ZeroMemory(remote.PublicKey);
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or CryptographicException or InvalidDataException or OperationCanceledException)
        {
            AppendLog($"Pairing failed safely: {ex.Message}");
            System.Windows.MessageBox.Show(this, ex.Message, "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            UpdateSelectedDeviceUi();
        }
    }

    private async Task<bool> ConfirmSelectedPairingAsync(DeviceListItem selected, PairingConfirmation confirmation)
    {
        if (confirmation.Peer.DeviceId != selected.DeviceId ||
            !string.Equals(confirmation.PublicKeyFingerprint, selected.PublicKeyFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            await Dispatcher.InvokeAsync(() => AppendLog("Pairing stopped: discovery identity changed before confirmation."));
            return false;
        }

        return await ConfirmPairingAsync(confirmation);
    }

    private async Task<bool> ConfirmPairingAsync(PairingConfirmation confirmation)
    {
        var operation = Dispatcher.InvokeAsync(() =>
        {
            var text =
                $"Устройство: {confirmation.Peer.DeviceName}\n\n" +
                $"Код проверки:\n\n        {confirmation.VerificationCode}\n\n" +
                "Убедитесь, что на втором устройстве показан ТОЧНО такой же код.\n\n" +
                "Коды совпадают?";

            return System.Windows.MessageBox.Show(
                this,
                text,
                "Безопасное сопряжение Genia Link",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No) == MessageBoxResult.Yes;
        });

        return await operation.Task;
    }

    private void SaveTrustedPeer(PairingPeerInfo peer)
    {
        var deviceKind = _discovered.TryGetValue(peer.DeviceId, out var discovered)
            ? discovered.Kind
            : DeviceKind.Unknown;
        var sameNameCandidates = _trustedDevices.GetAll()
            .Where(device => device.DeviceId != peer.DeviceId &&
                             string.Equals(device.DeviceName, peer.DeviceName, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        _trustedDevices.Upsert(peer, deviceKind);
        AppendLog($"Trusted device saved: {peer.DeviceName} ({FormatFingerprint(PairingProtocol.GetPublicKeyFingerprint(peer.PublicKey))}).");

        if (sameNameCandidates.Length > 0)
        {
            var result = System.Windows.MessageBox.Show(
                this,
                $"В доверенных устройствах уже есть {peer.DeviceName}, но у нового сопряжения другая криптографическая идентичность.\n\n" +
                "Так бывает после переустановки Genia Link. Если это то же физическое устройство, старую запись можно безопасно удалить.\n\n" +
                "Заменить старую запись новой?",
                "Genia Link · возможная переустановка",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question,
                MessageBoxResult.No);

            if (result == MessageBoxResult.Yes)
            {
                foreach (var oldDevice in sameNameCandidates)
                {
                    if (_trustedDevices.Remove(oldDevice.DeviceId))
                    {
                        RemoveRetainedDeviceIfStale(oldDevice.DeviceId);
                        AppendLog($"Replaced old trusted identity for {oldDevice.DeviceName} after explicit user confirmation.");
                    }
                }
            }
        }

        RefreshDeviceList();
    }

    private void ForgetButton_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesListBox.SelectedItem is not DeviceListItem selected || !selected.IsTrusted)
        {
            return;
        }

        var result = System.Windows.MessageBox.Show(
            this,
            $"Удалить доверие к устройству {selected.DeviceName}?\nДля следующей передачи потребуется новое сопряжение.",
            "Genia Link",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);

        if (result != MessageBoxResult.Yes)
        {
            return;
        }

        if (_trustedDevices.Remove(selected.DeviceId))
        {
            RemoveRetainedDeviceIfStale(selected.DeviceId);
            AppendLog($"Forgot trusted device: {selected.DeviceName}.");
            RefreshDeviceList();
        }
    }

    private void ChooseFilesButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Multiselect = true,
            CheckFileExists = true,
            Title = "Выберите файлы для Genia Link"
        };

        if (dialog.ShowDialog(this) == true)
        {
            SetSelectedPaths(dialog.FileNames);
        }
    }

    private void Window_DragOver(object sender, System.Windows.DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(System.Windows.DataFormats.FileDrop) ? System.Windows.DragDropEffects.Copy : System.Windows.DragDropEffects.None;
        e.Handled = true;
    }

    private void Window_Drop(object sender, System.Windows.DragEventArgs e)
    {
        if (e.Data.GetData(System.Windows.DataFormats.FileDrop) is not string[] paths)
        {
            return;
        }

        var existing = paths.Where(path => File.Exists(path) || Directory.Exists(path)).ToArray();
        if (existing.Length == 0)
        {
            return;
        }

        SetSelectedPaths(existing);
    }

    private void ChooseFolderButton_Click(object sender, RoutedEventArgs e)
    {
        using var dialog = new Forms.FolderBrowserDialog
        {
            Description = "Выберите папку для Genia Link",
            UseDescriptionForTitle = true,
            ShowNewFolderButton = false
        };

        if (dialog.ShowDialog() == Forms.DialogResult.OK && !string.IsNullOrWhiteSpace(dialog.SelectedPath))
        {
            SetSelectedPaths([dialog.SelectedPath]);
        }
    }

    private void SetSelectedPaths(IEnumerable<string> paths)
    {
        try
        {
            _selectedSources = TransferSelection.Expand(paths).ToArray();
            var totalBytes = _selectedSources.Sum(source => new FileInfo(source.FullPath).Length);
            SelectedFilesTextBlock.Text = _selectedSources.Length switch
            {
                0 => "Файлы не выбраны",
                1 when string.IsNullOrEmpty(_selectedSources[0].RelativeDirectory) => Path.GetFileName(_selectedSources[0].FullPath),
                1 => $"{_selectedSources[0].RelativeDirectory}/{Path.GetFileName(_selectedSources[0].FullPath)}",
                _ => $"В очереди файлов: {_selectedSources.Length} · {FormatBytes(totalBytes)}"
            };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            _selectedSources = Array.Empty<TransferFileSource>();
            SelectedFilesTextBlock.Text = "Файлы не выбраны";
            AppendLog($"Selection rejected safely: {ex.Message}");
            System.Windows.MessageBox.Show(this, ex.Message, "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        UpdateSelectedDeviceUi();
    }

    private async void SendButton_Click(object sender, RoutedEventArgs e)
    {
        if (DevicesListBox.SelectedItem is not DeviceListItem selected ||
            !selected.IsTrusted ||
            !selected.IdentityMatches ||
            _selectedSources.Length == 0 ||
            _isReceiving)
        {
            return;
        }

        await SendSourcesAsync(selected, _selectedSources, notifyWhenDone: false);
    }

    private async Task<bool> SendSourcesAsync(
        DeviceListItem selected,
        TransferFileSource[] sources,
        bool notifyWhenDone)
    {
        if (_cancelSend is not null || _isReceiving || sources.Length == 0)
        {
            return false;
        }

        var trusted = _trustedDevices.Get(selected.DeviceId);
        if (trusted is null || !selected.IdentityMatches)
        {
            RefreshDeviceList();
            return false;
        }

        byte[] peerPublicKey;
        try
        {
            peerPublicKey = trusted.GetPublicKey();
        }
        catch (FormatException ex)
        {
            AppendLog($"Stored trusted key is invalid: {ex.Message}");
            return false;
        }

        var authorization = _trustedDevices.GetSessionAuthorization(selected.DeviceId);
        if (authorization is null)
        {
            AppendLog($"GNP/1 M2.5.2.1 send blocked because {selected.DeviceName} is no longer Active and trusted.");
            RefreshDeviceList();
            return false;
        }

        var sharedKey = Array.Empty<byte>();
        using var sendCts = new CancellationTokenSource();
        using var trustLinkedCts = CancellationTokenSource.CreateLinkedTokenSource(sendCts.Token, authorization.LifetimeToken);
        _cancelSend = sendCts.Cancel;
        SendButton.IsEnabled = false;
        CancelSendButton.IsEnabled = true;
        ResetProgress();
        var success = false;

        try
        {
            sharedKey = _identity.DeriveSharedKey(peerPublicKey);
            if (!selected.IsRecentlySeen)
            {
                AppendLog($"{selected.DeviceName} has no fresh discovery; trying the last known LAN endpoint with the trusted handshake.");
            }
            AppendLog($"Connecting securely to {selected.DeviceName} ({selected.Address})...");
            await FileTransferClient.SendFilesAsync(
                selected.Address,
                selected.TransferPort,
                _identity.DeviceId,
                selected.DeviceId,
                sharedKey,
                sources,
                _progress,
                trustLinkedCts.Token);

            TryPersistVerifiedEndpoint(selected, "authenticated transfer");
            AppendLog("All queued files were sent and verified successfully.");
            ProgressTextBlock.Text = "Передача завершена";
            TransferProgressBar.Value = 100;
            success = true;
            if (notifyWhenDone || !IsVisible)
            {
                NotifyUser("Genia Link", $"Передача на {selected.DeviceName} завершена.");
            }
        }
        catch (OperationCanceledException) when (authorization.LifetimeToken.IsCancellationRequested)
        {
            AppendLog($"GNP/1 M2.5.2.1 outgoing transfer to {selected.DeviceName} terminated because trust was revoked or forgotten.");
            TransferProgressBar.Value = 0;
            SpeedTextBlock.Text = string.Empty;
            ProgressTextBlock.Text = "Доверие отозвано";
            if (notifyWhenDone || !IsVisible)
            {
                NotifyUser("Genia Link", $"Передача на {selected.DeviceName} остановлена: доверие отозвано.");
            }
        }
        catch (OperationCanceledException) when (sendCts.IsCancellationRequested)
        {
            AppendLog("Send cancelled safely.");
            TransferProgressBar.Value = 0;
            SpeedTextBlock.Text = string.Empty;
            ProgressTextBlock.Text = "Отменено";
            if (notifyWhenDone || !IsVisible)
            {
                NotifyUser("Genia Link", "Передача отменена.");
            }
        }
        catch (OperationCanceledException)
        {
            AppendLog("Connection timed out safely.");
            TransferProgressBar.Value = 0;
            SpeedTextBlock.Text = string.Empty;
            ProgressTextBlock.Text = "Тайм-аут";
            if (notifyWhenDone || !IsVisible)
            {
                NotifyUser("Genia Link", "Передача остановлена по тайм-ауту. Повторная попытка продолжит файл с сохранённого места.");
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or InvalidDataException or AuthenticationException or CryptographicException)
        {
            AppendLog($"Send failed safely: {ex.Message}");
            TransferProgressBar.Value = 0;
            SpeedTextBlock.Text = string.Empty;
            ProgressTextBlock.Text = "Ошибка передачи";
            if (notifyWhenDone || !IsVisible)
            {
                NotifyUser("Genia Link", "Ошибка передачи. Повторная отправка попробует докачать незавершённый файл.");
            }
        }
        finally
        {
            if (sharedKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(sharedKey);
            }

            CryptographicOperations.ZeroMemory(peerPublicKey);
            _cancelSend = null;
            CancelSendButton.IsEnabled = false;
            UpdateSelectedDeviceUi();
        }

        return success;
    }

    private void OnIncomingTransferStarted(string fileName, long size)
    {
        _isReceiving = true;
        _progressFileName = string.Empty;
        _progressStopwatch.Reset();
        TransferProgressBar.Value = 0;
        SpeedTextBlock.Text = string.Empty;
        ProgressTextBlock.Text = $"Получение: {fileName} · 0%";
        CancelSendButton.IsEnabled = false;
        AppendLog($"Incoming transfer started: {fileName} ({size:N0} bytes).");
        UpdateSelectedDeviceUi();
    }

    private void OnIncomingTransferEnded(string fileName, bool success, string message)
    {
        _isReceiving = false;
        SpeedTextBlock.Text = string.Empty;
        if (success)
        {
            TransferProgressBar.Value = 100;
            ProgressTextBlock.Text = $"Получено: {fileName} · SHA-256 проверен";
        }
        else
        {
            TransferProgressBar.Value = 0;
            ProgressTextBlock.Text = "Передача прервана";
        }

        AppendLog(success
            ? $"Incoming transfer completed: {fileName}."
            : $"Incoming transfer failed safely: {message}");
        UpdateSelectedDeviceUi();
    }


    private void MenuButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button button && button.ContextMenu is not null)
        {
            button.ContextMenu.PlacementTarget = button;
            button.ContextMenu.IsOpen = true;
        }
    }

    private void DiagnosticsMenuItem_Click(object sender, RoutedEventArgs e)
    {
        var show = DiagnosticsPanel.Visibility != Visibility.Visible;
        DiagnosticsPanel.Visibility = show ? Visibility.Visible : Visibility.Collapsed;
        DiagnosticsMenuItem.Header = show ? "Скрыть диагностику" : "Показать диагностику";
        if (show)
        {
            LogTextBox.ScrollToEnd();
        }
    }

    private void OpenReceiveFolderButton_Click(object sender, RoutedEventArgs e) => OpenReceiveFolder();

    internal bool ShouldStartMinimizedOnStartup => _settings.StartMinimized;

    internal void HideToTrayForStartup()
    {
        ShowInTaskbar = false;
        Hide();
    }

    private async void SettingsButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SettingsWindow(
            this,
            _settings,
            BuildTrustedDeviceSettingsItems(),
            () => RefreshSendToForOnlineDevices(force: true, ignoreSetting: true),
            RemoveSendToIntegration,
            ForgetTrustedDeviceFromSettings,
            SetTrustedDeviceLifecycleFromSettings,
            FormatFingerprint(_identity.GetPublicKeyFingerprint()),
            _identity.KeyGeneration,
            _identity.SigningKeyId,
            () => LocalIdentity.RequestSigningKeyRotation(_appDataDirectory, _identity));

        if (dialog.ShowDialog() != true || dialog.ResultSettings is null)
        {
            RefreshDeviceList();
            return;
        }

        var previousReceiveFolder = GetReceiveFolder();
        var previousCapabilities = _settings.Capabilities;
        AppSettings requestedSettings;
        bool receiveFolderChanged;
        try
        {
            var normalizedFolder = ReceiveFolderPolicy.Normalize(dialog.ResultSettings.ReceiveFolder);
            receiveFolderChanged = !ReceiveFolderPolicy.PathsEqual(previousReceiveFolder, normalizedFolder);
            if (receiveFolderChanged && (_isReceiving || _cancelSend is not null))
            {
                System.Windows.MessageBox.Show(
                    this,
                    "Папку Genia Link нельзя менять во время активной передачи. Завершите или отмените передачу и повторите изменение.",
                    "Genia Link",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                RefreshDeviceList();
                return;
            }

            var preparedFolder = receiveFolderChanged
                ? ReceiveFolderPolicy.ValidateAndPrepare(normalizedFolder)
                : previousReceiveFolder;
            requestedSettings = dialog.ResultSettings with { ReceiveFolder = preparedFolder };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException or NotSupportedException or System.Security.SecurityException)
        {
            AppendLog($"Receive folder rejected safely: {ex.Message}");
            System.Windows.MessageBox.Show(
                this,
                $"Не удалось использовать выбранную папку Genia Link.\n\n{ex.Message}",
                "Genia Link",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            RefreshDeviceList();
            return;
        }

        try
        {
            _settingsStore.Save(requestedSettings);
            _settings = _settingsStore.Current;
            ReceiveFolderTextBlock.Text = GetReceiveFolder();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException or NotSupportedException)
        {
            AppendLog($"Settings could not be saved: {ex.Message}");
            System.Windows.MessageBox.Show(
                this,
                "Не удалось сохранить настройки. Изменения не применены.",
                "Genia Link",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            RefreshDeviceList();
            return;
        }

        TryApplyStartupIntegration();
        try
        {
            if (_settings.EnableSendToIntegration)
            {
                _sendToOnlineSignature = null;
                RefreshSendToForOnlineDevices(force: true);
            }
            else
            {
                RemoveSendToIntegration();
                _sendToOnlineSignature = "disabled";
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or PlatformNotSupportedException or System.Reflection.TargetInvocationException)
        {
            AppendLog($"Windows SendTo setting could not be applied: {ex.Message}");
        }

        var capabilitiesChanged = previousCapabilities != _settings.Capabilities;
        if (receiveFolderChanged || capabilitiesChanged)
        {
            try
            {
                await RestartLocalServicesAsync();
                if (receiveFolderChanged)
                {
                    AppendLog($"Receive folder changed: {GetReceiveFolder()}");
                }

                if (capabilitiesChanged)
                {
                    AppendLog($"GNP/1 M2.6.2 local capabilities changed; authenticated advertisement restarted with {_settings.Capabilities}.");
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or SocketException or CryptographicException or ObjectDisposedException)
            {
                AppendLog($"Local services could not restart after settings change: {ex.Message}");
                ServiceStatusTextBlock.Text = "Требуется перезапуск приложения";
                System.Windows.MessageBox.Show(
                    this,
                    "Настройки сохранены, но локальные службы не удалось перезапустить. Перезапустите Genia Link перед следующей передачей.",
                    "Genia Link",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }

        AppendLog("Settings saved.");
        AppendLog($"GNP/1 M2.6.2 capability-derived role profile saved: {_settings.DeviceRole} · capabilities: {_settings.Capabilities}.");
        RefreshDeviceList();
    }

    private async Task RestartLocalServicesAsync()
    {
        ServiceStatusTextBlock.Text = "Перезапуск локальных служб…";
        var previousTask = _servicesTask;
        try
        {
            _cancelServices?.Invoke();
        }
        catch (ObjectDisposedException)
        {
        }

        if (previousTask is not null)
        {
            await previousTask;
        }

        _cancelServices = null;
        _servicesTask = null;

        var servicesCts = new CancellationTokenSource();
        _cancelServices = servicesCts.Cancel;
        _servicesTask = RunLocalServicesAsync(servicesCts);
    }

    private TrustedDeviceSettingsItem[] BuildTrustedDeviceSettingsItems()
    {
        var trustedById = _trustedDevices.GetAllIncludingInactive()
            .ToDictionary(device => device.DeviceId);

        return _trustedDevices.GetIdentityRegistryEntries()
            .Select(identity =>
            {
                trustedById.TryGetValue(identity.DeviceId, out var trusted);
                var lifecycleState = identity.LifecycleState;
                var online = lifecycleState == TrustedIdentityLifecycleState.Active
                    ? _deviceItems.FirstOrDefault(item => item.DeviceId == identity.DeviceId)
                    : null;
                var deviceKind = online?.Kind ?? trusted?.Kind ?? DeviceKind.Unknown;
                var status = trusted is null
                    ? lifecycleState switch
                    {
                        TrustedIdentityLifecycleState.Retired => "Registry only · Не участвует",
                        TrustedIdentityLifecycleState.Revoked => "Registry only · Заблокировано",
                        _ => "Registry only · Требует нового сопряжения"
                    }
                    : lifecycleState switch
                    {
                        TrustedIdentityLifecycleState.Retired => "Не участвует",
                        TrustedIdentityLifecycleState.Revoked => "Заблокировано",
                        _ => online is null
                            ? "Офлайн"
                            : online.IdentityMatches
                                ? online.IsRecentlySeen ? "Онлайн" : "Спит / нет свежего discovery"
                                : "КЛЮЧ ИЗМЕНЁН"
                    };
                var rawFingerprint = trusted is null
                    ? identity.PairingKeyId[..Math.Min(32, identity.PairingKeyId.Length)]
                    : GetTrustedFingerprint(trusted) ?? "недоступен";
                return new TrustedDeviceSettingsItem(
                    identity.DeviceId,
                    identity.DeviceName,
                    deviceKind,
                    status,
                    lifecycleState,
                    trusted?.PairedAtUtc ?? identity.FirstTrustedAtUtc,
                    FormatFingerprint(rawFingerprint));
            })
            .OrderBy(item => item.LifecycleState == TrustedIdentityLifecycleState.Active ? 0 : item.LifecycleState == TrustedIdentityLifecycleState.Retired ? 1 : 2)
            .ThenBy(item => item.Kind is DeviceKind.WindowsComputer ? 0 : item.Kind is DeviceKind.AndroidPhone or DeviceKind.AndroidTablet ? 1 : 2)
            .ThenBy(item => item.DeviceName, StringComparer.CurrentCultureIgnoreCase)
            .ToArray();
    }

    private bool SetTrustedDeviceLifecycleFromSettings(Guid deviceId, TrustedIdentityLifecycleState lifecycleState)
    {
        var trusted = _trustedDevices.GetAny(deviceId);
        var identity = _trustedDevices.GetIdentityRegistryEntry(deviceId);
        if (identity is null)
        {
            return false;
        }

        var reason = lifecycleState switch
        {
            TrustedIdentityLifecycleState.Active => "Reactivated by local user in Windows settings.",
            TrustedIdentityLifecycleState.Retired => "Retired by local user in Windows settings.",
            TrustedIdentityLifecycleState.Revoked => "Trust revoked by local user in Windows settings.",
            _ => null
        };
        var changed = _trustedDevices.SetLifecycleState(deviceId, lifecycleState, reason);
        if (!changed)
        {
            return false;
        }

        if (lifecycleState != TrustedIdentityLifecycleState.Active)
        {
            _discovered.Remove(deviceId);
            _staleDevices.Remove(deviceId);
            _identityBindingInFlight.Remove(deviceId);
            _identityBindingRetryAfter.Remove(deviceId);
        }

        _sendToOnlineSignature = null;
        RefreshDeviceList();
        AppendLog($"GNP/1 M2.5.2 lifecycle state set for {trusted?.DeviceName ?? identity.DeviceName}: {lifecycleState}.");
        return true;
    }

    private bool ForgetTrustedDeviceFromSettings(Guid deviceId)
    {
        var trusted = _trustedDevices.GetAny(deviceId);
        var identity = _trustedDevices.GetIdentityRegistryEntry(deviceId);
        if (identity is null || !_trustedDevices.Remove(deviceId))
        {
            return false;
        }

        RemoveRetainedDeviceIfStale(deviceId);
        AppendLog($"Forgot trusted device from settings: {trusted?.DeviceName ?? identity.DeviceName}.");
        RefreshDeviceList();
        return true;
    }

    private void RemoveRetainedDeviceIfStale(Guid deviceId)
    {
        if (_staleDevices.Remove(deviceId))
        {
            _discovered.Remove(deviceId);
        }
    }

    private int RemoveSendToIntegration()
    {
        var removed = SendToIntegration.Remove();
        _sendToOnlineSignature = null;
        AppendLog($"Removed Windows SendTo shortcuts: {removed}.");
        return removed;
    }

    private void TryApplyStartupIntegration()
    {
        try
        {
            ApplyStartupIntegration();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or InvalidOperationException or PlatformNotSupportedException or System.Security.SecurityException)
        {
            AppendLog($"Windows startup integration could not be refreshed: {ex.Message}");
        }
    }

    private void ApplyStartupIntegration()
    {
        var executablePath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Не удалось определить путь GeniaLink.exe.");
        StartupIntegration.SetEnabled(_settings.StartWithWindows, executablePath);
    }

    private void SendToIntegrationButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var count = RefreshSendToForOnlineDevices(force: true, ignoreSetting: true);
            System.Windows.MessageBox.Show(
                this,
                count > 0
                    ? $"В «ПКМ → Отправить» добавлено доступных устройств: {count}."
                    : "Сейчас нет доступных доверенных устройств. Старые Genia Link ярлыки удалены из меню «Отправить».",
                "Genia Link",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or PlatformNotSupportedException or System.Reflection.TargetInvocationException)
        {
            AppendLog($"Could not update Windows SendTo integration: {ex.Message}");
            System.Windows.MessageBox.Show(this, "Не удалось обновить меню Windows «Отправить».", "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void TryRefreshSendToForOnlineDevices()
    {
        try
        {
            RefreshSendToForOnlineDevices();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or PlatformNotSupportedException or System.Reflection.TargetInvocationException)
        {
            AppendLog($"Automatic SendTo refresh skipped safely: {ex.Message}");
        }
    }

    private int RefreshSendToForOnlineDevices(bool force = false, bool ignoreSetting = false)
    {
        if (!_settings.EnableSendToIntegration && !ignoreSetting)
        {
            if (!string.Equals(_sendToOnlineSignature, "disabled", StringComparison.Ordinal))
            {
                var removed = SendToIntegration.Remove();
                _sendToOnlineSignature = "disabled";
                AppendLog($"Windows SendTo integration disabled; removed {removed} shortcut(s).");
            }

            return 0;
        }

        var onlineDevices = _deviceItems
            .Where(item => item.IsTrusted && item.IdentityMatches)
            .Select(item => _trustedDevices.Get(item.DeviceId))
            .OfType<TrustedDevice>()
            .GroupBy(device => device.DeviceId)
            .Select(group => group.First())
            .OrderBy(device => device.DeviceName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(device => device.DeviceId)
            .ToArray();

        var signature = string.Join("|", onlineDevices.Select(device => $"{device.DeviceId:N}:{device.DeviceName}"));
        if (!force && string.Equals(_sendToOnlineSignature, signature, StringComparison.Ordinal))
        {
            return onlineDevices.Length;
        }

        var executablePath = Environment.ProcessPath
            ?? throw new InvalidOperationException("Не удалось определить путь GeniaLink.exe.");
        var count = SendToIntegration.InstallOrRefresh(executablePath, onlineDevices);
        _sendToOnlineSignature = signature;
        AppendLog($"Windows SendTo integration refreshed: {count} online trusted device shortcut(s).");
        return count;
    }

    public static bool IsExternalSendCommand(IReadOnlyList<string> args) =>
        args.Count >= 3 && string.Equals(args[0], "--send-to", StringComparison.OrdinalIgnoreCase);

    public async Task HandleCommandLineAsync(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (args.Length == 0 || (args.Length == 1 && string.Equals(args[0], "--show", StringComparison.OrdinalIgnoreCase)))
        {
            ShowFromTray();
            return;
        }

        if (!IsExternalSendCommand(args) || !Guid.TryParse(args[1], out var deviceId))
        {
            ShowFromTray();
            NotifyUser("Genia Link", "Команда отправки не распознана.");
            return;
        }

        TransferFileSource[] sources;
        try
        {
            sources = TransferSelection.Expand(args.Skip(2)).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or ArgumentException)
        {
            AppendLog($"External selection rejected safely: {ex.Message}");
            NotifyUser("Genia Link", "Выбранные файлы или папка не прошли безопасную проверку.");
            return;
        }

        _externalSendQueue.Enqueue(new ExternalSendRequest(deviceId, sources));
        AppendLog($"External SendTo request queued: {sources.Length} file(s).");
        await ProcessExternalSendQueueAsync();
    }

    private async Task ProcessExternalSendQueueAsync()
    {
        if (_externalQueueRunning)
        {
            return;
        }

        _externalQueueRunning = true;
        try
        {
            while (_externalSendQueue.Count > 0)
            {
                var request = _externalSendQueue.Dequeue();
                while (_isReceiving || _cancelSend is not null)
                {
                    await Task.Delay(500);
                }

                var target = await WaitForTrustedDeviceAsync(request.DeviceId, TimeSpan.FromSeconds(20));
                if (target is null)
                {
                    NotifyUser("Genia Link", "Устройство сейчас недоступно в локальной сети.");
                    continue;
                }

                await SendSourcesAsync(target, request.Sources, notifyWhenDone: true);
            }
        }
        finally
        {
            _externalQueueRunning = false;
        }
    }

    private async Task<DeviceListItem?> WaitForTrustedDeviceAsync(Guid deviceId, TimeSpan timeout)
    {
        var trusted = _trustedDevices.Get(deviceId);
        if (trusted is null)
        {
            return null;
        }

        var deadline = DateTimeOffset.UtcNow + timeout;
        while (DateTimeOffset.UtcNow < deadline)
        {
            var item = _deviceItems.FirstOrDefault(candidate =>
                candidate.DeviceId == deviceId && candidate.IsTrusted && candidate.IdentityMatches);
            if (item is not null)
            {
                return item;
            }

            await Task.Delay(500);
        }

        return null;
    }

    private void InitializeTrayIcon()
    {
        var menu = new Forms.ContextMenuStrip();
        menu.Items.Add("Открыть Genia Link", null, (_, _) => Dispatcher.Invoke(ShowFromTray));
        menu.Items.Add("Открыть папку входящих", null, (_, _) => Dispatcher.Invoke(OpenReceiveFolder));
        menu.Items.Add("Настройки", null, (_, _) => Dispatcher.Invoke(() => SettingsButton_Click(this, new RoutedEventArgs())));
        menu.Items.Add("Обновить меню «Отправить»", null, (_, _) => Dispatcher.Invoke(() => SendToIntegrationButton_Click(this, new RoutedEventArgs())));
        menu.Items.Add("Убрать Genia Link из «Отправить»", null, (_, _) => Dispatcher.Invoke(() => RemoveSendToIntegration()));
        menu.Items.Add(new Forms.ToolStripSeparator());
        menu.Items.Add("Выход", null, (_, _) => Dispatcher.Invoke(ExitApplication));

        _trayIconImage = CreateTrayIcon();
        _trayIcon = new Forms.NotifyIcon
        {
            Icon = _trayIconImage,
            Text = "Genia Link",
            Visible = true,
            ContextMenuStrip = menu
        };
        _trayIcon.DoubleClick += (_, _) => Dispatcher.Invoke(ShowFromTray);
    }

    private static Drawing.Icon CreateTrayIcon()
    {
        var processPath = Environment.ProcessPath;
        if (!string.IsNullOrWhiteSpace(processPath))
        {
            var associatedIcon = Drawing.Icon.ExtractAssociatedIcon(processPath);
            if (associatedIcon is not null)
            {
                return associatedIcon;
            }
        }

        return (Drawing.Icon)Drawing.SystemIcons.Application.Clone();
    }

    private void Window_StateChanged(object? sender, EventArgs e)
    {
        if (WindowState != WindowState.Minimized)
        {
            return;
        }

        ShowInTaskbar = false;
        Hide();
        if (!_minimizeNoticeShown)
        {
            _minimizeNoticeShown = true;
            NotifyUser("Genia Link", "Genia Link свернут в трей и продолжает работать в локальной сети.");
        }
    }

    private void NotifyUser(string title, string message)
    {
        if (_trayIcon is null || !_settings.ShowNotifications)
        {
            return;
        }

        _trayIcon.BalloonTipTitle = title;
        _trayIcon.BalloonTipText = message;
        _trayIcon.BalloonTipIcon = Forms.ToolTipIcon.Info;
        _trayIcon.ShowBalloonTip(3500);
    }

    private void ShowFromTray()
    {
        ShowInTaskbar = true;
        if (!IsVisible)
        {
            Show();
        }

        if (WindowState == WindowState.Minimized)
        {
            WindowState = WindowState.Normal;
        }

        Activate();
        Topmost = true;
        Topmost = false;
        Focus();
    }

    private void OpenReceiveFolder()
    {
        try
        {
            var folder = GetReceiveFolder();
            Directory.CreateDirectory(folder);
            Process.Start(new ProcessStartInfo
            {
                FileName = folder,
                UseShellExecute = true
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.ComponentModel.Win32Exception)
        {
            AppendLog($"Could not open receive folder: {ex.Message}");
        }
    }

    private void ExitApplication()
    {
        _cancelSend?.Invoke();
        _cancelServices?.Invoke();
        DisposeTrayIcon();

        Close();
        System.Windows.Application.Current.Shutdown();
    }

    private void CancelSendButton_Click(object sender, RoutedEventArgs e) => _cancelSend?.Invoke();

    private void ResetProgress()
    {
        _progressFileName = string.Empty;
        _progressStopwatch.Reset();
        TransferProgressBar.Value = 0;
        SpeedTextBlock.Text = string.Empty;
        ProgressTextBlock.Text = "Подготовка передачи…";
    }

    private void UpdateProgress(TransferProgress progress)
    {
        if (!string.Equals(_progressFileName, progress.FileName, StringComparison.Ordinal))
        {
            _progressFileName = progress.FileName;
            _progressStopwatch.Restart();
        }

        TransferProgressBar.Value = progress.Percentage;
        var verb = progress.IsReceiving ? "Получение" : "Отправка";
        ProgressTextBlock.Text = $"{verb}: {progress.FileName} · {progress.Percentage:F1}%";

        var elapsed = _progressStopwatch.Elapsed.TotalSeconds;
        if (elapsed > 0.25 && progress.BytesTransferred > 0)
        {
            var bytesPerSecond = progress.BytesTransferred / elapsed;
            var megabytesPerSecond = bytesPerSecond / (1024d * 1024d);
            var remainingBytes = Math.Max(0, progress.TotalBytes - progress.BytesTransferred);
            var etaSeconds = bytesPerSecond > 1 ? remainingBytes / bytesPerSecond : 0;
            SpeedTextBlock.Text = etaSeconds > 0
                ? $"{megabytesPerSecond:F1} MB/s · ~{FormatDuration(etaSeconds)}"
                : $"{megabytesPerSecond:F1} MB/s";
        }
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} Б";
        var value = bytes / 1024d;
        if (value < 1024) return $"{value:F1} КБ";
        value /= 1024d;
        if (value < 1024) return $"{value:F1} МБ";
        value /= 1024d;
        return $"{value:F2} ГБ";
    }

    private static string FormatDuration(double seconds)
    {
        if (seconds < 60)
        {
            return $"{Math.Ceiling(seconds):F0} с";
        }

        return $"{Math.Ceiling(seconds / 60):F0} мин";
    }

    private void AppendLog(string message)
    {
        LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}{Environment.NewLine}");
        LogTextBox.ScrollToEnd();
    }

    private string GetReceiveFolder() =>
        _settings.ReceiveFolder ?? ReceiveFolderPolicy.GetDefaultReceiveFolder();

    private static string GetLocalIPv4Addresses()
    {
        try
        {
            var addresses = NetworkInterface.GetAllNetworkInterfaces()
                .Where(network => network.OperationalStatus == OperationalStatus.Up &&
                                  network.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .SelectMany(network => network.GetIPProperties().UnicastAddresses)
                .Select(unicast => unicast.Address)
                .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork &&
                             LocalNetworkPolicy.IsAllowedAddress(ip) &&
                             !IPAddress.IsLoopback(ip))
                .Select(ip => ip.ToString())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            return addresses.Length == 0 ? "Локальный IPv4 не найден" : string.Join(" · ", addresses);
        }
        catch (NetworkInformationException)
        {
            return "Не удалось определить локальный IPv4";
        }
    }

    private static string FormatFingerprint(string fingerprint)
    {
        if (fingerprint.Length != 32)
        {
            return fingerprint;
        }

        return string.Join("-", Enumerable.Range(0, 8).Select(index => fingerprint.Substring(index * 4, 4)));
    }

    protected override void OnClosing(CancelEventArgs e)
    {
        _cancelSend?.Invoke();
        _cancelServices?.Invoke();
        TryRemoveSendToIntegration();
        base.OnClosing(e);
    }

    protected override void OnClosed(EventArgs e)
    {
        _cancelSend?.Invoke();
        _cancelServices?.Invoke();
        DisposeTrayIcon();
        base.OnClosed(e);
    }

    private void TryRemoveSendToIntegration()
    {
        try
        {
            var removed = SendToIntegration.Remove();
            if (removed > 0)
            {
                AppendLog($"Removed Windows SendTo shortcuts on exit: {removed}.");
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            AppendLog($"Could not remove Windows SendTo shortcuts on exit: {ex.Message}");
        }
    }

    private void DisposeTrayIcon()
    {
        if (_trayIcon is not null)
        {
            _trayIcon.Visible = false;
            _trayIcon.Dispose();
            _trayIcon = null;
        }

        _trayIconImage?.Dispose();
        _trayIconImage = null;
    }

    private sealed record ExternalSendRequest(Guid DeviceId, TransferFileSource[] Sources);
}
