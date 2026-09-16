using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.OS;
using GeniaLink.Core.Capabilities;
using GeniaLink.Core.Discovery;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Pairing;

namespace GeniaLink.Android.Services;

[Service(
    Name = "com.geniapixia.genialink.LocalAvailabilityService",
    Exported = false,
    ForegroundServiceType = ForegroundService.TypeConnectedDevice)]
public sealed class LocalAvailabilityService : Service
{
    private const string ChannelId = "genialink_availability";
    private const int NotificationId = 47504;
    private const string ActionStart = "com.geniapixia.genialink.action.AVAILABILITY_START";
    private const string ActionStop = "com.geniapixia.genialink.action.AVAILABILITY_STOP";
    private static readonly object StaticGate = new();

    private static LocalAvailabilityService? _current;
    private readonly object _discoveryGate = new();
    private readonly object _servicesGate = new();
    private readonly Dictionary<Guid, DateTimeOffset> _lastSeen = new();
    private readonly Dictionary<Guid, DiscoveredDevice> _latestDiscovered = new();
    private readonly HashSet<Guid> _identityBindingInFlight = new();
    private readonly Dictionary<Guid, DateTimeOffset> _identityBindingRetryAfter = new();
    private AndroidLocalIdentity _identity = null!;
    private TrustedDeviceStore _trustedDevices = null!;
    private AndroidResumeIndex _resumeIndex = null!;
    private ContentResolver _resolver = null!;
    private CancellationTokenSource? _servicesCts;
    private Task? _servicesTask;
    private CancellationTokenSource? _networkRecoveryCts;
    private global::Android.Net.ConnectivityManager? _connectivityManager;
    private LocalNetworkCallback? _networkCallback;
    private volatile bool _networkSuspended;
    private volatile bool _restartPending;
    private volatile bool _destroyed;
    private volatile bool _isReceiving;

    public static event Action<DiscoveredDevice>? DeviceSeen;
    public static event Action<Guid>? DeviceExpired;
    public static event Action? DevicesCleared;
    public static event Action<TransferProgress>? TransferProgressChanged;
    public static event Action<string, long>? IncomingTransferStarted;
    public static event Action<string, bool, string>? IncomingTransferEnded;
    public static event Action<PairingPeerInfo>? TrustedPeerSaved;
    public static event Action<TrustedSigningIdentity>? TrustedSigningIdentitySaved;
    public static event Action<Guid, IPAddress, int, int, DeviceKind>? TrustedEndpointSaved;
    public static event Action<string>? LogMessage;
    public static event Action? StateChanged;

    public static Func<PairingConfirmation, Task<bool>>? PairingConfirmationHandler { get; set; }

    public static bool IsRunning
    {
        get
        {
            lock (StaticGate)
            {
                return _current is not null;
            }
        }
    }

    public static bool IsNetworkAvailable
    {
        get
        {
            lock (StaticGate)
            {
                return _current is { _networkSuspended: false };
            }
        }
    }

    public static bool IsReceiving
    {
        get
        {
            lock (StaticGate)
            {
                return _current?._isReceiving == true;
            }
        }
    }

    public static bool AreLocalServicesActive
    {
        get
        {
            LocalAvailabilityService? current;
            lock (StaticGate)
            {
                current = _current;
            }

            return current?.HasActiveLocalServices() == true && !current._networkSuspended;
        }
    }

    public override void OnCreate()
    {
        base.OnCreate();
        try
        {
            _resolver = ContentResolver ?? throw new InvalidOperationException("Android ContentResolver is unavailable.");
            _identity = AndroidLocalIdentity.LoadOrCreate(this, Log);
            _trustedDevices = new TrustedDeviceStore(this, Log);
            _resumeIndex = new AndroidResumeIndex(this, Log);
            TransferForegroundService.CancelRequested += OnTransferCancelRequested;
            CreateNotificationChannel();
            RegisterNetworkCallback();
            lock (StaticGate)
            {
                _current = this;
            }
            Log("Background availability service created.");
        }
        catch
        {
            lock (StaticGate)
            {
                if (ReferenceEquals(_current, this))
                {
                    _current = null;
                }
            }

            throw;
        }
    }

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        if (string.Equals(intent?.Action, ActionStop, StringComparison.Ordinal))
        {
            Log("Background availability stopped by user.");
            StopForeground(StopForegroundFlags.Remove);
            StopSelf();
            return StartCommandResult.NotSticky;
        }

        var notification = BuildReadyNotification();
        StartForeground(NotificationId, notification, ForegroundService.TypeConnectedDevice);
        if (!_networkSuspended)
        {
            StartLocalServices();
        }

        StateChanged?.Invoke();
        return StartCommandResult.Sticky;
    }

    public override global::Android.OS.IBinder? OnBind(Intent? intent) => null;

    public override void OnDestroy()
    {
        _destroyed = true;
        TransferForegroundService.CancelRequested -= OnTransferCancelRequested;
        CancelNetworkRecovery();
        UnregisterNetworkCallback();
        StopLocalServices();

        lock (StaticGate)
        {
            if (ReferenceEquals(_current, this))
            {
                _current = null;
            }
        }

        StateChanged?.Invoke();
        base.OnDestroy();
    }

    public static void Begin(Context context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var intent = new Intent(context, typeof(LocalAvailabilityService));
        intent.SetAction(ActionStart);
        context.StartForegroundService(intent);
    }

    public static void End()
    {
        LocalAvailabilityService? current;
        lock (StaticGate)
        {
            current = _current;
        }

        if (current is null)
        {
            return;
        }

        current.StopForeground(StopForegroundFlags.Remove);
        current.StopSelf();
    }

    public static void RefreshAlwaysReadyConfiguration()
    {
        LocalAvailabilityService? current;
        lock (StaticGate)
        {
            current = _current;
        }

        current?.RefreshReadyNotification();
        StateChanged?.Invoke();
    }

    public static void UpsertTrustedPeer(PairingPeerInfo peer)
    {
        ArgumentNullException.ThrowIfNull(peer);
        LocalAvailabilityService? current;
        lock (StaticGate)
        {
            current = _current;
        }

        current?._trustedDevices.Upsert(peer);
    }

    public static void RemoveTrustedPeer(Guid deviceId)
    {
        LocalAvailabilityService? current;
        lock (StaticGate)
        {
            current = _current;
        }

        current?._trustedDevices.Remove(deviceId);
    }

    public static void UpdateTrustedEndpoint(
        Guid deviceId,
        IPAddress address,
        int transferPort,
        int pairingPort,
        DeviceKind deviceKind)
    {
        ArgumentNullException.ThrowIfNull(address);
        LocalAvailabilityService? current;
        lock (StaticGate)
        {
            current = _current;
        }

        current?.UpdateTrustedEndpointCore(deviceId, address, transferPort, pairingPort, deviceKind, notifyUi: false);
    }

    public static void CancelIncomingTransfer()
    {
        LocalAvailabilityService? current;
        lock (StaticGate)
        {
            current = _current;
        }

        current?.CancelIncomingTransferCore();
    }

    private void StartLocalServices()
    {
        CancellationTokenSource owner;
        Task task;
        lock (_servicesGate)
        {
            if (_destroyed || _networkSuspended || (_servicesTask is not null && !_servicesTask.IsCompleted))
            {
                return;
            }

            owner = new CancellationTokenSource();
            task = RunLocalServicesAsync(owner.Token);
            _servicesCts = owner;
            _servicesTask = task;
        }

        _ = ObserveServicesAsync(task, owner);
        StateChanged?.Invoke();
    }

    private bool HasActiveLocalServices()
    {
        lock (_servicesGate)
        {
            return _servicesTask is not null && !_servicesTask.IsCompleted;
        }
    }

    private void StopLocalServices()
    {
        CancellationTokenSource? servicesCts;
        lock (_servicesGate)
        {
            servicesCts = _servicesCts;
        }

        try
        {
            servicesCts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private async Task RunLocalServicesAsync(CancellationToken cancellationToken)
    {
        var localPeer = _identity.ToPairingPeerInfo();
        try
        {
            var advertisement = new DiscoveryAdvertisement(
                _identity.DeviceId,
                _identity.DeviceName,
                ProtocolConstants.Port,
                ProtocolConstants.PairingPort,
                PairingProtocol.GetPublicKeyFingerprint(localPeer.PublicKey),
                _identity.DeviceKind);

            Log("Starting background receiver, discovery, and pairing services.");
            using var serviceCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var serviceToken = serviceCts.Token;

            var externalStoragePath = ApplicationContext?.GetExternalFilesDir(null)?.AbsolutePath
                ?? ApplicationContext?.FilesDir?.AbsolutePath
                ?? throw new InvalidOperationException("Android storage path is unavailable.");

            var transferTask = AndroidFileTransferServer.RunAsync(
                _resolver,
                _resumeIndex,
                externalStoragePath,
                ProtocolConstants.Port,
                _identity.DeviceId,
                _identity.DeviceName,
                ResolveSharedKey,
                _trustedDevices.GetSessionAuthorization,
                new DirectProgressReporter(OnTransferProgress),
                OnIncomingTransferStartedCore,
                OnIncomingTransferEndedCore,
                OnAuthenticatedPeerSeenCore,
                Log,
                serviceToken);

            var pairingTask = PairingServer.RunAsync(
                ProtocolConstants.PairingPort,
                localPeer,
                ConfirmPairingAsync,
                SaveTrustedPeer,
                Log,
                serviceToken);

            var identityBindingTask = IdentityBindingService.RunServerAsync(
                ProtocolConstants.IdentityBindingPort,
                _identity,
                ResolveSharedKey,
                (identity, address) => OnTrustedSigningIdentityBoundCore(identity, address, "incoming authenticated binding"),
                Log,
                serviceToken);

            var identityRevisionPath = Path.Combine(
                ApplicationContext?.FilesDir?.AbsolutePath ?? throw new InvalidOperationException("Android files directory is unavailable."),
                "identity-assertion-revision.json");
            var identityRevision = IdentityAssertionRevisionStore.LoadOrAdvance(identityRevisionPath, _identity, Log);
            var localCapabilities = DeviceCapabilityProfiles.GetPreset(DeviceRoleProfile.Client);
            var capabilityRevisionPath = Path.Combine(
                ApplicationContext?.FilesDir?.AbsolutePath ?? throw new InvalidOperationException("Android files directory is unavailable."),
                "capability-assertion-revision.json");
            var capabilityRevision = CapabilityAssertionRevisionStore.LoadOrAdvance(
                capabilityRevisionPath,
                _identity,
                localCapabilities,
                Log);
            var discoveryTask = DiscoveryService.RunAsync(
                advertisement,
                _identity,
                identityRevision,
                localCapabilities,
                capabilityRevision,
                OnDeviceSeenCore,
                Log,
                serviceToken);

            var cleanupTask = CleanupDiscoveredDevicesAsync(serviceToken);
            var allTasks = new[] { transferTask, pairingTask, identityBindingTask, discoveryTask, cleanupTask };
            await Task.WhenAny(allTasks).ConfigureAwait(false);
            serviceCts.Cancel();
            await Task.WhenAll(allTasks).ConfigureAwait(false);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(localPeer.PublicKey);
        }
    }

    private async Task ObserveServicesAsync(Task servicesTask, CancellationTokenSource owner)
    {
        var expectedStop = false;
        try
        {
            await servicesTask.ConfigureAwait(false);
        }
        catch (System.OperationCanceledException) when (owner.IsCancellationRequested)
        {
            expectedStop = true;
        }
        catch (System.OperationCanceledException ex)
        {
            Log($"Background local service timed out safely: {ex.Message}");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SocketException or AuthenticationException or CryptographicException or InvalidDataException or InvalidOperationException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException)
        {
            Log($"Background local service stopped safely: {ex.Message}");
        }
        finally
        {
            expectedStop |= owner.IsCancellationRequested;
            owner.Dispose();
            lock (_servicesGate)
            {
                if (ReferenceEquals(_servicesCts, owner))
                {
                    _servicesCts = null;
                    _servicesTask = null;
                }
            }

            StateChanged?.Invoke();
            if (!_networkSuspended)
            {
                if (_restartPending)
                {
                    _restartPending = false;
                    StartLocalServices();
                }
                else if (!expectedStop)
                {
                    _ = RestartAfterDelayAsync();
                }
            }
        }
    }

    private async Task RestartAfterDelayAsync()
    {
        await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        if (!_destroyed && !_networkSuspended && !HasActiveLocalServices())
        {
            Log("Restarting background local services after recoverable failure.");
            StartLocalServices();
        }
    }

    private void OnDeviceSeenCore(DiscoveredDevice device)
    {
        if (_trustedDevices.IsKnownInactive(device.DeviceId))
        {
            lock (_discoveryGate)
            {
                _lastSeen.Remove(device.DeviceId);
                _latestDiscovered.Remove(device.DeviceId);
            }

            return;
        }

        TryApplyAuthenticatedSignedDiscovery(device);
        lock (_discoveryGate)
        {
            _lastSeen[device.DeviceId] = device.LastSeenUtc;
            _latestDiscovered[device.DeviceId] = device;
        }

        TryStartSigningIdentityBinding(device);
        DeviceSeen?.Invoke(device);
    }

    private void TryApplyAuthenticatedSignedDiscovery(DiscoveredDevice device)
    {
        try
        {
            _ = _trustedDevices.TryApplyAuthenticatedSignedDiscovery(device);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or CryptographicException or FormatException)
        {
            Log($"GNP/1 M2.5 authenticated rename/discovery state could not be persisted for {device.DeviceName}; existing trust was kept: {ex.Message}");
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
        lock (_discoveryGate)
        {
            if (_identityBindingInFlight.Contains(device.DeviceId) ||
                (_identityBindingRetryAfter.TryGetValue(device.DeviceId, out var retryAfter) && retryAfter > now))
            {
                return;
            }

            _identityBindingInFlight.Add(device.DeviceId);
            _identityBindingRetryAfter[device.DeviceId] = now + TimeSpan.FromMinutes(1);
        }

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
            CancellationToken serviceToken;
            lock (_servicesGate)
            {
                serviceToken = _servicesCts?.Token ?? CancellationToken.None;
            }

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(serviceToken);
            timeoutCts.CancelAfter(ProtocolConstants.HandshakeTimeout + TimeSpan.FromSeconds(5));
            remoteIdentity = await IdentityBindingService.BindAsync(
                discovered.Address,
                ProtocolConstants.IdentityBindingPort,
                _identity,
                discovered.DeviceId,
                sharedKey,
                timeoutCts.Token).ConfigureAwait(false);

            OnTrustedSigningIdentityBoundCore(remoteIdentity, discovered.Address, "outgoing authenticated binding");
            if (!string.Equals(discovered.SigningKeyId, remoteIdentity.SigningKeyId, StringComparison.OrdinalIgnoreCase))
            {
                Log($"Signed discovery key differed from the authenticated binding for {trusted.DeviceName}; discovery proof was not trusted for key replacement.");
            }
        }
        catch (System.OperationCanceledException)
        {
            Log($"GNP/1 M2.3 signing-identity binding timed out for {discovered.DeviceName}; existing trust was kept.");
        }
        catch (Exception ex) when (ex is IOException or SocketException or AuthenticationException or CryptographicException or InvalidDataException or ArgumentException)
        {
            Log($"GNP/1 M2.3 signing-identity binding unavailable for {discovered.DeviceName}; existing trust was kept: {ex.Message}");
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

            lock (_discoveryGate)
            {
                _identityBindingInFlight.Remove(discovered.DeviceId);
            }
        }
    }

    private void OnTrustedSigningIdentityBoundCore(TrustedSigningIdentity identity, IPAddress address, string source)
    {
        var trusted = _trustedDevices.Get(identity.DeviceId);
        if (trusted is null)
        {
            return;
        }

        try
        {
            var update = _trustedDevices.UpdateSigningIdentity(identity);
            var signingKeyId = identity.SigningKeyId;
            var keyGeneration = identity.KeyGeneration;
            var action = update switch
            {
                SigningIdentityBindingUpdate.Bound => "bound",
                SigningIdentityBindingUpdate.Rotated => "rotated",
                _ => "verified"
            };
            var milestone = update == SigningIdentityBindingUpdate.Rotated ? "M2.4.2" : "M2.3";
            DiscoveredDevice? latestDiscovery;
            lock (_discoveryGate)
            {
                _latestDiscovered.TryGetValue(identity.DeviceId, out latestDiscovery);
            }

            if (latestDiscovery is not null)
            {
                TryApplyAuthenticatedSignedDiscovery(latestDiscovery);
            }

            TrustedSigningIdentitySaved?.Invoke(identity);
            Log($"GNP/1 {milestone} trusted signing identity {action} for {trusted.DeviceName} after {source}: {signingKeyId} (generation {keyGeneration}, {address}).");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or InvalidDataException or ArgumentException)
        {
            Log($"Authenticated signing identity could not be persisted: {ex.Message}");
            throw;
        }
    }

    private async Task CleanupDiscoveredDevicesAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(TimeSpan.FromSeconds(2), cancellationToken).ConfigureAwait(false);
            var cutoff = DateTimeOffset.UtcNow - ProtocolConstants.DiscoveryExpiry;
            Guid[] expired;
            lock (_discoveryGate)
            {
                expired = _lastSeen.Where(pair => pair.Value < cutoff).Select(pair => pair.Key).ToArray();
                foreach (var deviceId in expired)
                {
                    _lastSeen.Remove(deviceId);
                    _latestDiscovered.Remove(deviceId);
                }
            }

            foreach (var deviceId in expired)
            {
                DeviceExpired?.Invoke(deviceId);
            }
        }
    }

    private byte[]? ResolveSharedKey(Guid remoteDeviceId)
    {
        var trusted = _trustedDevices.Get(remoteDeviceId);
        if (trusted is null)
        {
            return null;
        }

        byte[]? publicKey = null;
        try
        {
            publicKey = trusted.GetPublicKey();
            return _identity.DeriveSharedKey(publicKey);
        }
        catch (Exception ex) when (ex is FormatException or CryptographicException or InvalidDataException)
        {
            Log($"Trusted key could not be used: {ex.Message}");
            return null;
        }
        finally
        {
            if (publicKey is not null)
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }
    }

    private async Task<bool> ConfirmPairingAsync(PairingConfirmation confirmation)
    {
        var handler = PairingConfirmationHandler;
        if (handler is null)
        {
            Log("Pairing request rejected because Genia Link is not open for SAS confirmation.");
            return false;
        }

        return await handler(confirmation).ConfigureAwait(false);
    }

    private void OnAuthenticatedPeerSeenCore(Guid deviceId, IPAddress address)
    {
        UpdateTrustedEndpointCore(
            deviceId,
            address,
            ProtocolConstants.Port,
            ProtocolConstants.PairingPort,
            DeviceKind.Unknown,
            notifyUi: true);
    }

    private void UpdateTrustedEndpointCore(
        Guid deviceId,
        IPAddress address,
        int transferPort,
        int pairingPort,
        DeviceKind deviceKind,
        bool notifyUi)
    {
        try
        {
            _trustedDevices.UpdateVerifiedEndpoint(deviceId, address, transferPort, pairingPort, deviceKind);
            if (_trustedDevices.Get(deviceId) is null)
            {
                return;
            }

            if (notifyUi)
            {
                TrustedEndpointSaved?.Invoke(deviceId, address, transferPort, pairingPort, deviceKind);
            }

            Log($"Authenticated LAN endpoint saved for trusted device {deviceId:N}.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            Log($"Authenticated LAN endpoint could not be saved: {ex.Message}");
        }
    }

    private void SaveTrustedPeer(PairingPeerInfo peer)
    {
        _trustedDevices.Upsert(peer);
        TrustedPeerSaved?.Invoke(peer);
        Log($"Trusted device saved in background service: {peer.DeviceName}.");
    }

    private void OnTransferProgress(TransferProgress progress)
    {
        TransferForegroundService.Report(progress);
        TransferProgressChanged?.Invoke(progress);
    }

    private void OnIncomingTransferStartedCore(string fileName, long totalBytes)
    {
        _isReceiving = true;
        try
        {
            TransferForegroundService.Begin(this, fileName, totalBytes, incoming: true);
        }
        catch (Exception ex) when (ex is Java.Lang.SecurityException or Java.Lang.IllegalStateException or InvalidOperationException)
        {
            Log($"Transfer progress service could not start: {ex.Message}");
        }

        IncomingTransferStarted?.Invoke(fileName, totalBytes);
    }

    private void OnIncomingTransferEndedCore(string fileName, bool success, string message)
    {
        _isReceiving = false;
        TransferForegroundService.End(success, success ? $"Получено: {fileName}" : message);
        IncomingTransferEnded?.Invoke(fileName, success, message);
    }

    private void OnTransferCancelRequested()
    {
        if (_isReceiving)
        {
            CancelIncomingTransferCore();
        }
    }

    private void CancelIncomingTransferCore()
    {
        if (!_isReceiving)
        {
            return;
        }

        Log("Incoming transfer cancellation requested; rebuilding receiver services.");
        _restartPending = true;
        StopLocalServices();
    }

    private void RegisterNetworkCallback()
    {
        try
        {
            var manager = GetSystemService(ConnectivityService) as global::Android.Net.ConnectivityManager;
            if (manager is null)
            {
                _networkSuspended = false;
                Log("ConnectivityManager unavailable; background network recovery disabled.");
                return;
            }

            using var builder = new global::Android.Net.NetworkRequest.Builder();
            var configured = builder.AddTransportType(global::Android.Net.TransportType.Wifi)
                ?? throw new InvalidOperationException("Unable to configure Wi-Fi callback.");
            using var request = configured.Build()
                ?? throw new InvalidOperationException("Unable to build Wi-Fi callback request.");

            using var activeNetwork = manager.ActiveNetwork;
            using var capabilities = manager.GetNetworkCapabilities(activeNetwork);
            _networkSuspended = capabilities?.HasTransport(global::Android.Net.TransportType.Wifi) != true;

            var callback = new LocalNetworkCallback(this);
            manager.RegisterNetworkCallback(request, callback);
            _connectivityManager = manager;
            _networkCallback = callback;
            Log("Background Wi-Fi recovery callback registered.");
        }
        catch (Exception ex) when (ex is InvalidOperationException or Java.Lang.SecurityException or Java.Lang.IllegalArgumentException)
        {
            _networkSuspended = false;
            Log($"Background Wi-Fi recovery callback unavailable: {ex.Message}");
        }
    }

    private void UnregisterNetworkCallback()
    {
        var manager = _connectivityManager;
        var callback = _networkCallback;
        _connectivityManager = null;
        _networkCallback = null;
        if (manager is null || callback is null)
        {
            return;
        }

        try
        {
            manager.UnregisterNetworkCallback(callback);
        }
        catch (Exception ex) when (ex is Java.Lang.IllegalArgumentException or Java.Lang.SecurityException)
        {
            Log($"Background Wi-Fi callback cleanup warning: {ex.Message}");
        }
        finally
        {
            callback.Dispose();
        }
    }

    private void OnNetworkLost()
    {
        if (_destroyed)
        {
            return;
        }

        _networkSuspended = true;
        _restartPending = false;
        CancelNetworkRecovery();
        StopLocalServices();
        lock (_discoveryGate)
        {
            _lastSeen.Clear();
            _latestDiscovered.Clear();
        }
        DevicesCleared?.Invoke();
        Log("Wi-Fi lost; background local services paused.");
        RefreshReadyNotification();
        StateChanged?.Invoke();
    }

    private void OnNetworkAvailable()
    {
        if (_destroyed)
        {
            return;
        }

        var wasSuspended = _networkSuspended;
        _networkSuspended = false;
        if (wasSuspended)
        {
            ScheduleNetworkRecovery();
        }
        else if (!HasActiveLocalServices())
        {
            StartLocalServices();
        }

        RefreshReadyNotification();
        StateChanged?.Invoke();
    }

    private void ScheduleNetworkRecovery()
    {
        CancelNetworkRecovery();
        var recovery = new CancellationTokenSource();
        _networkRecoveryCts = recovery;
        _ = RecoverAfterNetworkChangeAsync(recovery);
    }

    private async Task RecoverAfterNetworkChangeAsync(CancellationTokenSource recovery)
    {
        try
        {
            await Task.Delay(TimeSpan.FromMilliseconds(900), recovery.Token).ConfigureAwait(false);
        }
        catch (System.OperationCanceledException) when (recovery.IsCancellationRequested)
        {
            return;
        }

        if (_destroyed || !ReferenceEquals(_networkRecoveryCts, recovery) || _networkSuspended)
        {
            return;
        }

        _networkRecoveryCts = null;
        recovery.Dispose();
        Log("Wi-Fi available; rebuilding background sockets and discovery.");
        if (HasActiveLocalServices())
        {
            _restartPending = true;
            StopLocalServices();
        }
        else
        {
            _restartPending = false;
            StartLocalServices();
        }
    }

    private void CancelNetworkRecovery()
    {
        var recovery = _networkRecoveryCts;
        _networkRecoveryCts = null;
        if (recovery is null)
        {
            return;
        }

        try
        {
            recovery.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
        finally
        {
            recovery.Dispose();
        }
    }

    private void RefreshReadyNotification()
    {
        var manager = GetSystemService(NotificationService) as NotificationManager;
        manager?.Notify(NotificationId, BuildReadyNotification());
    }

    private Notification BuildReadyNotification()
    {
        var openIntent = new Intent(this, typeof(MainActivity));
        openIntent.SetFlags(ActivityFlags.SingleTop | ActivityFlags.ClearTop);
        var pendingIntent = PendingIntent.GetActivity(
            this,
            0,
            openIntent,
            PendingIntentFlags.UpdateCurrent | PendingIntentFlags.Immutable);

        using var builder = new Notification.Builder(this, ChannelId);
        builder.SetSmallIcon(Resource.Drawable.ic_transfer_notification);
        builder.SetContentTitle("Genia Link");
        var detail = _networkSuspended
            ? "Ожидание Wi-Fi"
            : AlwaysReadySettings.IsEffective(this)
                ? "Всегда готов к приёму • локальная сеть"
                : "Готов к приёму • локальная сеть";
        builder.SetContentText(detail);
        builder.SetContentIntent(pendingIntent);
        builder.SetOnlyAlertOnce(true);
        builder.SetOngoing(true);
        builder.SetCategory(Notification.CategoryService);

        var stopIntent = new Intent(this, typeof(LocalAvailabilityService));
        stopIntent.SetAction(ActionStop);
        var stopPendingIntent = PendingIntent.GetService(
            this,
            2,
            stopIntent,
            PendingIntentFlags.UpdateCurrent | PendingIntentFlags.Immutable);
        using var stopIcon = global::Android.Graphics.Drawables.Icon.CreateWithResource(this, Resource.Drawable.ic_transfer_notification);
        using var stopActionBuilder = new Notification.Action.Builder(stopIcon, "Остановить", stopPendingIntent);
        using var stopAction = stopActionBuilder.Build();
        if (stopAction is not null)
        {
            builder.AddAction(stopAction);
        }

        return builder.Build()
            ?? throw new InvalidOperationException("Android did not build availability notification.");
    }

    private void CreateNotificationChannel()
    {
        var manager = GetSystemService(NotificationService) as NotificationManager;
        if (manager is null)
        {
            return;
        }

        using var channel = new NotificationChannel(
            ChannelId,
            "Фоновая доступность Genia Link",
            NotificationImportance.Low)
        {
            Description = "Genia Link остаётся доступным доверенным устройствам в локальной сети"
        };
        channel.SetSound(null, null);
        channel.SetShowBadge(false);
        manager.CreateNotificationChannel(channel);
    }

    private static void Log(string message)
    {
        LogMessage?.Invoke(message);
    }

    private sealed class DirectProgressReporter(Action<TransferProgress> report) : IProgress<TransferProgress>
    {
        public void Report(TransferProgress value) => report(value);
    }

    private sealed class LocalNetworkCallback(LocalAvailabilityService owner)
        : global::Android.Net.ConnectivityManager.NetworkCallback
    {
        private readonly WeakReference<LocalAvailabilityService> _owner = new(owner);

        public override void OnAvailable(global::Android.Net.Network network)
        {
            base.OnAvailable(network);
            if (_owner.TryGetTarget(out var service))
            {
                service.OnNetworkAvailable();
            }
        }

        public override void OnLost(global::Android.Net.Network network)
        {
            base.OnLost(network);
            if (_owner.TryGetTarget(out var service))
            {
                service.OnNetworkLost();
            }
        }
    }
}
