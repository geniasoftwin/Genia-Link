using Stopwatch = System.Diagnostics.Stopwatch;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Content.Res;
using Android.Graphics;
using Android.Graphics.Drawables;
using Android.OS;
using Android.Provider;
using Android.Views;
using Android.Widget;
using GeniaLink.Android.Models;
using GeniaLink.Android.Services;
using GeniaLink.Core.Discovery;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Models;
using GeniaLink.Core.Network;
using GeniaLink.Core.Pairing;
using GeniaLink.Core.Transfers;

namespace GeniaLink.Android;

[Activity(
    Label = "@string/app_name",
    Icon = "@mipmap/ic_launcher",
    MainLauncher = true,
    Exported = true,
    LaunchMode = LaunchMode.SingleTask,
    Theme = "@android:style/Theme.Material.Light.NoActionBar",
    ConfigurationChanges = ConfigChanges.Orientation | ConfigChanges.ScreenSize | ConfigChanges.UiMode)]
[IntentFilter([Intent.ActionSend], Categories = [Intent.CategoryDefault], DataMimeType = "*/*")]
[IntentFilter([Intent.ActionSendMultiple], Categories = [Intent.CategoryDefault], DataMimeType = "*/*")]
public sealed class MainActivity : Activity
{
    private const int PickFilesRequestCode = 4107;
    private const int NotificationPermissionRequestCode = 4108;
    private const string PostNotificationsPermission = "android.permission.POST_NOTIFICATIONS";
    private const int MaxSelectedDocuments = 128;
    private const int MaxLogCharacters = 64 * 1024;
    private const string UiPreferencesName = "genialink_ui";
    private const string LastTargetPreferenceKey = "last_target_device_id";

    private readonly Dictionary<Guid, DiscoveredDevice> _discovered = new();
    private readonly HashSet<Guid> _staleDevices = new();
    private readonly List<DeviceListItem> _visibleDevices = [];
    private readonly List<SelectedDocument> _selectedDocuments = [];
    private readonly object _deviceGate = new();
    private readonly object _logGate = new();
    private readonly StringBuilder _logBuffer = new();
    private readonly Stopwatch _progressStopwatch = new();

    private AndroidLocalIdentity _identity = null!;
    private TrustedDeviceStore _trustedDevices = null!;
    private ContentResolver _resolver = null!;
    private Progress<TransferProgress> _progress = null!;
    private CancellationTokenSource? _sendCts;
    private CancellationTokenSource? _browseCts;
    private bool _identityReady;
    private bool _activityStarted;
    private bool _signingKeyRotationPending;
    private volatile bool _isSending;
    private volatile bool _isReceiving;
    private volatile bool _isBrowsing;
    private Guid? _selectedDeviceId;
    private TaskCompletionSource<bool>? _pendingPairingConfirmation;
    private AlertDialog? _pairingDialog;
    private string _progressFileKey = string.Empty;
    private Action? _alwaysReadyUiRefresh;

    private TextView _statusText = null!;
    private TextView _identityText = null!;
    private TextView _deviceCountText = null!;
    private TextView _emptyDevicesText = null!;
    private LinearLayout _devicesContainer = null!;
    private Button _pairButton = null!;
    private Button _forgetButton = null!;
    private Button _browseButton = null!;
    private TextView _selectedDeviceText = null!;
    private TextView _selectedFilesText = null!;
    private Button _chooseFilesButton = null!;
    private Button _sendButton = null!;
    private Button _cancelSendButton = null!;
    private ProgressBar _transferProgress = null!;
    private TextView _progressText = null!;
    private TextView _speedText = null!;

    protected override void OnCreate(Bundle? savedInstanceState)
    {
        base.OnCreate(savedInstanceState);
        BuildUi();

        try
        {
            _resolver = ContentResolver ?? throw new InvalidOperationException("Android ContentResolver is unavailable.");
            _progress = new Progress<TransferProgress>(progress =>
            {
                TransferForegroundService.Report(progress);
                RunOnUiThreadIfAlive(() => UpdateProgress(progress));
            });
            _identity = AndroidLocalIdentity.LoadOrCreate(this, AppendLog);
            _trustedDevices = new TrustedDeviceStore(this, AppendLog);
            TransferForegroundService.CancelRequested += CancelActiveTransfer;
            LocalAvailabilityService.DeviceSeen += OnDeviceSeen;
            LocalAvailabilityService.DeviceExpired += OnDeviceExpired;
            LocalAvailabilityService.DevicesCleared += OnDevicesCleared;
            LocalAvailabilityService.TransferProgressChanged += OnBackgroundTransferProgress;
            LocalAvailabilityService.IncomingTransferStarted += OnIncomingTransferStarted;
            LocalAvailabilityService.IncomingTransferEnded += OnIncomingTransferEnded;
            LocalAvailabilityService.TrustedPeerSaved += OnBackgroundTrustedPeerSaved;
            LocalAvailabilityService.TrustedSigningIdentitySaved += OnBackgroundTrustedSigningIdentitySaved;
            LocalAvailabilityService.TrustedEndpointSaved += OnBackgroundTrustedEndpointSaved;
            LocalAvailabilityService.LogMessage += AppendLog;
            LocalAvailabilityService.StateChanged += OnAvailabilityStateChanged;
            _identityText.Text = $"{_identity.DeviceName}\nКлюч: {FormatFingerprint(_identity.GetPublicKeyFingerprint())}";
            RestorePersistedTrustedEndpoints();
            AppendLog("Genia Link Android v0.3.1 RC4 started. Local TCP/UDP only; no HTTP, cloud, analytics, or third-party packages.");
            AppendLog($"Local Device ID: {_identity.DeviceId:D}");
            AppendLog($"GNP/1 M2 Signing Key ID: {_identity.SigningKeyId} (generation {_identity.KeyGeneration})");
            _identityReady = true;
            UpdateMainStatus();
            UpdateSelectedDeviceUi();
            HandleIncomingShareIntent(Intent);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or InvalidOperationException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException)
        {
            _statusText.Text = "Ошибка запуска";
            AppendLog($"Startup failed safely: {ex.Message}");
            DisableNetworkActions();
        }
    }

    protected override void OnNewIntent(Intent? intent)
    {
        base.OnNewIntent(intent);
        if (intent is null)
        {
            return;
        }

        // .NET for Android 36 exposes Activity.SetIntent(Intent, ComponentCaller);
        // the share handler already consumes the new intent directly, so replacing
        // Activity.Intent is unnecessary and would couple us to that API-35 overload.
        HandleIncomingShareIntent(intent);
    }

    protected override void OnResume()
    {
        base.OnResume();
        AlwaysReadySettings.ResolvePendingEnableRequest(this);
        _alwaysReadyUiRefresh?.Invoke();
        LocalAvailabilityService.RefreshAlwaysReadyConfiguration();
        UpdateMainStatus();
    }

    protected override void OnStart()
    {
        base.OnStart();
        _activityStarted = true;
        _isReceiving = LocalAvailabilityService.IsReceiving;
        LocalAvailabilityService.PairingConfirmationHandler = ConfirmPairingAsync;
        RequestNotificationPermissionIfNeeded();
        if (_identityReady && !_signingKeyRotationPending)
        {
            try
            {
                LocalAvailabilityService.Begin(this);
            }
            catch (Exception ex) when (ex is Java.Lang.SecurityException or Java.Lang.IllegalStateException or InvalidOperationException)
            {
                AppendLog($"Background availability service could not start: {ex.Message}");
            }
        }

        UpdateMainStatus();
    }

    protected override void OnStop()
    {
        _activityStarted = false;
        LocalAvailabilityService.PairingConfirmationHandler = null;
        CancelPendingPairingConfirmation();
        DismissPairingDialog();
        CancelBrowse();
        if (!IsTransferActive)
        {
            CancelSend();
        }
        else
        {
            AppendLog("Activity moved to background; transfer and local availability continue in foreground services.");
        }

        UpdateMainStatus();
        base.OnStop();
    }

    protected override void OnDestroy()
    {
        _activityStarted = false;
        LocalAvailabilityService.PairingConfirmationHandler = null;
        CancelPendingPairingConfirmation();
        DismissPairingDialog();
        CancelBrowse();
        if (!IsTransferActive)
        {
            CancelSend();
        }

        TransferForegroundService.CancelRequested -= CancelActiveTransfer;
        LocalAvailabilityService.DeviceSeen -= OnDeviceSeen;
        LocalAvailabilityService.DeviceExpired -= OnDeviceExpired;
        LocalAvailabilityService.DevicesCleared -= OnDevicesCleared;
        LocalAvailabilityService.TransferProgressChanged -= OnBackgroundTransferProgress;
        LocalAvailabilityService.IncomingTransferStarted -= OnIncomingTransferStarted;
        LocalAvailabilityService.IncomingTransferEnded -= OnIncomingTransferEnded;
        LocalAvailabilityService.TrustedPeerSaved -= OnBackgroundTrustedPeerSaved;
        LocalAvailabilityService.TrustedSigningIdentitySaved -= OnBackgroundTrustedSigningIdentitySaved;
        LocalAvailabilityService.TrustedEndpointSaved -= OnBackgroundTrustedEndpointSaved;
        LocalAvailabilityService.LogMessage -= AppendLog;
        LocalAvailabilityService.StateChanged -= OnAvailabilityStateChanged;
        base.OnDestroy();
    }

    private bool IsTransferActive => _isSending || _isReceiving;

    private void BuildUi()
    {
        var page = new ScrollView(this)
        {
            FillViewport = true,
            Background = new ColorDrawable(ParseColor("#F7F8FA"))
        };

        var root = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        var contentLeft = Dp(16);
        var contentTop = Dp(12);
        var contentRight = Dp(16);
        var contentBottom = Dp(22);
        root.SetPadding(contentLeft, contentTop, contentRight, contentBottom);
        page.SetOnApplyWindowInsetsListener(
            new SystemBarsPaddingListener(root, contentLeft, contentTop, contentRight, contentBottom));
        page.AddView(root, new ViewGroup.LayoutParams(ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent));

        var header = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Horizontal
        };
        header.SetGravity(GravityFlags.CenterVertical);

        var logo = new ImageView(this);
        logo.SetImageResource(Resource.Mipmap.ic_launcher);
        header.AddView(logo, new LinearLayout.LayoutParams(Dp(40), Dp(40)));

        var headerText = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        var headerParams = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f)
        {
            LeftMargin = Dp(10)
        };
        header.AddView(headerText, headerParams);

        var title = new TextView(this)
        {
            Text = "Genia Link",
            TextSize = 22f,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        title.SetTextColor(ParseColor("#111827"));
        headerText.AddView(title);

        _statusText = new TextView(this)
        {
            Text = "Запуск локальной сети…",
            TextSize = 12.5f
        };
        _statusText.SetTextColor(ParseColor("#64748B"));
        headerText.AddView(_statusText);

        var menuButton = CreateMenuButton();
        menuButton.Click += (_, _) => ShowMainMenu(menuButton);
        header.AddView(menuButton, new LinearLayout.LayoutParams(Dp(44), Dp(40)));
        root.AddView(header);

        // Existing lifecycle code keeps writing the local identity here; detailed information is now opened from the menu.
        _identityText = new TextView(this)
        {
            Text = "Подготовка защищённой идентичности…",
            TextSize = 13f
        };

        var devicesHeading = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Horizontal
        };
        devicesHeading.SetGravity(GravityFlags.CenterVertical);
        var devicesTitle = CreateSectionTitle("Устройства");
        devicesHeading.AddView(devicesTitle, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));
        _deviceCountText = new TextView(this)
        {
            Text = "0",
            TextSize = 12f,
            Gravity = GravityFlags.Center
        };
        _deviceCountText.SetTextColor(ParseColor("#475569"));
        _deviceCountText.Background = CreateRoundedDrawable("#E7ECF2", 14);
        _deviceCountText.SetPadding(Dp(9), Dp(3), Dp(9), Dp(3));
        devicesHeading.AddView(_deviceCountText);
        root.AddView(devicesHeading, WithTopMargin(14));

        _devicesContainer = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        _emptyDevicesText = new TextView(this)
        {
            Text = "Поиск устройств в локальной сети…",
            TextSize = 13f,
            Gravity = GravityFlags.Center
        };
        _emptyDevicesText.SetTextColor(ParseColor("#64748B"));
        _emptyDevicesText.SetPadding(Dp(10), Dp(18), Dp(10), Dp(18));
        _devicesContainer.AddView(_emptyDevicesText);
        root.AddView(_devicesContainer, WithTopMargin(6));

        root.AddView(CreateSectionTitle("Передача"), WithTopMargin(14));
        var transferCard = CreateCard("#FFFFFF", 14, "#E2E8F0");
        transferCard.SetPadding(Dp(13), Dp(10), Dp(13), Dp(10));

        _selectedDeviceText = new TextView(this)
        {
            Text = "Выберите устройство",
            TextSize = 14f,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        _selectedDeviceText.SetTextColor(ParseColor("#1E293B"));
        transferCard.AddView(_selectedDeviceText);

        _pairButton = CreateButton("Сопрячь", primary: true);
        _pairButton.Visibility = ViewStates.Gone;
        _pairButton.Click += async (_, _) => await PairSelectedAsync();
        transferCard.AddView(_pairButton, WithTopMargin(6));

        // Kept as internal state holders; secondary actions are exposed through the compact device rows/menu.
        _forgetButton = CreateButton("Забыть", primary: false);
        _forgetButton.Visibility = ViewStates.Gone;
        _forgetButton.Click += (_, _) => ForgetSelectedDevice();
        _browseButton = CreateButton("Файлы", primary: false);
        _browseButton.Visibility = ViewStates.Gone;
        _browseButton.Click += async (_, _) => await BrowseSelectedDeviceAsync();

        _selectedFilesText = new TextView(this)
        {
            Text = "Файлы не выбраны",
            TextSize = 12.5f
        };
        _selectedFilesText.SetTextColor(ParseColor("#64748B"));
        transferCard.AddView(_selectedFilesText, WithTopMargin(4));

        var sendActions = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Horizontal
        };
        _chooseFilesButton = CreateButton("Выбрать файлы", primary: false);
        _chooseFilesButton.Click += (_, _) => ChooseFiles();
        sendActions.AddView(_chooseFilesButton, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));

        _sendButton = CreateButton("Отправить", primary: true);
        _sendButton.Click += async (_, _) => await SendSelectedFilesAsync();
        var sendParams = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f)
        {
            LeftMargin = Dp(8)
        };
        sendActions.AddView(_sendButton, sendParams);
        transferCard.AddView(sendActions, WithTopMargin(8));

        _cancelSendButton = CreateButton("Отмена", primary: false);
        _cancelSendButton.Visibility = ViewStates.Gone;
        _cancelSendButton.Click += (_, _) => CancelActiveTransfer();
        transferCard.AddView(_cancelSendButton, WithTopMargin(6));

        _transferProgress = new ProgressBar(this, null, global::Android.Resource.Attribute.ProgressBarStyleHorizontal)
        {
            Max = 1000,
            Progress = 0
        };
        transferCard.AddView(_transferProgress, WithTopMargin(8));

        _progressText = new TextView(this)
        {
            Text = "Готово к передаче",
            TextSize = 12.5f
        };
        _progressText.SetTextColor(ParseColor("#334155"));
        transferCard.AddView(_progressText, WithTopMargin(4));

        _speedText = new TextView(this)
        {
            Text = string.Empty,
            TextSize = 11.5f
        };
        _speedText.SetTextColor(ParseColor("#64748B"));
        transferCard.AddView(_speedText, WithTopMargin(1));
        root.AddView(transferCard, WithTopMargin(6));

        var footer = new TextView(this)
        {
            Text = "Локальная сеть · без аккаунта и облака",
            TextSize = 11.5f,
            Gravity = GravityFlags.Center
        };
        footer.SetTextColor(ParseColor("#94A3B8"));
        root.AddView(footer, WithTopMargin(12));

        SetContentView(page);
        DisableNetworkActions();
    }

    private void ShowMainMenu(View anchor)
    {
        var popup = new PopupMenu(this, anchor);
        var menu = popup.Menu;
        if (menu is null)
        {
            return;
        }

        menu.Add("Открыть Загрузки");
        menu.Add("Моё устройство");
        menu.Add("Сменить signing key");
        if (GetSelectedDevice()?.IsTrusted == true)
        {
            menu.Add("Забыть выбранное устройство");
        }

        menu.Add("Всегда готов к приёму");
        menu.Add("Диагностика");
        menu.Add("О программе");

        popup.MenuItemClick += (_, args) =>
        {
            var title = args.Item?.TitleFormatted?.ToString() ?? string.Empty;
            switch (title)
            {
                case "Открыть Загрузки":
                    OpenDownloads();
                    break;
                case "Моё устройство":
                    ShowLocalDeviceInfo();
                    break;
                case "Сменить signing key":
                    ConfirmSigningKeyRotation();
                    break;
                case "Забыть выбранное устройство":
                    ForgetSelectedDevice();
                    break;
                case "Всегда готов к приёму":
                    ShowAlwaysReadySettings();
                    break;
                case "Диагностика":
                    ShowDiagnostics();
                    break;
                case "О программе":
                    ShowAbout();
                    break;
            }
        };

        popup.Show();
    }

    private void ShowLocalDeviceInfo()
    {
        if (!_identityReady)
        {
            return;
        }

        var content = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        content.SetPadding(Dp(20), Dp(4), Dp(20), Dp(4));

        var deviceName = new TextView(this)
        {
            Text = _identity.DeviceName,
            TextSize = 17f,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        deviceName.SetTextColor(ParseColor("#0F172A"));
        content.AddView(deviceName);

        var deviceType = new TextView(this)
        {
            Text = "Android · локальное защищённое устройство",
            TextSize = 12f
        };
        deviceType.SetTextColor(ParseColor("#64748B"));
        content.AddView(deviceType, WithTopMargin(2));

        var keyLabel = new TextView(this)
        {
            Text = "Ключ устройства",
            TextSize = 12f,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        keyLabel.SetTextColor(ParseColor("#334155"));
        content.AddView(keyLabel, WithTopMargin(14));

        var fingerprint = new TextView(this)
        {
            Text = FormatFingerprint(_identity.GetPublicKeyFingerprint()),
            TextSize = 12f,
            Typeface = global::Android.Graphics.Typeface.Monospace
        };
        fingerprint.SetTextColor(ParseColor("#0F172A"));
        fingerprint.SetTextIsSelectable(true);
        content.AddView(fingerprint, WithTopMargin(3));

        var signingIdentity = new TextView(this)
        {
            Text = $"Signing identity: generation {_identity.KeyGeneration}\n{_identity.SigningKeyId}",
            TextSize = 11.5f,
            Typeface = global::Android.Graphics.Typeface.Monospace
        };
        signingIdentity.SetTextColor(ParseColor("#334155"));
        signingIdentity.SetTextIsSelectable(true);
        content.AddView(signingIdentity, WithTopMargin(12));

        var ports = new TextView(this)
        {
            Text = $"Локальные службы: TCP {ProtocolConstants.Port} · pairing {ProtocolConstants.PairingPort} · discovery {ProtocolConstants.DiscoveryPort}",
            TextSize = 11.5f
        };
        ports.SetTextColor(ParseColor("#64748B"));
        content.AddView(ports, WithTopMargin(13));

        var builder = new AlertDialog.Builder(this);
        builder.SetTitle("Моё устройство");
        builder.SetView(content);
        builder.SetPositiveButton("Закрыть", (_, _) => { });
        builder.Show();
    }

    private void ConfirmSigningKeyRotation()
    {
        if (!_identityReady)
        {
            return;
        }

        if (IsTransferActive)
        {
            _ = ShowMessageAsync("Genia Link", "Смену signing key нельзя планировать во время активной передачи.");
            return;
        }

        var builder = new AlertDialog.Builder(this);
        builder.SetTitle("Trusted Key Rotation");
        builder.SetMessage(
            "Запланировать безопасную смену signing key?\n\nПри следующем чистом запуске старый signing key подпишет новый. Device ID, ECDH-ключ и существующие сопряжения не меняются. Все устройства должны быть обновлены до GNP/1 M2.4.2, чтобы принять новый ключ без повторного сопряжения.");
        builder.SetNegativeButton("Отмена", (_, _) => { });
        builder.SetPositiveButton("Запланировать", (_, _) =>
        {
            try
            {
                AndroidLocalIdentity.RequestSigningKeyRotation(this, _identity);
                _signingKeyRotationPending = true;
                LocalAvailabilityService.End();
                AppendLog($"GNP/1 M2.4.2 signing-key rotation requested for generation {_identity.KeyGeneration} -> {_identity.KeyGeneration + 1}.");
                _ = ShowMessageAsync(
                    "Genia Link",
                    "Смена signing key запланирована. Полностью закройте Genia Link (смахните приложение из списка недавних) и откройте снова. При следующем запуске generation увеличится на 1, а переход будет подписан текущим ключом.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or CryptographicException or Java.Lang.SecurityException or Java.Lang.IllegalStateException)
            {
                AppendLog($"Signing-key rotation request failed safely: {ex.Message}");
                _ = ShowMessageAsync("Genia Link", $"Не удалось запланировать смену signing key.\n\n{ex.Message}");
            }
        });
        builder.Show();
    }

    private void ShowAbout()
    {
        var content = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        content.SetPadding(Dp(20), Dp(4), Dp(20), Dp(4));

        var version = new TextView(this)
        {
            Text = "v0.3.1 RC4",
            TextSize = 15f,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        version.SetTextColor(ParseColor("#0F172A"));
        content.AddView(version);

        var description = new TextView(this)
        {
            Text = "Локальная защищённая передача файлов без аккаунта, облака, аналитики и внешних API.",
            TextSize = 12.5f
        };
        description.SetTextColor(ParseColor("#475569"));
        content.AddView(description, WithTopMargin(8));

        var builder = new AlertDialog.Builder(this);
        builder.SetTitle("Genia Link");
        builder.SetView(content);
        builder.SetPositiveButton("Закрыть", (_, _) => { });
        builder.Show();
    }

    private void ShowAlwaysReadySettings()
    {
        var content = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        content.SetPadding(Dp(20), Dp(6), Dp(20), Dp(6));

        var toggle = new global::Android.Widget.Switch(this)
        {
            Text = "Всегда готов к приёму",
            TextSize = 15.5f,
            Checked = AlwaysReadySettings.IsEnabled(this)
        };
        toggle.SetTextColor(ParseColor("#0F172A"));
        content.AddView(toggle);

        var status = new TextView(this)
        {
            TextSize = 12.5f
        };
        status.SetTextColor(ParseColor("#475569"));
        status.SetLineSpacing(0f, 1.08f);
        content.AddView(status, WithTopMargin(10));

        var systemStatus = new TextView(this)
        {
            TextSize = 11.5f
        };
        systemStatus.SetTextColor(ParseColor("#64748B"));
        systemStatus.SetLineSpacing(0f, 1.06f);
        content.AddView(systemStatus, WithTopMargin(12));

        var openBatterySettings = new Button(this)
        {
            Text = "Настройки батареи Android",
            TextSize = 12.5f,
            Visibility = ViewStates.Gone
        };
        openBatterySettings.SetAllCaps(false);
        content.AddView(openBatterySettings, WithTopMargin(12));

        var updating = false;
        void Refresh()
        {
            if (IsFinishing || IsDestroyed)
            {
                return;
            }

            var enabled = AlwaysReadySettings.IsEnabled(this);
            var exempt = AlwaysReadySettings.IsBatteryOptimizationExempt(this);
            var effective = enabled && exempt;

            updating = true;
            toggle.Checked = enabled;
            updating = false;

            if (effective)
            {
                status.Text = "Телефон сможет принимать файлы от доверенных устройств даже после долгого простоя с выключенным экраном.";
                systemStatus.Text = "Режим включён. Передача остаётся полностью локальной.";
                openBatterySettings.Visibility = ViewStates.Gone;
            }
            else if (enabled)
            {
                status.Text = "Чтобы принимать файлы после долгого простоя, Android должен разрешить Genia Link работать без ограничений батареи.";
                systemStatus.Text = "Системное разрешение ещё не получено.";
                openBatterySettings.Visibility = ViewStates.Visible;
            }
            else if (exempt)
            {
                status.Text = "Режим в Genia Link выключен.";
                systemStatus.Text = "Android всё ещё не ограничивает Genia Link по батарее. Для полного возврата обычной экономии откройте настройки и разрешите оптимизацию батареи для Genia Link.";
                openBatterySettings.Visibility = ViewStates.Visible;
            }
            else
            {
                status.Text = "Обычный режим. После долгого простоя Android может временно приостанавливать фоновый приём.";
                systemStatus.Text = "Включите режим только если телефон должен принимать файлы после долгого простоя с выключенным экраном.";
                openBatterySettings.Visibility = ViewStates.Gone;
            }
        }

        void OpenBatterySettings()
        {
            try
            {
                AlwaysReadySettings.OpenBatteryOptimizationSettings(this);
            }
            catch (Exception ex) when (ex is ActivityNotFoundException or Java.Lang.SecurityException)
            {
                AppendLog($"Battery optimization settings unavailable: {ex.Message}");
                _ = ShowMessageAsync("Genia Link", "Не удалось открыть системные настройки батареи на этом устройстве.");
            }
        }

        void RequestExemption()
        {
            try
            {
                AlwaysReadySettings.MarkEnableRequestPending(this);
                AlwaysReadySettings.RequestBatteryOptimizationExemption(this);
            }
            catch (Exception ex) when (ex is ActivityNotFoundException or Java.Lang.SecurityException or Java.Lang.IllegalArgumentException)
            {
                AppendLog($"Always Ready direct battery request unavailable: {ex.Message}");
                try
                {
                    AlwaysReadySettings.MarkEnableRequestPending(this);
                    AlwaysReadySettings.OpenBatteryOptimizationSettings(this);
                }
                catch (Exception settingsEx) when (settingsEx is ActivityNotFoundException or Java.Lang.SecurityException)
                {
                    AlwaysReadySettings.SetEnabled(this, false);
                    AppendLog($"Battery optimization settings unavailable: {settingsEx.Message}");
                    _ = ShowMessageAsync("Genia Link", "Не удалось открыть системные настройки батареи на этом устройстве.");
                }
            }
        }

        openBatterySettings.Click += (_, _) => OpenBatterySettings();

        toggle.CheckedChange += (_, args) =>
        {
            if (updating)
            {
                return;
            }

            if (args.IsChecked)
            {
                AppendLog("Always Ready requested by user.");
                AlwaysReadySettings.SetEnabled(this, true);
                if (!AlwaysReadySettings.IsBatteryOptimizationExempt(this))
                {
                    RequestExemption();
                }
            }
            else
            {
                AppendLog("Always Ready disabled by user.");
                AlwaysReadySettings.SetEnabled(this, false);
            }

            Refresh();
            LocalAvailabilityService.RefreshAlwaysReadyConfiguration();
            UpdateMainStatus();
        };

        var builder = new AlertDialog.Builder(this);
        builder.SetTitle("Приём файлов");
        builder.SetView(content);
        builder.SetPositiveButton("Готово", (_, _) => { });
        builder.SetOnDismissListener(new DialogDismissListener(() => _alwaysReadyUiRefresh = null));
        Refresh();
        _alwaysReadyUiRefresh = Refresh;
        builder.Show();
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
            AppendLog($"Trusted key could not be used: {ex.Message}");
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

    private void OnDeviceSeen(DiscoveredDevice device)
    {
        if (_trustedDevices.IsKnownInactive(device.DeviceId))
        {
            lock (_deviceGate)
            {
                _discovered.Remove(device.DeviceId);
                _staleDevices.Remove(device.DeviceId);
            }

            RunOnUiThreadIfAlive(RefreshDeviceList);
            return;
        }

        device = PromoteKnownAuthenticatedSignedDiscoveryToUi(device);
        var refreshUi = false;
        lock (_deviceGate)
        {
            if (_staleDevices.Remove(device.DeviceId))
            {
                refreshUi = true;
            }

            if (!_discovered.TryGetValue(device.DeviceId, out var previous) ||
                !string.Equals(previous.DeviceName, device.DeviceName, StringComparison.Ordinal) ||
                !Equals(previous.Address, device.Address) ||
                previous.TransferPort != device.TransferPort ||
                previous.PairingPort != device.PairingPort ||
                previous.Kind != device.Kind ||
                previous.IdentityProof != device.IdentityProof ||
                previous.Capabilities != device.Capabilities ||
                previous.CapabilityRevision != device.CapabilityRevision ||
                !string.Equals(previous.SigningKeyId, device.SigningKeyId, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(previous.PublicKeyFingerprint, device.PublicKeyFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                refreshUi = true;
            }

            _discovered[device.DeviceId] = device;
        }

        if (refreshUi)
        {
            RunOnUiThreadIfAlive(RefreshDeviceList);
        }
    }

    private DiscoveredDevice PromoteKnownAuthenticatedSignedDiscoveryToUi(DiscoveredDevice device)
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
            AppendLog($"GNP/1 M2.6.2 authenticated discovery state could not be mirrored into the UI store for {device.DeviceName}: {ex.Message}");
            return device;
        }
    }

    private void OnDeviceExpired(Guid deviceId)
    {
        var changed = false;
        var isTrusted = _trustedDevices.Get(deviceId) is not null;
        lock (_deviceGate)
        {
            if (isTrusted && _discovered.ContainsKey(deviceId))
            {
                changed = _staleDevices.Add(deviceId);
            }
            else
            {
                changed = _discovered.Remove(deviceId);
                _staleDevices.Remove(deviceId);
            }
        }

        if (changed)
        {
            RunOnUiThreadIfAlive(RefreshDeviceList);
        }
    }

    private void OnDevicesCleared()
    {
        lock (_deviceGate)
        {
            _discovered.Clear();
            _staleDevices.Clear();
        }

        RunOnUiThreadIfAlive(RestorePersistedTrustedEndpoints);
    }

    private void OnBackgroundTransferProgress(TransferProgress progress)
    {
        RunOnUiThreadIfAlive(() => UpdateProgress(progress));
    }

    private void OnAvailabilityStateChanged()
    {
        RunOnUiThreadIfAlive(UpdateMainStatus);
    }

    private void RefreshDeviceList()
    {
        DiscoveredDevice[] devices;
        HashSet<Guid> staleDevices;
        lock (_deviceGate)
        {
            devices = _discovered.Values
                .OrderBy(device => device.DeviceName, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();
            staleDevices = new HashSet<Guid>(_staleDevices);
        }

        _visibleDevices.Clear();
        foreach (var device in devices)
        {
            var trusted = _trustedDevices.GetAny(device.DeviceId);
            var registryEntry = _trustedDevices.GetIdentityRegistryEntry(device.DeviceId);
            var cryptographicBindingTrusted = registryEntry?.State == TrustedIdentityRegistryState.Trusted;
            var trustedFingerprint = trusted is null ? null : GetTrustedFingerprint(trusted);
            var isRecentlySeen = !staleDevices.Contains(device.DeviceId);
            var agreementIdentityMatches = trusted is null ||
                                           (trustedFingerprint is not null &&
                                            string.Equals(trustedFingerprint, device.PublicKeyFingerprint, StringComparison.OrdinalIgnoreCase));
            // Legacy GLD2 has no signing key and therefore cannot prove key replacement.
            // Only a signed/authenticated mismatch is a signing-key conflict; transfers remain
            // protected by the already trusted ECDH session handshake.
            var signingIdentityMatches = trusted is null ||
                                         string.IsNullOrWhiteSpace(trusted.SigningKeyId) ||
                                         !isRecentlySeen ||
                                         device.IdentityProof == DiscoveryIdentityProof.LegacyUnsigned ||
                                         ((device.IdentityProof is DiscoveryIdentityProof.SignedIdentityV2 or DiscoveryIdentityProof.ReplayProtectedSignedIdentityV2 or DiscoveryIdentityProof.AuthenticatedTrustedIdentityV2) &&
                                          !string.IsNullOrWhiteSpace(device.SigningKeyId) &&
                                          string.Equals(trusted.SigningKeyId, device.SigningKeyId, StringComparison.OrdinalIgnoreCase));
            var identityMatches = agreementIdentityMatches && signingIdentityMatches &&
                                  (trusted is null || cryptographicBindingTrusted);
            _visibleDevices.Add(new DeviceListItem(device, isRecentlySeen, trusted is not null, identityMatches));
        }

        // Keep the selected trusted device ID across short discovery gaps. If no target is
        // selected and exactly one trusted device is currently available, select it automatically.
        if ((_selectedDeviceId is null || _visibleDevices.All(item => item.Device.DeviceId != _selectedDeviceId.Value)))
        {
            var trustedTargets = _visibleDevices
                .Where(item => item.IsTrusted && item.IdentityMatches)
                .ToArray();
            if (trustedTargets.Length == 1)
            {
                _selectedDeviceId = trustedTargets[0].Device.DeviceId;
            }
        }

        _devicesContainer.RemoveAllViews();
        _deviceCountText.Text = _visibleDevices.Count.ToString(System.Globalization.CultureInfo.CurrentCulture);

        if (_visibleDevices.Count == 0)
        {
            _devicesContainer.AddView(_emptyDevicesText);
        }
        else
        {
            foreach (var item in _visibleDevices)
            {
                _devicesContainer.AddView(CreateDeviceRow(item), WithBottomMargin(8));
            }
        }

        UpdateSelectedDeviceUi();
    }

    private LinearLayout CreateDeviceRow(DeviceListItem item)
    {
        var selected = _selectedDeviceId == item.Device.DeviceId;
        var row = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Horizontal,
            Clickable = true,
            Focusable = true
        };
        row.SetGravity(GravityFlags.CenterVertical);
        row.SetPadding(Dp(12), Dp(8), Dp(9), Dp(8));

        var background = selected ? "#EEF4FF" : "#FFFFFF";
        var border = selected ? "#6EA8FE" : "#E2E8F0";
        row.Background = CreateRoundedDrawable(background, 12, border, selected ? 2 : 1);

        var textColumn = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        row.AddView(textColumn, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));

        var name = new TextView(this)
        {
            Text = item.Device.DeviceName,
            TextSize = 15f,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        name.SetTextColor(ParseColor("#0F172A"));
        textColumn.AddView(name);

        var stateText = item.IsTrusted
            ? item.IdentityMatches
                ? item.IsRecentlySeen ? "Доступен" : "Спит"
                : "Ключ изменился"
            : "Новое устройство";
        var kindText = item.Device.Kind switch
        {
            DeviceKind.WindowsComputer => "Windows",
            DeviceKind.AndroidPhone => "Android",
            DeviceKind.AndroidTablet => "Android · планшет",
            _ => "Устройство"
        };
        var stateColor = item.IsTrusted && !item.IdentityMatches
            ? "#DC2626"
            : item.IsTrusted && item.IdentityMatches && item.IsRecentlySeen
                ? "#059669"
                : item.IsTrusted
                    ? "#94A3B8"
                    : "#2563EB";

        var detailRow = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Horizontal
        };
        detailRow.SetGravity(GravityFlags.CenterVertical);

        var kind = new TextView(this)
        {
            Text = kindText + " ·",
            TextSize = 11.5f
        };
        kind.SetTextColor(ParseColor("#64748B"));
        detailRow.AddView(kind);

        var dot = new TextView(this)
        {
            Text = "●",
            TextSize = 9f
        };
        dot.SetTextColor(ParseColor(stateColor));
        var dotParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WrapContent, ViewGroup.LayoutParams.WrapContent)
        {
            LeftMargin = Dp(4),
            RightMargin = Dp(4)
        };
        detailRow.AddView(dot, dotParams);

        var state = new TextView(this)
        {
            Text = stateText,
            TextSize = 11.5f
        };
        state.SetTextColor(ParseColor(item.IsTrusted && !item.IdentityMatches ? "#B91C1C" : "#64748B"));
        detailRow.AddView(state);
        textColumn.AddView(detailRow, WithTopMargin(1));

        var actionText = item.IsTrusted && item.IdentityMatches ? "Файлы" : "Сопрячь";
        var action = CreateButton(actionText, primary: false);
        action.SetMinHeight(Dp(36));
        action.SetMinWidth(Dp(76));
        action.TextSize = 11.5f;
        action.Click += async (_, _) =>
        {
            _selectedDeviceId = item.Device.DeviceId;
            RefreshDeviceList();
            if (item.IsTrusted && item.IdentityMatches)
            {
                await BrowseSelectedDeviceAsync();
            }
            else
            {
                await PairSelectedAsync();
            }
        };
        var actionParams = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WrapContent, ViewGroup.LayoutParams.WrapContent)
        {
            LeftMargin = Dp(7)
        };
        row.AddView(action, actionParams);

        row.ContentDescription = $"{item.Device.DeviceName}, {kindText}, {stateText}";
        row.Click += (_, _) =>
        {
            _selectedDeviceId = item.Device.DeviceId;
            RefreshDeviceList();
        };
        return row;
    }

    private DeviceListItem? GetSelectedDevice() =>
        _selectedDeviceId is Guid id
            ? _visibleDevices.FirstOrDefault(item => item.Device.DeviceId == id)
            : null;

    private void UpdateSelectedDeviceUi()
    {
        var selected = GetSelectedDevice();
        if (selected is null)
        {
            _selectedDeviceText.Text = "Выберите устройство";
            _pairButton.Text = "Сопрячь";
            _pairButton.Enabled = false;
            _pairButton.Visibility = ViewStates.Gone;
            _forgetButton.Enabled = false;
            _browseButton.Enabled = false;
            _sendButton.Enabled = false;
        }
        else
        {
            var compactStatus = selected.IsTrusted
                ? selected.IdentityMatches
                    ? selected.IsRecentlySeen ? "доступен" : "спит"
                    : "ключ изменился"
                : "новое устройство";
            _selectedDeviceText.Text = $"{selected.Device.DeviceName} · {compactStatus}";

            var pairingRequired = !selected.IsTrusted || !selected.IdentityMatches;
            _pairButton.Text = selected.IsTrusted ? "Сопрячь заново" : "Сопрячь";
            _pairButton.Enabled = !IsTransferActive && !_isBrowsing && _activityStarted && pairingRequired;
            _pairButton.Visibility = pairingRequired ? ViewStates.Visible : ViewStates.Gone;

            _forgetButton.Enabled = !IsTransferActive && !_isBrowsing && selected.IsTrusted;
            _browseButton.Enabled = !IsTransferActive && !_isBrowsing && selected.IsTrusted && selected.IdentityMatches;
            _sendButton.Enabled = !IsTransferActive && !_isBrowsing && selected.IsTrusted && selected.IdentityMatches && _selectedDocuments.Count > 0;
        }

        _chooseFilesButton.Enabled = !IsTransferActive && !_isBrowsing;
        _cancelSendButton.Enabled = IsTransferActive;
        _cancelSendButton.Visibility = IsTransferActive ? ViewStates.Visible : ViewStates.Gone;
        UpdateSelectedFilesUi();
    }

    private async Task BrowseSelectedDeviceAsync()
    {
        var selected = GetSelectedDevice();
        if (selected is null ||
            !selected.IsTrusted ||
            !selected.IdentityMatches ||
            IsTransferActive ||
            _isBrowsing)
        {
            return;
        }

        var trusted = _trustedDevices.Get(selected.Device.DeviceId);
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
        using var browseCts = new CancellationTokenSource();
        _browseCts = browseCts;
        _isBrowsing = true;
        UpdateSelectedDeviceUi();
        try
        {
            sharedKey = _identity.DeriveSharedKey(peerPublicKey);
            AppendLog($"Reading protected Genia Link folder on {selected.Device.DeviceName} ({selected.Device.Address})…");
            var files = await GeniaLink.Core.Transfers.RemoteFolderClient.ListFilesAsync(
                selected.Device.Address,
                selected.Device.TransferPort,
                _identity.DeviceId,
                _identity.DeviceName,
                selected.Device.DeviceId,
                sharedKey,
                browseCts.Token);

            TryPersistVerifiedEndpoint(selected.Device, "authenticated Genia Link folder browse");
            AppendLog($"Remote Genia Link folder on {selected.Device.DeviceName}: {files.Count} file(s).");
            if (files.Count == 0)
            {
                await ShowMessageAsync("Файлы Genia Link", "На выбранном устройстве папка Genia Link пуста.").ConfigureAwait(false);
                return;
            }

            var requested = await ChooseRemoteFilesAsync(
                selected.Device.DeviceName,
                files,
                async cancellationToken =>
                {
                    var refreshed = await RemoteFolderClient.ListFilesAsync(
                        selected.Device.Address,
                        selected.Device.TransferPort,
                        _identity.DeviceId,
                        _identity.DeviceName,
                        selected.Device.DeviceId,
                        sharedKey,
                        cancellationToken);
                    TryPersistVerifiedEndpoint(selected.Device, "authenticated Genia Link folder refresh");
                    return refreshed;
                },
                async (relativePath, cancellationToken) =>
                {
                    var preview = await RemoteFolderClient.GetPreviewAsync(
                        selected.Device.Address,
                        selected.Device.TransferPort,
                        _identity.DeviceId,
                        _identity.DeviceName,
                        selected.Device.DeviceId,
                        sharedKey,
                        relativePath,
                        cancellationToken);
                    TryPersistVerifiedEndpoint(selected.Device, "authenticated Genia Link file preview");
                    return preview;
                },
                browseCts.Token);
            if (requested is null || requested.Count == 0)
            {
                return;
            }

            AppendLog($"Requesting {requested.Count} file(s) from {selected.Device.DeviceName}; incoming files will be saved to Downloads/Genia Link.");
            // Let the selection dialog fully dismiss before the remote peer opens the callback transfer.
            // This avoids overlapping the dialog/window transition with the incoming foreground transfer on vendor Android builds.
            await Task.Delay(120, browseCts.Token);
            await GeniaLink.Core.Transfers.RemoteFolderClient.RequestDownloadAsync(
                selected.Device.Address,
                selected.Device.TransferPort,
                ProtocolConstants.Port,
                _identity.DeviceId,
                _identity.DeviceName,
                selected.Device.DeviceId,
                sharedKey,
                requested,
                browseCts.Token);
            TryPersistVerifiedEndpoint(selected.Device, "authenticated remote download request");
            RunOnUiThreadIfAlive(() =>
            {
                _progressText.Text = $"Запрошено файлов: {requested.Count}";
                _speedText.Text = "Ожидание входящей передачи…";
            });
            AppendLog("Remote device accepted the protected download request; files will arrive through the normal verified receiver.");
        }
        catch (System.OperationCanceledException) when (browseCts.IsCancellationRequested)
        {
            AppendLog("Remote Genia Link folder request canceled safely.");
        }
        catch (System.OperationCanceledException)
        {
            AppendLog("Remote Genia Link folder request timed out safely.");
            await ShowMessageAsync("Файлы Genia Link", "Устройство не ответило вовремя.").ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or InvalidDataException or AuthenticationException or CryptographicException or InvalidOperationException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException)
        {
            AppendLog($"Remote Genia Link folder request failed safely: {ex.Message}");
            await ShowMessageAsync("Файлы Genia Link", ex.Message).ConfigureAwait(false);
        }
        finally
        {
            if (sharedKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(sharedKey);
            }

            CryptographicOperations.ZeroMemory(peerPublicKey);
            if (ReferenceEquals(_browseCts, browseCts))
            {
                _browseCts = null;
            }

            _isBrowsing = false;
            RunOnUiThreadIfAlive(UpdateSelectedDeviceUi);
        }
    }

    private Task<IReadOnlyList<string>?> ChooseRemoteFilesAsync(
        string deviceName,
        IReadOnlyList<RemoteFileEntry> files,
        Func<CancellationToken, Task<IReadOnlyList<RemoteFileEntry>>> refreshLoader,
        Func<string, CancellationToken, Task<RemoteFilePreview>> previewLoader,
        CancellationToken cancellationToken)
    {
        if (!_activityStarted || IsDestroyed)
        {
            return Task.FromResult<IReadOnlyList<string>?>(null);
        }

        var completion = new TaskCompletionSource<IReadOnlyList<string>?>(TaskCreationOptions.RunContinuationsAsynchronously);
        RunOnUiThread(() =>
        {
            if (!_activityStarted || IsDestroyed)
            {
                completion.TrySetResult(null);
                return;
            }

            IReadOnlyList<RemoteFileEntry> currentFiles = files;
            var selectedPaths = new HashSet<string>(StringComparer.Ordinal);
            var currentDirectory = string.Empty;
            RemoteBrowserEntry[] visibleEntries = [];

            var root = new LinearLayout(this)
            {
                Orientation = global::Android.Widget.Orientation.Vertical
            };
            root.SetPadding(Dp(8), Dp(2), Dp(8), Dp(4));

            var toolbar = new LinearLayout(this)
            {
                Orientation = global::Android.Widget.Orientation.Horizontal
            };
            toolbar.SetGravity(GravityFlags.CenterVertical);

            var upButton = CreateButton("↑", primary: false);
            upButton.SetMinWidth(Dp(44));
            var pathText = new TextView(this)
            {
                Text = "Genia Link",
                TextSize = 12.5f,
                Typeface = global::Android.Graphics.Typeface.DefaultBold
            };
            pathText.SetTextColor(ParseColor("#334155"));
            pathText.SetSingleLine(true);
            pathText.Ellipsize = global::Android.Text.TextUtils.TruncateAt.Middle;

            var refreshButton = CreateButton("Обновить", primary: false);
            refreshButton.SetMinWidth(Dp(88));
            toolbar.AddView(upButton, new LinearLayout.LayoutParams(Dp(48), ViewGroup.LayoutParams.WrapContent));
            toolbar.AddView(pathText, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f)
            {
                LeftMargin = Dp(8),
                RightMargin = Dp(6)
            });
            toolbar.AddView(refreshButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WrapContent, ViewGroup.LayoutParams.WrapContent));
            root.AddView(toolbar);

            var list = new ListView(this)
            {
                DividerHeight = 0
            };
            list.SetPadding(0, Dp(4), 0, Dp(4));
            list.SetClipToPadding(false);
            root.AddView(list, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, Dp(360)));

            var footer = new LinearLayout(this)
            {
                Orientation = global::Android.Widget.Orientation.Horizontal
            };
            footer.SetGravity(GravityFlags.CenterVertical);
            footer.SetPadding(Dp(4), Dp(6), Dp(4), Dp(2));

            var selectionText = new TextView(this)
            {
                Text = $"Файлов: {currentFiles.Count} · Выбрано: 0",
                TextSize = 12f
            };
            selectionText.SetTextColor(ParseColor("#64748B"));
            var previewButton = CreateButton("Просмотр", primary: false);
            previewButton.Enabled = false;
            footer.AddView(selectionText, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f));
            footer.AddView(previewButton, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WrapContent, ViewGroup.LayoutParams.WrapContent));
            root.AddView(footer);

            AlertDialog? dialog = null;

            void UpdateSummary()
            {
                var byPath = currentFiles.ToDictionary(file => file.RelativePath, StringComparer.Ordinal);
                selectedPaths.RemoveWhere(path => !byPath.ContainsKey(path));
                var selected = selectedPaths
                    .Select(path => byPath.TryGetValue(path, out var file) ? file : null)
                    .Where(file => file is not null)
                    .Cast<RemoteFileEntry>()
                    .ToArray();
                var totalBytes = selected.Sum(file => file.FileSize);
                selectionText.Text = selected.Length == 0
                    ? $"Файлов: {currentFiles.Count} · Выбрано: 0"
                    : $"Файлов: {currentFiles.Count} · Выбрано: {selected.Length} · {AndroidDocumentAccess.FormatBytes(totalBytes)}";
                previewButton.Enabled = selected.Length == 1 &&
                    (RemotePreviewPolicy.IsImagePath(selected[0].RelativePath) || RemotePreviewPolicy.IsTextPath(selected[0].RelativePath));
                if (dialog is not null)
                {
                    var downloadButton = dialog.GetButton((int)DialogButtonType.Positive);
                    if (downloadButton is not null)
                    {
                        downloadButton.Enabled = selected.Length > 0;
                    }
                }
            }

            void RebuildList()
            {
                var entries = RemoteBrowserIndex.BuildDirectory(currentFiles, currentDirectory);
                visibleEntries = entries
                    .OrderByDescending(entry => entry.IsDirectory)
                    .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
                    .ToArray();

                list.Adapter = new RemoteBrowserListAdapter(this, visibleEntries, selectedPaths);
                pathText.Text = FormatRemotePath(currentDirectory);
                upButton.Enabled = currentDirectory.Length > 0;
                UpdateSummary();
            }

            list.ItemClick += (_, e) =>
            {
                if (e.Position < 0 || e.Position >= visibleEntries.Length)
                {
                    return;
                }

                var entry = visibleEntries[e.Position];
                if (entry.IsDirectory)
                {
                    currentDirectory = entry.RelativePath;
                    RebuildList();
                    return;
                }

                if (!selectedPaths.Add(entry.RelativePath))
                {
                    selectedPaths.Remove(entry.RelativePath);
                }

                (list.Adapter as RemoteBrowserListAdapter)?.NotifyDataSetChanged();
                UpdateSummary();
            };

            upButton.Click += (_, _) =>
            {
                if (currentDirectory.Length == 0)
                {
                    return;
                }

                currentDirectory = RemoteBrowserIndex.GetParentDirectory(currentDirectory);
                RebuildList();
            };

            refreshButton.Click += async (_, _) =>
            {
                refreshButton.Enabled = false;
                try
                {
                    currentFiles = await refreshLoader(cancellationToken);
                    var existing = currentFiles.Select(file => file.RelativePath).ToHashSet(StringComparer.Ordinal);
                    selectedPaths.RemoveWhere(path => !existing.Contains(path));
                    if (currentDirectory.Length > 0 &&
                        !currentFiles.Any(file => file.RelativePath.StartsWith(currentDirectory + "/", StringComparison.Ordinal)))
                    {
                        currentDirectory = string.Empty;
                    }

                    RebuildList();
                }
                catch (System.OperationCanceledException)
                {
                }
                catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or InvalidDataException or AuthenticationException or CryptographicException or InvalidOperationException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException)
                {
                    await ShowMessageAsync("Файлы Genia Link", ex.Message);
                }
                finally
                {
                    refreshButton.Enabled = true;
                }
            };

            previewButton.Click += async (_, _) =>
            {
                var selectedPath = selectedPaths.SingleOrDefault();
                if (string.IsNullOrEmpty(selectedPath))
                {
                    return;
                }

                var selectedFile = currentFiles.FirstOrDefault(file => string.Equals(file.RelativePath, selectedPath, StringComparison.Ordinal));
                if (selectedFile is null)
                {
                    return;
                }

                previewButton.Enabled = false;
                var previousText = previewButton.Text;
                previewButton.Text = "Загрузка…";
                try
                {
                    await ShowRemotePreviewAsync(selectedFile, previewLoader, cancellationToken);
                }
                finally
                {
                    previewButton.Text = previousText;
                    UpdateSummary();
                }
            };

            var titlePanel = new LinearLayout(this)
            {
                Orientation = global::Android.Widget.Orientation.Vertical
            };
            titlePanel.SetPadding(Dp(24), Dp(16), Dp(24), Dp(8));
            var titleText = new TextView(this)
            {
                Text = $"{deviceName} · Файлы Genia Link",
                TextSize = 18.5f,
                Typeface = global::Android.Graphics.Typeface.DefaultBold
            };
            titleText.SetTextColor(ParseColor("#0F172A"));
            titlePanel.AddView(titleText);
            var titleHint = new TextView(this)
            {
                Text = "Просмотр фото/текста и скачивание выбранных файлов.",
                TextSize = 11.5f
            };
            titleHint.SetTextColor(ParseColor("#64748B"));
            titlePanel.AddView(titleHint, WithTopMargin(3));

            var builder = new AlertDialog.Builder(this);
            builder.SetCustomTitle(titlePanel);
            builder.SetView(root);
            builder.SetNegativeButton("Отмена", (_, _) => completion.TrySetResult(null));
            builder.SetPositiveButton("Скачать", (_, _) => completion.TrySetResult(selectedPaths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray()));
            builder.SetOnCancelListener(new DialogCancelListener(() => completion.TrySetResult(null)));
            dialog = builder.Create();
            if (dialog is null)
            {
                completion.TrySetResult(null);
                return;
            }

            dialog.Show();
            RebuildList();
        });

        return completion.Task;
    }

    private async Task ShowRemotePreviewAsync(
        RemoteFileEntry file,
        Func<string, CancellationToken, Task<RemoteFilePreview>> previewLoader,
        CancellationToken cancellationToken)
    {
        RemoteFilePreview preview;
        try
        {
            preview = await previewLoader(file.RelativePath, cancellationToken);
        }
        catch (System.OperationCanceledException)
        {
            return;
        }
        catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or InvalidDataException or AuthenticationException or CryptographicException or InvalidOperationException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException)
        {
            await ShowMessageAsync("Предпросмотр", ex.Message);
            return;
        }

        RunOnUiThreadIfAlive(() =>
        {
            if (!_activityStarted || IsDestroyed)
            {
                return;
            }

            var panel = new LinearLayout(this)
            {
                Orientation = global::Android.Widget.Orientation.Vertical
            };
            panel.SetPadding(Dp(18), Dp(8), Dp(18), Dp(8));

            var meta = new TextView(this)
            {
                Text = $"{AndroidDocumentAccess.FormatBytes(file.FileSize)} · {FormatRemoteModified(file.ModifiedUnixTimeSeconds)}",
                TextSize = 11.5f
            };
            meta.SetTextColor(ParseColor("#64748B"));
            panel.AddView(meta);

            Bitmap? previewBitmap = null;
            switch (preview.Kind)
            {
                case RemotePreviewKind.ImageJpeg:
                {
                    previewBitmap = BitmapFactory.DecodeByteArray(preview.Data, 0, preview.Data.Length);
                    if (previewBitmap is null)
                    {
                        panel.AddView(CreatePreviewMessage("Не удалось открыть миниатюру изображения."), WithTopMargin(10));
                        break;
                    }

                    var image = new ImageView(this);
                    image.SetAdjustViewBounds(true);
                    image.SetImageBitmap(previewBitmap);
                    image.SetPadding(0, Dp(10), 0, 0);
                    panel.AddView(image, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent));
                    break;
                }
                case RemotePreviewKind.TextUtf8:
                {
                    var text = new TextView(this)
                    {
                        Text = Encoding.UTF8.GetString(preview.Data),
                        TextSize = 11.5f,
                        Typeface = global::Android.Graphics.Typeface.Monospace
                    };
                    text.SetTextColor(ParseColor("#172033"));
                    text.SetTextIsSelectable(true);
                    text.SetPadding(0, Dp(10), 0, Dp(6));
                    var scroll = new ScrollView(this);
                    scroll.AddView(text);
                    panel.AddView(scroll, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, Dp(360)));
                    break;
                }
                default:
                    panel.AddView(CreatePreviewMessage(
                        string.IsNullOrWhiteSpace(preview.Message)
                            ? "Предпросмотр для этого типа файла пока недоступен."
                            : preview.Message), WithTopMargin(10));
                    break;
            }

            var builder = new AlertDialog.Builder(this);
            builder.SetTitle(file.FileName);
            builder.SetView(panel);
            builder.SetPositiveButton("Закрыть", (_, _) => { });
            if (previewBitmap is not null)
            {
                builder.SetOnDismissListener(new DialogDismissListener(previewBitmap.Dispose));
            }

            builder.Show();
        });
    }

    private TextView CreatePreviewMessage(string message)
    {
        var text = new TextView(this)
        {
            Text = message,
            TextSize = 13f,
            Gravity = GravityFlags.Center
        };
        text.SetTextColor(ParseColor("#475569"));
        text.SetPadding(Dp(8), Dp(24), Dp(8), Dp(24));
        return text;
    }

    private void CancelBrowse()
    {
        try
        {
            _browseCts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private async Task PairSelectedAsync()
    {
        var selected = GetSelectedDevice();
        if (selected is null)
        {
            return;
        }

        if (!_activityStarted || !LocalAvailabilityService.IsRunning || !LocalAvailabilityService.IsNetworkAvailable)
        {
            AppendLog("Pairing is unavailable because background local services are not active.");
            UpdateSelectedDeviceUi();
            return;
        }

        _pairButton.Enabled = false;
        using var pairingCts = new CancellationTokenSource(ProtocolConstants.PairingTimeout);
        var pairingToken = pairingCts.Token;
        try
        {
            AppendLog($"Pairing with {selected.Device.DeviceName} at {selected.Device.Address}…");
            var localPeer = _identity.ToPairingPeerInfo();
            try
            {
                var remote = await PairingClient.PairAsync(
                    selected.Device.Address,
                    selected.Device.PairingPort,
                    localPeer,
                    confirmation => ConfirmSelectedPairingAsync(selected.Device, confirmation),
                    pairingToken);
                try
                {
                    if (remote.DeviceId != selected.Device.DeviceId)
                    {
                        throw new AuthenticationException("Discovered device ID changed during pairing.");
                    }

                    SaveTrustedPeer(remote, selected.Device.Kind);
                    TryPersistVerifiedEndpoint(selected.Device, "successful pairing");
                    AppendLog($"Trusted pairing completed with {remote.DeviceName}.");
                    await ShowMessageAsync("Сопряжение завершено", $"{remote.DeviceName} теперь доверенное устройство.").ConfigureAwait(false);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(remote.PublicKey);
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(localPeer.PublicKey);
            }
        }
        catch (System.OperationCanceledException) when (pairingToken.IsCancellationRequested)
        {
            AppendLog("Pairing canceled because the app left the foreground.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SocketException or AuthenticationException or CryptographicException or InvalidDataException or InvalidOperationException)
        {
            AppendLog($"Pairing failed safely: {ex.Message}");
            await ShowMessageAsync("Сопряжение", ex.Message).ConfigureAwait(false);
        }
        finally
        {
            RunOnUiThreadIfAlive(RefreshDeviceList);
        }
    }

    private Task<bool> ConfirmSelectedPairingAsync(DiscoveredDevice selected, PairingConfirmation confirmation)
    {
        if (confirmation.Peer.DeviceId != selected.DeviceId ||
            !string.Equals(confirmation.PublicKeyFingerprint, selected.PublicKeyFingerprint, StringComparison.OrdinalIgnoreCase))
        {
            AppendLog("Pairing stopped: discovery identity changed before confirmation.");
            return Task.FromResult(false);
        }

        return ConfirmPairingAsync(confirmation);
    }

    private Task<bool> ConfirmPairingAsync(PairingConfirmation confirmation)
    {
        if (!_activityStarted || IsDestroyed)
        {
            return Task.FromResult(false);
        }

        var completion = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (Interlocked.CompareExchange(ref _pendingPairingConfirmation, completion, null) is not null)
        {
            return Task.FromResult(false);
        }

        RunOnUiThread(() =>
        {
            if (!_activityStarted || IsDestroyed)
            {
                CompletePairingConfirmation(completion, false);
                return;
            }

            var builder = new AlertDialog.Builder(this);
            builder.SetTitle("Безопасное сопряжение");
            builder.SetMessage(
                $"Устройство: {confirmation.Peer.DeviceName}\n\n" +
                $"Код проверки:\n\n        {confirmation.VerificationCode}\n\n" +
                "Сравните код на обоих устройствах и подтверждайте только при полном совпадении.");
            builder.SetPositiveButton("Коды совпадают", (_, _) => CompletePairingConfirmation(completion, true));
            builder.SetNegativeButton("Отмена", (_, _) => CompletePairingConfirmation(completion, false));
            builder.SetOnCancelListener(new DialogCancelListener(() => CompletePairingConfirmation(completion, false)));

            var dialog = builder.Create();
            if (dialog is null)
            {
                CompletePairingConfirmation(completion, false);
                return;
            }

            _pairingDialog = dialog;
            dialog.Show();
        });

        return completion.Task;
    }

    private void CompletePairingConfirmation(TaskCompletionSource<bool> completion, bool accepted)
    {
        completion.TrySetResult(accepted);
        Interlocked.CompareExchange(ref _pendingPairingConfirmation, null, completion);
        _pairingDialog = null;
    }

    private void CancelPendingPairingConfirmation()
    {
        var completion = Interlocked.Exchange(ref _pendingPairingConfirmation, null);
        completion?.TrySetResult(false);
    }

    private void DismissPairingDialog()
    {
        var dialog = _pairingDialog;
        _pairingDialog = null;
        if (dialog is not null && dialog.IsShowing)
        {
            dialog.Dismiss();
        }
    }

    private void SaveTrustedPeer(PairingPeerInfo peer, DeviceKind deviceKind = DeviceKind.Unknown)
    {
        var sameNameCandidates = FindSameNameTrustedCandidates(peer);
        _trustedDevices.Upsert(peer, deviceKind);
        LocalAvailabilityService.UpsertTrustedPeer(peer);
        AppendLog($"Trusted device saved: {peer.DeviceName} ({FormatFingerprint(PairingProtocol.GetPublicKeyFingerprint(peer.PublicKey))}).");
        RunOnUiThreadIfAlive(() =>
        {
            RefreshDeviceList();
            OfferReplaceSameNameTrustedDevice(peer.DeviceName, sameNameCandidates);
        });
    }

    private void OnBackgroundTrustedPeerSaved(PairingPeerInfo peer)
    {
        try
        {
            var sameNameCandidates = FindSameNameTrustedCandidates(peer);
            _trustedDevices.Upsert(peer);
            RunOnUiThreadIfAlive(() =>
            {
                RefreshDeviceList();
                OfferReplaceSameNameTrustedDevice(peer.DeviceName, sameNameCandidates);
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AppendLog($"Could not mirror background trust state into UI store: {ex.Message}");
        }
    }

    private void OnBackgroundTrustedSigningIdentitySaved(TrustedSigningIdentity identity)
    {
        try
        {
            _trustedDevices.UpdateSigningIdentity(identity);
            RunOnUiThreadIfAlive(() =>
            {
                PromoteAuthenticatedSigningIdentityToUi(identity);
                RefreshDeviceList();
            });
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or CryptographicException or InvalidDataException or ArgumentException)
        {
            AppendLog($"Could not mirror background signing identity into UI store: {ex.Message}");
        }
    }

    private void PromoteAuthenticatedSigningIdentityToUi(TrustedSigningIdentity identity)
    {
        var trusted = _trustedDevices.Get(identity.DeviceId);
        var trustedFingerprint = trusted is null ? null : GetTrustedFingerprint(trusted);
        if (trusted is null || trustedFingerprint is null)
        {
            return;
        }

        lock (_deviceGate)
        {
            if (!_discovered.TryGetValue(identity.DeviceId, out var current) ||
                !string.Equals(current.PublicKeyFingerprint, trustedFingerprint, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            current = PromoteKnownAuthenticatedSignedDiscoveryToUi(current);

            // The background service raises this event only after an M2.3 binding authenticated
            // through the existing ECDH trust. Preserve a real agreement-key mismatch, but do
            // not make the UI request re-pairing merely because the latest UDP packet was GLD2.
            _discovered[identity.DeviceId] = current with
            {
                LastSeenUtc = DateTimeOffset.UtcNow,
                IdentityProof = DiscoveryIdentityProof.AuthenticatedTrustedIdentityV2,
                SigningKeyId = identity.SigningKeyId,
                IdentityVersion = identity.IdentityVersion,
                SigningKeyGeneration = identity.KeyGeneration
            };
            _staleDevices.Remove(identity.DeviceId);
        }
    }

    private TrustedDevice[] FindSameNameTrustedCandidates(PairingPeerInfo peer)
    {
        return _trustedDevices.GetAll()
            .Where(device => device.DeviceId != peer.DeviceId &&
                             string.Equals(device.DeviceName, peer.DeviceName, StringComparison.OrdinalIgnoreCase))
            .ToArray();
    }

    private void OfferReplaceSameNameTrustedDevice(string deviceName, TrustedDevice[] candidates)
    {
        if (candidates.Length == 0 || !_activityStarted || IsDestroyed)
        {
            return;
        }

        var builder = new AlertDialog.Builder(this);
        builder.SetTitle("Возможная переустановка");
        builder.SetMessage(
            $"В доверенных устройствах уже есть {deviceName}, но у нового сопряжения другая криптографическая идентичность.\n\n" +
            "Так бывает после переустановки Genia Link. Если это то же физическое устройство, можно заменить старую запись новой.");
        builder.SetNegativeButton("Оставить оба", (_, _) => { });
        builder.SetPositiveButton("Заменить старое", (_, _) =>
        {
            try
            {
                foreach (var oldDevice in candidates)
                {
                    if (!_trustedDevices.Remove(oldDevice.DeviceId))
                    {
                        continue;
                    }

                    LocalAvailabilityService.RemoveTrustedPeer(oldDevice.DeviceId);
                    lock (_deviceGate)
                    {
                        if (_staleDevices.Remove(oldDevice.DeviceId))
                        {
                            _discovered.Remove(oldDevice.DeviceId);
                        }
                    }
                    AppendLog($"Replaced old trusted identity for {oldDevice.DeviceName} after explicit user confirmation.");
                }

                RefreshDeviceList();
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                AppendLog($"Could not replace old trusted identity safely: {ex.Message}");
                _ = ShowMessageAsync("Genia Link", "Не удалось обновить список доверенных устройств.");
            }
        });
        builder.Show();
    }

    private void ForgetSelectedDevice()
    {
        var selected = GetSelectedDevice();
        if (selected is null || !selected.IsTrusted || IsTransferActive)
        {
            return;
        }

        var builder = new AlertDialog.Builder(this);
        builder.SetTitle("Удалить доверие?");
        builder.SetMessage($"Для {selected.Device.DeviceName} снова потребуется безопасное сопряжение перед передачей файлов.");
        builder.SetNegativeButton("Отмена", (_, _) => { });
        builder.SetPositiveButton("Забыть", (_, _) =>
        {
            try
            {
                if (_trustedDevices.Remove(selected.Device.DeviceId))
                {
                    LocalAvailabilityService.RemoveTrustedPeer(selected.Device.DeviceId);
                    lock (_deviceGate)
                    {
                        if (_staleDevices.Remove(selected.Device.DeviceId))
                        {
                            _discovered.Remove(selected.Device.DeviceId);
                        }
                    }
                    AppendLog($"Forgot trusted device: {selected.Device.DeviceName}.");
                    RefreshDeviceList();
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                AppendLog($"Could not update trusted-device database: {ex.Message}");
                _ = ShowMessageAsync("Genia Link", "Не удалось обновить список доверенных устройств.");
            }
        });
        builder.Show();
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
        lock (_deviceGate)
        {
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

                if (_discovered.ContainsKey(trusted.DeviceId))
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
        }

        if (restored > 0)
        {
            AppendLog($"Restored {restored} trusted sleeping endpoint(s) from authenticated history.");
        }

        RefreshDeviceList();
    }

    private void TryPersistVerifiedEndpoint(DiscoveredDevice device, string source)
    {
        try
        {
            _trustedDevices.UpdateVerifiedEndpoint(
                device.DeviceId,
                device.Address,
                device.TransferPort,
                device.PairingPort,
                device.Kind);
            LocalAvailabilityService.UpdateTrustedEndpoint(
                device.DeviceId,
                device.Address,
                device.TransferPort,
                device.PairingPort,
                device.Kind);
            RunOnUiThreadIfAlive(() => ApplyAuthenticatedEndpointToUi(
                device.DeviceId,
                device.Address,
                device.TransferPort,
                device.PairingPort,
                device.Kind));
            AppendLog($"Remembered authenticated LAN endpoint for {device.DeviceName} after {source}.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AppendLog($"Authenticated endpoint could not be persisted: {ex.Message}");
        }
    }

    private void OnBackgroundTrustedEndpointSaved(
        Guid deviceId,
        IPAddress address,
        int transferPort,
        int pairingPort,
        DeviceKind deviceKind)
    {
        try
        {
            _trustedDevices.UpdateVerifiedEndpoint(deviceId, address, transferPort, pairingPort, deviceKind);
            RunOnUiThreadIfAlive(() => ApplyAuthenticatedEndpointToUi(deviceId, address, transferPort, pairingPort, deviceKind));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            AppendLog($"Could not mirror authenticated endpoint into UI store: {ex.Message}");
        }
    }

    private void ApplyAuthenticatedEndpointToUi(
        Guid deviceId,
        IPAddress address,
        int transferPort,
        int pairingPort,
        DeviceKind deviceKind)
    {
        var trusted = _trustedDevices.Get(deviceId);
        var fingerprint = trusted is null ? null : GetTrustedFingerprint(trusted);
        if (trusted is null || fingerprint is null)
        {
            return;
        }

        var kind = deviceKind != DeviceKind.Unknown ? deviceKind : trusted.Kind;
        lock (_deviceGate)
        {
            _discovered[deviceId] = new DiscoveredDevice(
                deviceId,
                trusted.DeviceName,
                address,
                transferPort,
                pairingPort,
                fingerprint,
                kind,
                DateTimeOffset.UtcNow,
                string.IsNullOrWhiteSpace(trusted.SigningKeyId)
                    ? DiscoveryIdentityProof.LegacyUnsigned
                    : DiscoveryIdentityProof.AuthenticatedTrustedIdentityV2,
                trusted.SigningKeyId,
                trusted.SigningIdentityVersion > 0 ? trusted.SigningIdentityVersion : 1,
                trusted.SigningKeyGeneration);
            _staleDevices.Remove(deviceId);
        }

        RefreshDeviceList();
    }

    private void HandleIncomingShareIntent(Intent? intent)
    {
        if (!_identityReady || intent is null || IsTransferActive)
        {
            return;
        }

        var action = intent.Action;
        if (!string.Equals(action, Intent.ActionSend, StringComparison.Ordinal) &&
            !string.Equals(action, Intent.ActionSendMultiple, StringComparison.Ordinal))
        {
            return;
        }

        var uris = new List<global::Android.Net.Uri>();
        if (intent.ClipData is { } clipData)
        {
            for (var index = 0; index < clipData.ItemCount && uris.Count < MaxSelectedDocuments; index++)
            {
                var uri = clipData.GetItemAt(index)?.Uri;
                if (uri is not null)
                {
                    uris.Add(uri);
                }
            }
        }

#pragma warning disable CS0618, CA1422
        if (uris.Count == 0 && intent.GetParcelableExtra(Intent.ExtraStream) is global::Android.Net.Uri legacyExtraUri)
        {
            uris.Add(legacyExtraUri);
        }
#pragma warning restore CS0618, CA1422

        if (uris.Count == 0 && intent.Data is { } dataUri)
        {
            uris.Add(dataUri);
        }

        if (uris.Count == 0)
        {
            _ = ShowMessageAsync("Genia Link", "Приложение-источник не передало доступный файл.");
            return;
        }

        LoadSharedDocuments(uris);
        if (_selectedDocuments.Count == 0)
        {
            _ = ShowMessageAsync("Genia Link", "Не удалось открыть файлы из системного меню «Поделиться».");
            return;
        }

        AppendLog($"Получено из Android Share: файлов {_selectedDocuments.Count}.");
        SendSharedDocumentsToTrustedDevice();
    }

    private void LoadSharedDocuments(IEnumerable<global::Android.Net.Uri> uris)
    {
        var distinctUris = uris
            .Where(uri => uri is not null)
            .GroupBy(uri => uri.ToString(), StringComparer.Ordinal)
            .Select(group => group.First())
            .Take(MaxSelectedDocuments)
            .ToArray();

        var nextDocuments = new List<SelectedDocument>(distinctUris.Length);
        foreach (var uri in distinctUris)
        {
            try
            {
                nextDocuments.Add(AndroidDocumentAccess.Describe(_resolver, uri));
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException or InvalidOperationException)
            {
                AppendLog($"Skipped shared document safely: {ex.Message}");
            }
        }

        _selectedDocuments.Clear();
        _selectedDocuments.AddRange(nextDocuments);
        ResetProgress("Готово к отправке");
        RefreshDeviceList();
    }

    private void SendSharedDocumentsToTrustedDevice()
    {
        RunOnUiThreadIfAlive(() =>
        {
            var lastTargetId = GetLastTargetDeviceId();
            var targets = _visibleDevices
                .Where(item => item.IsTrusted && item.IdentityMatches)
                .OrderByDescending(item => item.IsRecentlySeen)
                .ThenByDescending(item => item.Device.DeviceId == lastTargetId)
                .ThenBy(item => item.Device.DeviceName, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();

            if (targets.Length == 0)
            {
                _ = ShowMessageAsync(
                    "Genia Link",
                    "Файлы выбраны. Пока нет сохранённого доверенного устройства для быстрой отправки.");
                return;
            }

            if (targets.Length == 1)
            {
                _selectedDeviceId = targets[0].Device.DeviceId;
                SaveLastTargetDeviceId(targets[0].Device.DeviceId);
                RefreshDeviceList();
                _ = SendSelectedFilesAsync();
                return;
            }

            var content = new LinearLayout(this)
            {
                Orientation = global::Android.Widget.Orientation.Vertical
            };
            content.SetPadding(Dp(18), Dp(2), Dp(18), Dp(4));

            var summary = new TextView(this)
            {
                Text = BuildShareSelectionSummary(),
                TextSize = 12.5f
            };
            summary.SetTextColor(ParseColor("#64748B"));
            content.AddView(summary, WithBottomMargin(10));

            var list = new LinearLayout(this)
            {
                Orientation = global::Android.Widget.Orientation.Vertical
            };
            var scroll = new ScrollView(this);
            scroll.AddView(list);
            content.AddView(scroll);

            AlertDialog? dialog = null;
            foreach (var target in targets)
            {
                var row = CreateShareTargetRow(
                    target,
                    target.Device.DeviceId == lastTargetId,
                    () =>
                    {
                        dialog?.Dismiss();
                        _selectedDeviceId = target.Device.DeviceId;
                        SaveLastTargetDeviceId(target.Device.DeviceId);
                        RefreshDeviceList();
                        _ = SendSelectedFilesAsync();
                    });
                list.AddView(row, WithBottomMargin(7));
            }

            var builder = new AlertDialog.Builder(this);
            builder.SetTitle("Отправить через Genia Link");
            builder.SetView(content);
            builder.SetNegativeButton("Отмена", (_, _) => { });
            dialog = builder.Create();
            dialog?.Show();
        });
    }

    private LinearLayout CreateShareTargetRow(DeviceListItem item, bool isLastTarget, Action onClick)
    {
        var row = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Horizontal,
            Clickable = true,
            Focusable = true
        };
        row.SetGravity(GravityFlags.CenterVertical);
        row.SetPadding(Dp(12), Dp(9), Dp(12), Dp(9));
        row.Background = CreateRoundedDrawable(item.IsRecentlySeen ? "#F8FBFF" : "#FFFFFF", 11, "#E2E8F0");

        var icon = new TextView(this)
        {
            Text = item.Device.Kind is DeviceKind.WindowsComputer ? "PC" : "A",
            TextSize = item.Device.Kind is DeviceKind.WindowsComputer ? 9.5f : 11f,
            Gravity = GravityFlags.Center,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        icon.SetTextColor(ParseColor(item.IsRecentlySeen ? "#2563EB" : "#64748B"));
        icon.Background = CreateRoundedDrawable(item.IsRecentlySeen ? "#EAF2FF" : "#F1F5F9", 7);
        row.AddView(icon, new LinearLayout.LayoutParams(Dp(32), Dp(32)));

        var textColumn = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        var textParams = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WrapContent, 1f)
        {
            LeftMargin = Dp(8)
        };
        row.AddView(textColumn, textParams);

        var name = new TextView(this)
        {
            Text = item.Device.DeviceName,
            TextSize = 14.5f,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        name.SetTextColor(ParseColor("#0F172A"));
        textColumn.AddView(name);

        var kindText = item.Device.Kind switch
        {
            DeviceKind.WindowsComputer => "Windows",
            DeviceKind.AndroidTablet => "Android · планшет",
            DeviceKind.AndroidPhone => "Android",
            _ => "Устройство"
        };
        var status = item.IsRecentlySeen ? "Доступен" : "Спит";
        var detail = new TextView(this)
        {
            Text = isLastTarget
                ? $"{kindText} · {status} · последнее устройство"
                : $"{kindText} · {status}",
            TextSize = 11.5f
        };
        detail.SetTextColor(item.IsRecentlySeen ? ParseColor("#047857") : ParseColor("#64748B"));
        textColumn.AddView(detail, WithTopMargin(1));

        row.ContentDescription = $"{item.Device.DeviceName}, {kindText}, {status}";
        row.Click += (_, _) => onClick();
        return row;
    }

    private string BuildShareSelectionSummary()
    {
        var countLabel = FormatFileCount(_selectedDocuments.Count);
        if (_selectedDocuments.Count == 0 || !_selectedDocuments.All(document => document.ReportedSize.HasValue))
        {
            return countLabel;
        }

        var totalBytes = _selectedDocuments.Sum(document => document.ReportedSize ?? 0);
        return $"{countLabel} · {AndroidDocumentAccess.FormatBytes(totalBytes)}";
    }

    private static string FormatFileCount(int count)
    {
        var mod100 = count % 100;
        var mod10 = count % 10;
        var word = mod100 is >= 11 and <= 14
            ? "файлов"
            : mod10 switch
            {
                1 => "файл",
                2 or 3 or 4 => "файла",
                _ => "файлов"
            };
        return $"{count} {word}";
    }

    private Guid? GetLastTargetDeviceId()
    {
        var preferences = GetSharedPreferences(UiPreferencesName, FileCreationMode.Private);
        var value = preferences?.GetString(LastTargetPreferenceKey, null);
        return Guid.TryParse(value, out var deviceId) ? deviceId : null;
    }

    private void SaveLastTargetDeviceId(Guid deviceId)
    {
        var preferences = GetSharedPreferences(UiPreferencesName, FileCreationMode.Private);
        var editor = preferences?.Edit();
        editor?.PutString(LastTargetPreferenceKey, deviceId.ToString("D"));
        editor?.Apply();
    }

    private void ChooseFiles()
    {
        if (IsTransferActive)
        {
            return;
        }

        try
        {
            var intent = new Intent(Intent.ActionOpenDocument);
            intent.AddCategory(Intent.CategoryOpenable);
            intent.SetType("*/*");
            intent.PutExtra(Intent.ExtraAllowMultiple, true);
            intent.PutExtra(Intent.ExtraLocalOnly, true);
            intent.AddFlags(ActivityFlags.GrantReadUriPermission);
            StartActivityForResult(intent, PickFilesRequestCode);
        }
        catch (ActivityNotFoundException)
        {
            _ = ShowMessageAsync("Genia Link", "Системный выбор файлов недоступен на этом устройстве.");
        }
    }

    protected override void OnActivityResult(int requestCode, Result resultCode, Intent? data)
    {
        base.OnActivityResult(requestCode, resultCode, data);
        if (requestCode != PickFilesRequestCode || resultCode != Result.Ok || data is null)
        {
            return;
        }

        var uris = new List<global::Android.Net.Uri>();
        if (data.ClipData is { } clipData)
        {
            for (var index = 0; index < clipData.ItemCount && uris.Count < MaxSelectedDocuments; index++)
            {
                var uri = clipData.GetItemAt(index)?.Uri;
                if (uri is not null)
                {
                    uris.Add(uri);
                }
            }
        }
        else if (data.Data is { } singleUri)
        {
            uris.Add(singleUri);
        }

        var distinctUris = uris
            .GroupBy(uri => uri.ToString(), StringComparer.Ordinal)
            .Select(group => group.First())
            .Take(MaxSelectedDocuments)
            .ToArray();

        var nextDocuments = new List<SelectedDocument>(distinctUris.Length);
        foreach (var uri in distinctUris)
        {
            try
            {
                nextDocuments.Add(AndroidDocumentAccess.Describe(_resolver, uri));
            }
            catch (Exception ex) when (ex is IOException or InvalidDataException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException or InvalidOperationException)
            {
                AppendLog($"Skipped selected document safely: {ex.Message}");
            }
        }

        _selectedDocuments.Clear();
        _selectedDocuments.AddRange(nextDocuments);
        ResetProgress("Готово к отправке");
        UpdateSelectedDeviceUi();

        if (_selectedDocuments.Count == 0)
        {
            _ = ShowMessageAsync("Genia Link", "Не удалось открыть выбранные файлы.");
        }
    }

    private void UpdateSelectedFilesUi()
    {
        if (_selectedDocuments.Count == 0)
        {
            _selectedFilesText.Text = "Файлы не выбраны";
            return;
        }

        if (_selectedDocuments.Count == 1)
        {
            var document = _selectedDocuments[0];
            _selectedFilesText.Text = document.ReportedSize is long size
                ? $"{document.DisplayName} • {AndroidDocumentAccess.FormatBytes(size)}"
                : document.DisplayName;
            return;
        }

        var knownSize = _selectedDocuments.Where(document => document.ReportedSize.HasValue).Sum(document => document.ReportedSize ?? 0);
        var allKnown = _selectedDocuments.All(document => document.ReportedSize.HasValue);
        _selectedFilesText.Text = allKnown
            ? $"Выбрано файлов: {_selectedDocuments.Count} • {AndroidDocumentAccess.FormatBytes(knownSize)}"
            : $"Выбрано файлов: {_selectedDocuments.Count}";
    }

    private async Task SendSelectedFilesAsync()
    {
        var selected = GetSelectedDevice();
        if (selected is null ||
            !selected.IsTrusted ||
            !selected.IdentityMatches ||
            _selectedDocuments.Count == 0 ||
            _isSending)
        {
            return;
        }

        SaveLastTargetDeviceId(selected.Device.DeviceId);

        var trusted = _trustedDevices.Get(selected.Device.DeviceId);
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

        var authorization = _trustedDevices.GetSessionAuthorization(selected.Device.DeviceId);
        if (authorization is null)
        {
            AppendLog($"GNP/1 M2.5.2.1 send blocked because {selected.Device.DeviceName} is no longer Active and trusted.");
            RefreshDeviceList();
            return;
        }

        var sharedKey = Array.Empty<byte>();
        using var sendCts = new CancellationTokenSource();
        using var trustLinkedCts = CancellationTokenSource.CreateLinkedTokenSource(sendCts.Token, authorization.LifetimeToken);
        _sendCts = sendCts;
        _isSending = true;
        var foregroundLabel = _selectedDocuments.Count == 1
            ? _selectedDocuments[0].DisplayName
            : $"Файлов: {_selectedDocuments.Count}";
        var foregroundBytes = _selectedDocuments.All(document => document.ReportedSize.HasValue)
            ? _selectedDocuments.Sum(document => document.ReportedSize ?? 0)
            : 0;
        TryBeginForegroundTransfer(foregroundLabel, foregroundBytes, incoming: false);
        SetKeepScreenOn(true);
        ResetProgress($"Подготовка: {FormatFileCount(_selectedDocuments.Count)}…");
        UpdateSelectedDeviceUi();
        var transferSucceeded = false;
        var foregroundResult = "Передача прервана.";

        try
        {
            sharedKey = _identity.DeriveSharedKey(peerPublicKey);
            if (!selected.IsRecentlySeen)
            {
                AppendLog($"{selected.Device.DeviceName} has no fresh discovery; trying the last known LAN endpoint with the trusted handshake.");
            }
            AppendLog($"Connecting securely to {selected.Device.DeviceName} ({selected.Device.Address})…");
            var documents = _selectedDocuments.ToArray();
            await AndroidFileTransferClient.SendFilesAsync(
                _resolver,
                selected.Device.Address,
                selected.Device.TransferPort,
                _identity.DeviceId,
                _identity.DeviceName,
                selected.Device.DeviceId,
                sharedKey,
                documents,
                _progress,
                AppendLog,
                trustLinkedCts.Token);

            TryPersistVerifiedEndpoint(selected.Device, "authenticated transfer");
            AppendLog("All selected files were sent and verified successfully.");
            transferSucceeded = true;
            foregroundResult = "Файлы переданы и проверены.";
            RunOnUiThreadIfAlive(() =>
            {
                _transferProgress.Progress = 1000;
                _progressText.Text = $"Передано: {FormatFileCount(_selectedDocuments.Count)} • SHA‑256 проверен";
                _speedText.Text = string.Empty;
            });
            await ShowMessageAsync("Готово", "Файлы переданы и проверены на втором устройстве.").ConfigureAwait(false);
        }
        catch (System.OperationCanceledException) when (authorization.LifetimeToken.IsCancellationRequested)
        {
            AppendLog($"GNP/1 M2.5.2.1 outgoing transfer to {selected.Device.DeviceName} terminated because trust was revoked or forgotten.");
            foregroundResult = "Передача остановлена: доверие отозвано.";
            RunOnUiThreadIfAlive(() =>
            {
                _transferProgress.Progress = 0;
                _progressText.Text = "Доверие отозвано";
                _speedText.Text = string.Empty;
            });
        }
        catch (System.OperationCanceledException) when (sendCts.IsCancellationRequested)
        {
            AppendLog("Send cancelled safely.");
            foregroundResult = "Передача отменена.";
            RunOnUiThreadIfAlive(() =>
            {
                _transferProgress.Progress = 0;
                _progressText.Text = "Передача отменена";
                _speedText.Text = string.Empty;
            });
        }
        catch (System.OperationCanceledException)
        {
            AppendLog("Connection timed out safely.");
            foregroundResult = "Соединение не отвечало и было закрыто.";
            RunOnUiThreadIfAlive(() =>
            {
                _transferProgress.Progress = 0;
                _progressText.Text = "Тайм-аут соединения";
                _speedText.Text = string.Empty;
            });
        }
        catch (Exception ex) when (ex is IOException or SocketException or UnauthorizedAccessException or InvalidDataException or AuthenticationException or CryptographicException or InvalidOperationException or Java.Lang.SecurityException or Java.IO.IOException or Java.Lang.IllegalArgumentException)
        {
            AppendLog($"Send failed safely: {ex.Message}");
            foregroundResult = "Ошибка передачи: " + SanitizeForLog(ex.Message);
            RunOnUiThreadIfAlive(() =>
            {
                _transferProgress.Progress = 0;
                _progressText.Text = "Ошибка передачи";
                _speedText.Text = string.Empty;
            });
            await ShowMessageAsync("Передача не выполнена", ex.Message).ConfigureAwait(false);
        }
        finally
        {
            if (sharedKey.Length > 0)
            {
                CryptographicOperations.ZeroMemory(sharedKey);
            }

            CryptographicOperations.ZeroMemory(peerPublicKey);
            if (ReferenceEquals(_sendCts, sendCts))
            {
                _sendCts = null;
            }

            _isSending = false;
            if (!_isReceiving)
            {
                TransferForegroundService.End(transferSucceeded, foregroundResult);
                SetKeepScreenOn(false);
            }

            ReleaseDestroyedActivityHooksIfIdle();
            RunOnUiThreadIfAlive(UpdateSelectedDeviceUi);
        }
    }

    private void OnIncomingTransferStarted(string fileName, long totalBytes)
    {
        _isReceiving = true;
        SetKeepScreenOn(true);
        AppendLog($"Foreground receive protection enabled for {fileName}.");
        RunOnUiThreadIfAlive(() =>
        {
            UpdateMainStatus();
            UpdateSelectedDeviceUi();
        });
    }

    private void OnIncomingTransferEnded(string fileName, bool success, string message)
    {
        _isReceiving = false;
        if (!_isSending)
        {
            SetKeepScreenOn(false);
        }

        AppendLog(success
            ? $"Foreground receive completed: {fileName}."
            : $"Foreground receive ended: {SanitizeForLog(message)}");

        ReleaseDestroyedActivityHooksIfIdle();
        RunOnUiThreadIfAlive(() =>
        {
            if (success)
            {
                _transferProgress.Progress = 1000;
                _progressText.Text = $"Получено: {fileName} • SHA‑256 проверен";
            }
            else
            {
                _transferProgress.Progress = 0;
                _progressText.Text = "Передача прервана";
            }

            _speedText.Text = string.Empty;
            UpdateMainStatus();
            UpdateSelectedDeviceUi();
        });
    }

    private void CancelActiveTransfer()
    {
        AppendLog("Transfer cancellation requested from Android notification.");
        CancelSend();
        if (_isReceiving)
        {
            LocalAvailabilityService.CancelIncomingTransfer();
        }
    }

    private void TryBeginForegroundTransfer(string fileName, long totalBytes, bool incoming)
    {
        try
        {
            TransferForegroundService.Begin(this, fileName, totalBytes, incoming);
        }
        catch (Exception ex) when (ex is Java.Lang.SecurityException or Java.Lang.IllegalStateException or InvalidOperationException)
        {
            AppendLog($"Foreground service could not start; transfer continues while Activity remains alive: {ex.Message}");
        }
    }

    private void SetKeepScreenOn(bool enabled)
    {
        RunOnUiThreadIfAlive(() =>
        {
            var window = Window;
            if (window is null)
            {
                return;
            }

            if (enabled)
            {
                window.AddFlags(WindowManagerFlags.KeepScreenOn);
            }
            else if (!IsTransferActive)
            {
                window.ClearFlags(WindowManagerFlags.KeepScreenOn);
            }
        });
    }

    private void ReleaseDestroyedActivityHooksIfIdle()
    {
        if (!IsTransferActive && (IsDestroyed || IsFinishing))
        {
            TransferForegroundService.CancelRequested -= CancelActiveTransfer;
        }
    }

    private void RequestNotificationPermissionIfNeeded()
    {
        if (Build.VERSION.SdkInt < BuildVersionCodes.Tiramisu)
        {
            return;
        }

        if (CheckSelfPermission(PostNotificationsPermission) == Permission.Granted)
        {
            return;
        }

        RequestPermissions(
            [PostNotificationsPermission],
            NotificationPermissionRequestCode);
    }

    private void CancelSend()
    {
        try
        {
            _sendCts?.Cancel();
        }
        catch (ObjectDisposedException)
        {
        }
    }

    private void ResetProgress(string text)
    {
        _progressFileKey = string.Empty;
        _progressStopwatch.Reset();
        _transferProgress.Progress = 0;
        _progressText.Text = text;
        _speedText.Text = string.Empty;
    }

    private void UpdateProgress(TransferProgress progress)
    {
        if (IsDestroyed)
        {
            return;
        }

        var fileKey = $"{(progress.IsReceiving ? 'R' : 'S')}:{progress.FileName}";
        if (!string.Equals(_progressFileKey, fileKey, StringComparison.Ordinal))
        {
            _progressFileKey = fileKey;
            _progressStopwatch.Restart();
        }

        _transferProgress.Progress = (int)Math.Round(progress.Percentage * 10d);
        var receiveCompleted = progress.IsReceiving && progress.BytesTransferred == progress.TotalBytes;
        var verb = progress.IsReceiving ? "Получение" : "Отправка";
        _progressText.Text = receiveCompleted
            ? $"Получено: {progress.FileName} • SHA‑256 проверен"
            : $"{verb}: {progress.FileName} • {progress.Percentage:F1}%";

        var elapsed = _progressStopwatch.Elapsed.TotalSeconds;
        if (elapsed > 0.25 && progress.BytesTransferred > 0)
        {
            var bytesPerSecond = progress.BytesTransferred / elapsed;
            var megabytesPerSecond = bytesPerSecond / (1024d * 1024d);
            var remainingBytes = Math.Max(0, progress.TotalBytes - progress.BytesTransferred);
            var etaSeconds = bytesPerSecond > 1 ? remainingBytes / bytesPerSecond : 0;
            _speedText.Text = etaSeconds > 0
                ? $"{megabytesPerSecond:F1} МБ/с • осталось ~{FormatDuration(etaSeconds)}"
                : $"{megabytesPerSecond:F1} МБ/с";
        }
    }

    private static string FormatDuration(double seconds)
    {
        if (seconds < 60)
        {
            return $"{Math.Ceiling(seconds):F0} с";
        }

        return $"{Math.Ceiling(seconds / 60):F0} мин";
    }

    private void OpenDownloads()
    {
        try
        {
            StartActivity(new Intent(DownloadManager.ActionViewDownloads));
            return;
        }
        catch (ActivityNotFoundException)
        {
        }

        try
        {
            var pickerIntent = new Intent(Intent.ActionOpenDocument);
            pickerIntent.AddCategory(Intent.CategoryOpenable);
            pickerIntent.SetType("*/*");
            pickerIntent.PutExtra(Intent.ExtraLocalOnly, true);
            StartActivity(pickerIntent);
        }
        catch (ActivityNotFoundException)
        {
            _ = ShowMessageAsync("Genia Link", "Откройте системное приложение «Файлы» → Загрузки → Genia Link.");
        }
    }

    private void ShowDiagnostics()
    {
        string snapshot;
        lock (_logGate)
        {
            snapshot = _logBuffer.Length == 0 ? "Журнал пока пуст." : _logBuffer.ToString();
        }

        var content = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        content.SetPadding(Dp(16), Dp(2), Dp(16), Dp(2));

        var serviceStatus = new TextView(this)
        {
            Text = LocalAvailabilityService.AreLocalServicesActive
                ? "● Локальные службы активны"
                : LocalAvailabilityService.IsRunning
                    ? "● Локальные службы восстанавливаются"
                    : "● Локальная служба не запущена",
            TextSize = 12f,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        serviceStatus.SetTextColor(LocalAvailabilityService.AreLocalServicesActive
            ? ParseColor("#047857")
            : ParseColor("#B45309"));
        content.AddView(serviceStatus, WithBottomMargin(8));

        var alwaysReadyStatus = new TextView(this)
        {
            Text = AlwaysReadySettings.IsEffective(this)
                ? "Всегда готов: включено • системное исключение активно"
                : AlwaysReadySettings.IsEnabled(this)
                    ? "Всегда готов: требуется разрешение Android"
                    : AlwaysReadySettings.IsBatteryOptimizationExempt(this)
                        ? "Всегда готов: выключено • системное исключение ещё активно"
                        : "Всегда готов: выключено • обычная оптимизация батареи",
            TextSize = 11.5f
        };
        alwaysReadyStatus.SetTextColor(ParseColor("#64748B"));
        content.AddView(alwaysReadyStatus, WithBottomMargin(8));

        var text = new TextView(this)
        {
            Text = snapshot,
            TextSize = 11.5f,
            Typeface = global::Android.Graphics.Typeface.Monospace
        };
        text.SetTextColor(ParseColor("#0F172A"));
        text.SetTextIsSelectable(true);
        text.SetPadding(Dp(10), Dp(9), Dp(10), Dp(9));
        text.Background = CreateRoundedDrawable("#F8FAFC", 8, "#E2E8F0");

        var scroll = new ScrollView(this);
        scroll.AddView(text);
        content.AddView(scroll, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, Dp(360)));

        var builder = new AlertDialog.Builder(this);
        builder.SetTitle("Диагностика");
        builder.SetView(content);
        builder.SetNeutralButton("Копировать", (_, _) => CopyDiagnostics(snapshot));
        builder.SetPositiveButton("Закрыть", (_, _) => { });
        builder.Show();
    }

    private void CopyDiagnostics(string snapshot)
    {
        if (GetSystemService(ClipboardService) is not global::Android.Content.ClipboardManager clipboard)
        {
            return;
        }

        clipboard.PrimaryClip = ClipData.NewPlainText("Genia Link diagnostics", snapshot);
    }

    private void UpdateMainStatus()
    {
        if (!_identityReady)
        {
            _statusText.Text = "Подготовка защищённого устройства…";
            return;
        }

        if (IsTransferActive)
        {
            _statusText.Text = _activityStarted
                ? "● Передача активна"
                : "● Фоновая передача активна";
            return;
        }

        if (LocalAvailabilityService.IsRunning)
        {
            _statusText.Text = !LocalAvailabilityService.IsNetworkAvailable
                ? "Ожидание Wi-Fi • фоновая служба активна"
                : LocalAvailabilityService.AreLocalServicesActive
                    ? AlwaysReadySettings.IsEffective(this)
                        ? "● Всегда готов к приёму"
                        : "● Готов к приёму"
                    : "Восстановление локальных служб…";
            return;
        }

        _statusText.Text = "Запуск фоновой локальной службы…";
    }

    private static string FormatRemotePath(string relativeDirectory) =>
        string.IsNullOrEmpty(relativeDirectory)
            ? "Genia Link"
            : "Genia Link › " + relativeDirectory.Replace("/", " › ", StringComparison.Ordinal);

    private static string GetRemoteFileIcon(string fileName) => System.IO.Path.GetExtension(fileName).ToLowerInvariant() switch
    {
        ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".webp" => "🖼️",
        ".mp4" or ".mkv" or ".avi" or ".mov" or ".webm" => "🎬",
        ".mp3" or ".flac" or ".wav" or ".m4a" or ".ogg" => "🎵",
        ".pdf" or ".doc" or ".docx" or ".txt" or ".md" => "📄",
        ".zip" or ".7z" or ".rar" or ".tar" or ".gz" => "📦",
        _ => "📎"
    };

    private static string GetRemoteFileTypeText(string fileName)
    {
        var extension = System.IO.Path.GetExtension(fileName);
        return string.IsNullOrEmpty(extension) ? "Файл" : extension.TrimStart('.').ToUpperInvariant();
    }

    private static string FormatRemoteModified(long unixSeconds)
    {
        if (unixSeconds <= 0)
        {
            return "дата неизвестна";
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(unixSeconds)
                .ToLocalTime()
                .ToString("g", System.Globalization.CultureInfo.CurrentCulture);
        }
        catch (ArgumentOutOfRangeException)
        {
            return "дата неизвестна";
        }
    }

    private void DisableNetworkActions()
    {
        _pairButton.Enabled = false;
        _forgetButton.Enabled = false;
        _browseButton.Enabled = false;
        _sendButton.Enabled = false;
        _cancelSendButton.Enabled = false;
    }

    private Task ShowMessageAsync(string title, string message)
    {
        var safeMessage = SanitizeForLog(message);
        RunOnUiThreadIfAlive(() =>
        {
            if (_activityStarted)
            {
                Toast.MakeText(this, $"{title}: {safeMessage}", ToastLength.Long)?.Show();
            }
        });
        return Task.CompletedTask;
    }

    private void AppendLog(string message)
    {
        var safe = SanitizeForLog(message);
        var prefix = DateTime.Now.ToString("HH:mm:ss", System.Globalization.CultureInfo.InvariantCulture);
        lock (_logGate)
        {
            _logBuffer.Append(prefix).Append("  ").Append(safe).Append('\n');
            if (_logBuffer.Length > MaxLogCharacters)
            {
                _logBuffer.Remove(0, _logBuffer.Length - MaxLogCharacters);
            }
        }
    }

    private void RunOnUiThreadIfAlive(Action action)
    {
        ArgumentNullException.ThrowIfNull(action);
        if (IsDestroyed)
        {
            return;
        }

        RunOnUiThread(() =>
        {
            if (!IsDestroyed)
            {
                action();
            }
        });
    }

    private static string SanitizeForLog(string value)
    {
        var chars = value
            .Where(ch => ch is '\n' or '\t' || (!char.IsControl(ch) && System.Globalization.CharUnicodeInfo.GetUnicodeCategory(ch) != System.Globalization.UnicodeCategory.Format))
            .Take(400)
            .ToArray();
        return new string(chars);
    }

    private static string FormatFingerprint(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length % 4 != 0)
        {
            return value;
        }

        return string.Join(" ", Enumerable.Range(0, value.Length / 4).Select(index => value.Substring(index * 4, 4)));
    }

    private TextView CreateSectionTitle(string text)
    {
        var title = new TextView(this)
        {
            Text = text,
            TextSize = 18f,
            Typeface = global::Android.Graphics.Typeface.DefaultBold
        };
        title.SetTextColor(ParseColor("#0F172A"));
        return title;
    }

    private LinearLayout CreateCard(string background, int radiusDp, string? border = null)
    {
        var card = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical,
            Background = CreateRoundedDrawable(background, radiusDp, border)
        };
        return card;
    }

    private FrameLayout CreateMenuButton()
    {
        var button = new FrameLayout(this)
        {
            Clickable = true,
            Focusable = true,
            ContentDescription = "Меню",
            Elevation = 0f
        };
        button.Background = CreateRoundedDrawable("#FFFFFF", 5, "#D7DEE8");

        var bars = new LinearLayout(this)
        {
            Orientation = global::Android.Widget.Orientation.Vertical
        };
        bars.SetGravity(GravityFlags.Center);

        for (var index = 0; index < 3; index++)
        {
            var bar = new View(this)
            {
                Background = CreateRoundedDrawable("#334155", 1)
            };
            var barParams = new LinearLayout.LayoutParams(Dp(16), Dp(2))
            {
                Gravity = GravityFlags.CenterHorizontal,
                BottomMargin = index < 2 ? Dp(4) : 0
            };
            bars.AddView(bar, barParams);
        }

        var barsParams = new FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.WrapContent,
            ViewGroup.LayoutParams.WrapContent)
        {
            Gravity = GravityFlags.Center
        };
        button.AddView(bars, barsParams);
        return button;
    }

    private Button CreateButton(string text, bool primary)
    {
        var button = new Button(this)
        {
            Text = text,
            TextSize = 13f
        };
        button.SetMinHeight(Dp(42));
        button.SetAllCaps(false);
        button.BackgroundTintList = ColorStateList.ValueOf(primary ? ParseColor("#2563EB") : ParseColor("#E2E8F0"));
        button.SetTextColor(primary ? Color.White : ParseColor("#1E293B"));
        return button;
    }

    private GradientDrawable CreateRoundedDrawable(string background, int radiusDp, string? border = null, int borderDp = 1)
    {
        var drawable = new GradientDrawable();
        drawable.SetColor(ParseColor(background));
        drawable.SetCornerRadius(Dp(radiusDp));
        if (!string.IsNullOrWhiteSpace(border))
        {
            drawable.SetStroke(Dp(borderDp), ParseColor(border));
        }
        return drawable;
    }

    private LinearLayout.LayoutParams WithTopMargin(int dp)
    {
        var layout = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent);
        layout.TopMargin = Dp(dp);
        return layout;
    }

    private LinearLayout.LayoutParams WithBottomMargin(int dp)
    {
        var layout = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MatchParent, ViewGroup.LayoutParams.WrapContent);
        layout.BottomMargin = Dp(dp);
        return layout;
    }

    private int Dp(int value) => (int)Math.Round(value * (Resources?.DisplayMetrics?.Density ?? 1f));

    private static Color ParseColor(string value) => Color.ParseColor(value);



    private sealed class RemoteBrowserListAdapter(
        MainActivity owner,
        RemoteBrowserEntry[] entries,
        HashSet<string> selectedPaths) : BaseAdapter<RemoteBrowserEntry>
    {
        public override int Count => entries.Length;

        public override RemoteBrowserEntry this[int position] => entries[position];

        public override long GetItemId(int position) => position;

        public override View GetView(int position, View? convertView, ViewGroup? parent)
        {
            var view = convertView ?? owner.LayoutInflater.Inflate(Resource.Layout.remote_browser_row, parent, false)
                ?? throw new InvalidOperationException("Could not inflate remote browser row.");
            var entry = entries[position];
            var icon = view.FindViewById<TextView>(Resource.Id.remote_browser_icon)
                ?? throw new InvalidOperationException("Remote browser icon view is missing.");
            var name = view.FindViewById<TextView>(Resource.Id.remote_browser_name)
                ?? throw new InvalidOperationException("Remote browser name view is missing.");
            var detail = view.FindViewById<TextView>(Resource.Id.remote_browser_detail)
                ?? throw new InvalidOperationException("Remote browser detail view is missing.");
            var check = view.FindViewById<CheckBox>(Resource.Id.remote_browser_check)
                ?? throw new InvalidOperationException("Remote browser selection view is missing.");

            icon.Text = entry.IsDirectory ? "📁" : GetRemoteFileIcon(entry.Name);
            name.Text = entry.Name;
            if (entry.IsDirectory)
            {
                detail.Text = $"{entry.DescendantFileCount} файлов · {AndroidDocumentAccess.FormatBytes(entry.DescendantBytes)}";
                check.Visibility = ViewStates.Gone;
                view.SetBackgroundResource(Resource.Drawable.remote_browser_row_background);
            }
            else
            {
                detail.Text = $"{GetRemoteFileTypeText(entry.Name)} · {AndroidDocumentAccess.FormatBytes(entry.FileSize)} · {FormatRemoteModified(entry.ModifiedUnixTimeSeconds)}";
                check.Visibility = ViewStates.Visible;
                check.Checked = selectedPaths.Contains(entry.RelativePath);
                view.SetBackgroundResource(check.Checked
                    ? Resource.Drawable.remote_browser_row_selected_background
                    : Resource.Drawable.remote_browser_row_background);
            }

            return view;
        }
    }

    private sealed class SystemBarsPaddingListener(
        View content,
        int baseLeft,
        int baseTop,
        int baseRight,
        int baseBottom) : Java.Lang.Object, View.IOnApplyWindowInsetsListener
    {
        public WindowInsets OnApplyWindowInsets(View v, WindowInsets insets)
        {
            var safeInsets = insets.GetInsets(
                WindowInsets.Type.SystemBars() | WindowInsets.Type.DisplayCutout());
            content.SetPadding(
                baseLeft + safeInsets.Left,
                baseTop + safeInsets.Top,
                baseRight + safeInsets.Right,
                baseBottom + safeInsets.Bottom);
            return insets;
        }
    }

    private sealed class DialogCancelListener(Action onCancel) : Java.Lang.Object, IDialogInterfaceOnCancelListener
    {
        public void OnCancel(IDialogInterface? dialog) => onCancel();
    }

    private sealed class DialogDismissListener(Action onDismiss) : Java.Lang.Object, IDialogInterfaceOnDismissListener
    {
        public void OnDismiss(IDialogInterface? dialog) => onDismiss();
    }
}
