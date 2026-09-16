using Android.App;
using Android.Content;
using Android.Content.PM;
using Android.Graphics.Drawables;
using Android.OS;
using GeniaLink.Core.Models;

namespace GeniaLink.Android.Services;

[Service(
    Name = "com.geniapixia.genialink.TransferForegroundService",
    Exported = false,
    ForegroundServiceType = ForegroundService.TypeDataSync)]
public sealed class TransferForegroundService : Service
{
    private const string ChannelId = "genialink_transfers";
    private const int NotificationId = 47500;
    private const int CompletionNotificationId = 47503;
    private const string ActionStart = "com.geniapixia.genialink.action.TRANSFER_START";
    private const string ActionCancel = "com.geniapixia.genialink.action.TRANSFER_CANCEL";
    private const string ExtraFileName = "file_name";
    private const string ExtraTotalBytes = "total_bytes";
    private const string ExtraIncoming = "incoming";
    private static readonly object StaticGate = new();

    private static TransferForegroundService? _current;
    private PowerManager.WakeLock? _wakeLock;
    private string _fileName = "Файл";
    private long _totalBytes;
    private bool _incoming;
    private int _lastProgress = -1;
    private long _lastNotificationTicks;

    public static event Action? CancelRequested;

    public override void OnCreate()
    {
        base.OnCreate();
        lock (StaticGate)
        {
            _current = this;
        }

        CreateNotificationChannel();
    }

    public override StartCommandResult OnStartCommand(Intent? intent, StartCommandFlags flags, int startId)
    {
        if (string.Equals(intent?.Action, ActionCancel, StringComparison.Ordinal))
        {
            CancelRequested?.Invoke();
            UpdateNotification("Отмена передачи…", 0, indeterminate: true, force: true);
            return StartCommandResult.NotSticky;
        }

        _fileName = intent?.GetStringExtra(ExtraFileName) ?? "Файл";
        _totalBytes = Math.Max(0, intent?.GetLongExtra(ExtraTotalBytes, 0) ?? 0);
        _incoming = intent?.GetBooleanExtra(ExtraIncoming, false) ?? false;
        _lastProgress = -1;
        _lastNotificationTicks = 0;

        AcquireWakeLock();
        var notification = BuildNotification(
            _incoming ? "Получение файла" : "Отправка файла",
            0,
            indeterminate: _totalBytes <= 0,
            ongoing: true,
            includeCancel: true);
        StartForeground(NotificationId, notification, ForegroundService.TypeDataSync);
        return StartCommandResult.NotSticky;
    }

    public override global::Android.OS.IBinder? OnBind(Intent? intent) => null;

    public override void OnDestroy()
    {
        ReleaseWakeLock();
        lock (StaticGate)
        {
            if (ReferenceEquals(_current, this))
            {
                _current = null;
            }
        }

        base.OnDestroy();
    }

    public override void OnTimeout(int startId, ForegroundService fgsType)
    {
        CancelRequested?.Invoke();
        Finish(success: false, "Системный лимит фоновой передачи достигнут.");
    }

    public static void Begin(Context context, string fileName, long totalBytes, bool incoming)
    {
        ArgumentNullException.ThrowIfNull(context);
        var intent = new Intent(context, typeof(TransferForegroundService));
        intent.SetAction(ActionStart);
        intent.PutExtra(ExtraFileName, fileName ?? "Файл");
        intent.PutExtra(ExtraTotalBytes, totalBytes);
        intent.PutExtra(ExtraIncoming, incoming);
        context.StartForegroundService(intent);
    }

    public static void Report(TransferProgress progress)
    {
        TransferForegroundService? current;
        lock (StaticGate)
        {
            current = _current;
        }

        current?.ReportProgress(progress);
    }

    public static void End(bool success, string message)
    {
        TransferForegroundService? current;
        lock (StaticGate)
        {
            current = _current;
        }

        current?.Finish(success, message);
    }

    private void ReportProgress(TransferProgress progress)
    {
        _fileName = progress.FileName;
        _totalBytes = progress.TotalBytes;
        var value = progress.TotalBytes <= 0
            ? 0
            : (int)Math.Clamp(Math.Round(progress.BytesTransferred * 1000d / progress.TotalBytes), 0, 1000);
        var label = progress.IsReceiving ? "Получение файла" : "Отправка файла";
        UpdateNotification(label, value, indeterminate: progress.TotalBytes <= 0, force: value >= 1000);
    }

    private void UpdateNotification(string label, int progress, bool indeterminate, bool force)
    {
        var now = global::System.Environment.TickCount64;
        if (!force && progress == _lastProgress && now - _lastNotificationTicks < 500)
        {
            return;
        }

        if (!force && now - _lastNotificationTicks < 200)
        {
            return;
        }

        _lastProgress = progress;
        _lastNotificationTicks = now;
        var manager = GetSystemService(NotificationService) as NotificationManager;
        manager?.Notify(
            NotificationId,
            BuildNotification(label, progress, indeterminate, ongoing: true, includeCancel: true));
    }

    private void Finish(bool success, string message)
    {
        ReleaseWakeLock();
        StopForeground(StopForegroundFlags.Remove);

        if (!LocalAvailabilityService.IsRunning)
        {
            var manager = GetSystemService(NotificationService) as NotificationManager;
            manager?.Notify(
                CompletionNotificationId,
                BuildNotification(
                    success ? "Передача завершена" : "Передача прервана",
                    success ? 1000 : 0,
                    indeterminate: false,
                    ongoing: false,
                    includeCancel: false,
                    detailOverride: message));
        }

        StopSelf();
    }

    private Notification BuildNotification(
        string title,
        int progress,
        bool indeterminate,
        bool ongoing,
        bool includeCancel,
        string? detailOverride = null)
    {
        var openIntent = new Intent(this, typeof(MainActivity));
        openIntent.SetFlags(ActivityFlags.SingleTop | ActivityFlags.ClearTop);
        var openPendingIntent = PendingIntent.GetActivity(
            this,
            0,
            openIntent,
            PendingIntentFlags.UpdateCurrent | PendingIntentFlags.Immutable);

        using var builder = new Notification.Builder(this, ChannelId);
        builder.SetSmallIcon(Resource.Drawable.ic_transfer_notification);
        builder.SetContentTitle(title);
        builder.SetContentText(detailOverride ?? _fileName);
        builder.SetContentIntent(openPendingIntent);
        builder.SetOnlyAlertOnce(true);
        builder.SetOngoing(ongoing);
        builder.SetAutoCancel(!ongoing);
        builder.SetProgress(1000, progress, indeterminate);
        builder.SetCategory(Notification.CategoryProgress);

        if (includeCancel)
        {
            var cancelIntent = new Intent(this, typeof(TransferForegroundService));
            cancelIntent.SetAction(ActionCancel);
            var cancelPendingIntent = PendingIntent.GetService(
                this,
                1,
                cancelIntent,
                PendingIntentFlags.UpdateCurrent | PendingIntentFlags.Immutable);
            using var cancelIcon = Icon.CreateWithResource(this, Resource.Drawable.ic_transfer_notification);
            using var actionBuilder = new Notification.Action.Builder(cancelIcon, "Отменить", cancelPendingIntent);
            using var action = actionBuilder.Build();
            if (action is not null)
            {
                builder.AddAction(action);
            }
        }

        return builder.Build()
            ?? throw new InvalidOperationException("Android did not build the transfer notification.");
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
            "Передачи Genia Link",
            NotificationImportance.Low)
        {
            Description = "Прогресс локальной передачи файлов"
        };
        channel.SetSound(null, null);
        manager.CreateNotificationChannel(channel);
    }

    private void AcquireWakeLock()
    {
        if (_wakeLock?.IsHeld == true)
        {
            return;
        }

        var powerManager = GetSystemService(PowerService) as PowerManager;
        _wakeLock = powerManager?.NewWakeLock(WakeLockFlags.Partial, "GeniaLink:Transfer");
        _wakeLock?.Acquire(6 * 60 * 60 * 1000L);
    }

    private void ReleaseWakeLock()
    {
        try
        {
            if (_wakeLock?.IsHeld == true)
            {
                _wakeLock.Release();
            }
        }
        catch (Java.Lang.RuntimeException)
        {
            // Best effort release during service teardown.
        }
        finally
        {
            _wakeLock?.Dispose();
            _wakeLock = null;
        }
    }
}
