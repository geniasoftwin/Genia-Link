using Android.App;
using Android.Content;
using Android.OS;
using Android.Provider;

namespace GeniaLink.Android.Services;

internal static class AlwaysReadySettings
{
    private const string PreferencesName = "genialink_background";
    private const string EnabledKey = "always_ready_user_enabled_v3";
    private const string PendingEnableKey = "always_ready_enable_pending";

    public static bool IsEnabled(Context context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var preferences = context.GetSharedPreferences(PreferencesName, FileCreationMode.Private);
        return preferences?.GetBoolean(EnabledKey, false) ?? false;
    }

    public static void SetEnabled(Context context, bool enabled)
    {
        ArgumentNullException.ThrowIfNull(context);
        var preferences = context.GetSharedPreferences(PreferencesName, FileCreationMode.Private)
            ?? throw new InvalidOperationException("Android preferences are unavailable.");
        var editor = preferences.Edit()
            ?? throw new InvalidOperationException("Android preferences editor is unavailable.");
        editor.PutBoolean(EnabledKey, enabled);
        if (!enabled)
        {
            editor.PutBoolean(PendingEnableKey, false);
        }
        editor.Apply();
    }

    public static bool IsBatteryOptimizationExempt(Context context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var packageName = context.PackageName;
        if (string.IsNullOrWhiteSpace(packageName))
        {
            return false;
        }

        var powerManager = context.GetSystemService(Context.PowerService) as PowerManager;
        return powerManager?.IsIgnoringBatteryOptimizations(packageName) == true;
    }

    public static bool IsEffective(Context context) =>
        IsEnabled(context) && IsBatteryOptimizationExempt(context);

    public static void MarkEnableRequestPending(Context context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var preferences = context.GetSharedPreferences(PreferencesName, FileCreationMode.Private)
            ?? throw new InvalidOperationException("Android preferences are unavailable.");
        var editor = preferences.Edit()
            ?? throw new InvalidOperationException("Android preferences editor is unavailable.");
        editor.PutBoolean(PendingEnableKey, true);
        editor.Apply();
    }

    public static void ResolvePendingEnableRequest(Context context)
    {
        ArgumentNullException.ThrowIfNull(context);
        var preferences = context.GetSharedPreferences(PreferencesName, FileCreationMode.Private);
        if (preferences?.GetBoolean(PendingEnableKey, false) != true)
        {
            return;
        }

        var exempt = IsBatteryOptimizationExempt(context);
        var editor = preferences.Edit()
            ?? throw new InvalidOperationException("Android preferences editor is unavailable.");
        editor.PutBoolean(PendingEnableKey, false);
        editor.PutBoolean(EnabledKey, exempt);
        editor.Apply();
    }

    public static void RequestBatteryOptimizationExemption(Activity activity)
    {
        ArgumentNullException.ThrowIfNull(activity);
        var packageName = activity.PackageName;
        if (string.IsNullOrWhiteSpace(packageName))
        {
            throw new InvalidOperationException("Android package name is unavailable.");
        }

        var intent = new Intent(Settings.ActionRequestIgnoreBatteryOptimizations);
        intent.SetData(global::Android.Net.Uri.Parse($"package:{packageName}"));
        activity.StartActivity(intent);
    }

    public static void OpenBatteryOptimizationSettings(Activity activity)
    {
        ArgumentNullException.ThrowIfNull(activity);
        activity.StartActivity(new Intent(Settings.ActionIgnoreBatteryOptimizationSettings));
    }
}
