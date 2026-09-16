using System.IO;
using System.Windows;
using GeniaLink.Windows.Services;

namespace GeniaLink.Windows;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1001:Types that own disposable fields should be disposable", Justification = "WPF application lifetime disposes the single-instance broker in OnExit.")]
public partial class App : System.Windows.Application
{
    private SingleInstanceBroker? _broker;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        var startupRequest = e.Args.Length == 1 &&
                             string.Equals(e.Args[0], "--startup", StringComparison.OrdinalIgnoreCase);

        _broker = new SingleInstanceBroker();
        if (!_broker.IsPrimary)
        {
            if (!startupRequest)
            {
                try
                {
                    using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(4));
                    var forwardedArgs = e.Args.Length == 0 ? new[] { "--show" } : e.Args;
                    _broker.SendToPrimaryAsync(forwardedArgs, timeout.Token).GetAwaiter().GetResult();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or TimeoutException or OperationCanceledException)
                {
                    System.Windows.MessageBox.Show(
                        "Не удалось передать команду уже запущенному Genia Link.",
                        "Genia Link",
                        MessageBoxButton.OK,
                        MessageBoxImage.Warning);
                }
            }

            Shutdown();
            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        _broker.CommandReceived += args =>
        {
            _ = Dispatcher.InvokeAsync(async () => await window.HandleCommandLineAsync(args));
        };
        _broker.StartServer();

        var externalSend = GeniaLink.Windows.MainWindow.IsExternalSendCommand(e.Args);
        window.Show();
        if (externalSend)
        {
            window.Hide();
        }
        else if (startupRequest && window.ShouldStartMinimizedOnStartup)
        {
            window.HideToTrayForStartup();
        }

        if (e.Args.Length > 0 && !startupRequest)
        {
            _ = window.HandleCommandLineAsync(e.Args);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        _broker?.Dispose();
        _broker = null;
        base.OnExit(e);
    }
}
