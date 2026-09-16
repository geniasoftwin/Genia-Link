using System.Globalization;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using GeniaLink.Core.Models;
using GeniaLink.Core.Transfers;

namespace GeniaLink.Windows;

public sealed partial class RemoteFilesWindow : Window, IDisposable
{
    private readonly string _deviceName;
    private readonly Func<CancellationToken, Task<IReadOnlyList<RemoteFileEntry>>> _refreshLoader;
    private readonly Func<string, CancellationToken, Task<RemoteFilePreview>> _previewLoader;
    private readonly HashSet<string> _selectedPaths = new(StringComparer.Ordinal);
    private IReadOnlyList<RemoteFileEntry> _files;
    private RemoteBrowserRow[] _rows = [];
    private string _currentDirectory = string.Empty;
    private bool _suppressSelectionChanged;
    private bool _ready;
    private CancellationTokenSource? _previewCts;
    private CancellationTokenSource? _refreshCts;
    private bool _disposed;

    public RemoteFilesWindow(
        string deviceName,
        IReadOnlyList<RemoteFileEntry> files,
        Func<CancellationToken, Task<IReadOnlyList<RemoteFileEntry>>> refreshLoader,
        Func<string, CancellationToken, Task<RemoteFilePreview>> previewLoader)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceName);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(refreshLoader);
        ArgumentNullException.ThrowIfNull(previewLoader);
        InitializeComponent();
        _deviceName = deviceName;
        _files = files;
        _refreshLoader = refreshLoader;
        _previewLoader = previewLoader;
        Title = $"Файлы Genia Link — {deviceName}";
        TitleTextBlock.Text = $"{deviceName} · Файлы Genia Link";
        _ready = true;
        RebuildRows();
    }

    public IReadOnlyList<string> SelectedRelativePaths
    {
        get
        {
            CaptureCurrentSelection();
            return _selectedPaths.OrderBy(path => path, StringComparer.OrdinalIgnoreCase).ToArray();
        }
    }

    private void RebuildRows()
    {
        _suppressSelectionChanged = true;
        try
        {
            var entries = RemoteBrowserIndex.BuildDirectory(_files, _currentDirectory);
            var sortMode = SortComboBox.SelectedIndex;
            var ordered = sortMode switch
            {
                1 => entries.OrderByDescending(entry => entry.IsDirectory)
                    .ThenByDescending(entry => entry.ModifiedUnixTimeSeconds)
                    .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase),
                2 => entries.OrderByDescending(entry => entry.IsDirectory)
                    .ThenByDescending(entry => entry.IsDirectory ? entry.DescendantBytes : entry.FileSize)
                    .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase),
                _ => entries.OrderByDescending(entry => entry.IsDirectory)
                    .ThenBy(entry => entry.Name, StringComparer.OrdinalIgnoreCase)
            };

            _rows = ordered.Select(CreateRow).ToArray();
            FilesListBox.ItemsSource = _rows;
            FilesListBox.SelectedItems.Clear();
            foreach (var row in _rows.Where(row => !row.IsDirectory && _selectedPaths.Contains(row.RelativePath)))
            {
                FilesListBox.SelectedItems.Add(row);
            }

            PathTextBlock.Text = FormatPath(_currentDirectory);
            UpButton.IsEnabled = _currentDirectory.Length > 0;
        }
        finally
        {
            _suppressSelectionChanged = false;
        }

        UpdateSelectionSummary();
        UpdatePreviewButton();
    }

    private void CaptureCurrentSelection()
    {
        if (_suppressSelectionChanged)
        {
            return;
        }

        foreach (var row in _rows.Where(row => !row.IsDirectory))
        {
            _selectedPaths.Remove(row.RelativePath);
        }

        foreach (var row in FilesListBox.SelectedItems.OfType<RemoteBrowserRow>().Where(row => !row.IsDirectory))
        {
            _selectedPaths.Add(row.RelativePath);
        }
    }

    private void FilesListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressSelectionChanged)
        {
            return;
        }

        CaptureCurrentSelection();
        UpdateSelectionSummary();
        UpdatePreviewButton();
    }

    private void FilesListBox_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (FilesListBox.SelectedItem is not RemoteBrowserRow row)
        {
            return;
        }

        if (row.IsDirectory)
        {
            CaptureCurrentSelection();
            _currentDirectory = row.RelativePath;
            ClearPreview("Откройте файл для предпросмотра.");
            RebuildRows();
            return;
        }

        if (CanPreview(row.RelativePath))
        {
            _ = LoadPreviewAsync(row);
        }
    }

    private void UpButton_Click(object sender, RoutedEventArgs e)
    {
        if (_currentDirectory.Length == 0)
        {
            return;
        }

        CaptureCurrentSelection();
        _currentDirectory = RemoteBrowserIndex.GetParentDirectory(_currentDirectory);
        ClearPreview("Откройте файл для предпросмотра.");
        RebuildRows();
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e)
    {
        _refreshCts?.Cancel();
        _refreshCts?.Dispose();
        _refreshCts = new CancellationTokenSource();
        RefreshButton.IsEnabled = false;
        try
        {
            CaptureCurrentSelection();
            var refreshed = await _refreshLoader(_refreshCts.Token);
            _files = refreshed;
            var existing = refreshed.Select(file => file.RelativePath).ToHashSet(StringComparer.Ordinal);
            _selectedPaths.RemoveWhere(path => !existing.Contains(path));
            if (_currentDirectory.Length > 0 && !refreshed.Any(file => file.RelativePath.StartsWith(_currentDirectory + "/", StringComparison.Ordinal)))
            {
                _currentDirectory = string.Empty;
            }

            ClearPreview("Список обновлён. Откройте файл для предпросмотра.");
            RebuildRows();
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException or System.Security.Cryptography.CryptographicException or InvalidOperationException)
        {
            System.Windows.MessageBox.Show(this, ex.Message, "Genia Link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            RefreshButton.IsEnabled = true;
        }
    }

    private void SortComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!_ready)
        {
            return;
        }

        CaptureCurrentSelection();
        RebuildRows();
    }

    private void PreviewButton_Click(object sender, RoutedEventArgs e)
    {
        var selected = FilesListBox.SelectedItems.OfType<RemoteBrowserRow>()
            .Where(row => !row.IsDirectory)
            .Take(2)
            .ToArray();
        if (selected.Length == 1 && CanPreview(selected[0].RelativePath))
        {
            _ = LoadPreviewAsync(selected[0]);
        }
    }

    private async Task LoadPreviewAsync(RemoteBrowserRow row)
    {
        ShowPreviewPanel();
        _previewCts?.Cancel();
        _previewCts?.Dispose();
        _previewCts = new CancellationTokenSource();
        PreviewButton.IsEnabled = false;
        PreviewTitleTextBlock.Text = row.Name;
        PreviewMetaTextBlock.Text = $"{row.SizeText} · {row.ModifiedText}";
        PreviewImage.Visibility = Visibility.Collapsed;
        PreviewTextBox.Visibility = Visibility.Collapsed;
        PreviewMessageTextBlock.Visibility = Visibility.Visible;
        PreviewMessageTextBlock.Text = "Загрузка безопасного предпросмотра…";
        try
        {
            var preview = await _previewLoader(row.RelativePath, _previewCts.Token);
            if (!string.Equals(preview.RelativePath, row.RelativePath, StringComparison.Ordinal))
            {
                throw new InvalidDataException("Удалённое устройство вернуло предпросмотр другого файла.");
            }

            switch (preview.Kind)
            {
                case RemotePreviewKind.ImageJpeg:
                    PreviewImage.Source = DecodeBitmap(preview.Data);
                    PreviewImage.Visibility = Visibility.Visible;
                    PreviewMessageTextBlock.Visibility = Visibility.Collapsed;
                    break;
                case RemotePreviewKind.TextUtf8:
                    PreviewTextBox.Text = Encoding.UTF8.GetString(preview.Data);
                    PreviewTextBox.Visibility = Visibility.Visible;
                    PreviewMessageTextBlock.Visibility = Visibility.Collapsed;
                    break;
                default:
                    PreviewMessageTextBlock.Text = string.IsNullOrWhiteSpace(preview.Message)
                        ? "Предпросмотр для этого типа файла недоступен."
                        : preview.Message;
                    break;
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or System.Net.Sockets.SocketException or System.Security.Authentication.AuthenticationException or System.Security.Cryptography.CryptographicException or InvalidOperationException)
        {
            PreviewMessageTextBlock.Text = "Не удалось получить предпросмотр: " + ex.Message;
        }
        finally
        {
            UpdatePreviewButton();
        }
    }

    private void UpdateSelectionSummary()
    {
        var selectedFiles = _files.Where(file => _selectedPaths.Contains(file.RelativePath)).ToArray();
        DownloadButton.IsEnabled = selectedFiles.Length > 0;
        if (_files.Count == 0)
        {
            SelectionTextBlock.Text = "Папка Genia Link пуста";
            return;
        }

        if (selectedFiles.Length == 0)
        {
            SelectionTextBlock.Text = $"Файлов: {_files.Count} · Выбрано: 0";
            return;
        }

        var totalBytes = selectedFiles.Sum(file => file.FileSize);
        SelectionTextBlock.Text = $"Файлов: {_files.Count} · Выбрано: {selectedFiles.Length} · {FormatBytes(totalBytes)}";
    }

    private void UpdatePreviewButton()
    {
        var selected = FilesListBox.SelectedItems.OfType<RemoteBrowserRow>()
            .Where(row => !row.IsDirectory)
            .Take(2)
            .ToArray();
        PreviewButton.IsEnabled = selected.Length == 1 && CanPreview(selected[0].RelativePath);
    }

    private void ClearPreview(string message)
    {
        _previewCts?.Cancel();
        HidePreviewPanel();
        PreviewTitleTextBlock.Text = "Предпросмотр";
        PreviewMetaTextBlock.Text = _currentDirectory.Length == 0 ? "Genia Link" : FormatPath(_currentDirectory);
        PreviewImage.Source = null;
        PreviewImage.Visibility = Visibility.Collapsed;
        PreviewTextBox.Text = string.Empty;
        PreviewTextBox.Visibility = Visibility.Collapsed;
        PreviewMessageTextBlock.Text = message;
        PreviewMessageTextBlock.Visibility = Visibility.Visible;
    }


    private static bool CanPreview(string relativePath) =>
        RemotePreviewPolicy.IsImagePath(relativePath) || RemotePreviewPolicy.IsTextPath(relativePath);

    private void ShowPreviewPanel()
    {
        PreviewSpacerColumn.Width = new GridLength(12);
        PreviewColumn.Width = new GridLength(300);
        PreviewPanel.Visibility = Visibility.Visible;
        if (WindowState == WindowState.Normal && Width < 1000)
        {
            Width = 1000;
        }
    }

    private void HidePreviewPanel()
    {
        PreviewPanel.Visibility = Visibility.Collapsed;
        PreviewSpacerColumn.Width = new GridLength(0);
        PreviewColumn.Width = new GridLength(0);
        if (WindowState == WindowState.Normal && Width > 840)
        {
            Width = 820;
        }
    }

    private void Window_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key != Key.Escape)
        {
            return;
        }

        e.Handled = true;
        DialogResult = false;
    }

    private void Window_Closed(object? sender, EventArgs e)
    {
        Dispose();
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _previewCts?.Cancel();
        _previewCts?.Dispose();
        _previewCts = null;
        _refreshCts?.Cancel();
        _refreshCts?.Dispose();
        _refreshCts = null;
        PreviewImage.Source = null;
        GC.SuppressFinalize(this);
    }

    private void DownloadButton_Click(object sender, RoutedEventArgs e)
    {
        CaptureCurrentSelection();
        if (_selectedPaths.Count == 0)
        {
            return;
        }

        DialogResult = true;
    }

    private static RemoteBrowserRow CreateRow(RemoteBrowserEntry entry)
    {
        if (entry.IsDirectory)
        {
            var fileWord = entry.DescendantFileCount == 1 ? "файл" : "файлов";
            return new RemoteBrowserRow(
                true,
                "📁",
                entry.Name,
                entry.RelativePath,
                $"{entry.DescendantFileCount} {fileWord}",
                FormatBytes(entry.DescendantBytes),
                FormatModified(entry.ModifiedUnixTimeSeconds),
                0);
        }

        var sizeText = FormatBytes(entry.FileSize);
        var modifiedText = FormatModified(entry.ModifiedUnixTimeSeconds);
        return new RemoteBrowserRow(
            false,
            GetFileIcon(entry.Name),
            entry.Name,
            entry.RelativePath,
            $"{GetFileTypeText(entry.Name)} · {sizeText} · {modifiedText}",
            sizeText,
            modifiedText,
            entry.FileSize);
    }

    private static BitmapImage DecodeBitmap(byte[] data)
    {
        using var stream = new MemoryStream(data, writable: false);
        var bitmap = new BitmapImage();
        bitmap.BeginInit();
        bitmap.CacheOption = BitmapCacheOption.OnLoad;
        bitmap.StreamSource = stream;
        bitmap.EndInit();
        bitmap.Freeze();
        return bitmap;
    }

    private static string FormatPath(string relativeDirectory) =>
        relativeDirectory.Length == 0 ? "Genia Link" : "Genia Link › " + relativeDirectory.Replace("/", " › ", StringComparison.Ordinal);

    private static string GetFileIcon(string fileName) => Path.GetExtension(fileName).ToLowerInvariant() switch
    {
        ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".webp" => "🖼️",
        ".mp4" or ".mkv" or ".avi" or ".mov" or ".webm" => "🎬",
        ".mp3" or ".flac" or ".wav" or ".m4a" or ".ogg" => "🎵",
        ".pdf" or ".doc" or ".docx" or ".txt" or ".md" => "📄",
        ".zip" or ".7z" or ".rar" or ".tar" or ".gz" => "📦",
        _ => "📎"
    };

    private static string GetFileTypeText(string fileName)
    {
        var extension = Path.GetExtension(fileName);
        return string.IsNullOrEmpty(extension) ? "Файл" : extension.TrimStart('.').ToUpperInvariant();
    }

    private static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
        {
            return $"{bytes.ToString(CultureInfo.CurrentCulture)} Б";
        }

        var value = bytes / 1024d;
        if (value < 1024)
        {
            return $"{value:F1} КБ";
        }

        value /= 1024d;
        if (value < 1024)
        {
            return $"{value:F1} МБ";
        }

        value /= 1024d;
        return $"{value:F2} ГБ";
    }

    private static string FormatModified(long unixSeconds)
    {
        if (unixSeconds <= 0)
        {
            return "—";
        }

        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(unixSeconds).ToLocalTime().ToString("g", CultureInfo.CurrentCulture);
        }
        catch (ArgumentOutOfRangeException)
        {
            return "—";
        }
    }

    private sealed record RemoteBrowserRow(
        bool IsDirectory,
        string Icon,
        string Name,
        string RelativePath,
        string DetailText,
        string SizeText,
        string ModifiedText,
        long FileSize);
}
