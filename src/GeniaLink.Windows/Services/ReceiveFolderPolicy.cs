using System.Globalization;
using System.IO;

namespace GeniaLink.Windows.Services;

internal static class ReceiveFolderPolicy
{
    public static string GetDefaultReceiveFolder() => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
        "Downloads",
        "Genia Link");

    public static string Normalize(string? path)
    {
        var candidate = string.IsNullOrWhiteSpace(path) ? GetDefaultReceiveFolder() : path.Trim();
        if (candidate.Any(ch => char.IsControl(ch) || CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.Format))
        {
            throw new InvalidDataException("Путь папки приёма содержит небезопасные управляющие символы.");
        }

        if (candidate.StartsWith("\\\\", StringComparison.Ordinal) || candidate.StartsWith("//", StringComparison.Ordinal))
        {
            throw new InvalidDataException("Сетевая папка UNC не может использоваться как папка приёма.");
        }

        var fullPath = Path.TrimEndingDirectorySeparator(Path.GetFullPath(candidate));
        if (!Path.IsPathFullyQualified(fullPath))
        {
            throw new InvalidDataException("Папка приёма должна иметь полный локальный путь.");
        }

        var root = Path.GetPathRoot(fullPath);
        if (string.IsNullOrWhiteSpace(root))
        {
            throw new InvalidDataException("Не удалось определить локальный диск папки приёма.");
        }

        var normalizedRoot = Path.TrimEndingDirectorySeparator(Path.GetFullPath(root));
        if (string.Equals(fullPath, normalizedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Корень диска нельзя использовать как папку приёма Genia Link.");
        }

        RejectProtectedSystemLocation(fullPath, Environment.GetFolderPath(Environment.SpecialFolder.Windows));
        RejectProtectedSystemLocation(fullPath, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
        RejectProtectedSystemLocation(fullPath, Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86));
        RejectProtectedSystemLocation(fullPath, Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
        RejectProtectedSystemLocation(fullPath, Environment.GetFolderPath(Environment.SpecialFolder.Startup));
        RejectProtectedSystemLocation(fullPath, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup));
        RejectProtectedSystemLocation(fullPath, Environment.GetFolderPath(Environment.SpecialFolder.SendTo));
        RejectProtectedSystemLocation(
            fullPath,
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Genia Link"));

        var executableDirectory = Environment.ProcessPath is { Length: > 0 } executablePath
            ? Path.GetDirectoryName(executablePath)
            : null;
        RejectExactLocation(fullPath, executableDirectory);
        return fullPath;
    }

    public static string ValidateAndPrepare(string? path)
    {
        var fullPath = Normalize(path);
        Directory.CreateDirectory(fullPath);
        var attributes = File.GetAttributes(fullPath);
        if ((attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("Папка приёма не должна быть символической ссылкой или junction.");
        }

        var probePath = Path.Combine(fullPath, $".genialink-write-test-{Guid.NewGuid():N}.tmp");
        try
        {
            using var probe = new FileStream(
                probePath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 1,
                FileOptions.WriteThrough);
            probe.WriteByte(0);
            probe.Flush(flushToDisk: true);
        }
        finally
        {
            TryDelete(probePath);
        }

        return fullPath;
    }

    public static bool PathsEqual(string left, string right) =>
        string.Equals(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(left)),
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(right)),
            StringComparison.OrdinalIgnoreCase);

    private static void RejectExactLocation(string candidate, string? protectedPath)
    {
        if (string.IsNullOrWhiteSpace(protectedPath))
        {
            return;
        }

        var normalized = Path.TrimEndingDirectorySeparator(Path.GetFullPath(protectedPath));
        if (string.Equals(candidate, normalized, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Папка приёма не должна совпадать с папкой запуска Genia Link.");
        }
    }

    private static void RejectProtectedSystemLocation(string candidate, string? protectedRoot)
    {
        if (string.IsNullOrWhiteSpace(protectedRoot))
        {
            return;
        }

        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(protectedRoot));
        var prefix = root + Path.DirectorySeparatorChar;
        if (string.Equals(candidate, root, StringComparison.OrdinalIgnoreCase) ||
            candidate.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("Защищённую системную или служебную папку нельзя использовать как папку приёма Genia Link.");
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
