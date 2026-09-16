using System.IO;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace GeniaLink.Windows.Services;

internal sealed class SingleInstanceBroker : IDisposable
{
    private const int MaxCommandBytes = 1024 * 1024;
    private readonly Mutex _mutex;
    private readonly string _pipeName;
    private readonly CancellationTokenSource _cts = new();
    private Task? _serverTask;
    private bool _ownsMutex;

    public SingleInstanceBroker()
    {
        var scope = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
            Environment.UserDomainName + "\\" + Environment.UserName))).Substring(0, 16);
        var mutexName = $"Local\\GeniaLink.SingleInstance.{scope}";
        _pipeName = $"GeniaLink.Command.{scope}";
        _mutex = new Mutex(initiallyOwned: true, mutexName, out var createdNew);
        IsPrimary = createdNew;
        _ownsMutex = createdNew;
    }

    public bool IsPrimary { get; }
    public event Action<string[]>? CommandReceived;

    public void StartServer()
    {
        if (!IsPrimary || _serverTask is not null)
        {
            return;
        }

        _serverTask = RunServerAsync(_cts.Token);
    }

    public async Task<bool> SendToPrimaryAsync(string[] args, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(args);
        if (IsPrimary)
        {
            return false;
        }

        var payload = JsonSerializer.Serialize(args);
        var payloadBytes = Encoding.UTF8.GetByteCount(payload);
        if (payloadBytes <= 0 || payloadBytes > MaxCommandBytes)
        {
            throw new InvalidDataException("Genia Link command is too large.");
        }

        using var client = new NamedPipeClientStream(
            serverName: ".",
            pipeName: _pipeName,
            direction: PipeDirection.Out,
            options: PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        await client.ConnectAsync(cancellationToken).ConfigureAwait(false);
        await using var writer = new StreamWriter(client, new UTF8Encoding(false), leaveOpen: true)
        {
            AutoFlush = true
        };
        await writer.WriteLineAsync(payload.AsMemory(), cancellationToken).ConfigureAwait(false);
        return true;
    }

    private async Task RunServerAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await using var server = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.In,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                using var reader = new StreamReader(
                    server,
                    Encoding.UTF8,
                    detectEncodingFromByteOrderMarks: false,
                    bufferSize: 4096,
                    leaveOpen: true);
                var line = await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(line) || Encoding.UTF8.GetByteCount(line) > MaxCommandBytes)
                {
                    continue;
                }

                var args = JsonSerializer.Deserialize<string[]>(line);
                if (args is { Length: > 0 })
                {
                    CommandReceived?.Invoke(args);
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
            {
                await Task.Delay(250, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        try
        {
            _serverTask?.Wait(TimeSpan.FromSeconds(1));
        }
        catch (AggregateException)
        {
        }

        _cts.Dispose();
        if (_ownsMutex)
        {
            try
            {
                _mutex.ReleaseMutex();
            }
            catch (ApplicationException)
            {
            }

            _ownsMutex = false;
        }

        _mutex.Dispose();
        GC.SuppressFinalize(this);
    }
}
