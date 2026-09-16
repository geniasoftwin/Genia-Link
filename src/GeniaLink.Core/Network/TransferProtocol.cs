using System.Buffers.Binary;
using System.IO;
using System.Text;
using GeniaLink.Core.Models;

namespace GeniaLink.Core.Network;

public enum MessageType : byte
{
    Hello = 1,
    HelloAck = 2,
    FileOffer = 10,
    FileAccept = 11,
    FileReject = 12,
    FileChunk = 13,
    FileComplete = 14,
    TransferResult = 15,
    BrowseRequest = 30,
    BrowseListStart = 31,
    BrowseEntry = 32,
    BrowseListEnd = 33,
    DownloadRequestStart = 34,
    DownloadRequestItem = 35,
    DownloadRequestCommit = 36,
    DownloadRequestAccepted = 37,
    DownloadRequestRejected = 38,
    PreviewRequest = 39,
    PreviewResponse = 40
}

public sealed record FileOffer(
    Guid TransferId,
    string FileName,
    string RelativeDirectory,
    long FileSize,
    byte[] Sha256);

public sealed record FileAccept(Guid TransferId, long ResumeOffset);
public sealed record FileChunk(Guid TransferId, long Offset, byte[] Data);
public sealed record TransferResult(Guid TransferId, bool Success, string Message);

public static class TransferProtocol
{
    private const int MaxStringBytes = 1024;
    private const int MaxPathBytes = 4096;
    private static readonly UTF8Encoding StrictUtf8 = new(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true);

    public static byte[] CreateHello(Guid deviceId, string deviceName) => Build(MessageType.Hello, writer =>
    {
        writer.WriteInt32(ProtocolConstants.Version);
        writer.WriteGuid(deviceId);
        writer.WriteString(deviceName, MaxStringBytes);
    });

    public static byte[] CreateHelloAck(Guid deviceId, string deviceName) => Build(MessageType.HelloAck, writer =>
    {
        writer.WriteInt32(ProtocolConstants.Version);
        writer.WriteGuid(deviceId);
        writer.WriteString(deviceName, MaxStringBytes);
    });

    public static byte[] CreateFileOffer(FileOffer offer) => Build(MessageType.FileOffer, writer =>
    {
        writer.WriteGuid(offer.TransferId);
        writer.WriteString(offer.FileName, MaxStringBytes);
        writer.WriteString(offer.RelativeDirectory, MaxPathBytes);
        writer.WriteInt64(offer.FileSize);
        writer.WriteFixedBytes(offer.Sha256, 32);
    });

    public static byte[] CreateFileAccept(Guid transferId, long resumeOffset) => Build(MessageType.FileAccept, writer =>
    {
        writer.WriteGuid(transferId);
        writer.WriteInt64(resumeOffset);
    });

    public static byte[] CreateFileReject(Guid transferId, string reason) => Build(MessageType.FileReject, writer =>
    {
        writer.WriteGuid(transferId);
        writer.WriteString(reason, MaxStringBytes);
    });

    public static byte[] CreateFileChunk(Guid transferId, long offset, ReadOnlySpan<byte> data)
    {
        if (offset < 0)
        {
            throw new InvalidDataException("Chunk offset must not be negative.");
        }

        if (data.Length <= 0 || data.Length > ProtocolConstants.MaxChunkSize)
        {
            throw new InvalidDataException("Chunk size is outside the allowed range.");
        }

        using var stream = new MemoryStream();
        stream.WriteByte((byte)MessageType.FileChunk);
        var writer = new ProtocolWriter(stream);
        writer.WriteGuid(transferId);
        writer.WriteInt64(offset);
        writer.WriteBytes(data);
        return stream.ToArray();
    }

    public static byte[] CreateFileComplete(Guid transferId) => Build(MessageType.FileComplete, writer => writer.WriteGuid(transferId));

    public static byte[] CreateTransferResult(Guid transferId, bool success, string message) => Build(MessageType.TransferResult, writer =>
    {
        writer.WriteGuid(transferId);
        writer.WriteByte(success ? (byte)1 : (byte)0);
        writer.WriteString(message, MaxStringBytes);
    });

    public static byte[] CreateBrowseRequest() => Build(MessageType.BrowseRequest, _ => { });

    public static byte[] CreateBrowseListStart(int count) => Build(MessageType.BrowseListStart, writer =>
    {
        if (count < 0 || count > ProtocolConstants.MaxBatchFiles)
        {
            throw new InvalidDataException("Remote file count is outside the allowed range.");
        }

        writer.WriteInt32(count);
    });

    public static byte[] CreateBrowseEntry(RemoteFileEntry entry) => Build(MessageType.BrowseEntry, writer =>
    {
        ArgumentNullException.ThrowIfNull(entry);
        writer.WriteString(entry.RelativePath, MaxPathBytes);
        writer.WriteInt64(entry.FileSize);
        writer.WriteInt64(entry.ModifiedUnixTimeSeconds);
    });

    public static byte[] CreateBrowseListEnd() => Build(MessageType.BrowseListEnd, _ => { });

    public static byte[] CreateDownloadRequestStart(int count, int returnTransferPort) => Build(MessageType.DownloadRequestStart, writer =>
    {
        if (count <= 0 || count > ProtocolConstants.MaxBatchFiles)
        {
            throw new InvalidDataException("Download request file count is outside the allowed range.");
        }

        if (returnTransferPort is < 1 or > 65535)
        {
            throw new InvalidDataException("Download return port is invalid.");
        }

        writer.WriteInt32(count);
        writer.WriteInt32(returnTransferPort);
    });

    public static byte[] CreateDownloadRequestItem(string relativePath) => Build(MessageType.DownloadRequestItem, writer =>
        writer.WriteString(relativePath, MaxPathBytes));

    public static byte[] CreateDownloadRequestCommit() => Build(MessageType.DownloadRequestCommit, _ => { });

    public static byte[] CreateDownloadRequestAccepted(int count) => Build(MessageType.DownloadRequestAccepted, writer =>
    {
        if (count <= 0 || count > ProtocolConstants.MaxBatchFiles)
        {
            throw new InvalidDataException("Accepted download file count is outside the allowed range.");
        }

        writer.WriteInt32(count);
    });

    public static byte[] CreateDownloadRequestRejected(string reason) => Build(MessageType.DownloadRequestRejected, writer =>
        writer.WriteString(reason, MaxStringBytes));

    public static byte[] CreatePreviewRequest(string relativePath) => Build(MessageType.PreviewRequest, writer =>
        writer.WriteString(relativePath, MaxPathBytes));

    public static byte[] CreatePreviewResponse(RemoteFilePreview preview) => Build(MessageType.PreviewResponse, writer =>
    {
        ArgumentNullException.ThrowIfNull(preview);
        if (!Enum.IsDefined(preview.Kind) || preview.Data.Length > ProtocolConstants.MaxPreviewBytes)
        {
            throw new InvalidDataException("Remote preview metadata is invalid.");
        }

        writer.WriteString(preview.RelativePath, MaxPathBytes);
        writer.WriteByte((byte)preview.Kind);
        writer.WriteString(preview.MediaType, MaxStringBytes);
        writer.WriteBytes(preview.Data);
        writer.WriteString(preview.Message, MaxStringBytes);
    });

    public static MessageType GetMessageType(ReadOnlySpan<byte> message)
    {
        if (message.Length < 1 || !Enum.IsDefined((MessageType)message[0]))
        {
            throw new InvalidDataException("Unknown protocol message type.");
        }

        return (MessageType)message[0];
    }

    public static (int Version, Guid DeviceId, string DeviceName) ParseHello(ReadOnlySpan<byte> message, MessageType expectedType)
    {
        var reader = CreateReader(message, expectedType);
        var version = reader.ReadInt32();
        var deviceId = reader.ReadGuid();
        var deviceName = reader.ReadString(MaxStringBytes);
        reader.EnsureFinished();
        return (version, deviceId, deviceName);
    }

    public static FileOffer ParseFileOffer(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.FileOffer);
        var result = new FileOffer(
            reader.ReadGuid(),
            reader.ReadString(MaxStringBytes),
            reader.ReadString(MaxPathBytes),
            reader.ReadInt64(),
            reader.ReadFixedBytes(32));
        reader.EnsureFinished();
        return result;
    }

    public static FileAccept ParseFileAccept(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.FileAccept);
        var result = new FileAccept(reader.ReadGuid(), reader.ReadInt64());
        reader.EnsureFinished();
        return result;
    }

    public static Guid ParseTransferId(ReadOnlySpan<byte> message, MessageType expectedType)
    {
        var reader = CreateReader(message, expectedType);
        var id = reader.ReadGuid();
        reader.EnsureFinished();
        return id;
    }

    public static (Guid TransferId, string Reason) ParseFileReject(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.FileReject);
        var result = (reader.ReadGuid(), reader.ReadString(MaxStringBytes));
        reader.EnsureFinished();
        return result;
    }

    public static FileChunk ParseFileChunk(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.FileChunk);
        var transferId = reader.ReadGuid();
        var offset = reader.ReadInt64();
        var data = reader.ReadBytes(ProtocolConstants.MaxChunkSize);
        reader.EnsureFinished();
        if (offset < 0 || data.Length == 0)
        {
            throw new InvalidDataException("Invalid file chunk metadata.");
        }

        return new FileChunk(transferId, offset, data);
    }

    public static TransferResult ParseTransferResult(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.TransferResult);
        var transferId = reader.ReadGuid();
        var success = reader.ReadByte() switch
        {
            0 => false,
            1 => true,
            _ => throw new InvalidDataException("Invalid boolean value.")
        };
        var text = reader.ReadString(MaxStringBytes);
        reader.EnsureFinished();
        return new TransferResult(transferId, success, text);
    }

    public static void ParseBrowseRequest(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.BrowseRequest);
        reader.EnsureFinished();
    }

    public static int ParseBrowseListStart(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.BrowseListStart);
        var count = reader.ReadInt32();
        reader.EnsureFinished();
        return count;
    }

    public static RemoteFileEntry ParseBrowseEntry(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.BrowseEntry);
        var entry = new RemoteFileEntry(
            reader.ReadString(MaxPathBytes),
            reader.ReadInt64(),
            reader.ReadInt64());
        reader.EnsureFinished();
        return entry;
    }

    public static void ParseBrowseListEnd(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.BrowseListEnd);
        reader.EnsureFinished();
    }

    public static (int Count, int ReturnTransferPort) ParseDownloadRequestStart(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.DownloadRequestStart);
        var result = (reader.ReadInt32(), reader.ReadInt32());
        reader.EnsureFinished();
        return result;
    }

    public static string ParseDownloadRequestItem(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.DownloadRequestItem);
        var path = reader.ReadString(MaxPathBytes);
        reader.EnsureFinished();
        return path;
    }

    public static void ParseDownloadRequestCommit(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.DownloadRequestCommit);
        reader.EnsureFinished();
    }

    public static int ParseDownloadRequestAccepted(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.DownloadRequestAccepted);
        var count = reader.ReadInt32();
        reader.EnsureFinished();
        return count;
    }

    public static string ParseDownloadRequestRejected(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.DownloadRequestRejected);
        var reason = reader.ReadString(MaxStringBytes);
        reader.EnsureFinished();
        return reason;
    }

    public static string ParsePreviewRequest(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.PreviewRequest);
        var path = reader.ReadString(MaxPathBytes);
        reader.EnsureFinished();
        return path;
    }

    public static RemoteFilePreview ParsePreviewResponse(ReadOnlySpan<byte> message)
    {
        var reader = CreateReader(message, MessageType.PreviewResponse);
        var relativePath = reader.ReadString(MaxPathBytes);
        var rawKind = reader.ReadByte();
        if (!Enum.IsDefined((RemotePreviewKind)rawKind))
        {
            throw new InvalidDataException("Remote preview kind is invalid.");
        }

        var mediaType = reader.ReadString(MaxStringBytes);
        var data = reader.ReadBytes(ProtocolConstants.MaxPreviewBytes);
        var previewMessage = reader.ReadString(MaxStringBytes);
        reader.EnsureFinished();
        return new RemoteFilePreview(relativePath, (RemotePreviewKind)rawKind, mediaType, data, previewMessage);
    }

    private static byte[] Build(MessageType type, Action<ProtocolWriter> writeBody)
    {
        using var stream = new MemoryStream();
        stream.WriteByte((byte)type);
        var writer = new ProtocolWriter(stream);
        writeBody(writer);
        return stream.ToArray();
    }

    private static ProtocolReader CreateReader(ReadOnlySpan<byte> message, MessageType expectedType)
    {
        if (GetMessageType(message) != expectedType)
        {
            throw new InvalidDataException($"Expected {expectedType} message.");
        }

        return new ProtocolReader(message[1..].ToArray());
    }

    private sealed class ProtocolWriter(Stream stream)
    {
        public void WriteByte(byte value) => stream.WriteByte(value);

        public void WriteInt32(int value)
        {
            Span<byte> buffer = stackalloc byte[4];
            BinaryPrimitives.WriteInt32BigEndian(buffer, value);
            stream.Write(buffer);
        }

        public void WriteInt64(long value)
        {
            Span<byte> buffer = stackalloc byte[8];
            BinaryPrimitives.WriteInt64BigEndian(buffer, value);
            stream.Write(buffer);
        }

        public void WriteGuid(Guid value) => stream.Write(value.ToByteArray());

        public void WriteString(string value, int maximumBytes)
        {
            var bytes = StrictUtf8.GetBytes(value ?? string.Empty);
            if (bytes.Length > maximumBytes)
            {
                throw new InvalidDataException("Protocol string is too long.");
            }

            WriteInt32(bytes.Length);
            stream.Write(bytes);
        }

        public void WriteFixedBytes(ReadOnlySpan<byte> value, int expectedLength)
        {
            if (value.Length != expectedLength)
            {
                throw new InvalidDataException("Unexpected fixed field length.");
            }

            stream.Write(value);
        }

        public void WriteBytes(ReadOnlySpan<byte> value)
        {
            WriteInt32(value.Length);
            stream.Write(value);
        }
    }

    private sealed class ProtocolReader(byte[] data)
    {
        private int _position;

        public byte ReadByte()
        {
            EnsureAvailable(1);
            return data[_position++];
        }

        public int ReadInt32()
        {
            EnsureAvailable(4);
            var value = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(_position, 4));
            _position += 4;
            return value;
        }

        public long ReadInt64()
        {
            EnsureAvailable(8);
            var value = BinaryPrimitives.ReadInt64BigEndian(data.AsSpan(_position, 8));
            _position += 8;
            return value;
        }

        public Guid ReadGuid()
        {
            EnsureAvailable(16);
            var result = new Guid(data.AsSpan(_position, 16));
            _position += 16;
            return result;
        }

        public string ReadString(int maximumLength)
        {
            var length = ReadLength(maximumLength);
            try
            {
                var result = StrictUtf8.GetString(data, _position, length);
                _position += length;
                return result;
            }
            catch (DecoderFallbackException ex)
            {
                throw new InvalidDataException("Protocol string is not valid UTF-8.", ex);
            }
        }

        public byte[] ReadFixedBytes(int length)
        {
            EnsureAvailable(length);
            var result = data.AsSpan(_position, length).ToArray();
            _position += length;
            return result;
        }

        public byte[] ReadBytes(int maximumLength)
        {
            var length = ReadLength(maximumLength);
            var result = data.AsSpan(_position, length).ToArray();
            _position += length;
            return result;
        }

        public void EnsureFinished()
        {
            if (_position != data.Length)
            {
                throw new InvalidDataException("Protocol message contains trailing data.");
            }
        }

        private int ReadLength(int maximumLength)
        {
            var length = ReadInt32();
            if (length < 0 || length > maximumLength)
            {
                throw new InvalidDataException("Invalid protocol field length.");
            }

            EnsureAvailable(length);
            return length;
        }

        private void EnsureAvailable(int count)
        {
            if (count < 0 || _position > data.Length - count)
            {
                throw new EndOfStreamException("Truncated protocol message.");
            }
        }
    }
}
