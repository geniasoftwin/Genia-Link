using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using GeniaLink.Core.Network;

namespace GeniaLink.Core.Discovery;

public static class DiscoveryPacket
{
    private const int MaxNameBytes = 160;
    private const int FingerprintBytes = 16;
    private static readonly byte[] Magic = "GLD2"u8.ToArray();
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public static byte[] Create(DiscoveryAdvertisement advertisement)
    {
        ArgumentNullException.ThrowIfNull(advertisement);
        if (advertisement.DeviceId == Guid.Empty)
        {
            throw new InvalidDataException("Discovery device ID cannot be empty.");
        }

        ValidatePort(advertisement.TransferPort);
        ValidatePort(advertisement.PairingPort);
        ValidateDeviceName(advertisement.DeviceName);
        ValidateDeviceKind(advertisement.Kind);

        var nameBytes = StrictUtf8.GetBytes(advertisement.DeviceName);
        byte[] fingerprint;
        try
        {
            fingerprint = Convert.FromHexString(advertisement.PublicKeyFingerprint);
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("Invalid discovery public-key fingerprint.", ex);
        }

        if (fingerprint.Length != FingerprintBytes)
        {
            throw new InvalidDataException("Invalid discovery public-key fingerprint length.");
        }

        var packet = new byte[4 + 4 + 16 + 4 + 4 + 4 + nameBytes.Length + FingerprintBytes + 1];
        var offset = 0;
        Magic.CopyTo(packet, offset);
        offset += 4;
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(offset, 4), ProtocolConstants.Version);
        offset += 4;
        advertisement.DeviceId.TryWriteBytes(packet.AsSpan(offset, 16));
        offset += 16;
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(offset, 4), advertisement.TransferPort);
        offset += 4;
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(offset, 4), advertisement.PairingPort);
        offset += 4;
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(offset, 4), nameBytes.Length);
        offset += 4;
        nameBytes.CopyTo(packet, offset);
        offset += nameBytes.Length;
        fingerprint.CopyTo(packet, offset);
        offset += fingerprint.Length;
        packet[offset] = (byte)advertisement.Kind;
        CryptographicOperations.ZeroMemory(fingerprint);
        return packet;
    }

    public static DiscoveryAdvertisement Parse(ReadOnlySpan<byte> packet)
    {
        const int fixedSize = 4 + 4 + 16 + 4 + 4 + 4 + FingerprintBytes;
        if (packet.Length < fixedSize || !packet[..4].SequenceEqual(Magic))
        {
            throw new InvalidDataException("Invalid Genia Link discovery packet.");
        }

        var offset = 4;
        var version = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(offset, 4));
        offset += 4;
        if (version != ProtocolConstants.Version)
        {
            throw new InvalidDataException("Incompatible discovery protocol version.");
        }

        var deviceId = new Guid(packet.Slice(offset, 16));
        if (deviceId == Guid.Empty)
        {
            throw new InvalidDataException("Discovery device ID cannot be empty.");
        }

        offset += 16;
        var transferPort = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(offset, 4));
        offset += 4;
        var pairingPort = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(offset, 4));
        offset += 4;
        ValidatePort(transferPort);
        ValidatePort(pairingPort);

        var nameLength = BinaryPrimitives.ReadInt32BigEndian(packet.Slice(offset, 4));
        offset += 4;
        var legacyLength = fixedSize + nameLength;
        if (nameLength is < 1 or > MaxNameBytes ||
            (packet.Length != legacyLength && packet.Length != legacyLength + 1))
        {
            throw new InvalidDataException("Invalid discovery device-name length.");
        }

        string name;
        try
        {
            name = StrictUtf8.GetString(packet.Slice(offset, nameLength));
        }
        catch (DecoderFallbackException ex)
        {
            throw new InvalidDataException("Discovery device name is not valid UTF-8.", ex);
        }

        ValidateDeviceName(name);
        offset += nameLength;
        var fingerprint = Convert.ToHexString(packet.Slice(offset, FingerprintBytes));
        offset += FingerprintBytes;

        var deviceKind = DeviceKind.Unknown;
        if (packet.Length == legacyLength + 1)
        {
            deviceKind = (DeviceKind)packet[offset];
            ValidateDeviceKind(deviceKind);
        }

        return new DiscoveryAdvertisement(deviceId, name, transferPort, pairingPort, fingerprint, deviceKind);
    }

    private static void ValidateDeviceName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name) ||
            name.Any(ch => char.IsControl(ch) || CharUnicodeInfo.GetUnicodeCategory(ch) == UnicodeCategory.Format))
        {
            throw new InvalidDataException("Discovery device name contains unsafe characters.");
        }

        var byteCount = StrictUtf8.GetByteCount(name);
        if (byteCount is < 1 or > MaxNameBytes)
        {
            throw new InvalidDataException("Discovery device name is outside the allowed size.");
        }
    }

    private static void ValidateDeviceKind(DeviceKind deviceKind)
    {
        if (deviceKind is not DeviceKind.Unknown and
            not DeviceKind.WindowsComputer and
            not DeviceKind.AndroidPhone and
            not DeviceKind.AndroidTablet)
        {
            throw new InvalidDataException("Invalid discovery device kind.");
        }
    }

    private static void ValidatePort(int port)
    {
        if (port is <= 0 or > IPEndPoint.MaxPort)
        {
            throw new InvalidDataException("Invalid discovery TCP port.");
        }
    }
}
