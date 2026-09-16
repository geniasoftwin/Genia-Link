using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using GeniaLink.Core.Discovery;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Pairing;

namespace GeniaLink.Windows.Services;

internal sealed class LocalIdentity : IDeviceSigningIdentity, ISigningKeyRotationSource
{
    private const string AgreementKeyPrefix = "GeniaLink-ECDH-";
    private const string SigningKeyPrefix = "GeniaLink-ECDSA-";
    private const string RotationRequestFileName = "rotate-signing-key.request.json";
    private const long MaxRotationRequestBytes = 16 * 1024;
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };
    private static readonly object IdentityGate = new();
    private readonly string _identityPath;
    private readonly SigningKeyRotationCertificate[] _rotationChain;

    private LocalIdentity(
        Guid deviceId,
        string keyName,
        string signingKeyName,
        int keyGeneration,
        DateTimeOffset createdAtUtc,
        string identityPath,
        SigningKeyRotationCertificate[] rotationChain)
    {
        DeviceId = deviceId;
        KeyName = keyName;
        SigningKeyName = signingKeyName;
        KeyGeneration = keyGeneration;
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        _identityPath = identityPath;
        _rotationChain = rotationChain.Select(certificate => certificate.DeepCopy()).ToArray();
        SigningKeyId = GetSigningKeyId(signingKeyName);
    }

    public Guid DeviceId { get; }
    public string KeyName { get; }
    public string SigningKeyName { get; }
    public string DeviceName { get; } = Environment.MachineName;
    public int IdentityVersion { get; } = DeviceIdentityV2.CurrentVersion;
    public int KeyGeneration { get; }
    public DateTimeOffset CreatedAtUtc { get; }
    public DeviceKind DeviceKind { get; } = DeviceKind.WindowsComputer;
    public string DisplayName => DeviceName;
    public string SigningKeyId { get; }

    public static LocalIdentity LoadOrCreate(string appDataDirectory, Action<string>? log)
    {
        lock (IdentityGate)
        {
            return LoadOrCreateCore(appDataDirectory, log);
        }
    }

    private static LocalIdentity LoadOrCreateCore(string appDataDirectory, Action<string>? log)
    {
        Directory.CreateDirectory(appDataDirectory);
        var identityPath = Path.Combine(appDataDirectory, "identity.json");

        if (File.Exists(identityPath))
        {
            try
            {
                var json = File.ReadAllText(identityPath);
                var stored = JsonSerializer.Deserialize<StoredIdentity>(json);
                if (stored is not null &&
                    stored.DeviceId != Guid.Empty &&
                    !string.IsNullOrWhiteSpace(stored.KeyName) &&
                    stored.KeyName.StartsWith(AgreementKeyPrefix, StringComparison.Ordinal) &&
                    CngKey.Exists(stored.KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
                {
                    var signing = EnsureSigningKey(stored, log);
                    var rotationState = NormalizeStoredRotationChain(stored, signing, log);
                    var existing = new LocalIdentity(
                        stored.DeviceId,
                        stored.KeyName,
                        signing.KeyName,
                        signing.KeyGeneration,
                        signing.CreatedAtUtc,
                        identityPath,
                        rotationState.Chain);
                    existing.ValidateAgreementKey();
                    existing.ValidateSigningKey();
                    existing.ValidateRotationChain();

                    if (signing.MetadataChanged ||
                        rotationState.MetadataChanged ||
                        stored.IdentityVersion != DeviceIdentityV2.CurrentVersion ||
                        stored.KeyGeneration != signing.KeyGeneration ||
                        stored.CreatedAtUtc != signing.CreatedAtUtc ||
                        !string.Equals(stored.SigningKeyName, signing.KeyName, StringComparison.Ordinal))
                    {
                        existing.SaveMetadata();
                        log?.Invoke("Upgraded the existing Windows identity metadata without changing Device ID or ECDH key.");
                    }

                    return TryApplyRequestedSigningKeyRotation(existing, log);
                }

                log?.Invoke("Local identity metadata was incomplete; a new identity will be created.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or CryptographicException)
            {
                log?.Invoke($"Could not load local identity; a new identity will be created: {ex.Message}");
            }
        }

        return CreateNew(identityPath, log);
    }

    public byte[] ExportPublicKey()
    {
        using var key = CngKey.Open(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        using var ecdh = new ECDiffieHellmanCng(key);
        return ecdh.ExportSubjectPublicKeyInfo();
    }

    public byte[] DeriveSharedKey(ReadOnlySpan<byte> peerPublicKey)
    {
        using var key = CngKey.Open(KeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        using var local = new ECDiffieHellmanCng(key);
        using var peer = ECDiffieHellman.Create();
        var publicKeyCopy = peerPublicKey.ToArray();
        try
        {
            peer.ImportSubjectPublicKeyInfo(publicKeyCopy, out var bytesRead);
            if (bytesRead != publicKeyCopy.Length || peer.KeySize != 256)
            {
                throw new CryptographicException("Trusted peer key is not a valid ECDH P-256 public key.");
            }

            return local.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKeyCopy);
        }
    }

    public byte[] ExportSigningPublicKey()
    {
        using var key = CngKey.Open(SigningKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        using var ecdsa = new ECDsaCng(key);
        return ecdsa.ExportSubjectPublicKeyInfo();
    }

    public byte[] Sign(ReadOnlySpan<byte> payload)
    {
        using var key = CngKey.Open(SigningKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        using var ecdsa = new ECDsaCng(key);
        return ecdsa.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
    }

    public bool VerifySignature(ReadOnlySpan<byte> payload, ReadOnlySpan<byte> signature)
    {
        var publicKey = ExportSigningPublicKey();
        try
        {
            return DeviceSignature.Verify(publicKey, payload, signature);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    public SigningKeyRotationCertificate[] ExportSigningKeyRotationChain() =>
        _rotationChain.Select(certificate => certificate.DeepCopy()).ToArray();

    public static void RequestSigningKeyRotation(string appDataDirectory, LocalIdentity currentIdentity)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(appDataDirectory);
        ArgumentNullException.ThrowIfNull(currentIdentity);
        Directory.CreateDirectory(appDataDirectory);
        var request = new SigningKeyRotationRequest(
            currentIdentity.DeviceId,
            currentIdentity.KeyGeneration,
            currentIdentity.SigningKeyId,
            DateTimeOffset.UtcNow);
        var path = Path.Combine(appDataDirectory, RotationRequestFileName);
        var tempPath = path + ".tmp";
        try
        {
            File.WriteAllText(tempPath, JsonSerializer.Serialize(request, IndentedJsonOptions));
            File.Move(tempPath, path, overwrite: true);
        }
        finally
        {
            TryDeleteFile(tempPath);
        }
    }

    public DeviceIdentityV2 ToDeviceIdentityV2()
    {
        var publicKey = ExportSigningPublicKey();
        try
        {
            return new DeviceIdentityV2(DeviceId, DisplayName, DeviceKind, KeyGeneration, CreatedAtUtc, publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    public PairingPeerInfo ToPairingPeerInfo()
    {
        return new PairingPeerInfo(DeviceId, DeviceName, ExportPublicKey());
    }

    public string GetPublicKeyFingerprint()
    {
        var publicKey = ExportPublicKey();
        try
        {
            return PairingProtocol.GetPublicKeyFingerprint(publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static LocalIdentity CreateNew(string identityPath, Action<string>? log)
    {
        var deviceId = Guid.NewGuid();
        var agreementKeyName = AgreementKeyPrefix + deviceId.ToString("N");
        var signingKeyName = SigningKeyPrefix + deviceId.ToString("N");
        var agreementCreated = false;
        var signingCreated = false;
        try
        {
            CreateAgreementKey(agreementKeyName);
            agreementCreated = true;
            CreateSigningKey(signingKeyName);
            signingCreated = true;

            var identity = new LocalIdentity(
                deviceId,
                agreementKeyName,
                signingKeyName,
                1,
                DateTimeOffset.UtcNow,
                identityPath,
                []);
            identity.ValidateAgreementKey();
            identity.ValidateSigningKey();
            identity.SaveMetadata();
            log?.Invoke("Created a new Windows CNG identity with separate non-exportable ECDH and ECDSA P-256 private keys.");
            return identity;
        }
        catch
        {
            if (signingCreated)
            {
                TryDeleteKey(signingKeyName, log);
            }

            if (agreementCreated)
            {
                TryDeleteKey(agreementKeyName, log);
            }

            throw;
        }
    }

    private static SigningState EnsureSigningKey(StoredIdentity stored, Action<string>? log)
    {
        var expectedName = SigningKeyPrefix + stored.DeviceId.ToString("N");
        var signingKeyName = stored.SigningKeyName;
        var keyGeneration = stored.KeyGeneration >= 1 ? stored.KeyGeneration : 1;
        var createdAtUtc = stored.CreatedAtUtc == default
            ? DateTimeOffset.UtcNow
            : stored.CreatedAtUtc.ToUniversalTime();
        var continuityBroken = false;
        var metadataChanged = stored.IdentityVersion != DeviceIdentityV2.CurrentVersion ||
            stored.KeyGeneration < 1 ||
            stored.CreatedAtUtc == default;
        var hadSigningMetadata = !string.IsNullOrWhiteSpace(signingKeyName) &&
            signingKeyName.StartsWith(SigningKeyPrefix, StringComparison.Ordinal);

        if (!hadSigningMetadata)
        {
            signingKeyName = expectedName;
            if (!CngKey.Exists(signingKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            {
                CreateSigningKey(signingKeyName);
            }

            keyGeneration = 1;
            createdAtUtc = DateTimeOffset.UtcNow;
            metadataChanged = true;
        }
        else if (!CngKey.Exists(signingKeyName!, CngProvider.MicrosoftSoftwareKeyStorageProvider))
        {
            signingKeyName = expectedName;
            if (CngKey.Exists(signingKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            {
                TryDeleteKey(signingKeyName, log);
            }

            CreateSigningKey(signingKeyName);
            keyGeneration = checked(keyGeneration + 1);
            createdAtUtc = DateTimeOffset.UtcNow;
            metadataChanged = true;
            continuityBroken = true;
            log?.Invoke("Windows signing key was missing and was regenerated without continuity proof; existing peers will require explicit re-pairing for the new signing key.");
        }

        try
        {
            ValidateSigningKeyName(signingKeyName!);
        }
        catch (CryptographicException)
        {
            TryDeleteKey(signingKeyName!, log);
            signingKeyName = expectedName;
            if (CngKey.Exists(signingKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            {
                TryDeleteKey(signingKeyName, log);
            }

            CreateSigningKey(signingKeyName);
            keyGeneration = checked(keyGeneration + 1);
            createdAtUtc = DateTimeOffset.UtcNow;
            metadataChanged = true;
            continuityBroken = true;
            log?.Invoke("Windows signing key failed validation and was regenerated without continuity proof; existing peers will require explicit re-pairing for the new signing key.");
        }

        return new SigningState(signingKeyName!, keyGeneration, createdAtUtc, metadataChanged, continuityBroken);
    }

    private static void CreateAgreementKey(string keyName)
    {
        var creation = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.KeyAgreement
        };

        using (CngKey.Create(CngAlgorithm.ECDiffieHellmanP256, keyName, creation))
        {
        }
    }

    private static void CreateSigningKey(string keyName)
    {
        var creation = new CngKeyCreationParameters
        {
            Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
            ExportPolicy = CngExportPolicies.None,
            KeyUsage = CngKeyUsages.Signing
        };

        using (CngKey.Create(CngAlgorithm.ECDsaP256, keyName, creation))
        {
        }
    }

    private static void ValidateSigningKeyName(string signingKeyName)
    {
        using var key = CngKey.Open(signingKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        using var ecdsa = new ECDsaCng(key);
        if (ecdsa.KeySize != DeviceSignature.P256KeySizeBits)
        {
            throw new CryptographicException("Windows signing key is not ECDSA P-256.");
        }

        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        try
        {
            DeviceSignature.ValidatePublicKey(publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static string GetSigningKeyId(string signingKeyName)
    {
        using var key = CngKey.Open(signingKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        using var ecdsa = new ECDsaCng(key);
        var publicKey = ecdsa.ExportSubjectPublicKeyInfo();
        try
        {
            return DeviceSignature.GetSigningKeyId(publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static void TryDeleteKey(string keyName, Action<string>? log)
    {
        try
        {
            if (!CngKey.Exists(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            {
                return;
            }

            using var key = CngKey.Open(keyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
            key.Delete();
        }
        catch (CryptographicException ex)
        {
            log?.Invoke($"Could not remove an unused Windows CNG key: {ex.Message}");
        }
    }

    private static RotationState NormalizeStoredRotationChain(StoredIdentity stored, SigningState signing, Action<string>? log)
    {
        if (signing.ContinuityBroken)
        {
            return new RotationState([], stored.SigningKeyRotationChain is { Length: > 0 });
        }

        var storedChain = stored.SigningKeyRotationChain ?? [];
        if (storedChain.Length == 0)
        {
            return new RotationState([], false);
        }

        try
        {
            var publicKey = ExportSigningPublicKey(signing.KeyName);
            try
            {
                var presentation = new TrustedSigningIdentity(
                    stored.DeviceId,
                    DeviceIdentityV2.CurrentVersion,
                    signing.KeyGeneration,
                    publicKey,
                    storedChain.Select(certificate => certificate.DeepCopy()).ToArray());
                presentation.Validate();
                return new RotationState(storedChain.Select(certificate => certificate.DeepCopy()).ToArray(), false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(publicKey);
            }
        }
        catch (Exception ex) when (ex is InvalidDataException or CryptographicException or ArgumentException)
        {
            log?.Invoke($"Stored Windows signing-key rotation chain was invalid and was discarded safely; existing peers may require explicit re-pairing: {ex.Message}");
            return new RotationState([], true);
        }
    }

    private static LocalIdentity TryApplyRequestedSigningKeyRotation(LocalIdentity existing, Action<string>? log)
    {
        var directory = Path.GetDirectoryName(existing._identityPath) ?? string.Empty;
        var requestPath = Path.Combine(directory, RotationRequestFileName);
        if (!File.Exists(requestPath))
        {
            return existing;
        }

        try
        {
            if (new FileInfo(requestPath).Length > MaxRotationRequestBytes)
            {
                throw new InvalidDataException("Signing-key rotation request is unexpectedly large.");
            }

            var request = JsonSerializer.Deserialize<SigningKeyRotationRequest>(File.ReadAllText(requestPath))
                ?? throw new InvalidDataException("Signing-key rotation request is empty.");
            if (request.DeviceId != existing.DeviceId ||
                request.ExpectedKeyGeneration != existing.KeyGeneration ||
                !string.Equals(request.ExpectedSigningKeyId, existing.SigningKeyId, StringComparison.OrdinalIgnoreCase))
            {
                TryDeleteFile(requestPath);
                log?.Invoke("Discarded a stale Windows signing-key rotation request because the local identity has already changed.");
                return existing;
            }

            return RotateSigningKey(existing, requestPath, log);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or CryptographicException or OverflowException)
        {
            log?.Invoke($"Windows signing-key rotation request was not applied: {ex.Message}");
            return existing;
        }
    }

    private static LocalIdentity RotateSigningKey(LocalIdentity existing, string requestPath, Action<string>? log)
    {
        var newGeneration = checked(existing.KeyGeneration + 1);
        var newSigningKeyName = $"{SigningKeyPrefix}{existing.DeviceId:N}-g{newGeneration}";
        var newKeyCreated = false;
        byte[]? newPublicKey = null;
        try
        {
            if (CngKey.Exists(newSigningKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider))
            {
                TryDeleteKey(newSigningKeyName, log);
            }

            CreateSigningKey(newSigningKeyName);
            newKeyCreated = true;
            newPublicKey = ExportSigningPublicKey(newSigningKeyName);
            var certificate = SigningKeyRotationCertificate.Create(existing, newGeneration, newPublicKey);
            var chain = existing.ExportSigningKeyRotationChain().ToList();
            chain.Add(certificate);
            if (chain.Count > SigningKeyRotationCertificate.MaxChainLength)
            {
                chain.RemoveRange(0, chain.Count - SigningKeyRotationCertificate.MaxChainLength);
            }

            var rotated = new LocalIdentity(
                existing.DeviceId,
                existing.KeyName,
                newSigningKeyName,
                newGeneration,
                DateTimeOffset.UtcNow,
                existing._identityPath,
                chain.ToArray());
            rotated.ValidateAgreementKey();
            rotated.ValidateSigningKey();
            rotated.ValidateRotationChain();
            rotated.SaveMetadata();
            TryDeleteFile(requestPath);
            if (!string.Equals(existing.SigningKeyName, newSigningKeyName, StringComparison.Ordinal))
            {
                TryDeleteKey(existing.SigningKeyName, log);
            }

            log?.Invoke($"GNP/1 M2.4.2 Windows signing key rotated with continuity proof: generation {existing.KeyGeneration} -> {newGeneration}.");
            newKeyCreated = false;
            return rotated;
        }
        catch
        {
            if (newKeyCreated)
            {
                TryDeleteKey(newSigningKeyName, log);
            }

            throw;
        }
        finally
        {
            if (newPublicKey is not null)
            {
                CryptographicOperations.ZeroMemory(newPublicKey);
            }
        }
    }

    private static byte[] ExportSigningPublicKey(string signingKeyName)
    {
        using var key = CngKey.Open(signingKeyName, CngProvider.MicrosoftSoftwareKeyStorageProvider);
        using var ecdsa = new ECDsaCng(key);
        return ecdsa.ExportSubjectPublicKeyInfo();
    }

    private void ValidateRotationChain()
    {
        if (_rotationChain.Length == 0)
        {
            return;
        }

        var publicKey = ExportSigningPublicKey();
        try
        {
            var presentation = new TrustedSigningIdentity(
                DeviceId,
                IdentityVersion,
                KeyGeneration,
                publicKey,
                ExportSigningKeyRotationChain());
            presentation.Validate();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private void ValidateAgreementKey()
    {
        var publicKey = ExportPublicKey();
        try
        {
            PairingProtocol.ValidatePublicKey(publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private void ValidateSigningKey()
    {
        ValidateSigningKeyName(SigningKeyName);
    }

    private void SaveMetadata()
    {
        var json = JsonSerializer.Serialize(
            new StoredIdentity
            {
                DeviceId = DeviceId,
                KeyName = KeyName,
                IdentityVersion = IdentityVersion,
                SigningKeyName = SigningKeyName,
                KeyGeneration = KeyGeneration,
                CreatedAtUtc = CreatedAtUtc,
                SigningKeyRotationChain = ExportSigningKeyRotationChain()
            },
            IndentedJsonOptions);
        var tempPath = _identityPath + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, _identityPath, overwrite: true);
    }

    private sealed class StoredIdentity
    {
        public Guid DeviceId { get; init; }
        public string? KeyName { get; init; }
        public int IdentityVersion { get; init; }
        public string? SigningKeyName { get; init; }
        public int KeyGeneration { get; init; }
        public DateTimeOffset CreatedAtUtc { get; init; }
        public SigningKeyRotationCertificate[]? SigningKeyRotationChain { get; init; }
    }

    private sealed record SigningState(
        string KeyName,
        int KeyGeneration,
        DateTimeOffset CreatedAtUtc,
        bool MetadataChanged,
        bool ContinuityBroken);

    private sealed record RotationState(SigningKeyRotationCertificate[] Chain, bool MetadataChanged);

    private sealed record SigningKeyRotationRequest(
        Guid DeviceId,
        int ExpectedKeyGeneration,
        string ExpectedSigningKeyId,
        DateTimeOffset RequestedAtUtc);
}
