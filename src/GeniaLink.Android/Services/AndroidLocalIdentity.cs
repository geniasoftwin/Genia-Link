using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using Android.Security.Keystore;
using GeniaLink.Core.Discovery;
using GeniaLink.Core.Identity;
using GeniaLink.Core.Pairing;
using Java.Security;
using Java.Security.Spec;
using Javax.Crypto;

namespace GeniaLink.Android.Services;

internal sealed class AndroidLocalIdentity : IDeviceSigningIdentity, ISigningKeyRotationSource
{
    private const long MaxIdentityMetadataBytes = 64 * 1024;
    private const string AgreementKeyPrefix = "GeniaLink-ECDH-";
    private const string PrimaryAgreementKeyAlias = AgreementKeyPrefix + "Identity";
    private const string SigningKeyPrefix = "GeniaLink-ECDSA-";
    private const string PrimarySigningKeyAlias = SigningKeyPrefix + "Signing";
    private const string RotationRequestFileName = "rotate-signing-key.request.json";
    private const long MaxRotationRequestBytes = 16 * 1024;
    private const string AndroidKeyStoreProvider = "AndroidKeyStore";
    private static readonly JsonSerializerOptions IndentedJsonOptions = new() { WriteIndented = true };
    private static readonly object IdentityGate = new();
    private readonly string _identityPath;
    private readonly SigningKeyRotationCertificate[] _rotationChain;

    private AndroidLocalIdentity(
        Guid deviceId,
        string keyAlias,
        string signingKeyAlias,
        string deviceName,
        DeviceKind deviceKind,
        int keyGeneration,
        DateTimeOffset createdAtUtc,
        string identityPath,
        SigningKeyRotationCertificate[] rotationChain)
    {
        DeviceId = deviceId;
        KeyAlias = keyAlias;
        SigningKeyAlias = signingKeyAlias;
        DeviceName = deviceName;
        DeviceKind = deviceKind;
        KeyGeneration = keyGeneration;
        CreatedAtUtc = createdAtUtc.ToUniversalTime();
        _identityPath = identityPath;
        _rotationChain = rotationChain.Select(certificate => certificate.DeepCopy()).ToArray();
        SigningKeyId = GetSigningKeyId(signingKeyAlias);
    }

    public Guid DeviceId { get; }
    public string KeyAlias { get; }
    public string SigningKeyAlias { get; }
    public string DeviceName { get; }
    public int IdentityVersion { get; } = DeviceIdentityV2.CurrentVersion;
    public int KeyGeneration { get; }
    public DateTimeOffset CreatedAtUtc { get; }
    public DeviceKind DeviceKind { get; }
    public string DisplayName => DeviceName;
    public string SigningKeyId { get; }

    public static AndroidLocalIdentity LoadOrCreate(global::Android.Content.Context context, Action<string>? log)
    {
        ArgumentNullException.ThrowIfNull(context);
        lock (IdentityGate)
        {
            return LoadOrCreateCore(context, log);
        }
    }

    private static AndroidLocalIdentity LoadOrCreateCore(global::Android.Content.Context context, Action<string>? log)
    {
        var filesDirectory = context.FilesDir?.AbsolutePath ?? throw new IOException("Android app files directory is unavailable.");
        Directory.CreateDirectory(filesDirectory);
        var identityPath = Path.Combine(filesDirectory, "identity.json");
        var deviceName = AndroidDeviceNaming.GetSafeDeviceName();
        var deviceKind = AndroidDeviceNaming.GetDeviceKind(context);

        string? invalidStoredAgreementAlias = null;
        string? invalidStoredSigningAlias = null;
        if (File.Exists(identityPath))
        {
            try
            {
                if (new FileInfo(identityPath).Length > MaxIdentityMetadataBytes)
                {
                    throw new InvalidDataException("Android identity metadata is unexpectedly large.");
                }

                var json = File.ReadAllText(identityPath);
                var stored = JsonSerializer.Deserialize<StoredIdentity>(json);
                if (stored is not null &&
                    !string.IsNullOrWhiteSpace(stored.KeyAlias) &&
                    stored.KeyAlias.StartsWith(AgreementKeyPrefix, StringComparison.Ordinal) &&
                    KeyExists(stored.KeyAlias))
                {
                    invalidStoredAgreementAlias = stored.KeyAlias;
                    if (!string.IsNullOrWhiteSpace(stored.SigningKeyAlias) &&
                        stored.SigningKeyAlias.StartsWith(SigningKeyPrefix, StringComparison.Ordinal))
                    {
                        invalidStoredSigningAlias = stored.SigningKeyAlias;
                    }

                    if (stored.DeviceId != Guid.Empty)
                    {
                        var signing = EnsureSigningKey(stored, log);
                        var rotationState = NormalizeStoredRotationChain(stored, signing, log);
                        var existing = new AndroidLocalIdentity(
                            stored.DeviceId,
                            stored.KeyAlias,
                            signing.KeyAlias,
                            deviceName,
                            deviceKind,
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
                            !string.Equals(stored.SigningKeyAlias, signing.KeyAlias, StringComparison.Ordinal))
                        {
                            existing.SaveMetadata();
                            log?.Invoke("Upgraded the existing Android identity metadata without changing Device ID or ECDH key.");
                        }

                        return TryApplyRequestedSigningKeyRotation(existing, log);
                    }
                }

                log?.Invoke("Android identity metadata or Keystore entry was incomplete; a new identity will be created.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or CryptographicException or InvalidOperationException or InvalidDataException)
            {
                log?.Invoke($"Could not load Android identity; a new identity will be created: {ex.Message}");
            }
        }

        if (invalidStoredAgreementAlias is not null && !string.Equals(invalidStoredAgreementAlias, PrimaryAgreementKeyAlias, StringComparison.Ordinal))
        {
            TryDeleteKey(invalidStoredAgreementAlias, log);
        }

        if (invalidStoredSigningAlias is not null && !string.Equals(invalidStoredSigningAlias, PrimarySigningKeyAlias, StringComparison.Ordinal))
        {
            TryDeleteKey(invalidStoredSigningAlias, log);
        }

        return CreateNew(identityPath, deviceName, deviceKind, log);
    }

    public byte[] ExportPublicKey()
    {
        return ExportPublicKey(KeyAlias, "Android Keystore public certificate is missing.");
    }

    public byte[] DeriveSharedKey(ReadOnlySpan<byte> peerPublicKey)
    {
        var peerKeyBytes = peerPublicKey.ToArray();
        byte[]? rawSecret = null;
        try
        {
            PairingProtocol.ValidatePublicKey(peerKeyBytes);

            using var keyStore = OpenKeyStore();
            var privateKey = keyStore.GetKey(KeyAlias, null)
                ?? throw new CryptographicException("Android Keystore private key is missing.");
            try
            {
                using var keyFactory = KeyFactory.GetInstance(KeyProperties.KeyAlgorithmEc)
                    ?? throw new CryptographicException("Android EC KeyFactory is unavailable.");
                using var publicKeySpec = new X509EncodedKeySpec(peerKeyBytes);
                var remotePublicKey = keyFactory.GeneratePublic(publicKeySpec)
                    ?? throw new CryptographicException("Peer ECDH public key could not be imported.");
                try
                {
                    using var agreement = KeyAgreement.GetInstance("ECDH", AndroidKeyStoreProvider)
                        ?? throw new CryptographicException("Android Keystore ECDH provider is unavailable.");
                    agreement.Init(privateKey);
                    agreement.DoPhase(remotePublicKey, true);
                    rawSecret = agreement.GenerateSecret()
                        ?? throw new CryptographicException("Android Keystore did not produce an ECDH shared secret.");
                    return SHA256.HashData(rawSecret);
                }
                finally
                {
                    remotePublicKey.Dispose();
                }
            }
            finally
            {
                privateKey.Dispose();
            }
        }
        catch (Exception ex) when (ex is Java.Security.GeneralSecurityException or InvalidDataException)
        {
            throw new CryptographicException("Android ECDH key agreement failed.", ex);
        }
        finally
        {
            if (rawSecret is not null)
            {
                CryptographicOperations.ZeroMemory(rawSecret);
            }

            CryptographicOperations.ZeroMemory(peerKeyBytes);
        }
    }

    public byte[] ExportSigningPublicKey()
    {
        return ExportPublicKey(SigningKeyAlias, "Android Keystore signing certificate is missing.");
    }

    public byte[] Sign(ReadOnlySpan<byte> payload)
    {
        var payloadCopy = payload.ToArray();
        try
        {
            using var keyStore = OpenKeyStore();
            var entry = keyStore.GetEntry(SigningKeyAlias, null)
                ?? throw new CryptographicException("Android Keystore signing private-key entry is missing.");
            try
            {
                if (entry is not KeyStore.PrivateKeyEntry privateKeyEntry)
                {
                    throw new CryptographicException("Android Keystore signing entry is not a PrivateKeyEntry.");
                }

                var privateKey = privateKeyEntry.PrivateKey
                    ?? throw new CryptographicException("Android Keystore signing private key is missing.");
                try
                {
                    using var signer = Signature.GetInstance("SHA256withECDSA")
                        ?? throw new CryptographicException("Android ECDSA signature engine is unavailable.");
                    signer.InitSign(privateKey);
                    signer.Update(payloadCopy);
                    return signer.Sign()
                        ?? throw new CryptographicException("Android Keystore did not produce an ECDSA signature.");
                }
                finally
                {
                    privateKey.Dispose();
                }
            }
            finally
            {
                entry.Dispose();
            }
        }
        catch (Java.Security.GeneralSecurityException ex)
        {
            throw new CryptographicException("Android ECDSA signing failed.", ex);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(payloadCopy);
        }
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

    public static void RequestSigningKeyRotation(global::Android.Content.Context context, AndroidLocalIdentity currentIdentity)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(currentIdentity);
        var filesDirectory = context.FilesDir?.AbsolutePath ?? throw new IOException("Android app files directory is unavailable.");
        Directory.CreateDirectory(filesDirectory);
        var request = new SigningKeyRotationRequest(
            currentIdentity.DeviceId,
            currentIdentity.KeyGeneration,
            currentIdentity.SigningKeyId,
            DateTimeOffset.UtcNow);
        var path = Path.Combine(filesDirectory, RotationRequestFileName);
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

    public PairingPeerInfo ToPairingPeerInfo() => new(DeviceId, DeviceName, ExportPublicKey());

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

    private static AndroidLocalIdentity CreateNew(
        string identityPath,
        string deviceName,
        DeviceKind deviceKind,
        Action<string>? log)
    {
        // Fixed app-owned aliases prevent repeated metadata corruption from accumulating
        // new Keystore entries. A full identity reset rotates both keys together.
        TryDeleteKey(PrimaryAgreementKeyAlias, log);
        TryDeleteKey(PrimarySigningKeyAlias, log);

        var deviceId = Guid.NewGuid();
        var agreementCreated = false;
        var signingCreated = false;
        try
        {
            CreateAgreementKey(PrimaryAgreementKeyAlias);
            agreementCreated = true;
            CreateSigningKey(PrimarySigningKeyAlias);
            signingCreated = true;

            var identity = new AndroidLocalIdentity(
                deviceId,
                PrimaryAgreementKeyAlias,
                PrimarySigningKeyAlias,
                deviceName,
                deviceKind,
                1,
                DateTimeOffset.UtcNow,
                identityPath,
                []);
            identity.ValidateAgreementKey();
            identity.ValidateSigningKey();
            identity.SaveMetadata();
            log?.Invoke("Created Android Keystore identity with separate non-exportable ECDH and ECDSA P-256 private keys.");
            return identity;
        }
        catch
        {
            if (signingCreated)
            {
                TryDeleteKey(PrimarySigningKeyAlias, log);
            }

            if (agreementCreated)
            {
                TryDeleteKey(PrimaryAgreementKeyAlias, log);
            }

            throw;
        }
    }

    private static SigningState EnsureSigningKey(StoredIdentity stored, Action<string>? log)
    {
        var signingKeyAlias = stored.SigningKeyAlias;
        var keyGeneration = stored.KeyGeneration >= 1 ? stored.KeyGeneration : 1;
        var createdAtUtc = stored.CreatedAtUtc == default
            ? DateTimeOffset.UtcNow
            : stored.CreatedAtUtc.ToUniversalTime();
        var continuityBroken = false;
        var metadataChanged = stored.IdentityVersion != DeviceIdentityV2.CurrentVersion ||
            stored.KeyGeneration < 1 ||
            stored.CreatedAtUtc == default;
        var hadSigningMetadata = !string.IsNullOrWhiteSpace(signingKeyAlias) &&
            signingKeyAlias.StartsWith(SigningKeyPrefix, StringComparison.Ordinal);

        if (!hadSigningMetadata)
        {
            signingKeyAlias = PrimarySigningKeyAlias;
            if (!KeyExists(signingKeyAlias))
            {
                CreateSigningKey(signingKeyAlias);
            }

            keyGeneration = 1;
            createdAtUtc = DateTimeOffset.UtcNow;
            metadataChanged = true;
        }
        else if (!KeyExists(signingKeyAlias!))
        {
            signingKeyAlias = PrimarySigningKeyAlias;
            TryDeleteKey(signingKeyAlias, log);
            CreateSigningKey(signingKeyAlias);
            keyGeneration = checked(keyGeneration + 1);
            createdAtUtc = DateTimeOffset.UtcNow;
            metadataChanged = true;
            continuityBroken = true;
            log?.Invoke("Android signing key was missing and was regenerated without continuity proof; existing peers will require explicit re-pairing for the new signing key.");
        }

        try
        {
            ValidateSigningKeyAlias(signingKeyAlias!);
        }
        catch (CryptographicException)
        {
            TryDeleteKey(signingKeyAlias!, log);
            signingKeyAlias = PrimarySigningKeyAlias;
            TryDeleteKey(signingKeyAlias, log);
            CreateSigningKey(signingKeyAlias);
            keyGeneration = checked(keyGeneration + 1);
            createdAtUtc = DateTimeOffset.UtcNow;
            metadataChanged = true;
            continuityBroken = true;
            log?.Invoke("Android signing key failed validation and was regenerated without continuity proof; existing peers will require explicit re-pairing for the new signing key.");
        }

        return new SigningState(signingKeyAlias!, keyGeneration, createdAtUtc, metadataChanged, continuityBroken);
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
            var publicKey = ExportPublicKey(signing.KeyAlias, "Android Keystore signing certificate is missing.");
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
            log?.Invoke($"Stored Android signing-key rotation chain was invalid and was discarded safely; existing peers may require explicit re-pairing: {ex.Message}");
            return new RotationState([], true);
        }
    }

    private static AndroidLocalIdentity TryApplyRequestedSigningKeyRotation(AndroidLocalIdentity existing, Action<string>? log)
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
                log?.Invoke("Discarded a stale Android signing-key rotation request because the local identity has already changed.");
                return existing;
            }

            return RotateSigningKey(existing, requestPath, log);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or CryptographicException or OverflowException)
        {
            log?.Invoke($"Android signing-key rotation request was not applied: {ex.Message}");
            return existing;
        }
    }

    private static AndroidLocalIdentity RotateSigningKey(AndroidLocalIdentity existing, string requestPath, Action<string>? log)
    {
        var newGeneration = checked(existing.KeyGeneration + 1);
        var newSigningKeyAlias = $"{PrimarySigningKeyAlias}-g{newGeneration}";
        var newKeyCreated = false;
        byte[]? newPublicKey = null;
        try
        {
            if (KeyExists(newSigningKeyAlias))
            {
                TryDeleteKey(newSigningKeyAlias, log);
            }

            CreateSigningKey(newSigningKeyAlias);
            newKeyCreated = true;
            newPublicKey = ExportPublicKey(newSigningKeyAlias, "Android Keystore rotated signing certificate is missing.");
            var certificate = SigningKeyRotationCertificate.Create(existing, newGeneration, newPublicKey);
            var chain = existing.ExportSigningKeyRotationChain().ToList();
            chain.Add(certificate);
            if (chain.Count > SigningKeyRotationCertificate.MaxChainLength)
            {
                chain.RemoveRange(0, chain.Count - SigningKeyRotationCertificate.MaxChainLength);
            }

            var rotated = new AndroidLocalIdentity(
                existing.DeviceId,
                existing.KeyAlias,
                newSigningKeyAlias,
                existing.DeviceName,
                existing.DeviceKind,
                newGeneration,
                DateTimeOffset.UtcNow,
                existing._identityPath,
                chain.ToArray());
            rotated.ValidateAgreementKey();
            rotated.ValidateSigningKey();
            rotated.ValidateRotationChain();
            rotated.SaveMetadata();
            TryDeleteFile(requestPath);
            if (!string.Equals(existing.SigningKeyAlias, newSigningKeyAlias, StringComparison.Ordinal))
            {
                TryDeleteKey(existing.SigningKeyAlias, log);
            }

            log?.Invoke($"GNP/1 M2.4.2 Android signing key rotated with continuity proof: generation {existing.KeyGeneration} -> {newGeneration}.");
            newKeyCreated = false;
            return rotated;
        }
        catch
        {
            if (newKeyCreated)
            {
                TryDeleteKey(newSigningKeyAlias, log);
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

    private static byte[] ExportPublicKey(string alias, string missingCertificateMessage)
    {
        try
        {
            using var keyStore = OpenKeyStore();
            using var certificate = keyStore.GetCertificate(alias)
                ?? throw new CryptographicException(missingCertificateMessage);
            var publicKey = certificate.PublicKey
                ?? throw new CryptographicException("Android Keystore public key is missing.");
            try
            {
                return publicKey.GetEncoded()
                    ?? throw new CryptographicException("Android Keystore did not export the public key.");
            }
            finally
            {
                publicKey.Dispose();
            }
        }
        catch (Java.Security.GeneralSecurityException ex)
        {
            throw new CryptographicException("Android Keystore public key could not be read.", ex);
        }
    }

    private static bool KeyExists(string alias)
    {
        try
        {
            using var keyStore = OpenKeyStore();
            return keyStore.ContainsAlias(alias);
        }
        catch (Java.Security.GeneralSecurityException ex)
        {
            throw new CryptographicException("Android Keystore alias could not be checked.", ex);
        }
    }

    private static void TryDeleteKey(string alias, Action<string>? log)
    {
        try
        {
            using var keyStore = OpenKeyStore();
            if (keyStore.ContainsAlias(alias))
            {
                keyStore.DeleteEntry(alias);
            }
        }
        catch (Exception ex) when (ex is Java.Security.GeneralSecurityException or CryptographicException)
        {
            log?.Invoke($"Could not remove an unused Android Keystore key: {ex.Message}");
        }
    }

    private static void CreateAgreementKey(string alias)
    {
        try
        {
            using var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmEc, AndroidKeyStoreProvider)
                ?? throw new CryptographicException("Android Keystore EC generator is unavailable.");
            using var curve = new ECGenParameterSpec("secp256r1");
            using var builder = new KeyGenParameterSpec.Builder(alias, KeyStorePurpose.AgreeKey);
            builder.SetAlgorithmParameterSpec(curve);
            using var specification = builder.Build();
            generator.Initialize(specification);
            using var keyPair = generator.GenerateKeyPair()
                ?? throw new CryptographicException("Android Keystore did not create an ECDH key pair.");
        }
        catch (Java.Security.GeneralSecurityException ex)
        {
            throw new CryptographicException("Could not create Android Keystore ECDH key.", ex);
        }
    }

    private static void CreateSigningKey(string alias)
    {
        try
        {
            using var generator = KeyPairGenerator.GetInstance(KeyProperties.KeyAlgorithmEc, AndroidKeyStoreProvider)
                ?? throw new CryptographicException("Android Keystore EC generator is unavailable.");
            using var curve = new ECGenParameterSpec("secp256r1");
            using var builder = new KeyGenParameterSpec.Builder(alias, KeyStorePurpose.Sign | KeyStorePurpose.Verify);
            builder.SetAlgorithmParameterSpec(curve);
            builder.SetDigests(KeyProperties.DigestSha256);
            using var specification = builder.Build();
            generator.Initialize(specification);
            using var keyPair = generator.GenerateKeyPair()
                ?? throw new CryptographicException("Android Keystore did not create an ECDSA signing key pair.");
        }
        catch (Java.Security.GeneralSecurityException ex)
        {
            throw new CryptographicException("Could not create Android Keystore ECDSA signing key.", ex);
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
        ValidateSigningKeyAlias(SigningKeyAlias);
    }

    private static void ValidateSigningKeyAlias(string alias)
    {
        var publicKey = ExportPublicKey(alias, "Android Keystore signing certificate is missing.");
        try
        {
            DeviceSignature.ValidatePublicKey(publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static string GetSigningKeyId(string alias)
    {
        var publicKey = ExportPublicKey(alias, "Android Keystore signing certificate is missing.");
        try
        {
            return DeviceSignature.GetSigningKeyId(publicKey);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(publicKey);
        }
    }

    private static KeyStore OpenKeyStore()
    {
        try
        {
            var keyStore = KeyStore.GetInstance(AndroidKeyStoreProvider)
                ?? throw new CryptographicException("Android Keystore provider is unavailable.");
            keyStore.Load(null);
            return keyStore;
        }
        catch (Exception ex) when (ex is Java.Security.GeneralSecurityException or Java.IO.IOException)
        {
            throw new CryptographicException("Android Keystore could not be opened.", ex);
        }
    }

    private void SaveMetadata()
    {
        var json = JsonSerializer.Serialize(
            new StoredIdentity
            {
                DeviceId = DeviceId,
                KeyAlias = KeyAlias,
                IdentityVersion = IdentityVersion,
                SigningKeyAlias = SigningKeyAlias,
                KeyGeneration = KeyGeneration,
                CreatedAtUtc = CreatedAtUtc,
                SigningKeyRotationChain = ExportSigningKeyRotationChain()
            },
            IndentedJsonOptions);
        var tempPath = _identityPath + ".tmp";
        try
        {
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _identityPath, overwrite: true);
        }
        finally
        {
            try
            {
                File.Delete(tempPath);
            }
            catch (IOException)
            {
                // identity.json is authoritative; stale temp metadata is ignored on load.
            }
            catch (UnauthorizedAccessException)
            {
                // identity.json is authoritative; stale temp metadata is ignored on load.
            }
        }
    }

    private sealed class StoredIdentity
    {
        public Guid DeviceId { get; init; }
        public string? KeyAlias { get; init; }
        public int IdentityVersion { get; init; }
        public string? SigningKeyAlias { get; init; }
        public int KeyGeneration { get; init; }
        public DateTimeOffset CreatedAtUtc { get; init; }
        public SigningKeyRotationCertificate[]? SigningKeyRotationChain { get; init; }
    }

    private sealed record SigningState(
        string KeyAlias,
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
