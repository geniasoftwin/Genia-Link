param(
    [switch]$IncludeAndroid
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$windowsProject = Join-Path $root 'src\GeniaLink.Windows\GeniaLink.Windows.csproj'
$selfTestProject = Join-Path $root 'src\GeniaLink.SelfTest\GeniaLink.SelfTest.csproj'
$androidProject = Join-Path $root 'src\GeniaLink.Android\GeniaLink.Android.csproj'

Write-Host '1/4 Build with .NET analyzers and warnings-as-errors'
# Build explicit projects instead of the whole solution. This keeps the proven Windows
# portable pipeline usable on machines that do not have the Android workload installed.
dotnet build $windowsProject -c Release --nologo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
dotnet build $selfTestProject -c Release --nologo
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if ($IncludeAndroid) {
    Write-Host '    Android workload check enabled: building GeniaLink.Android'
    dotnet build $androidProject -c Release --nologo
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

Write-Host '2/4 Run protocol/security self-tests'
dotnet run --project $selfTestProject -c Release --no-build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '3/4 Verify zero third-party PackageReference dependencies'
$projectFiles = Get-ChildItem (Join-Path $root 'src') -Recurse -File -Filter *.csproj
$packageReferences = $projectFiles | Select-String -Pattern '<PackageReference\b'
if ($packageReferences) {
    $packageReferences | ForEach-Object { Write-Host $_ }
    throw 'PackageReference found. Genia Link v0.3.1 RC4 is expected to have zero third-party NuGet dependencies.'
}

Write-Host '4/4 Offline cloud/risky-API static scan'
$patterns = @(
    'BinaryFormatter',
    'LosFormatter',
    'ObjectStateFormatter',
    'Assembly\.Load',
    'Assembly\.LoadFrom',
    'DllImport',
    'LibraryImport',
    'HttpClient',
    'HttpWebRequest',
    'WebClient',
    'GrpcChannel',
    'RestClient',
    'DangerousAcceptAnyServerCertificateValidator',
    'CertificateValidationCallback',
    'ApplicationInsights',
    'TelemetryClient',
    'Firebase',
    'Azure\.',
    'Sentry',
    'https?://'
)
$sourceFiles = Get-ChildItem (Join-Path $root 'src') -Recurse -File -Include *.cs
$matches = $sourceFiles | Select-String -Pattern $patterns
if ($matches) {
    $matches | ForEach-Object { Write-Host $_ }
    throw 'Offline/risky-API scan found code that requires manual security review.'
}

# Process.Start is allowed exactly once for the user-initiated "Open receive folder" button.
$processStarts = $sourceFiles | Select-String -Pattern 'Process\.Start'
$expectedProcessStartPath = Join-Path $root 'src\GeniaLink.Windows\MainWindow.xaml.cs'
if (@($processStarts).Count -ne 1 -or $processStarts[0].Path -ne $expectedProcessStartPath) {
    if ($processStarts) { $processStarts | ForEach-Object { Write-Host $_ } }
    throw 'Unexpected Process.Start usage found. Only the receive-folder button is allowed to launch Explorer.'
}

# GNP/1 Milestone 1 shared Device Identity contract. This is a source-level
# abstraction only: RC4 wire protocol/version and existing identity files stay unchanged.
$identityContractPath = Join-Path $root 'src\GeniaLink.Core\Identity\IDeviceIdentity.cs'
if (-not (Test-Path -LiteralPath $identityContractPath -PathType Leaf)) {
    throw 'GNP/1 Milestone 1 IDeviceIdentity contract is missing from GeniaLink.Core.'
}
$identityContractText = Get-Content -LiteralPath $identityContractPath -Raw
if ($identityContractText -notmatch 'interface\s+IDeviceIdentity' -or
    $identityContractText -notmatch 'Guid\s+DeviceId' -or
    $identityContractText -notmatch 'string\s+DeviceName' -or
    $identityContractText -notmatch 'PairingPeerInfo\s+ToPairingPeerInfo' -or
    $identityContractText -notmatch 'DeriveSharedKey') {
    throw 'GNP/1 Milestone 1 Device Identity contract is incomplete.'
}

$windowsIdentityPath = Join-Path $root 'src\GeniaLink.Windows\Services\LocalIdentity.cs'
$windowsIdentityText = Get-Content -LiteralPath $windowsIdentityPath -Raw
if ($windowsIdentityText -notmatch 'LocalIdentity\s*:\s*IDeviceSigningIdentity' -or
    $windowsIdentityText -notmatch 'CngKey' -or
    $windowsIdentityText -notmatch 'identity\.json') {
    throw 'Windows identity must implement the shared contract while retaining CNG-backed persistent identity.'
}
$windowsMainIdentityText = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Windows\MainWindow.xaml.cs') -Raw
if ($windowsMainIdentityText -notmatch 'readonly\s+LocalIdentity\s+_identity') {
    throw 'Windows application layer must use the CNG-backed LocalIdentity implementation of the shared IDeviceIdentity contract.'
}

$androidIdentityPath = Join-Path $root 'src\GeniaLink.Android\Services\AndroidLocalIdentity.cs'
$androidIdentityText = Get-Content -LiteralPath $androidIdentityPath -Raw
if ($androidIdentityText -notmatch 'AndroidLocalIdentity\s*:\s*IDeviceSigningIdentity' -or
    $androidIdentityText -notmatch 'AndroidKeyStore' -or
    $androidIdentityText -notmatch 'identity\.json') {
    throw 'Android identity must implement the shared contract while retaining Android Keystore-backed persistent identity.'
}
$androidMainIdentityText = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Android\MainActivity.cs') -Raw
$androidAvailabilityIdentityText = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Android\Services\LocalAvailabilityService.cs') -Raw
if ($androidMainIdentityText -notmatch 'AndroidLocalIdentity\s+_identity' -or
    $androidAvailabilityIdentityText -notmatch 'AndroidLocalIdentity\s+_identity') {
    throw 'Android application/background layers must use the Keystore-backed AndroidLocalIdentity implementation of the shared IDeviceIdentity contract.'
}

Write-Host 'GNP/1 M1 DEVICE IDENTITY CONTRACT CHECK PASSED'


# GNP/1 Milestone 2.1 signing identity is local-only at this stage. The existing
# protocol remains v3; private ECDSA keys stay non-exportable in platform secure storage.
$signingContractPath = Join-Path $root 'src\GeniaLink.Core\Identity\IDeviceSigningIdentity.cs'
$deviceIdentityV2Path = Join-Path $root 'src\GeniaLink.Core\Identity\DeviceIdentityV2.cs'
$deviceSignaturePath = Join-Path $root 'src\GeniaLink.Core\Identity\DeviceSignature.cs'
foreach ($requiredPath in @($signingContractPath, $deviceIdentityV2Path, $deviceSignaturePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "GNP/1 Milestone 2.1 signing identity file is missing: $requiredPath"
    }
}

$signingContractText = Get-Content -LiteralPath $signingContractPath -Raw
$deviceIdentityV2Text = Get-Content -LiteralPath $deviceIdentityV2Path -Raw
$deviceSignatureText = Get-Content -LiteralPath $deviceSignaturePath -Raw
if ($signingContractText -notmatch 'interface\s+IDeviceSigningIdentity\s*:\s*IDeviceIdentity' -or
    $signingContractText -notmatch 'int\s+KeyGeneration' -or
    $signingContractText -notmatch 'DateTimeOffset\s+CreatedAtUtc' -or
    $signingContractText -notmatch 'string\s+SigningKeyId' -or
    $signingContractText -notmatch 'byte\[\]\s+Sign\(' -or
    $signingContractText -notmatch 'VerifySignature' -or
    $signingContractText -notmatch 'ToDeviceIdentityV2') {
    throw 'GNP/1 Milestone 2.1 signing identity contract is incomplete.'
}
if ($deviceIdentityV2Text -notmatch 'CurrentVersion\s*=\s*2' -or
    $deviceIdentityV2Text -notmatch 'SigningKeyId' -or
    $deviceIdentityV2Text -notmatch 'ReadOnlyMemory<byte>\s+SigningPublicKey') {
    throw 'GNP/1 DeviceIdentityV2 public snapshot is incomplete.'
}
if ($deviceSignatureText -notmatch 'ECDsa\.Create' -or
    $deviceSignatureText -notmatch 'SHA256\.HashData' -or
    $deviceSignatureText -notmatch 'DSASignatureFormat\.Rfc3279DerSequence' -or
    $deviceSignatureText -notmatch 'P256KeySizeBits\s*=\s*256') {
    throw 'GNP/1 Device Identity v2 signature verification rules are incomplete.'
}

if ($windowsIdentityText -notmatch 'SigningKeyPrefix' -or
    $windowsIdentityText -notmatch 'CngAlgorithm\.ECDsaP256' -or
    $windowsIdentityText -notmatch 'CngKeyUsages\.Signing' -or
    $windowsIdentityText -notmatch 'CngExportPolicies\.None' -or
    $windowsIdentityText -notmatch 'DSASignatureFormat\.Rfc3279DerSequence' -or
    $windowsIdentityText -notmatch 'SigningKeyId' -or
    $windowsIdentityText -notmatch 'KeyGeneration') {
    throw 'Windows GNP/1 M2 signing identity must use a separate non-exportable CNG ECDSA P-256 key.'
}
if ($androidIdentityText -notmatch 'PrimarySigningKeyAlias' -or
    $androidIdentityText -notmatch 'KeyStorePurpose\.Sign\s*\|\s*KeyStorePurpose\.Verify' -or
    $androidIdentityText -notmatch 'KeyProperties\.DigestSha256' -or
    $androidIdentityText -notmatch 'SHA256withECDSA' -or
    $androidIdentityText -notmatch 'SigningKeyId' -or
    $androidIdentityText -notmatch 'KeyGeneration') {
    throw 'Android GNP/1 M2 signing identity must use a separate Android Keystore ECDSA P-256 key.'
}

$privateKeyExportMatches = $sourceFiles | Select-String -Pattern @(
    'ExportPkcs8PrivateKey',
    'ExportECPrivateKey',
    'ExportParameters\s*\(\s*true\s*\)',
    'CngExportPolicies\.AllowExport',
    'CngExportPolicies\.AllowPlaintextExport'
)
if ($privateKeyExportMatches) {
    $privateKeyExportMatches | ForEach-Object { Write-Host $_ }
    throw 'Private signing/agreement key export must remain disabled.'
}

Write-Host 'GNP/1 M2.1 SIGNING IDENTITY CHECK PASSED'


# GNP/1 Milestone 2.2 adds a separate self-signed discovery envelope while
# preserving the exact RC4 GLD2 discovery packet for older peers.
$signedDiscoveryPacketPath = Join-Path $root 'src\GeniaLink.Core\Discovery\SignedDiscoveryPacket.cs'
$signedDiscoveryAdvertisementPath = Join-Path $root 'src\GeniaLink.Core\Discovery\SignedDiscoveryAdvertisement.cs'
$discoveryServicePath = Join-Path $root 'src\GeniaLink.Core\Discovery\DiscoveryService.cs'
foreach ($requiredPath in @($signedDiscoveryPacketPath, $signedDiscoveryAdvertisementPath, $discoveryServicePath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "GNP/1 Milestone 2.2 signed discovery file is missing: $requiredPath"
    }
}

$signedDiscoveryPacketText = Get-Content -LiteralPath $signedDiscoveryPacketPath -Raw
$signedDiscoveryAdvertisementText = Get-Content -LiteralPath $signedDiscoveryAdvertisementPath -Raw
$discoveryServiceText = Get-Content -LiteralPath $discoveryServicePath -Raw
if ($signedDiscoveryPacketText -notmatch '"GLS1"u8' -or
    $signedDiscoveryPacketText -notmatch 'identity\.Sign\(' -or
    $signedDiscoveryPacketText -notmatch 'DeviceSignature\.Verify' -or
    $signedDiscoveryPacketText -notmatch 'ExportSigningPublicKey' -or
    $signedDiscoveryPacketText -notmatch 'PublicKeyFingerprint' -or
    $signedDiscoveryPacketText -notmatch 'KeyGeneration') {
    throw 'GNP/1 M2.2 signed discovery envelope must bind the legacy ECDH fingerprint and Device Identity v2 signing proof.'
}
if ($signedDiscoveryAdvertisementText -notmatch 'SignedDiscoveryAdvertisement' -or
    $signedDiscoveryAdvertisementText -notmatch 'SigningKeyId' -or
    $signedDiscoveryAdvertisementText -notmatch 'SigningPublicKey') {
    throw 'GNP/1 M2.2 verified signed-discovery model is incomplete.'
}
if ($discoveryServiceText -notmatch 'SignedDiscoveryPacket\.Create' -or
    $discoveryServiceText -notmatch 'SignedDiscoveryPacket\.ParseAndVerify' -or
    $discoveryServiceText -notmatch 'DiscoveryPacket\.Create' -or
    $discoveryServiceText -notmatch 'DiscoveryIdentityProof\.SignedIdentityV2' -or
    $discoveryServiceText -notmatch 'legacy GLD2 discovery remains active') {
    throw 'GNP/1 M2.2 discovery service must send/verify signed advertisements while retaining legacy GLD2 fallback.'
}

# These hashes are the verified M2.1 baseline. M2.2 intentionally adds a second
# discovery envelope instead of mutating protocol v3, legacy GLD2, pairing, trusted
# session handshake or transfer protocol. M2.3 may add a new fixed local port while preserving all existing protocol v3 constants.
$unchangedM22Files = @{
    'src\GeniaLink.Core\Discovery\DiscoveryPacket.cs' = '7E91DEBE30D2171EEF63A3B9893F90E619B479628244763049DFD7C33443C4B9'
    'src\GeniaLink.Core\Pairing\PairingProtocol.cs' = 'F0FEF3010CCE3309672E27B0B55A568187CE60C7391FED39BCB22F30DB945AA5'
    'src\GeniaLink.Core\Network\TrustedSessionHandshake.cs' = '4A8FAD86A23206942F374C22B6DF0D0C7540D42E23A70235071BBB706DF93A72'
    'src\GeniaLink.Core\Network\TransferProtocol.cs' = 'F6249C7EBE7FCAB8C554DA318FC55BAB8D51FD78CE46A5F956844346578AFF75'
}
foreach ($relativePath in $unchangedM22Files.Keys) {
    $actualHash = (Get-FileHash -LiteralPath (Join-Path $root $relativePath) -Algorithm SHA256).Hash
    if ($actualHash -ne $unchangedM22Files[$relativePath]) {
        throw "GNP/1 M2.2 compatibility boundary changed unexpectedly: $relativePath"
    }
}

$windowsMainM22Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Windows\MainWindow.xaml.cs') -Raw
$androidAvailabilityM22Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Android\Services\LocalAvailabilityService.cs') -Raw
if ($windowsMainM22Text -notmatch 'DiscoveryService\.RunAsync\(\s*advertisement,\s*_identity,' -or
    $androidAvailabilityM22Text -notmatch 'DiscoveryService\.RunAsync\(\s*advertisement,\s*_identity,') {
    throw 'Windows and Android must provide their secure signing identity to GNP/1 M2.2 discovery.'
}

$selfTestText = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.SelfTest\Program.cs') -Raw
if ($selfTestText -notmatch 'TestSignedDiscoveryRoundTrip' -or
    $selfTestText -notmatch 'TestSignedDiscoveryTamperDetection' -or
    $selfTestText -notmatch 'SignedDiscoveryPacket\.ParseAndVerify') {
    throw 'GNP/1 M2.2 signed discovery self-tests are missing.'
}

Write-Host 'GNP/1 M2.2 SIGNED DISCOVERY CHECK PASSED'


# GNP/1 Milestone 2.3 binds the persistent ECDSA signing public key to the
# already trusted ECDH relationship. The binding runs only on a new local TCP
# endpoint and reuses the existing trusted-session handshake + encrypted channel.
$bindingProtocolPath = Join-Path $root 'src\GeniaLink.Core\Network\IdentityBindingProtocol.cs'
$bindingServicePath = Join-Path $root 'src\GeniaLink.Core\Network\IdentityBindingService.cs'
$trustedSigningIdentityPath = Join-Path $root 'src\GeniaLink.Core\Identity\TrustedSigningIdentity.cs'
foreach ($requiredPath in @($bindingProtocolPath, $bindingServicePath, $trustedSigningIdentityPath)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "GNP/1 M2.3 trusted signing-identity binding file is missing: $requiredPath"
    }
}

$bindingProtocolText = Get-Content -LiteralPath $bindingProtocolPath -Raw
$bindingServiceText = Get-Content -LiteralPath $bindingServicePath -Raw
$trustedSigningIdentityText = Get-Content -LiteralPath $trustedSigningIdentityPath -Raw
if ($bindingProtocolText -notmatch '"GLI1"u8' -or
    $bindingProtocolText -notmatch 'DeviceSignature\.ValidatePublicKey' -or
    $bindingProtocolText -notmatch 'IdentityVersion' -or
    $bindingProtocolText -notmatch 'KeyGeneration') {
    throw 'GNP/1 M2.3 identity-binding payload must be bounded and carry the persistent signing public identity.'
}
if ($bindingServiceText -notmatch 'TrustedSessionHandshake\.CreateClientSessionKeyAsync' -or
    $bindingServiceText -notmatch 'TrustedSessionHandshake\.CreateServerSessionKeyAsync' -or
    $bindingServiceText -notmatch 'SecureChannel' -or
    $bindingServiceText -notmatch 'LocalNetworkPolicy\.IsAllowedAddress' -or
    $bindingServiceText -notmatch 'expectedRemoteDeviceId') {
    throw 'GNP/1 M2.3 signing-key binding must reuse authenticated trusted sessions and remain LAN-only.'
}
if ($trustedSigningIdentityText -notmatch 'SigningIdentityBindingUpdate' -or
    $trustedSigningIdentityText -notmatch 'DeviceSignature\.GetSigningKeyId') {
    throw 'GNP/1 M2.3 trusted signing-identity model is incomplete.'
}

$protocolConstantsM23Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Core\Network\ProtocolConstants.cs') -Raw
if ($protocolConstantsM23Text -notmatch 'Version\s*=\s*3' -or
    $protocolConstantsM23Text -notmatch 'Port\s*=\s*47500' -or
    $protocolConstantsM23Text -notmatch 'PairingPort\s*=\s*47501' -or
    $protocolConstantsM23Text -notmatch 'DiscoveryPort\s*=\s*47502' -or
    $protocolConstantsM23Text -notmatch 'IdentityBindingPort\s*=\s*47503') {
    throw 'GNP/1 M2.3 must preserve protocol v3 and all existing ports while adding only TCP 47503 for trusted signing-key binding.'
}

$windowsTrustedM23Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Windows\Services\TrustedDeviceStore.cs') -Raw
$androidTrustedM23Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Android\Services\TrustedDeviceStore.cs') -Raw
foreach ($trustedStoreM23Text in @($windowsTrustedM23Text, $androidTrustedM23Text)) {
    if ($trustedStoreM23Text -notmatch 'UpdateSigningIdentity' -or
        $trustedStoreM23Text -notmatch 'SigningKeyId' -or
        $trustedStoreM23Text -notmatch 'SigningPublicKeyBase64' -or
        $trustedStoreM23Text -notmatch 'SigningKeyGeneration' -or
        $trustedStoreM23Text -notmatch 'Trusted signing-key generation rollback was rejected') {
        throw 'Trusted-device stores must persist authenticated signing-key bindings and reject rollback/conflicting generations.'
    }
}

if ($windowsMainM22Text -notmatch 'IdentityBindingService\.RunServerAsync' -or
    $windowsMainM22Text -notmatch 'TryStartSigningIdentityBinding' -or
    $windowsMainM22Text -notmatch 'UpdateSigningIdentity' -or
    $windowsMainM22Text -notmatch 'PromoteAuthenticatedSigningIdentityToDiscovered' -or
    $windowsMainM22Text -notmatch 'AuthenticatedTrustedIdentityV2' -or
    $windowsMainM22Text -notmatch 'trusted\.SigningKeyId') {
    throw 'Windows must run M2.3 binding, persist authenticated signing keys, and include them in the active identity safety gate.'
}
if ($androidAvailabilityM22Text -notmatch 'IdentityBindingService\.RunServerAsync' -or
    $androidAvailabilityM22Text -notmatch 'TryStartSigningIdentityBinding' -or
    $androidAvailabilityM22Text -notmatch 'UpdateSigningIdentity' -or
    $androidAvailabilityM22Text -notmatch 'TrustedSigningIdentitySaved') {
    throw 'Android background availability must run M2.3 binding and authenticate signing-key migration for trusted signed peers.'
}
$androidMainM23Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Android\MainActivity.cs') -Raw
if ($androidMainM23Text -notmatch 'OnBackgroundTrustedSigningIdentitySaved' -or
    $androidMainM23Text -notmatch 'PromoteAuthenticatedSigningIdentityToUi' -or
    $androidMainM23Text -notmatch 'AuthenticatedTrustedIdentityV2' -or
    $androidMainM23Text -notmatch 'trusted\.SigningKeyId') {
    throw 'Android UI must mirror authenticated signing-key bindings and include them in the active identity safety gate.'
}
if ($selfTestText -notmatch 'TestIdentityBindingProtocolRoundTrip' -or
    $selfTestText -notmatch 'IdentityBindingProtocol\.ParseIdentity') {
    throw 'GNP/1 M2.3 identity-binding self-test is missing.'
}
if ($windowsMainM22Text -notmatch 'device\.IdentityProof == DiscoveryIdentityProof\.LegacyUnsigned' -or
    $androidMainM23Text -notmatch 'device\.IdentityProof == DiscoveryIdentityProof\.LegacyUnsigned') {
    throw 'M2.3 compatibility GLD2 must not be treated as cryptographic proof that a trusted signing key changed.'
}

Write-Host 'GNP/1 M2.3 TRUSTED SIGNING IDENTITY BINDING CHECK PASSED'


# GNP/1 Milestone 2.4.1 introduces a local Trusted Identity Registry without
# changing protocol v3 or weakening the already verified M2.3 pairing/signing path.
$trustedIdentityRegistryPath = Join-Path $root 'src\GeniaLink.Core\Identity\TrustedIdentityRegistry.cs'
if (-not (Test-Path -LiteralPath $trustedIdentityRegistryPath -PathType Leaf)) {
    throw 'GNP/1 M2.4.1 Trusted Identity Registry implementation is missing.'
}
$trustedIdentityRegistryText = Get-Content -LiteralPath $trustedIdentityRegistryPath -Raw
if ($trustedIdentityRegistryText -notmatch 'class\s+TrustedIdentityRegistry' -or
    $trustedIdentityRegistryText -notmatch 'CurrentSchemaVersion\s*=\s*5' -or
    $trustedIdentityRegistryText -notmatch 'TrustedIdentityRegistryState' -or
    $trustedIdentityRegistryText -notmatch 'SigningKeyHistory' -or
    $trustedIdentityRegistryText -notmatch 'RecordAuthenticatedSigningIdentity' -or
    $trustedIdentityRegistryText -notmatch 'Trusted Identity Registry rejected a signing-key generation rollback' -or
    $trustedIdentityRegistryText -notmatch 'GetPairingKeyId' -or
    $trustedIdentityRegistryText -notmatch '\.bak' -or
    $trustedIdentityRegistryText -notmatch 'MaxSigningKeyHistoryEntries') {
    throw 'GNP/1 M2.4.1 registry must pin the pairing anchor, retain bounded signing-key history, reject rollback, and keep a local backup.'
}

foreach ($trustedStoreM241Text in @($windowsTrustedM23Text, $androidTrustedM23Text)) {
    if ($trustedStoreM241Text -notmatch 'trusted-identities\.json' -or
        $trustedStoreM241Text -notmatch 'MigrateTrustedIdentityRegistry' -or
        $trustedStoreM241Text -notmatch 'TrySynchronizeIdentityRegistry' -or
        $trustedStoreM241Text -notmatch 'RecordAuthenticatedSigningIdentity' -or
        $trustedStoreM241Text -notmatch 'TryMarkRegistryAuthenticated' -or
        $trustedStoreM241Text -notmatch 'trustedDeviceDatabaseLoaded' -or
        $trustedStoreM241Text -notmatch 'preserved .* registry-only identity record' -or
        $trustedStoreM241Text -notmatch 'existing M2\.3 trust was kept') {
        throw 'Windows and Android trusted-device stores must migrate and mirror M2.3 trust into M2.4.1, preserve registry-only lifecycle/revocation history, and avoid making registry persistence a pairing-breaking dependency.'
    }
}

if ($selfTestText -notmatch 'TestTrustedIdentityRegistry' -or
    $selfTestText -notmatch 'Registry backup recovery must restore the last complete signing identity' -or
    $selfTestText -notmatch 'Changing the paired ECDH trust anchor must clear previous signing-key history') {
    throw 'GNP/1 M2.4.1 registry migration/rotation/rollback/backup self-test is missing.'
}

Write-Host 'GNP/1 M2.4.1 TRUSTED IDENTITY REGISTRY CHECK PASSED'

# GNP/1 Milestone 2.4.2 adds cryptographically authenticated signing-key rotation.
# A new trusted signing key may only replace the current key when the complete
# continuity chain is signed by the previously trusted key and advances generation
# exactly one step per certificate. GLI1 remains the pre-rotation compatibility form;
# rotated identities use the GLI2 envelope carrying the bounded certificate chain.
$rotationCertificatePath = Join-Path $root 'src\GeniaLink.Core\Identity\SigningKeyRotationCertificate.cs'
$rotationValidationPath = Join-Path $root 'src\GeniaLink.Core\Identity\SigningKeyRotation.cs'
$identityBindingM242Path = Join-Path $root 'src\GeniaLink.Core\Network\IdentityBindingProtocol.cs'
foreach ($requiredM242Path in @($rotationCertificatePath, $rotationValidationPath, $identityBindingM242Path)) {
    if (-not (Test-Path -LiteralPath $requiredM242Path -PathType Leaf)) {
        throw "GNP/1 M2.4.2 implementation file is missing: $requiredM242Path"
    }
}

$rotationCertificateText = Get-Content -LiteralPath $rotationCertificatePath -Raw
$rotationValidationText = Get-Content -LiteralPath $rotationValidationPath -Raw
$identityBindingM242Text = Get-Content -LiteralPath $identityBindingM242Path -Raw
if ($rotationCertificateText -notmatch 'GLR1' -or
    $rotationCertificateText -notmatch 'MaxChainLength\s*=\s*32' -or
    $rotationCertificateText -notmatch 'PreviousKeyGeneration\s*>=\s*int\.MaxValue' -or
    $rotationCertificateText -notmatch 'NewKeyGeneration\s*!=\s*PreviousKeyGeneration\s*\+\s*1' -or
    $rotationCertificateText -notmatch 'DeviceSignature\.Verify' -or
    $rotationCertificateText -notmatch 'previousIdentity\.Sign') {
    throw 'GNP/1 M2.4.2 rotation certificate must be bounded, advance generation exactly +1, and be signed/verified by the previous signing key.'
}
if ($rotationValidationText -notmatch 'ValidateTrustedTransition' -or
    $rotationValidationText -notmatch 'continuity certificate signed by the previous trusted key' -or
    $rotationValidationText -notmatch 'trustedKeyGeneration' -or
    $rotationValidationText -notmatch 'trustedSigningPublicKey') {
    throw 'GNP/1 M2.4.2 must anchor every accepted rotation chain at the currently trusted signing key and generation.'
}
if ($identityBindingM242Text -notmatch 'GLI1' -or
    $identityBindingM242Text -notmatch 'GLI2' -or
    $identityBindingM242Text -notmatch 'SigningKeyRotationCertificate\.Parse' -or
    $identityBindingM242Text -notmatch 'ISigningKeyRotationSource') {
    throw 'GNP/1 M2.4.2 identity binding must preserve GLI1 compatibility and carry validated rotation certificates in GLI2.'
}

$windowsLocalIdentityM242Path = Join-Path $root 'src\GeniaLink.Windows\Services\LocalIdentity.cs'
$androidLocalIdentityM242Path = Join-Path $root 'src\GeniaLink.Android\Services\AndroidLocalIdentity.cs'
$windowsLocalIdentityM242Text = Get-Content -LiteralPath $windowsLocalIdentityM242Path -Raw
$androidLocalIdentityM242Text = Get-Content -LiteralPath $androidLocalIdentityM242Path -Raw
foreach ($localIdentityM242Text in @($windowsLocalIdentityM242Text, $androidLocalIdentityM242Text)) {
    if ($localIdentityM242Text -notmatch 'ISigningKeyRotationSource' -or
        $localIdentityM242Text -notmatch 'rotate-signing-key\.request\.json' -or
        $localIdentityM242Text -notmatch 'RequestSigningKeyRotation' -or
        $localIdentityM242Text -notmatch 'SigningKeyRotationCertificate\.Create' -or
        $localIdentityM242Text -notmatch 'rotated with continuity proof') {
        throw 'Windows and Android local identities must schedule rotation for a clean restart and persist a previous-key continuity certificate.'
    }
}
foreach ($trustedStoreM242Text in @($windowsTrustedM23Text, $androidTrustedM23Text)) {
    if ($trustedStoreM242Text -notmatch 'SigningKeyRotation\.ValidateTrustedTransition' -or
        $trustedStoreM242Text -notmatch 'generation cannot increase without changing the signing key') {
        throw 'Windows and Android trusted-device stores must reject unproven key replacement and meaningless same-key generation increases.'
    }
}

$androidMainM242Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Android\MainActivity.cs') -Raw
$androidAvailabilityM242Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Android\Services\LocalAvailabilityService.cs') -Raw
if ($androidMainM242Text -notmatch '_signingKeyRotationPending' -or
    $androidMainM242Text -notmatch '_identityReady\s*&&\s*!_signingKeyRotationPending' -or
    $androidMainM242Text -notmatch 'LocalAvailabilityService\.End\(\)') {
    throw 'Android must keep the old in-memory identity isolated after scheduling rotation until a clean activity/service restart.'
}
if ($androidAvailabilityM242Text -notmatch 'public\s+static\s+void\s+End\(\)' -or
    $androidAvailabilityM242Text -match '(?s)public\s+static\s+void\s+End\(\).*?StartService\(') {
    throw 'Android rotation shutdown must never start a fresh availability service that could apply the pending rotation beside an old Activity identity.'
}
if ($trustedIdentityRegistryText -notmatch 'SigningKeyRotation\.ValidateTrustedTransition' -or
    $trustedIdentityRegistryText -notmatch 'allowLocalRecoveryWithoutRotationProof') {
    throw 'GNP/1 M2.4.2 registry must require continuity proof for authenticated network rotation while retaining the explicit local M2.3 migration path.'
}
if ($selfTestText -notmatch 'TestSigningKeyRotation' -or
    $selfTestText -notmatch 'complete 1->2->3 continuity chain' -or
    $selfTestText -notmatch 'higher signing-key generation without the previous-key continuity certificate must be rejected' -or
    $selfTestText -notmatch 'generation increase that reuses the same signing key' -or
    $selfTestText -notmatch 'rollback to a retired signing key generation' -or
    $selfTestText -notmatch 'GLI2') {
    throw 'GNP/1 M2.4.2 rotation-chain, skipped-generation, unproven-replacement, and GLI2 self-tests are missing.'
}

Write-Host 'GNP/1 M2.4.2 TRUSTED KEY ROTATION CHECK PASSED'


# GNP/1 Milestone 2.5 checkpoint 1 authenticates device-name changes with the
# already pinned signed-discovery identity. Rename must never replace DeviceId,
# pairing/signing anchors, or trust merely because a self-signed UDP name changed.
if ($trustedIdentityRegistryText -notmatch 'RecordAuthenticatedDeviceName' -or
    $trustedIdentityRegistryText -notmatch 'current\.State\s*!=\s*TrustedIdentityRegistryState\.Trusted' -or
    $trustedIdentityRegistryText -notmatch 'Authenticated rename pairing-key anchor does not match' -or
    $trustedIdentityRegistryText -notmatch 'Authenticated rename signing identity does not match') {
    throw 'GNP/1 M2.5 registry must accept rename only under the current Trusted pairing/signing identity.'
}

foreach ($trustedStoreM25Text in @($windowsTrustedM23Text, $androidTrustedM23Text)) {
    if ($trustedStoreM25Text -notmatch 'TryApplyAuthenticatedSignedDiscovery' -or
        $trustedStoreM25Text -notmatch 'DiscoveryIdentityProof\.SignedIdentityV2' -or
        $trustedStoreM25Text -notmatch 'PairingProtocol\.GetPublicKeyFingerprint' -or
        $trustedStoreM25Text -notmatch 'registryEntry\.State\s*!=\s*TrustedIdentityRegistryState\.Trusted' -or
        $trustedStoreM25Text -notmatch 'CurrentSigningKeyGeneration\s*!=\s*device\.SigningKeyGeneration' -or
        $trustedStoreM25Text -notmatch 'RecordAuthenticatedDeviceName' -or
        $trustedStoreM25Text -notmatch 'Device ID and trust anchors were preserved') {
        throw 'Windows and Android M2.5 rename propagation must require verified signed discovery and exact current ECDH/ECDSA trust anchors.'
    }
}

if ($windowsMainM22Text -notmatch 'PromoteKnownAuthenticatedSignedDiscovery' -or
    $windowsMainM22Text -notmatch 'TryApplyAuthenticatedSignedDiscovery') {
    throw 'Windows M2.5 must promote only signed discovery that matches the already trusted identity.'
}
if ($androidMainM23Text -notmatch 'PromoteKnownAuthenticatedSignedDiscoveryToUi' -or
    $androidMainM23Text -notmatch 'TryApplyAuthenticatedSignedDiscovery') {
    throw 'Android UI must mirror M2.5 authenticated rename into its trusted-device store.'
}
if ($androidAvailabilityM242Text -notmatch '_latestDiscovered' -or
    $androidAvailabilityM242Text -notmatch 'TryApplyAuthenticatedSignedDiscovery' -or
    $androidAvailabilityM242Text -notmatch '_latestDiscovered\.Remove' -or
    $androidAvailabilityM242Text -notmatch '_latestDiscovered\.Clear') {
    throw 'Android background availability must retain only bounded current discovery state needed to finish M2.5 rename after authenticated signing-key binding.'
}
if ($selfTestText -notmatch 'GENIABOOK' -or
    $selfTestText -notmatch 'Authenticated rename must preserve Device ID' -or
    $selfTestText -notmatch 'Authenticated rename must preserve the pairing trust anchor' -or
    $selfTestText -notmatch 'Authenticated rename must reject a mismatched pairing trust anchor' -or
    $selfTestText -notmatch 'Authenticated rename must reject a name signed by a non-trusted signing identity') {
    throw 'GNP/1 M2.5 authenticated rename preservation/rejection self-tests are missing.'
}

Write-Host 'GNP/1 M2.5 AUTHENTICATED RENAME CHECK PASSED'

# GNP/1 M2.5.2 separates cryptographic binding state from administrative lifecycle.
# Active is usable, Retired is reversible but inactive, and Revoked is terminal until
# the user explicitly forgets the identity and completes a new SAS pairing.
if ($trustedIdentityRegistryText -notmatch 'enum\s+TrustedIdentityLifecycleState' -or
    $trustedIdentityRegistryText -notmatch 'Active\s*=\s*1' -or
    $trustedIdentityRegistryText -notmatch 'Retired\s*=\s*2' -or
    $trustedIdentityRegistryText -notmatch 'Revoked\s*=\s*3' -or
    $trustedIdentityRegistryText -notmatch 'SetLifecycleState' -or
    $trustedIdentityRegistryText -notmatch 'A revoked trusted identity cannot be reactivated or retired' -or
    $trustedIdentityRegistryText -notmatch 'IdentityHistory' -or
    $trustedIdentityRegistryText -notmatch 'MaxIdentityHistoryEntries' -or
    $trustedIdentityRegistryText -notmatch 'SigningKeyRotated' -or
    $trustedIdentityRegistryText -notmatch 'PairingTrustReplaced') {
    throw 'GNP/1 M2.5.2 registry lifecycle/history implementation is incomplete.'
}

foreach ($trustedStoreM252Text in @($windowsTrustedM23Text, $androidTrustedM23Text)) {
    if ($trustedStoreM252Text -notmatch 'IsActiveTrusted' -or
        $trustedStoreM252Text -notmatch 'GetAllIncludingInactive' -or
        $trustedStoreM252Text -notmatch 'GetIdentityRegistryEntries' -or
        $trustedStoreM252Text -notmatch 'IsKnownInactive' -or
        $trustedStoreM252Text -notmatch 'SetLifecycleState' -or
        $trustedStoreM252Text -notmatch 'removedRegistryRecord' -or
        $trustedStoreM252Text -notmatch 'older build that does not understand' -or
        $trustedStoreM252Text -notmatch 'LifecycleState\s*!=\s*TrustedIdentityLifecycleState\.Active' -or
        $trustedStoreM252Text -notmatch 'Pairing was rejected because') {
        throw 'Windows and Android trusted-device stores must fail closed for Retired/Revoked identities and block automatic re-pair bypass.'
    }
}

$windowsSettingsM252Path = Join-Path $root 'src\GeniaLink.Windows\SettingsWindow.xaml.cs'
$windowsSettingsM252Text = Get-Content -LiteralPath $windowsSettingsM252Path -Raw
if ($windowsSettingsM252Text -notmatch 'TrustedIdentityLifecycleState\.Retired' -or
    $windowsSettingsM252Text -notmatch 'TrustedIdentityLifecycleState\.Revoked' -or
    $windowsSettingsM252Text -notmatch 'RetireReactivateButton_Click' -or
    $windowsSettingsM252Text -notmatch 'RevokeButton_Click') {
    throw 'Windows M2.5.2 settings UI must expose explicit Retire/reactivate and Revoke actions.'
}
if ($windowsMainM22Text -notmatch 'IsKnownInactive' -or
    $windowsMainM22Text -notmatch 'GetIdentityRegistryEntries' -or
    $windowsMainM22Text -notmatch 'GetIdentityRegistryEntry' -or
    $androidMainM23Text -notmatch 'IsKnownInactive' -or
    $androidAvailabilityM242Text -notmatch 'IsKnownInactive') {
    throw 'M2.5.2 inactive identities must be suppressed from normal Windows/Android discovery paths.'
}
if ($selfTestText -notmatch 'Schema-v1 trusted identity must migrate to Active lifecycle without repeat pairing' -or
    $selfTestText -notmatch 'Legacy RegistryState\.Revoked must migrate to terminal lifecycle Revoked' -or
    $selfTestText -notmatch 'Active identity must transition to Retired' -or
    $selfTestText -notmatch 'Startup synchronization must not reactivate Retired identity' -or
    $selfTestText -notmatch 'Revoked identity must be terminal until explicit forget/new SAS pairing' -or
    $selfTestText -notmatch 'Revoked identity must reject pairing-anchor replacement without explicit forget' -or
    $selfTestText -notmatch 'Revocation must be retained in identity history') {
    throw 'GNP/1 M2.5.2 lifecycle enforcement/history self-tests are missing.'
}

Write-Host 'GNP/1 M2.5.2 TRUSTED IDENTITY LIFECYCLE CHECK PASSED'

# GNP/1 M2.5.2.1 makes Revoked/Forget effective against already-authenticated
# transfer sessions and scopes resume state to the current trust relationship.
$coreServerM2521Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Core\Transfers\FileTransferServer.cs') -Raw
$androidServerM2521Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Android\Services\AndroidFileTransferServer.cs') -Raw
$fileSafetyM2521Text = Get-Content -LiteralPath (Join-Path $root 'src\GeniaLink.Core\Security\FileSafety.cs') -Raw
if ($trustedIdentityRegistryText -notmatch 'CurrentSchemaVersion\s*=\s*5' -or
    $trustedIdentityRegistryText -notmatch 'TrustRelationshipId' -or
    $trustedIdentityRegistryText -notmatch 'GetSessionAuthorization' -or
    $trustedIdentityRegistryText -notmatch 'InvalidateSessionLifetimeLocked' -or
    $trustedIdentityRegistryText -notmatch 'active trusted sessions invalidated') {
    throw 'GNP/1 M2.5.2.1 registry trust-relationship/session-lifetime enforcement is incomplete.'
}
foreach ($trustedStoreM2521Text in @($windowsTrustedM23Text, $androidTrustedM23Text)) {
    if ($trustedStoreM2521Text -notmatch 'GetSessionAuthorization') {
        throw 'Windows and Android trusted-device stores must expose trust-scoped session authorization.'
    }
}
if ($coreServerM2521Text -notmatch 'TrustedSessionRevokedException' -or
    $coreServerM2521Text -notmatch 'authorization\.TrustRelationshipId' -or
    $coreServerM2521Text -notmatch 'CreateLinkedTokenSource\(cancellationToken, authorization\.LifetimeToken\)' -or
    $androidServerM2521Text -notmatch 'TrustedSessionRevokedException' -or
    $androidServerM2521Text -notmatch 'authorization\.TrustRelationshipId' -or
    $androidServerM2521Text -notmatch 'CreateLinkedTokenSource\(cancellationToken, authorization\.LifetimeToken\)') {
    throw 'Windows/Android receivers must terminate live sessions when the trust lifetime is invalidated.'
}
if ($windowsMainM22Text -notmatch '_trustedDevices\.GetSessionAuthorization' -or
    $windowsMainM22Text -notmatch 'trustLinkedCts' -or
    $androidMainM23Text -notmatch '_trustedDevices\.GetSessionAuthorization' -or
    $androidMainM23Text -notmatch 'trustLinkedCts') {
    throw 'Windows/Android outgoing transfers must be linked to the current trusted-session lifetime.'
}
if ($fileSafetyM2521Text -notmatch 'GNP1-M2\.5\.2\.1-TRUST-RESUME' -or
    $fileSafetyM2521Text -notmatch 'remoteDeviceId' -or
    $fileSafetyM2521Text -notmatch 'trustRelationshipId') {
    throw 'Resume state must be scoped to remote Device ID and the current trust relationship.'
}
if ($selfTestText -notmatch 'Revocation must immediately cancel active session authorization' -or
    $selfTestText -notmatch 'Fresh SAS pairing after Forget must not inherit the revoked trust relationship ID' -or
    $selfTestText -notmatch 'A new trust relationship must invalidate the previous resume namespace' -or
    $selfTestText -notmatch 'Retiring an identity must not forcibly cancel a session that was already authenticated') {
    throw 'GNP/1 M2.5.2.1 live-session/re-pair resume self-tests are missing.'
}

Write-Host 'GNP/1 M2.5.2.1 REVOCATION SESSION ENFORCEMENT CHECK PASSED'


# GNP/1 M2.5.3 adds a monotonic signed identity revision to discovery (GLS2).
# GLS1/GLD2 remain compatibility envelopes, but unordered GLS1 must never mutate
# a trusted device name after replay-protected identity state is available.
$replayDiscoveryPath = Join-Path $root 'src\GeniaLink.Core\Discovery\ReplayProtectedSignedDiscoveryPacket.cs'
$identityRevisionStorePath = Join-Path $root 'src\GeniaLink.Core\Identity\IdentityAssertionRevisionStore.cs'
foreach ($requiredM253Path in @($replayDiscoveryPath, $identityRevisionStorePath)) {
    if (-not (Test-Path -LiteralPath $requiredM253Path -PathType Leaf)) {
        throw "GNP/1 M2.5.3 replay-hardening file is missing: $requiredM253Path"
    }
}
$replayDiscoveryText = Get-Content -LiteralPath $replayDiscoveryPath -Raw
$identityRevisionStoreText = Get-Content -LiteralPath $identityRevisionStorePath -Raw
if ($replayDiscoveryText -notmatch '"GLS2"u8' -or
    $replayDiscoveryText -notmatch 'WriteInt64BigEndian' -or
    $replayDiscoveryText -notmatch 'identityRevision' -or
    $replayDiscoveryText -notmatch 'DeviceSignature\.Verify' -or
    $replayDiscoveryText -notmatch 'SigningKeyId') {
    throw 'GNP/1 M2.5.3 GLS2 must cryptographically bind a positive monotonic identity revision to the signed discovery assertion.'
}
if ($identityRevisionStoreText -notmatch 'LoadOrAdvance' -or
    $identityRevisionStoreText -notmatch 'previous\.Revision \+ 1' -or
    $identityRevisionStoreText -notmatch 'DisplayName' -or
    $identityRevisionStoreText -notmatch 'KeyGeneration' -or
    $identityRevisionStoreText -notmatch 'SigningKeyId' -or
    $identityRevisionStoreText -notmatch '\.bak') {
    throw 'GNP/1 M2.5.3 local identity assertion revision must persist and advance across rename/signing-identity changes with backup recovery.'
}
if ($discoveryServiceText -notmatch 'ReplayProtectedSignedDiscoveryPacket\.Create' -or
    $discoveryServiceText -notmatch 'ReplayProtectedSignedDiscoveryPacket\.ParseAndVerify' -or
    $discoveryServiceText -notmatch 'ReplayProtectedSignedIdentityV2' -or
    $discoveryServiceText -notmatch 'Never downgrade a peer from GLS2') {
    throw 'GNP/1 M2.5.3 discovery must emit/verify GLS2 and suppress immediate GLS1 downgrade for replay-protected peers.'
}
if ($trustedIdentityRegistryText -notmatch 'CurrentSchemaVersion\s*=\s*5' -or
    $trustedIdentityRegistryText -notmatch 'LastAcceptedIdentityRevision' -or
    $trustedIdentityRegistryText -notmatch 'identityRevision < current\.LastAcceptedIdentityRevision' -or
    $trustedIdentityRegistryText -notmatch 'identityRevision == current\.LastAcceptedIdentityRevision && renamed' -or
    $trustedIdentityRegistryText -notmatch 'Replay-protected identity revision rollback was rejected') {
    throw 'GNP/1 M2.5.3 registry must persist the highest accepted identity revision and reject rollback/same-revision name conflicts.'
}
foreach ($trustedStoreM253Text in @($windowsTrustedM23Text, $androidTrustedM23Text)) {
    if ($trustedStoreM253Text -notmatch 'ReplayProtectedSignedIdentityV2' -or
        $trustedStoreM253Text -notmatch 'unordered legacy packet mutate the trusted name' -or
        $trustedStoreM253Text -notmatch 'device\.IdentityRevision' -or
        $trustedStoreM253Text -notmatch 'LastAcceptedIdentityRevision' -or
        $trustedStoreM253Text -notmatch 'replay-protected authenticated rename accepted') {
        throw 'Windows and Android trusted-device stores must require GLS2 revision ordering for automatic rename mutation and restore registry-authoritative names on startup.'
    }
}
if ($windowsMainM22Text -notmatch 'IdentityAssertionRevisionStore\.LoadOrAdvance' -or
    $androidAvailabilityM242Text -notmatch 'IdentityAssertionRevisionStore\.LoadOrAdvance') {
    throw 'Windows and Android must persist a local M2.5.3 identity assertion revision before advertising GLS2.'
}
if ($selfTestText -notmatch 'TestReplayProtectedSignedDiscoveryRoundTrip' -or
    $selfTestText -notmatch 'TestReplayProtectedSignedDiscoveryTamperDetection' -or
    $selfTestText -notmatch 'TestIdentityAssertionRevisionStore' -or
    $selfTestText -notmatch 'A lower signed identity revision must not replay an old device name' -or
    $selfTestText -notmatch 'A conflicting name at an already accepted identity revision must be rejected') {
    throw 'GNP/1 M2.5.3 signed revision, tamper, persistence, rollback and same-revision conflict self-tests are missing.'
}

Write-Host 'GNP/1 M2.5.3 IDENTITY HISTORY / REPLAY HARDENING CHECK PASSED'

$protocolConstantsPath = Join-Path $root 'src\GeniaLink.Core\Network\ProtocolConstants.cs'
$protocolText = Get-Content -LiteralPath $protocolConstantsPath -Raw
if ($protocolText -notmatch 'Version\s*=\s*3' -or
    $protocolText -notmatch 'PartialRetention' -or
    $protocolText -notmatch 'MaxPreviewBytes' -or
    $protocolText -notmatch 'MaxTextPreviewBytes') {
    throw 'Protocol v3 resume/preview safety policy is missing.'
}

$fileSafetyPath = Join-Path $root 'src\GeniaLink.Core\Security\FileSafety.cs'
$fileSafetyText = Get-Content -LiteralPath $fileSafetyPath -Raw
if ($fileSafetyText -notmatch 'IsSafeRelativeDirectory' -or
    $fileSafetyText -notmatch 'GetResumePartPath' -or
    $fileSafetyText -notmatch 'IsSafeRelativeFilePath' -or
    $fileSafetyText -notmatch 'ResolveSharedFilePath' -or
    $fileSafetyText -notmatch 'FileAttributes\.ReparsePoint') {
    throw 'Folder traversal/resume/remote-browser path protections are missing.'
}

$selectionPath = Join-Path $root 'src\GeniaLink.Core\Transfers\TransferSelection.cs'
$selectionText = Get-Content -LiteralPath $selectionPath -Raw
if ($selectionText -notmatch 'FileAttributes\.ReparsePoint' -or $selectionText -notmatch 'MaxBatchFiles') {
    throw 'Folder enumeration must reject reparse points and enforce a batch limit.'
}

$brokerPath = Join-Path $root 'src\GeniaLink.Windows\Services\SingleInstanceBroker.cs'
$brokerText = Get-Content -LiteralPath $brokerPath -Raw
if ($brokerText -notmatch 'PipeOptions\.CurrentUserOnly' -or $brokerText -notmatch 'MaxCommandBytes') {
    throw 'Windows local IPC must remain current-user-only and length bounded.'
}

$settingsPath = Join-Path $root 'src\GeniaLink.Windows\Services\AppSettingsStore.cs'
$settingsText = Get-Content -LiteralPath $settingsPath -Raw
if ($settingsText -notmatch 'MaxSettingsBytes' -or $settingsText -notmatch 'ReceiveFolderPolicy\.Normalize') {
    throw 'Windows settings must remain size-bounded and validate the configured receive folder.'
}

$receiveFolderPolicyPath = Join-Path $root 'src\GeniaLink.Windows\Services\ReceiveFolderPolicy.cs'
$receiveFolderPolicyText = Get-Content -LiteralPath $receiveFolderPolicyPath -Raw
if ($receiveFolderPolicyText -notmatch 'FileAttributes\.ReparsePoint' -or
    $receiveFolderPolicyText -notmatch 'candidate\.StartsWith' -or
    $receiveFolderPolicyText -notmatch 'SpecialFolder\.Windows' -or
    $receiveFolderPolicyText -notmatch 'CreateNew' -or
    $receiveFolderPolicyText -notmatch 'UnicodeCategory\.Format') {
    throw 'Custom receive-folder policy must reject reparse/UNC/system paths and verify write access.'
}

$startupPath = Join-Path $root 'src\GeniaLink.Windows\Services\StartupIntegration.cs'
$startupText = Get-Content -LiteralPath $startupPath -Raw
if ($startupText -notmatch 'Registry\.CurrentUser' -or $startupText -match 'LocalMachine') {
    throw 'Windows startup integration must remain current-user only.'
}

$trustedStorePath = Join-Path $root 'src\GeniaLink.Windows\Services\TrustedDeviceStore.cs'
$trustedStoreText = Get-Content -LiteralPath $trustedStorePath -Raw
if ($trustedStoreText -notmatch 'MaxTrustedDevices' -or
    $trustedStoreText -notmatch 'MaxStoreBytes' -or
    $trustedStoreText -notmatch 'ValidateDeviceKind' -or
    $trustedStoreText -notmatch 'LastVerifiedAddress' -or
    $trustedStoreText -notmatch 'UpdateVerifiedEndpoint' -or
    $trustedStoreText -notmatch 'LocalNetworkPolicy\.IsAllowedAddress') {
    throw 'Trusted-device store must remain bounded and validate persistent authenticated endpoint metadata.'
}

$discoveryPacketPath = Join-Path $root 'src\GeniaLink.Core\Discovery\DiscoveryPacket.cs'
$discoveryPacketText = Get-Content -LiteralPath $discoveryPacketPath -Raw
if ($discoveryPacketText -notmatch 'ValidateDeviceKind' -or $discoveryPacketText -notmatch 'legacyLength') {
    throw 'Discovery device-kind extension must remain validated and backward-readable.'
}

$windowsMainPath = Join-Path $root 'src\GeniaLink.Windows\MainWindow.xaml.cs'
$windowsMainText = Get-Content -LiteralPath $windowsMainPath -Raw
if ($windowsMainText -notmatch '_staleDevices' -or
    $windowsMainText -notmatch 'last known LAN endpoint' -or
    $windowsMainText -notmatch 'selected\.IdentityMatches' -or
    $windowsMainText -notmatch 'FileTransferClient\.SendFilesAsync' -or
    $windowsMainText -notmatch 'RestorePersistedTrustedEndpoints' -or
    $windowsMainText -notmatch 'TryPersistVerifiedEndpoint' -or
    $windowsMainText -notmatch 'OnAuthenticatedPeerSeen' -or
    $windowsMainText -notmatch 'RemoteFolderClient\.ListFilesAsync' -or
    $windowsMainText -notmatch 'RemoteFolderClient\.GetPreviewAsync' -or
    $windowsMainText -notmatch 'RemoteFolderClient\.RequestDownloadAsync') {
    throw 'Sleeping trusted-peer fallback and remote folder UI must retain identity checks, authenticated endpoint persistence, and trusted transfer clients.'
}

$onDeviceSeenMatch = [regex]::Match(
    $windowsMainText,
    'private void OnDeviceSeen\(DiscoveredDevice device\).*?private void RefreshDeviceList',
    [System.Text.RegularExpressions.RegexOptions]::Singleline)
if (-not $onDeviceSeenMatch.Success -or $onDeviceSeenMatch.Value -match 'UpdateVerifiedEndpoint') {
    throw 'UDP discovery must not persist a trusted endpoint on Windows.'
}

$coreServerPath = Join-Path $root 'src\GeniaLink.Core\Transfers\FileTransferServer.cs'
$coreServerText = Get-Content -LiteralPath $coreServerPath -Raw
if ($coreServerText -notmatch 'authenticatedPeerSeen\?\.Invoke\(remoteDeviceId, remoteAddress\)' -or
    $coreServerText -notmatch 'remoteDeviceId != handshake\.RemoteDeviceId' -or
    $coreServerText -notmatch 'MessageType\.BrowseRequest' -or
    $coreServerText -notmatch 'MessageType\.PreviewRequest' -or
    $coreServerText -notmatch 'RemotePreviewPolicy' -or
    $coreServerText -notmatch 'FileSafety\.ResolveSharedFilePath' -or
    $coreServerText -notmatch 'CreateDownloadRequestAccepted' -or
    $coreServerText -notmatch 'FileTransferClient\.SendFilesAsync' -or
    $coreServerText -notmatch 'SendRequestedFilesAfterCommandSessionAsync') {
    throw 'Windows receiver/remote-folder service must keep authenticated identity validation and root-confined reverse transfer.'
}

$remoteFolderClientPath = Join-Path $root 'src\GeniaLink.Core\Transfers\RemoteFolderClient.cs'
$remoteFolderClientText = Get-Content -LiteralPath $remoteFolderClientPath -Raw
if ($remoteFolderClientText -notmatch 'TrustedSessionHandshake\.CreateClientSessionKeyAsync' -or
    $remoteFolderClientText -notmatch 'LocalNetworkPolicy\.IsAllowedAddress' -or
    $remoteFolderClientText -notmatch 'expectedRemoteDeviceId' -or
    $remoteFolderClientText -notmatch 'IsSafeRelativeFilePath' -or
    $remoteFolderClientText -notmatch 'GetPreviewAsync' -or
    $remoteFolderClientText -notmatch 'CreatePreviewRequest') {
    throw 'Remote Genia Link folder client must remain local-only, trusted-session authenticated, and path validated.'
}


$previewPolicyPath = Join-Path $root 'src\GeniaLink.Core\Transfers\RemotePreviewPolicy.cs'
$previewPolicyText = Get-Content -LiteralPath $previewPolicyPath -Raw
if ($previewPolicyText -notmatch 'MaxTextPreviewBytes' -or
    $previewPolicyText -notmatch 'LooksBinary' -or
    $previewPolicyText -notmatch 'MaxPreviewBytes') {
    throw 'Remote preview must remain size-bounded and reject binary data from text preview.'
}

$remoteBrowserIndexPath = Join-Path $root 'src\GeniaLink.Core\Transfers\RemoteBrowserIndex.cs'
$remoteBrowserIndexText = Get-Content -LiteralPath $remoteBrowserIndexPath -Raw
if ($remoteBrowserIndexText -notmatch 'NormalizeRelativeDirectory' -or
    $remoteBrowserIndexText -notmatch 'StringComparison\.Ordinal') {
    throw 'Remote browser folder navigation must remain root-relative and ordinal.'
}

$remoteFilesWindowPath = Join-Path $root 'src\GeniaLink.Windows\RemoteFilesWindow.xaml.cs'
$remoteFilesWindowText = Get-Content -LiteralPath $remoteFilesWindowPath -Raw
if ($remoteFilesWindowText -notmatch 'RemoteBrowserIndex\.BuildDirectory' -or
    $remoteFilesWindowText -notmatch 'RemotePreviewKind' -or
    $remoteFilesWindowText -notmatch 'LoadPreviewAsync') {
    throw 'Windows remote-file browser navigation/preview UI is missing.'
}

$windowsProjectText = Get-Content -LiteralPath $windowsProject -Raw
$windowsIconPath = Join-Path $root 'src\GeniaLink.Windows\Assets\GeniaLink.ico'
$windowsIconPngPath = Join-Path $root 'src\GeniaLink.Windows\Assets\GeniaLink.png'
if (-not (Test-Path -LiteralPath $windowsIconPath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $windowsIconPngPath -PathType Leaf) -or
    $windowsProjectText -notmatch '<ApplicationIcon>Assets\\GeniaLink\.ico</ApplicationIcon>' -or
    $windowsProjectText -notmatch '<Resource Include="Assets\\GeniaLink\.ico"') {
    throw 'Windows Genia Link branding resources/ApplicationIcon are missing.'
}

$mainWindowXamlPath = Join-Path $root 'src\GeniaLink.Windows\MainWindow.xaml'
$settingsWindowXamlPath = Join-Path $root 'src\GeniaLink.Windows\SettingsWindow.xaml'
$mainWindowXamlText = Get-Content -LiteralPath $mainWindowXamlPath -Raw
$settingsWindowXamlText = Get-Content -LiteralPath $settingsWindowXamlPath -Raw
if ($mainWindowXamlText -notmatch 'Icon="Assets/GeniaLink\.ico"' -or
    $settingsWindowXamlText -notmatch 'Icon="Assets/GeniaLink\.ico"' -or
    $windowsMainText -notmatch 'CreateTrayIcon\(\)' -or
    $windowsMainText -notmatch 'ExtractAssociatedIcon') {
    throw 'Windows title-bar/tray branding integration is missing.'
}

# GNP/1 M2.6.1 introduces local role/capability profiles without changing wire identity.
$capabilitiesPath = Join-Path $root 'src\GeniaLink.Core\Capabilities\DeviceCapabilities.cs'
if (-not (Test-Path -LiteralPath $capabilitiesPath -PathType Leaf)) {
    throw 'GNP/1 M2.6.1 role/capability model is missing.'
}
$capabilitiesText = Get-Content -LiteralPath $capabilitiesPath -Raw
if ($capabilitiesText -notmatch 'enum\s+DeviceRoleProfile' -or
    $capabilitiesText -notmatch 'enum\s+DeviceCapability' -or
    $capabilitiesText -notmatch 'TrustedDiscovery' -or
    $capabilitiesText -notmatch 'TrustedTransport' -or
    $capabilitiesText -notmatch 'GetRequired' -or
    $capabilitiesText -notmatch 'GetPreset' -or
    $capabilitiesText -notmatch 'KnownCapabilities' -or
    $capabilitiesText -notmatch 'Normalize\(') {
    throw 'GNP/1 M2.6.1 role/capability dependency model is incomplete.'
}
if ($settingsText -notmatch 'DeviceRoleProfile\s+DeviceRole' -or
    $settingsText -notmatch 'DeviceCapability\s+Capabilities' -or
    $settingsText -notmatch 'DeviceCapabilityProfiles\.Normalize') {
    throw 'Windows settings must persist and normalize the M2.6 role/capability profile.'
}
if ($settingsWindowXamlText -notmatch 'DeviceRoleComboBox' -or
    $settingsWindowXamlText -notmatch 'TrustedDiscoveryCapabilityCheckBox' -or
    $settingsWindowXamlText -notmatch 'TrustedTransportCapabilityCheckBox') {
    throw 'Windows M2.6 role/capability settings UI is missing.'
}
if ($selfTestText -notmatch 'TestDeviceCapabilityProfiles' -or
    $selfTestText -notmatch 'Unknown capability bits must be stripped') {
    throw 'GNP/1 M2.6 role/capability self-tests are missing.'
}

Write-Host 'GNP/1 M2.6.1 ROLES/CAPABILITIES CHECK PASSED'

# GNP/1 M2.6.2 advertises capabilities only as a signed assertion and applies them
# only after the existing trusted pairing/signing identity is matched.
$capabilityPacketPath = Join-Path $root 'src\GeniaLink.Core\Discovery\CapabilitySignedDiscoveryPacket.cs'
$capabilityRevisionPath = Join-Path $root 'src\GeniaLink.Core\Capabilities\CapabilityAssertionRevisionStore.cs'
foreach ($requiredM262Path in @($capabilityPacketPath, $capabilityRevisionPath)) {
    if (-not (Test-Path -LiteralPath $requiredM262Path -PathType Leaf)) {
        throw "GNP/1 M2.6.2 authenticated capability file is missing: $requiredM262Path"
    }
}
$capabilityPacketText = Get-Content -LiteralPath $capabilityPacketPath -Raw
$capabilityRevisionText = Get-Content -LiteralPath $capabilityRevisionPath -Raw
if ($capabilityPacketText -notmatch '"GLC1"u8' -or
    $capabilityPacketText -notmatch 'capabilityRevision' -or
    $capabilityPacketText -notmatch 'rawCapabilities' -or
    $capabilityPacketText -notmatch 'knownCapabilityBits' -or
    $capabilityPacketText -notmatch 'DeviceCapabilityProfiles\.IsValidAdvertisement' -or
    $capabilityPacketText -notmatch 'DeviceSignature\.Verify') {
    throw 'GNP/1 M2.6.2 GLC1 must sign and verify a bounded capability set with its own monotonic revision and reject out-of-range 64-bit capability values safely.'
}
if ($capabilityRevisionText -notmatch 'LoadOrAdvance' -or
    $capabilityRevisionText -notmatch 'previous\.Revision \+ 1' -or
    $capabilityRevisionText -notmatch 'Capabilities' -or
    $capabilityRevisionText -notmatch '\.bak') {
    throw 'GNP/1 M2.6.2 local capability revision persistence is incomplete.'
}
if ($discoveryServiceText -notmatch 'CapabilitySignedDiscoveryPacket\.Create' -or
    $discoveryServiceText -notmatch 'CapabilitySignedDiscoveryPacket\.ParseAndVerify' -or
    $discoveryServiceText -notmatch 'CapabilitySignedIdentityV2') {
    throw 'GNP/1 M2.6.2 discovery must emit and parse GLC1 without removing legacy discovery envelopes.'
}
if ($trustedIdentityRegistryText -notmatch 'VerifiedCapabilities' -or
    $trustedIdentityRegistryText -notmatch 'LastAcceptedCapabilityRevision' -or
    $trustedIdentityRegistryText -notmatch 'RecordAuthenticatedCapabilities' -or
    $trustedIdentityRegistryText -notmatch 'capabilityRevision < current\.LastAcceptedCapabilityRevision') {
    throw 'GNP/1 M2.6.2 trusted registry must persist only authenticated capability state and reject revision rollback.'
}
foreach ($trustedStoreM262Text in @($windowsTrustedM23Text, $androidTrustedM23Text)) {
    if ($trustedStoreM262Text -notmatch 'CapabilitySignedIdentityV2' -or
        $trustedStoreM262Text -notmatch 'RecordAuthenticatedCapabilities') {
        throw 'Windows and Android must apply GLC1 capabilities only through their trusted-device identity validation path.'
    }
}
if ($capabilitiesText -notmatch 'ResolveProfile' -or
    $settingsWindowXamlText -notmatch 'CapabilityCheckBox_Changed' -or
    $selfTestText -notmatch 'TestCapabilitySignedDiscoveryRoundTrip' -or
    $selfTestText -notmatch 'TestCapabilitySignedDiscoveryTamperDetection' -or
    $selfTestText -notmatch 'TestCapabilitySignedDiscoveryRejectsUnknownHighBits' -or
    $selfTestText -notmatch 'TestCapabilityAssertionRevisionStore') {
    throw 'GNP/1 M2.6.2 automatic profile resolution or capability self-tests are missing.'
}

Write-Host 'GNP/1 M2.6.2 AUTHENTICATED CAPABILITY ADVERTISEMENT CHECK PASSED'

Write-Host 'WINDOWS BRANDING CHECK PASSED'

Write-Host 'V0.3.1 SETTINGS/DEVICE-GROUP/RESUME/FOLDER/TRAY/PERSISTENT-SLEEPING-PEER CHECK PASSED'
Write-Host 'SECURITY CHECK PASSED'
