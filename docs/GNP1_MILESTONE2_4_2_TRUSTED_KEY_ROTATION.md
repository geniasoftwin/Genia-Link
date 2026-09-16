# GNP/1 Milestone 2.4.2 — Trusted Key Rotation

## Цель

M2.4.2 добавляет контролируемую смену постоянного ECDSA P-256 signing key без нового SAS pairing и без изменения постоянного `DeviceId` или ECDH pairing anchor.

M2.3 подтверждал signing identity через уже доверенную ECDH-сессию, а M2.4.1 сохранял её и историю в Trusted Identity Registry. M2.4.2 усиливает правило замены: **одного более высокого `KeyGeneration` теперь недостаточно**. Новый signing key принимается только если peer предъявляет непрерывную цепочку сертификатов преемственности, подписанных предыдущими доверенными signing keys.

## Криптографическое правило

Каждый переход `generation N -> N+1` создаёт `GLR1` certificate со следующими полями:

- protocol version;
- persistent `DeviceId`;
- identity version;
- previous generation;
- new generation;
- previous ECDSA P-256 public key;
- new ECDSA P-256 public key;
- ECDSA/SHA-256 подпись всех предыдущих полей старым signing key.

При проверке обязательны:

1. тот же `DeviceId` и identity version;
2. ровно `NewGeneration = PreviousGeneration + 1`;
3. новый public key действительно отличается от старого;
4. оба public keys валидны как ECDSA P-256;
5. подпись certificate проверяется предыдущим public key;
6. цепочка непрерывна по generation и public key;
7. цепочка содержит текущий локально trusted key как anchor и доходит до предъявленного current key.

Если любое условие не выполняется, замена ключа отклоняется. Existing pairing при этом не переписывается автоматически.

## GLI1 / GLI2

До первой rotation M2.4.2 продолжает передавать прежний `GLI1(DeviceId, IdentityVersion, KeyGeneration, SigningPublicKey)`. Это сохраняет рабочую совместимость с M2.4.1 во время обновления сети.

После первой rotation локальная identity содержит continuity chain и на TCP 47503 передаёт `GLI2`:

- общий signing-identity header;
- число rotation certificates;
- current signing public key;
- bounded sequence of serialized `GLR1` certificates.

Максимальная цепочка — 32 certificates. Это позволяет устройству, которое долго спало и пропустило несколько rotations, проверить переход от последнего известного ему trusted generation до текущего. Если trusted generation старше первого сохранённого certificate, автоматическая continuity verification невозможна и требуется explicit re-pair.

## Локальная rotation

Rotation специально не выполняется «на лету» под работающими discovery/receiver/binding services.

Windows и Android используют двухшаговую процедуру:

1. пользователь выбирает **Trusted Key Rotation / Сменить signing key**;
2. приложение атомарно записывает локальный `rotate-signing-key.request.json`, привязанный к текущим `DeviceId`, generation и Signing Key ID;
3. на следующем чистом запуске request повторно сверяется с текущей identity;
4. создаётся новый non-exportable ECDSA P-256 private key;
5. текущий старый key подписывает `GLR1` переход `N -> N+1`;
6. новая metadata + continuity chain сохраняются;
7. только после успешного сохранения старый private signing key удаляется;
8. `DeviceId` и ECDH pairing key остаются неизменными.

Stale request, который больше не соответствует текущей identity, удаляется и не применяется.

## Потеря private signing key

Если signing private key неожиданно исчез или перестал проходить проверку, приложение может локально создать новый signing key, чтобы identity оставалась работоспособной, но **не может подделать continuity proof от потерянного ключа**. В этом случае continuity chain сбрасывается, и уже доверенные peers должны потребовать explicit re-pair для нового signing key.

Это намеренный fail-closed режим.

## Trusted Identity Registry

После аутентифицированной M2.4.2 rotation:

- `trusted-devices.json` принимает новый key только после `SigningKeyRotation.ValidateTrustedTransition`;
- `trusted-identities.json` независимо проверяет ту же continuity proof;
- предыдущий trusted signing key переносится в bounded history;
- current generation/public key/key id атомарно продвигаются вперёд;
- generation rollback и same-key generation increase отклоняются.

Локальная migration/recovery из уже существующего `trusted-devices.json` остаётся отдельным явно разрешённым путём M2.4.1 и не является сетевым разрешением на rotation.

## Rollout

**Важно: до первой реальной rotation обновить все устройства одной trust-группы до M2.4.2.**

Пока rotation ещё не выполнялась, M2.4.2 использует GLI1 и совместим с M2.4.1. После rotation peer начинает предъявлять GLI2; M2.4.1 не знает continuity-chain format и не сможет автоматически принять новый signing key.

Рекомендуемый rollout:

1. установить M2.4.2 на все Windows/Android устройства;
2. убедиться, что обычные передачи и M2.3 binding работают без изменения generation;
3. выбрать **одно** устройство и запланировать rotation;
4. полностью закрыть и заново запустить его;
5. убедиться в логе `generation N -> N+1` и новом Signing Key ID при неизменном Device ID;
6. дождаться authenticated binding с каждым peer;
7. убедиться, что peers логируют M2.4.2 `rotated`, не требуют нового pairing и сохраняют transfer;
8. только после этого тестировать rotation следующего устройства.

## Acceptance tests

Минимальный реальный тест M2.4.2:

- all peers updated before rotation;
- no-rotation regression: Windows ↔ Windows, Windows ↔ Android, Android ↔ Android;
- one Windows rotation `1 -> 2`;
- one Android rotation `1 -> 2`;
- transfer both directions after each rotation;
- sleeping peer misses a rotation and later validates the chain;
- second rotation `2 -> 3` validates on a peer that still trusts generation 1;
- tampered/unproven newer key is rejected;
- lower-generation rollback is rejected;
- same key with artificially raised generation is rejected;
- pairing Device ID/ECDH fingerprint remains unchanged;
- M2.4.1 registry history contains retired keys after successful rotation.

## Не меняется

- `ProtocolConstants.Version = 3`;
- TCP 47500 transfer;
- TCP 47501 SAS pairing;
- UDP 47502 signed discovery (`GLS1` + compatibility `GLD2`);
- TCP 47503 remains the trusted signing-identity binding endpoint;
- ECDH pairing anchor and Device ID are not rotated by this milestone;
- no cloud, account, telemetry or Internet dependency is introduced.
