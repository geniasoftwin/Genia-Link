# Genia Link protocol v3

Protocol v3 работает только в локальной IPv4-сети и добавляет resumable transfer и относительный каталог файла.

## Endpoints

- TCP 47500 — trusted encrypted file transfer.
- TCP 47501 — pairing.
- UDP 47502 — discovery.
- TCP 47503 — GNP/1 M2.3 trusted signing-identity binding (additive; protocol v3 transfer/pairing remain unchanged).

Все адреса дополнительно проходят `LocalNetworkPolicy`.

## Discovery device type extension (RC1 fix8)

Discovery advertisement v3 может содержать один дополнительный байт `DeviceKind` после 16-байтного fingerprint: `Unknown`, `WindowsComputer`, `AndroidPhone` или `AndroidTablet`. Новый parser принимает и прежний v3 discovery packet без этого байта и в таком случае использует `Unknown`.

`DeviceKind` — **только UI metadata** для иконок/групп «Компьютеры / Мобильные». UDP discovery не является доверенным, поэтому тип устройства никогда не участвует в авторизации, выборе shared key или проверке identity. Доверие определяется только сохранённой криптографической идентичностью peer.

## GNP/1 M2.2 signed discovery envelope

M2.2 не изменяет существующий `GLD2` discovery packet и не меняет `ProtocolConstants.Version = 3`. Новый узел дополнительно отправляет отдельный пакет `GLS1`, подписанный постоянным ECDSA P-256 signing key из Device Identity v2, а сразу после него — прежний `GLD2` для обратной совместимости.

Подпись `GLS1` связывает `DeviceId`, protocol/identity version, transfer/pairing ports, `DeviceKind`, key generation, имя устройства, прежний ECDH fingerprint и SubjectPublicKeyInfo signing key. `SigningKeyId` получатель вычисляет сам как SHA-256 от проверенного public signing key. Изменение любого подписанного байта делает пакет недействительным.

Это **self-signed proof**, а не trust grant: неизвестный узел всё ещё не становится доверенным только из-за корректной подписи собственным ключом. `GLS1` также не является доказательством свежести/liveness и в M2.2 не заменяет pairing или `TrustedSessionHandshake`. Подробный формат и acceptance test: `GNP1_MILESTONE2_2_SIGNED_DISCOVERY.md`.

## GNP/1 M2.3 trusted signing-identity binding

M2.3 не меняет `GLD2`, `GLS1`, pairing, transfer messages или `ProtocolConstants.Version = 3`. Для уже сопряжённых устройств добавлен отдельный TCP 47503. На нём сначала выполняется существующий `TrustedSessionHandshake` по сохранённому ECDH trust, затем внутри `SecureChannel` стороны обмениваются bounded `GLI1(DeviceId, IdentityVersion, KeyGeneration, SigningPublicKey)` и локально вычисляют `SigningKeyId`.

`GLI1` никогда не принимается как доверенный до успешной trusted-session аутентификации. Поэтому spoofed/self-signed UDP не может закрепить новый signing key в trusted store. В исходном M2.3 different key допускался через authenticated binding с более высоким `KeyGeneration`; начиная с M2.4.2 это правило усилено continuity proof, описанным ниже. Подробности базового binding: `GNP1_MILESTONE2_3_TRUSTED_SIGNING_BINDING.md`.

## GNP/1 M2.4.2 trusted signing-key rotation

M2.4.2 сохраняет TCP 47503 и `ProtocolConstants.Version = 3`, но добавляет rotation-aware `GLI2` envelope. Пока локальный signing key ни разу не вращался, узел продолжает отправлять `GLI1`, поэтому обновление M2.4.1 → M2.4.2 не меняет обычный binding. После rotation `GLI2` передаёт current signing identity и bounded chain (до 32) сертификатов `GLR1`.

Каждый `GLR1` связывает один persistent `DeviceId`, identity version, previous/new generation и previous/new ECDSA P-256 public keys и подписывается **previous signing key**. Generation обязан увеличиваться ровно на `+1`. Получатель проверяет подписи всей chain, её непрерывность, затем находит в ней собственный current trusted `(generation, public key)` и требует, чтобы цепочка дошла до предъявленного current signing key. Поэтому одной authenticated ECDH session и произвольного более высокого generation больше недостаточно для замены trusted signing key.

Сценарий multi-hop поддерживается: peer, доверяющий generation 1, может принять generation 3 через `1→2` + `2→3`. Если его trusted anchor старше первого из 32 сохранённых certificates, автоматическая rotation отклоняется и требуется explicit re-pair.

Rollout rule: **сначала обновить все peers trust-группы до M2.4.2, затем выполнять первую rotation**. M2.4.1 не распознаёт `GLI2`. Подробности: `GNP1_MILESTONE2_4_2_TRUSTED_KEY_ROTATION.md`.

## Sleeping trusted peers (RC1 fix10 / fix11)

`DiscoveryExpiry` по-прежнему означает, что свежего UDP advertisement давно не было. Для несопряжённых устройств такой peer удаляется из UI как раньше. Уже доверенное устройство остаётся в списке со статусом `спит / нет свежего discovery`, чтобы Android/MagicOS мог экономить батарею и при этом просыпаться от реального TCP-подключения.

Fix11 добавляет перезапускоустойчивый route cache для trusted peers. В `trusted-devices.json` сохраняются IPv4, transfer/pairing ports и время проверки **только после криптографически подтверждённого события**: успешного SAS pairing на стороне инициатора, успешной authenticated transfer-сессии отправителя или принятого incoming trusted-session после проверки shared identity/`DeviceId`. Обычный UDP discovery может обновлять текущий UI-сеанс, но сам по себе не записывает endpoint на диск. Старые fix10 records без endpoint остаются валидными и получают route после следующей подтверждённой связи.

При старте Windows/Android сохранённый trusted endpoint восстанавливается как stale/sleeping peer. Endpoint **не является источником доверия**: отправитель использует сохранённый public key/shared identity material, передаёт ожидаемый `DeviceId` в trusted-session handshake и начинает transfer только после успешной аутентификации. Если DHCP отдал старый IP другому хосту, соединение должно завершиться безопасной ошибкой/тайм-аутом; посторонний хост не получает файл.

## Pairing / trusted session

Pairing остаётся ECDH P-256 + SAS. После подтверждения peer public key хранится локально. Новое TCP 47500 соединение выполняет trusted-session handshake и создаёт per-session key; затем работает `SecureChannel` с аутентифицированными кадрами и sequence protection.

## Transfer flow v3

1. Sender → `Hello(version=3, deviceId, deviceName)`.
2. Receiver → `HelloAck(version=3, deviceId, deviceName)`.
3. Для каждого файла Sender → `FileOffer`:
   - random `TransferId`;
   - safe `FileName`;
   - safe `/`-separated `RelativeDirectory`;
   - `FileSize`;
   - SHA-256 полного файла.
4. Receiver ищет подходящий partial по deterministic resume-key и хеширует сохранённый prefix.
5. Receiver → `FileAccept(TransferId, ResumeOffset)` либо `FileReject`.
6. Sender начинает чтение с `ResumeOffset` и посылает `FileChunk(TransferId, Offset, Data)`.
7. Receiver требует строго последовательный `Offset` и не принимает данные сверх `FileSize`.
8. Sender → `FileComplete`.
9. Receiver проверяет полный размер и SHA-256, публикует/перемещает файл атомарно насколько позволяет платформа.
10. Receiver → `TransferResult`.
11. Следующий файл может идти по тому же SecureChannel, до safety batch limit.


## Protected Genia Link folder extension (RC1 fix13)

Protocol version остаётся `3`; новые message types являются additive extension. Обычный FileOffer/FileChunk flow не меняется.

После trusted-session handshake и `Hello/HelloAck` инициатор может отправить:

1. `BrowseRequest`.
2. Peer отвечает `BrowseListStart(count)`.
3. Затем ровно `count` сообщений `BrowseEntry(relativePath, fileSize, modifiedUnixSeconds)`.
4. Завершает `BrowseListEnd`.

`relativePath` всегда относится **только к локальной папке Genia Link** и проходит те же segment/traversal ограничения. На Windows reparse points не публикуются. На Android каталог строится только из MediaStore `Download/Genia Link`.

Для скачивания инициатор отправляет:

1. `DownloadRequestStart(count, returnTransferPort=47500)`.
2. `count` сообщений `DownloadRequestItem(relativePath)`.
3. `DownloadRequestCommit`.
4. Источник повторно разрешает каждый путь внутри своего shared root и отвечает `DownloadRequestAccepted(count)` либо `DownloadRequestRejected(reason)`.
5. После `Accepted` источник инициирует **новую обычную trusted transfer session** к IP аутентифицированного requester на TCP 47500 и отправляет выбранные файлы через FileOffer/FileAccept/FileChunk/FileComplete/TransferResult.

Таким образом control channel не создаёт второй файловый формат: SHA-256, resume, destination policy и expected DeviceId остаются теми же. Callback IP нельзя задавать в request, а callback port обязан быть 47500.

## Resume identity

Resume-key = SHA-256 от полного file hash + big-endian size + normalized relative directory + separator + file name; в имени partial используется 128-bit hex prefix digest. ResumeOffset никогда не считается доказательством целостности: сохранённый prefix входит в IncrementalHash, а конечный SHA-256 обязан совпасть с FileOffer.

## Compatibility

v3 intentionally rejects v2 transfer peers by protocol version. Fix13 сохраняет номер v3, поэтому обычная передача fix13 ↔ fix12 остаётся совместимой. Protected Genia Link folder extension требует fix13 на обеих сторонах; fix12 не знает BrowseRequest/DownloadRequest messages.

## Safe remote preview extension (RC2)

Protocol version остаётся `3`. После authenticated trusted-session и `Hello/HelloAck` клиент RC2 может отправить `PreviewRequest(relativePath)` (`MessageType = 39`). Peer RC2 отвечает одним `PreviewResponse` (`MessageType = 40`) с тем же нормализованным `relativePath`, типом предпросмотра, media type, bounded payload и коротким status/message.

Предпросмотр не меняет обычный download flow и не считается передачей файла. Ограничения обязательны:

- запрашиваемый путь повторно нормализуется и разрешается только внутри локальной папки Genia Link;
- произвольный absolute path, `..`, callback URL/host или другой filesystem root в preview request отсутствуют;
- текстовый preview читает максимум `64 KiB` полезного текста; бинарно выглядящие данные не декодируются как текст;
- изображение на стороне источника декодируется локально, уменьшается и перекодируется в JPEG-thumbnail; размер response payload не превышает `192 KiB`;
- PDF, видео, аудио, архивы и неизвестные типы в первой версии возвращают metadata/status без скрытого скачивания полного файла;
- preview response всё ещё идёт внутри существующего authenticated/encrypted `SecureChannel` и подчиняется frame-size limits;
- preview никогда не переносит trust: DeviceId/public key/shared identity проверяются до обработки запроса так же, как для browse/download.

Папки в UI RC2 не являются отдельным сетевым объектом протокола: они безопасно **выводятся** из уже проверенных `BrowseEntry(relativePath, ...)`. Поэтому источник по-прежнему публикует только файлы, а клиент строит навигацию по их нормализованным относительным путям. Пустые каталоги в этой версии не отображаются.

Совместимость additive: обычный protocol-v3 transfer и fix13 browse/download сохраняют wire-format. Preview требует RC2-compatible serving peer; более старый peer должен завершить неподдерживаемую preview-команду безопасной ошибкой, не изменяя trust и файлы.

## GNP/1 M2.5 authenticated rename propagation

M2.5 checkpoint 1 does not add a new packet or change `ProtocolConstants.Version = 3`. `GLS1` already cryptographically binds `DeviceName` to `DeviceId`, ECDH fingerprint, signing public key, identity version and key generation. The new rule allows that signed name to update local trusted state only when the verified advertisement exactly matches the already pinned ECDH and ECDSA identity and the Trusted Identity Registry remains in `Trusted` state.

Thus an OS rename such as `DESKTOP-TOFLGGG -> GENIABOOK` can propagate without SAS re-pair while preserving Device ID, ECDH key, Signing Key ID and generation. Legacy unsigned `GLD2`, an unknown/self-signed key, stale generation, mismatched ECDH fingerprint or an untrusted registry state cannot change the stored trusted name. If discovery carries a legitimately rotated signing key, M2.4.2 continuity binding must authenticate that key first; only then can the name signed by it be accepted. Details and acceptance test: `GNP1_MILESTONE2_5_AUTHENTICATED_RENAME.md`.

### M2.5 checkpoint-1 freshness note (superseded by M2.5.3)

The original `GLS1` envelope authenticates the advertised name but does not order historical valid assertions. M2.5.3 addresses this specific replay/rollback gap with `GLS2` and a signed monotonic `IdentityRevision`. On an M2.5.3 node, `GLS1` remains a compatibility proof but is no longer sufficient to mutate the persisted trusted name.

## GNP/1 M2.5.2 trusted identity lifecycle

M2.5.2 does not add a packet, port, or protocol-version change. It adds local administrative state to the Trusted Identity Registry: `Active`, `Retired`, and `Revoked`, independently of cryptographic `Trusted / Changed`. Only `Trusted + Active` identities are eligible for normal trusted network use. `Retired` is locally reversible; `Revoked` is terminal until explicit Forget + fresh SAS pairing. Startup synchronization, signed discovery, rename, key rotation and pairing-anchor replacement cannot reactivate an inactive identity.

M2.5.2 introduced registry schema version 3 with a bounded local event sequence plus a local `TrustRelationshipId` for trust, authenticated rename, signing-key rotation, lifecycle change and pairing-anchor replacement. These events are local audit/state-management data; M2.5.2 does not distribute lifecycle commands to other peers and does not create a network administrative authority. Details: `GNP1_MILESTONE2_5_2_TRUSTED_IDENTITY_LIFECYCLE.md`.


## GNP/1 M2.5.2.1 trust-scoped session/resume enforcement

No new packet or protocol-version change is introduced. After the normal trusted handshake, the receiver additionally obtains local session authorization for the authenticated remote Device ID. That authorization contains the current `TrustRelationshipId` and a lifetime token. `Revoked`, Forget, or explicit pairing-trust replacement cancels the prior lifetime; active receiver/sender loops terminate when the token is canceled. `Retired` denies new authorization but does not cancel an authorization already issued before retirement.

The deterministic local resume key is now scoped by `RemoteDeviceId + TrustRelationshipId` before the existing file hash/size/path/name material. This prevents a new trust relationship from silently adopting unfinished data from an old/revoked relationship while leaving protocol v3 `FileOffer/FileAccept` framing unchanged.


## GNP/1 M2.5.3 replay-protected identity assertions

M2.5.3 adds an additive discovery envelope `GLS2`; `ProtocolConstants.Version` remains 3. The sender transmits `GLS2` first, followed by `GLS1` and unchanged `GLD2` for backward compatibility. `GLS2` signs: magic/version, identity version, `DeviceId`, transfer/pairing ports, `DeviceKind`, signing-key generation, a positive signed 64-bit `IdentityRevision`, UTF-8 device name, existing ECDH pairing-key fingerprint, and the ECDSA P-256 signing public key. The receiver derives `SigningKeyId` from that verified public key exactly as with `GLS1`.

The local assertion revision is persistent. It remains unchanged while the signed public assertion is unchanged and advances when the device name/kind or current signing key generation/key changes. Trusted Identity Registry schema v4 stores `LastAcceptedIdentityRevision`. For an already pinned active trusted identity: `revision < last` is rejected; `revision == last` with a different name is rejected; `revision >= last` with the same name may refresh authentication state; a higher revision with a matching current ECDH/signing identity may authorize an authenticated rename. Historical GLS2 from an old signing generation is independently rejected by the current signing-key binding.

`GLS1` is deliberately not removed. Older peers can still discover M2.5.3 nodes, and M2.5.3 nodes can still authenticate compatible signed discovery. However unordered `GLS1` cannot mutate the trusted name on an M2.5.3 receiver. Consequently, mixed-version transfer remains compatible, while replay-protected automatic rename toward an M2.5.3 receiver requires a GLS2-capable sender. Local `Active / Retired / Revoked` remains local policy; this packet does not create or propagate network administrative authority.


## GNP/1 M2.6.1 local roles/capabilities

M2.6.1 does not change the wire protocol. `DeviceRoleProfile` and `DeviceCapability` are local configuration state only and are not trusted merely because a device selects them. Authenticated capability advertisement/authorization will require a later protocol checkpoint.

## GNP/1 M2.6.2 authenticated capability advertisement

M2.6.2 supersedes the M2.6.1 "local only" capability limitation with an additive signed discovery envelope `GLC1`; protocol version remains 3. GLC1 carries the M2.5.3 replay-protected identity assertion plus a separate positive monotonic `CapabilityRevision` and the bounded `DeviceCapability` bitset. Current nodes send `GLC1 -> GLS2 -> GLS1 -> GLD2`, preserving mixed-version discovery.

A verified GLC1 signature is not a trust grant. The advertised capability set is persisted only when the receiver already has an Active/Trusted identity whose ECDH pairing anchor and current pinned ECDSA signing identity/generation match the packet. Trusted Identity Registry schema v5 stores `VerifiedCapabilities`, `LastAcceptedCapabilityRevision` and `CapabilitiesLastVerifiedAtUtc`. Lower capability revisions and same-revision/different-set conflicts are rejected. Unknown bits or an advertisement missing the mandatory Trusted Discovery + Trusted Transport core are rejected.

The local capability assertion uses its own persistent `capability-assertion-revision.json`, because capabilities may change without changing the M2.5.3 public identity assertion. Roles are not sent as authority: the receiver/local UI derives Client/Server/Relay/Backup only when the authenticated capability set exactly matches a known preset; otherwise the presentation profile is Custom. See `GNP1_MILESTONE2_6_2_AUTHENTICATED_CAPABILITIES.md`.
