# Genia Link v0.3.1 RC4 — security notes

> **RC4 is the Android Always Ready release candidate.** It adds an explicit opt-in path for the official Android battery-optimization exemption so a trusted phone can remain reachable after long idle periods. The wire protocol, pairing, trusted-session handshake, AES-GCM transfer, SHA-256, resume, root-confined browse/preview and persistent authenticated endpoint rules remain unchanged. UDP discovery never grants folder or preview access.

## Security baseline from RC2

- **Preview is trusted-only:** `PreviewRequest` is accepted only after `TrustedSessionHandshake`, Hello identity verification and `SecureChannel` establishment, exactly like Browse/Download commands.
- **Preview is root-confined:** the requested path must pass `NormalizeRelativeFilePath`. Windows resolves it through `ResolveSharedFilePath`, which rejects traversal and reparse/symlink/junction components. Android resolves only against the MediaStore catalog already confined to `Download/Genia Link`.
- **Strict preview size caps:** text reads at most 64 KiB before truncation; one preview payload is capped at 192 KiB, below the encrypted frame limit. Binary-looking content is not exposed as text.
- **Image preview is generated locally:** Windows/Android decode the local image and send only a bounded JPEG thumbnail. The client does not need the original full image for preview. Unsupported/PDF/video/audio/archive types return metadata-only/unavailable preview rather than silently downloading the file.
- **No remote execution:** preview bytes are decoded/rendered in Genia Link UI only. They are not written to arbitrary paths, launched, or handed to shell applications.
- **Folder UI is derived from safe file metadata:** folders are virtual navigation nodes built from already validated relative file paths; they do not introduce a new filesystem operation. Empty folders are not published.
- **No trust-by-name replacement:** same-name DeviceId replacement remains explicit user choice only. IP/name never substitute for cryptographic identity.
- **Reverse download unchanged:** actual selected files still arrive through the normal authenticated encrypted transfer on fixed Genia Link TCP 47500 with expected DeviceId, SHA-256 and resume semantics.
- **Protocol compatibility:** wire version stays v3. New optional preview MessageTypes are 39/40. Older peers can still use ordinary transfer and the existing browse/download extension, but preview requires an RC2-or-newer serving peer.

## Security additions RC1 fix8

- **Пользовательская папка приёма:** принимается только полный локальный путь. Запрещены UNC/network path, корень диска, Windows/Program Files/ProgramData и выбранный root с `ReparsePoint`. До сохранения выполняется безопасная проверка записи через уникальный temporary `CreateNew` файл. Внутренние относительные пути и `.genialink-resume` дополнительно продолжают проходить `FileSafety` с traversal/reparse checks.
- **Смена папки во время transfer:** запрещена, чтобы не переключить destination root посреди зашифрованной сессии. После безопасной смены local receiver/discovery/pairing sockets перезапускаются.
- **Autostart:** используется только `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`; `HKLM`, служба и elevation не используются. Команда содержит quoted `Environment.ProcessPath` и фиксированный `--startup`.
- **Settings store:** JSON ограничен 64 KiB, записывается через temporary + replace/move и валидирует receive-folder при загрузке.
- **Trusted-device store:** ограничен 1 MiB / 1024 устройствами, проверяет имя, public key и `DeviceKind`, откатывает in-memory изменение при ошибке записи.
- **Persistent trusted endpoint (fix11):** trusted store может хранить последний подтверждённый local IPv4 + transfer/pairing ports + timestamp. Endpoint валидируется через `LocalNetworkPolicy`, обновляется после SAS pairing / authenticated transfer / authenticated incoming trusted-session и не создаёт trust сам по себе. Старый IP всегда повторно проходит expected `DeviceId` + trusted-session handshake перед FileOffer.
- **Discovery isolation (fix11):** `OnDeviceSeen` сохраняет свежий route только в памяти текущего UI-сеанса и не вызывает disk `UpdateVerifiedEndpoint`; spoofed UDP therefore может максимум вызвать временный DoS/route confusion, но не авторизует transfer.
- **DeviceKind:** поле discovery считается недоверенной UI-метаинформацией. Подмена типа (`телефон`/`ПК`) не даёт доверия и не влияет на shared key или authenticated transfer. Новый parser принимает старый v3 advertisement без поля как `Unknown` и отклоняет неизвестные enum values.
- **SendTo:** настройка только включает/выключает уже существующую current-user shell integration; в меню публикуются только online + trusted + identity-matching peers.

## Локальная идентичность Windows и Android

На Windows создаётся ECDH P-256 ключ в Microsoft Software Key Storage Provider через CNG. В `identity.json` сохраняются только DeviceId и имя CNG-ключа.

На Android stage 2 ECDH P-256 ключ создаётся в Android Keystore (`PURPOSE_AGREE_KEY`, `secp256r1`). В `identity.json` сохраняются только DeviceId и Keystore alias; приватный ключ код Genia Link не экспортирует. При неудачном создании metadata новый alias удаляется, чтобы не накапливать сиротские ключи.

На обеих платформах trusted-device store содержит публичные ключи peer и локальные метаданные. Начиная с fix11 к метаданным может относиться последний криптографически подтверждённый LAN endpoint; он используется только как route hint и никогда не заменяет trusted handshake.

## Что остаётся ограничением v0.2.4

- Протокол пока не проходил независимый внешний криптографический аудит.
- Долгосрочный ECDH даёт аутентификацию доверенного peer, но текущая схема не обеспечивает полноценную forward secrecy при последующей компрометации долгосрочного приватного ключа и наличии записанного сетевого трафика. Для production-уровня стоит перейти на аутентифицированный ephemeral ECDH handshake.
- 6-значный SAS не является паролем/ключом шифрования. Он предназначен только для визуального сравнения во время первичного сопряжения; повторные попытки pairing пока не rate-limited.
- UDP discovery раскрывает в локальной сети имя устройства, IP/порты и fingerprint публичного ключа. Содержимое файлов при этом не раскрывается.
- TCP pairing/transfer listeners пока обрабатывают подключения консервативно; полноценного per-IP throttling/ban-list ещё нет. Злоумышленник в LAN может создавать DoS-нагрузку соединениями.
- IP-адреса, размеры и timing сетевого трафика видимы участникам локальной сети.
- Android v0.2.4 реализует discovery, pairing и зашифрованную передачу TCP 47500 в обе стороны. Локальная доступность поддерживается foreground `connectedDevice` service; активная передача дополнительно использует foreground `dataSync` service и временный partial wake lock.
- USB ещё не реализован.

## Практические правила

- Разрешайте Genia Link в Windows Firewall только для Private network profile.
- На Android discovery/receiver/pairing принадлежат foreground `connectedDevice` service и продолжают работать при свёрнутой Activity, открытом системном проводнике и погашенном экране. Постоянное уведомление делает этот режим видимым пользователю и содержит действие `Остановить`. Partial wake lock используется только во время активной передачи, а не для простоя discovery.
- Не пробрасывайте TCP 47500/47501/47503 или UDP 47502 на интернет через роутер.
- При первом pairing нажимайте «Да» только если 6-значный код на двух устройствах совпадает полностью.
- Если доверенное устройство неожиданно показывает «идентичность изменилась», не отправляйте файлы до выяснения причины и нового осознанного pairing.

## RC2 hardening

- Browse/download command session и reverse file-transfer не перекрываются во времени: после authenticated `DownloadRequestAccepted` callback стартует отложенно и использует обычный trusted encrypted transfer.
- Ключ callback-сеанса зануляется после завершения/ошибки.
- Folder navigation строится только из уже безопасных относительных `BrowseEntry`; отдельной команды «открыть произвольный каталог» нет.
- Preview path повторно проверяется на serving peer и не может выйти за локальный Genia Link root.
- Text preview ограничен 64 KiB, image preview перекодируется в bounded JPEG thumbnail до 192 KiB; unsupported media не запускаются и не скачиваются скрытно.
- Windows preview resources и Android decoded preview bitmap освобождаются после использования; обычный receiver остаётся независимым.
- Android UI updates после authenticated network actions продолжают маршалиться на main thread.
- Protocol version остаётся 3; preview MessageTypes 39/40 являются additive extension.

## GNP/1 M2.1 signing identity checkpoint

The M2.1 development checkpoint adds a separate ECDSA P-256 signing key to each persistent installation identity. The existing ECDH P-256 key remains dedicated to key agreement. Windows keeps both private keys non-exportable in CNG; Android keeps both private keys in Android Keystore. `identity.json` contains only identifiers, aliases/key names, version/generation, and creation metadata; it never contains private key bytes. M2.1 does not change protocol v3 or transmit the signing public key yet. See `docs/GNP1_MILESTONE2_SIGNING_IDENTITY.md`.

## GNP/1 M2.2 signed discovery checkpoint

M2.2 introduces an additive self-signed `GLS1` UDP discovery envelope while continuing to broadcast the exact legacy `GLD2` packet. The ECDSA P-256 signature binds the existing Device ID and ECDH fingerprint to the included signing public key and advertised metadata. A valid `GLS1` signature proves possession of that included signing key and detects packet modification, but it is not yet a trust decision and is not a freshness/liveness proof. Trusted authorization continues to depend on pairing and `TrustedSessionHandshake`. The signing key must be authenticated/pinned by a later trust milestone before a signing-key mismatch can authorize or revoke trust. See `docs/GNP1_MILESTONE2_2_SIGNED_DISCOVERY.md`.

## GNP/1 M2.3 trusted signing-key binding checkpoint

M2.3 upgrades the M2.2 self-signed discovery key from an observation to an authenticated trusted-device binding. The new LAN-only TCP 47503 exchange first runs the existing ECDH-backed `TrustedSessionHandshake`, then exchanges `GLI1` signing public identities inside `SecureChannel`. Only a successfully authenticated peer may populate or rotate the signing-key fields in `trusted-devices.json`; UDP discovery alone cannot do so. Same/lower-generation conflicting keys are rejected, while a different key requires an authenticated higher `KeyGeneration`. Existing TCP 47500 transfer, TCP 47501 pairing, UDP 47502 discovery and protocol version 3 remain unchanged. See `docs/GNP1_MILESTONE2_3_TRUSTED_SIGNING_BINDING.md`.

## GNP/1 M2.4.2 trusted signing-key rotation checkpoint

M2.4.2 deliberately supersedes the weaker M2.3 replacement rule. An authenticated ECDH session plus a larger generation number is no longer sufficient to replace an already pinned signing key. Every intentional transition is represented by a bounded `GLR1` certificate signed by the immediately previous ECDSA P-256 key, with generation advancing exactly `N -> N+1`. Rotated identities present the complete retained certificate chain in `GLI2`; both `trusted-devices.json` and the M2.4.1 Trusted Identity Registry independently anchor that chain at their currently trusted public key before accepting the replacement. Missing proof, a broken chain, same-key generation inflation, rollback, Device ID mismatch, or signature failure is rejected fail-closed.

The local rotation operation is staged for the next clean process start: create new non-exportable key → sign continuity certificate with old key → validate chain → persist metadata → only then delete the old private key. Unexpected loss of the old private key cannot be converted into a continuity proof; peers must explicitly re-pair. Update all trusted peers to M2.4.2 before the first rotation because M2.4.1 does not parse the new `GLI2` presentation. See `docs/GNP1_MILESTONE2_4_2_TRUSTED_KEY_ROTATION.md`.

## GNP/1 M2.5 authenticated rename checkpoint

M2.5 does not treat a human-readable device name as a new trust anchor. M2.5 initially allowed a verified `GLS1` name to replace the stored trusted name when all existing trust anchors matched. M2.5.3 supersedes that mutation path: trusted-name changes now require replay-protected `GLS2` with a strictly ordered signed identity revision; `GLS1` remains a compatibility proof but cannot mutate the saved name. This permits legitimate OS/device renames without repeat pairing while preventing unsigned discovery or a different self-signed key from rewriting trusted identity state. A rotated signing key must first pass the existing M2.4.2 continuity proof before its signed name can propagate. Device ID, pairing key, signing key history and original trust timestamp remain unchanged. See `docs/GNP1_MILESTONE2_5_AUTHENTICATED_RENAME.md`.

## GNP/1 M2.5.2 trusted identity lifecycle checkpoint

M2.5.2 adds a second, independent state dimension: cryptographic `Trusted / Changed` remains the statement about key-binding integrity, while administrative `Active / Retired / Revoked` determines whether the local node permits use of that identity. All normal trusted-device lookups require `Trusted + Active`. Retired and Revoked records are suppressed from ordinary discovery presentation, do not retain a routable endpoint, and cannot refresh endpoint state, propagate rename, bind/rotate signing keys, or replace their pairing anchor. Retired can be explicitly reactivated only while its cryptographic binding remains Trusted. Revoked is terminal until the user explicitly forgets the record and performs a fresh SAS pairing.

M2.5.2 introduced registry schema v3 with the bounded local event history and a trust-relationship identifier for initial trust, authenticated rename, signing-key rotation, lifecycle transitions and pairing-trust replacement. Registry-only records survive compatibility-store recovery so revocation cannot be silently erased; Windows settings can still expose and Forget such records to prevent an administrative lockout. Revoking also removes the peer from legacy `trusted-devices.json` as defense in depth against accidental execution of a pre-lifecycle build. Lifecycle changes are **local policy only** in M2.5.2: there is no network-wide revocation authority or unsigned propagation of administrative state. M2.5.3 upgrades the registry to schema v4; local downgrade over current lifecycle/replay-managed app data is unsupported. See `docs/GNP1_MILESTONE2_5_2_TRUSTED_IDENTITY_LIFECYCLE.md`.


## GNP/1 M2.5.2.1 revocation session enforcement

`Revoked` and explicit Forget now invalidate a process-local lifetime token for the current `TrustRelationshipId`. Windows and Android inbound and outbound transfer loops link their cancellation to that lifetime, so an already-authenticated session is terminated when trust is withdrawn rather than remaining valid until disconnect. `Retired` remains intentionally softer: it denies new sessions without forcibly canceling one that already authenticated.

Resume state is additionally scoped to the remote Device ID and current trust relationship. A new SAS pairing after Forget receives a new relationship identifier and therefore cannot automatically reuse a partial transfer authorized by the former relationship. Old partial bytes may remain until bounded stale cleanup, but they are not selected for the new trust context. The transfer wire protocol remains v3.


## GNP/1 M2.5.3 identity replay hardening

`GLS2` signs a positive 64-bit `IdentityRevision` together with Device ID, ports, device kind/name, ECDH fingerprint, signing-key generation and ECDSA public key. The sender persists its current public assertion revision in `identity-assertion-revision.json` with `.bak` recovery and advances it when the signed public assertion changes. The receiver stores the highest accepted revision in Trusted Identity Registry schema v4. A lower revision is rejected as replay/rollback; a different name at an already accepted revision is rejected as an equivocation/conflict. Old signing-key generations are still rejected by the M2.4.2 pinned-key/continuity rules before rename ordering is considered.

For backward compatibility an M2.5.3 node still emits `GLS1` and `GLD2` after `GLS2`. Once ordered identity state is in use, an unordered `GLS1` packet cannot update the saved trusted name. This protects against replay of a historically valid signed name without requiring a protocol-v3 transfer change. A mixed-version peer remains discoverable and transferable, but replay-protected automatic rename into an M2.5.3 node requires the remote peer to emit `GLS2`. Administrative lifecycle state remains local and is not propagated by these self-signed packets.


## GNP/1 development checkpoint: M2.6.1 Roles & Capabilities

M2.6.1 adds persistent local role profiles (`Client`, `Server`, `Relay`, `Backup`, `Custom`) and an explicit capability/dependency model. Existing installations migrate safely to the Client preset. Role changes do not alter Device ID, keys, trust, lifecycle, TrustRelationshipId or M2.5.3 IdentityRevision. Server/Relay/Backup presets configure their required/recommended capabilities; future services such as Network Events, Sync and Relay routing are not activated by this checkpoint. See `docs/GNP1_MILESTONE2_6_1_ROLES_CAPABILITIES.md`.
