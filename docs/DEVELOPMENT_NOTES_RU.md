# Genia Link v0.3.1 RC4 — Windows ↔ Android, полностью локально

> **Android Always Ready release candidate.** RC4 закрепляет опциональный режим `Всегда готов к приёму` для Android после длительного простоя с выключенным экраном. Сетевой протокол остаётся v3; pairing, trusted identity, AES-GCM transfer, SHA-256, resume, remote Genia Link folder и UI/branding RC3 не переделываются.

## Что изменено в RC4

- **Always Ready для Android:** пользователь может явно разрешить Genia Link оставаться доступным после длительного idle/Doze.
- **Два независимых состояния:** пользовательский переключатель хранится отдельно от фактического системного исключения battery optimization; эффективный режим включён только когда выполнены оба условия.
- **Корректный отказ:** если Android не выдал исключение, переключатель автоматически возвращается в выключенное состояние.
- **Корректное выключение:** отключение режима в Genia Link не открывает системные настройки само; если исключение Android осталось, приложение честно предлагает вернуть обычную оптимизацию через отдельную кнопку.
- **Приватность не меняется:** режим не добавляет облако, аккаунты, аналитику или внешние серверы; передача остаётся только в локальной сети между доверенными устройствами.
- **Windows branding:** утверждённая иконка RC3 сохранена и используется в EXE/title bar/tray.
- **Версия:** Windows `v0.3.1 RC4`; Android `0.3.1-rc4`, `versionCode = 15`.
- **Feature freeze сохраняется:** встроенный медиаплеер, системный сетевой диск, удалённое удаление/переименование и доступ ко всей файловой системе не добавляются.

## База RC3, сохранённая в RC4

- Компактный профессиональный интерфейс Windows и Android.
- Контекстные действия `Сопрячь` / `Файлы` и упрощённые статусы устройств.
- Утверждённая единая иконка Genia Link для Windows и Android.
- Remote Genia Link folder с root-confined навигацией, bounded preview фото/текста и authenticated reverse download.
- Протокол передачи остаётся v3; ordinary transfer, AES-GCM, SHA-256, resume, queue и sleep/wake не менялись.
- Добавлен `docs/RC4_FINAL_TEST.md` — финальный regression-чеклист, включая long-idle Always Ready.

## Граница продукта

Основной Genia Link остаётся файловым инструментом. Встроенный медиаплеер, настоящий системный сетевой диск, удалённое удаление/переименование и доступ ко всей файловой системе **не входят в RC4**. Потоковое видео/аудио логичнее развивать отдельно в будущем Genia Link TV.

> Remote root остаётся строго один: Windows публикует настроенную пользователем папку входящих Genia Link, Android — `Download/Genia Link`. Доступа к остальной файловой системе, удалённого удаления/переименования и автоматического запуска файлов нет.

Genia Link — офлайн-приложение для прямого обмена файлами между устройствами в локальной сети. В ветке v0.2 ручной ввод IP и длинного ключа убран: устройства обнаруживают друг друга автоматически, один раз безопасно сопрягаются и затем узнают доверенного собеседника по криптографической идентичности.

## Branding

- Windows EXE, title bars and tray use `src/GeniaLink.Windows/Assets/GeniaLink.ico`.
- Android adaptive launcher icon uses the same approved artwork from `src/GeniaLink.Android/Resources/drawable-nodpi/genialink_logo.png`.
- Reproducible master artwork is kept in `branding/GeniaLink-icon-master.png`.



## Файлы Genia Link на другом устройстве

Для выбранного доверенного устройства доступна кнопка **Файлы Genia Link**. После криптографически аутентифицированного подключения приложение получает только метаданные файлов из Genia Link-папки: относительный путь, размер и время изменения.

- Windows remote root = текущая настроенная **Папка входящих файлов**.
- Android remote root = `Download/Genia Link`.
- Можно выбрать один или несколько файлов.
- После **Скачать** удалённое устройство само открывает обычную authenticated transfer-сессию обратно к запросившему устройству.
- Получатель сохраняет файлы тем же безопасным способом, что и обычную передачу: Windows — в свою настроенную Genia Link-папку, Android — в `Download/Genia Link`.
- Вложенная структура внутри Genia Link сохраняется.
- `.genialink-resume`, symbolic links/junctions/reparse points и path traversal не публикуются.
- Обратный transfer разрешён только на фиксированный TCP `47500` адреса уже аутентифицированного peer, поэтому BrowseRequest нельзя использовать как произвольный TCP proxy.

На Android отправка файлов по remote-download request удерживает временный `PARTIAL_WAKE_LOCK` только на время фактической обратной передачи, чтобы спящий телефон мог закончить чтение и отправку выбранных файлов.

## Что уже есть в v0.2.4

- Windows 11 WPF-клиент/приёмник на .NET 10.
- Автоматический поиск Genia Link в одной IPv4 LAN/Wi-Fi сети через UDP broadcast.
- TCP-передача файлов напрямую устройство ↔ устройство.
- Код транспорта принимает только loopback/private/link-local IPv4 (RFC1918, 169.254/16, 100.64/10) и отклоняет публичные IP-адреса.
- Первичное сопряжение с одинаковым 6-значным кодом проверки на обоих устройствах.
- Долгосрочная идентичность устройства ECDH P-256; приватный ключ создаётся и хранится Windows CNG и не экспортируется кодом Genia Link.
- Список доверенных устройств хранит только открытые ключи и метаданные.
- Каждое TCP-соединение получает новый ключ сеанса из ECDH-секрета и свежих случайных nonce обеих сторон.
- AES-256-GCM для всех кадров передачи.
- Разные ключи AES для направлений client→server и server→client.
- Номер кадра включён в authenticated data, поэтому повтор/перестановка зашифрованных кадров внутри соединения отклоняется.
- SHA-256 целого файла перед финальным сохранением.
- Безопасные `.part`-файлы и финальное переименование только после проверки.
- Защита имён/путей от path traversal, специальных Windows-имён, управляющих и BiDi/Format-символов.
- Ограничения размера файла, чанка и сетевого кадра; тайм-ауты handshake/idle/pairing.
- Drag & Drop файлов, несколько файлов за одну сессию, прогресс, средняя скорость и ETA.
- Полученные файлы никогда автоматически не запускаются и не открываются.
- Никаких аккаунтов, облака, HTTP-клиентов, телеметрии, аналитики, рекламы или внешних API.
- Ноль сторонних NuGet PackageReference.
- SelfTest и офлайн-скрипт проверки безопасности.

> Ветка v0.2 несовместима с v0.1.x по протоколу. Для теста на двух ПК используйте одну и ту же версию v0.2.4 на обоих устройствах.


### Изменения v0.2.4

Версия v0.2.4 — stability-этап после реальных тестов файла 1.4 ГБ Windows ↔ HONOR. Wire-format protocol v2 не менялся. Добавлены Android foreground `dataSync` service, notification progress, `PARTIAL_WAKE_LOCK` только на время активной передачи, продолжение передачи при сворачивании/погашенном экране, более короткий 30-секундный I/O/idle timeout после обрыва сети и явный сброс зависшего progress. В Windows добавлена кнопка `Открыть папку` для входящих файлов.

### Android stage 2 (HONOR / Wi‑Fi)

В это же решение входит `GeniaLink.Android` на native **.NET for Android (`net10.0-android`)**, без MAUI и без сторонних NuGet-пакетов. Android использует существующий protocol v2 для discovery, pairing, trusted-session handshake и шифрования передачи файлов.

На Android теперь работают:

- UDP 47502 discovery в обе стороны;
- TCP 47501 pairing и сохранение trust;
- TCP 47500 приём Windows → Android;
- TCP 47500 отправка Android → Windows;
- выбор нескольких локальных файлов через системный Storage Access Framework;
- сохранение входящих файлов через MediaStore в `Загрузки/Genia Link`;
- прогресс, скорость, отмена и безопасные состояния ошибок;
- отдельная диагностика вместо технического журнала на главном экране;
- `WindowInsets`-aware layout для Android 15/16 edge-to-edge и display cutout;
- явное имя приложения `Genia Link` и adaptive launcher icon;
- foreground service типа `dataSync` во время активной передачи;
- progress notification в шторке и действие `Отменить`;
- `PARTIAL_WAKE_LOCK` с жёстким ограничением по времени только на активную передачу;
- экран не гаснет сам, пока Genia Link открыт и передаёт файл; при ручном выключении экрана transfer продолжает foreground service;
- после потери Wi‑Fi незавершённая передача завершается тайм-аутом вместо бесконечно зависшего progress;
- foreground service типа `connectedDevice` держит receiver/pairing/discovery независимо от Activity; на агрессивных прошивках screen-off может задерживать UDP announcements, поэтому fix11 удерживает уже доверенный peer в списке как спящий; после криптографически подтверждённой связи его LAN endpoint сохраняется и может быть безопасно восстановлен после перезапуска приложения;
- persistent notification `Genia Link • Доступен в фоне` показывает, что локальная доступность включена, и содержит действие `Остановить`;
- **Always Ready (опционально):** в Android-меню можно включить `Всегда готов к приёму`; переключатель по умолчанию выключен и включается только пользователем. Режим считается активным только если Android реально выдал исключение из battery optimization. При выключении системные настройки не открываются автоматически; если системное исключение осталось, окно отдельно предлагает открыть настройки батареи Android. Патч не добавляет автозапуск после перезагрузки телефона;
- Android отслеживает возврат Wi‑Fi через `ConnectivityManager.NetworkCallback` внутри фоновой службы и автоматически пересоздаёт receiver/pairing/discovery sockets без сворачивания или перезапуска приложения.

Windows ↔ Windows v0.2.4 остаётся совместимой: protocol v2 не менялся.

## Настройки Windows RC1 fix8

Кнопка **Настройки** открывает отдельное окно без перегрузки главного интерфейса:

- **Общие:** автозагрузка через `HKCU` без администратора, запуск сразу в трей, системные уведомления.
- **Передача:** выбор локальной папки входящих файлов `Genia Link`; по умолчанию `%USERPROFILE%\Downloads\Genia Link`. Смена папки не выполняется во время активной передачи. Старые файлы не перемещаются автоматически.
- **Интеграция Windows:** включение/выключение `ПКМ → Отправить`, ручное обновление и удаление ярлыков.
- **Устройства:** все сохранённые trusted peers, тип, online/offline, fingerprint и явное удаление доверия.
- **Безопасность и о программе:** сведения о local-only режиме и fingerprint текущего ПК.

На главном экране online-устройства группируются как **Компьютеры** и **Мобильные устройства**. Тип устройства используется только для интерфейса и никогда не влияет на решение о доверии: передача по-прежнему разрешается только после криптографического pairing и проверки сохранённого ключа.

Если пользователь вручную выберет каталог, синхронизируемый OneDrive/Dropbox/другим ПО, Genia Link сам в облако не обращается, но внешняя программа может синхронизировать содержимое выбранной папки.

## Сборка в Visual Studio 2026

Требуется Windows 11 и Visual Studio 2026 с workload **.NET desktop development** / .NET 10 SDK.

1. Откройте `GeniaLink.sln`.
2. Запускаемый проект — `GeniaLink.Windows`.
3. В решении также лежит `GeniaLink.slnLaunch` с отдельными профилями **Genia Link Windows** и **Genia Link Android**.
4. Выберите `Build → Rebuild Solution`.
5. Нажмите F5.

## Сборка Android stage 2 в Visual Studio 2026

Нужны .NET 10 и установленный workload **.NET for Android**.

1. Откройте тот же `GeniaLink.sln`.
2. Подключите HONOR 600 Pro как Android debug device.
3. Запустите `scripts\SecurityCheck-Android.ps1`.
4. Убедитесь, что телефон виден через ADB как `device`.
5. Выполните `scripts\Install-Android.ps1` — скрипт сам найдёт ADB, проверит target, установит Debug-сборку и запустит Genia Link.
6. Телефон и Windows-ПК должны быть в одной локальной сети; ПК может быть подключён к роутеру Ethernet-кабелем, телефон — Wi‑Fi.
7. После discovery выберите доверенное устройство, выберите файлы и отправьте.
8. Android принимает файлы в `Загрузки/Genia Link`.

Для готового подписанного Release APK используйте:

```powershell
.\scripts\Build-Android-Apk.ps1
```

Готовый файл будет скопирован в `dist\GeniaLink-v0.3.1-RC4-Android.apk`, а скрипт выведет SHA-256.

Подробная инструкция и ручной тест: `docs\ANDROID_STAGE2.md`.

## Первый тест ПК ↔ ноутбук

1. Подключите оба Windows-компьютера к одной локальной Wi-Fi/LAN сети.
2. Запустите v0.2.4 на обоих. Разрешите Genia Link только в **частных** сетях Windows Firewall.
3. Через несколько секунд второй компьютер должен появиться в разделе «Устройства в локальной сети».
4. Выберите его и нажмите **Сопрячь**.
5. На обоих ПК появится 6-значный код. Подтверждайте **Да только если коды точно одинаковые**.
6. После успешного сопряжения устройство получит статус доверенного.
7. Перетащите файл в окно или нажмите **Выбрать файлы**, затем **Отправить**.
8. Полученный файл появится в `%USERPROFILE%\Downloads\Genia Link`.
9. При следующих запусках длинный ключ или IP вводить не нужно: доверие сохранено локально.

Если устройство не появляется, сначала проверьте, что оба ПК находятся в одной подсети, профиль сети Windows установлен как Private и локальный firewall не блокирует UDP 47502 / TCP 47500-47501; для M2.3 также нужен локальный TCP 47503 между устройствами.

## Портативная версия

Из PowerShell в корне проекта:

```powershell
.\scripts\Publish-Portable.ps1
```

Скрипт сначала выполняет сборку с анализаторами и warnings-as-errors, SelfTest и статический офлайн-аудит, затем создаёт self-contained single-file сборку:

`artifacts\portable-win-x64\GeniaLink.exe`

Отдельная установка .NET Runtime на целевой x64 Windows-ПК для этой self-contained публикации не требуется.

## Полностью офлайн — принцип проекта

Runtime Genia Link не должен обращаться в интернет. Разрешены только локальные сокеты для прямой связи Genia Link ↔ Genia Link. В исходниках намеренно нет HTTP/HTTPS клиентов, облачных SDK и PackageReference. Скрипт `SecurityCheck.ps1` проверяет это перед portable-публикацией. Windows portable pipeline намеренно не требует Android workload. Для полной проверки текущей Windows + Android сборки используйте `scripts\SecurityCheck-Android.ps1`.

## Дальше

После RC4 основной этап — реальный all-to-all regression test: Windows ↔ Windows, Windows ↔ Android и Android ↔ Android, включая сон/пробуждение, вложенные папки, preview и reverse download. После подтверждения на основных устройствах APK можно проверить на Samsung/One UI, Xiaomi/HyperOS, Pixel и других Android-моделях. Отдельный будущий Genia Link TV-клиент сможет использовать тот же trusted folder/preview фундамент, а потоковое видео/аудио лучше развивать уже как отдельное расширение, не смешивая его с базовой передачей файлов.

Подробности: `SECURITY.md`, `docs\PROTOCOL.md`, `docs\ANDROID_STAGE2.md`, `docs\SECURITY_REVIEW_Android_Stage2.md`, `docs\SECURITY_REVIEW_v0.2.4.md`, `docs\SECURITY_REVIEW_v0.2.3.md`.

## GNP/1 development checkpoint: M2.1 Signing Identity

This source snapshot extends the verified M1 installation identity with a separate ECDSA P-256 signing key on Windows CNG and Android Keystore. M2.1 preserves the existing Device ID/ECDH identity and keeps protocol v3 unchanged. Build/test details and the four-device acceptance procedure are in `docs/GNP1_MILESTONE2_SIGNING_IDENTITY.md`.

## GNP/1 development checkpoint: M2.2 Signed Discovery

This snapshot adds the first network use of Device Identity v2. Each M2.2 node broadcasts a self-signed `GLS1` identity advertisement and then the unchanged RC4 `GLD2` discovery packet for backward compatibility. The signed envelope binds the Device ID, device metadata, ports, existing ECDH fingerprint, signing-key generation, and ECDSA P-256 public key. Protocol version remains 3; pairing, trusted sessions, and transfer messages are unchanged. See `docs/GNP1_MILESTONE2_2_SIGNED_DISCOVERY.md`.

## GNP/1 development checkpoint: M2.3 Trusted Signing Identity Binding

M2.3 authenticates/pins the M2 ECDSA signing public key to the already trusted ECDH pairing relationship. It adds a LAN-only TCP 47503 binding service that reuses the unchanged `TrustedSessionHandshake` and `SecureChannel`; UDP signed discovery never writes or rotates a trusted signing key by itself. Existing Device IDs, pairings, transfer/pairing protocols and protocol version 3 remain unchanged. See `docs/GNP1_MILESTONE2_3_TRUSTED_SIGNING_BINDING.md`.

## GNP/1 development checkpoint: M2.4.1 Trusted Identity Registry

M2.4.1 keeps the verified M2.3 `fix3` pairing/signing behavior unchanged and adds a separate local `trusted-identities.json` registry. Existing `trusted-devices.json` records are migrated automatically without repeat pairing; the registry pins the trusted ECDH pairing fingerprint, mirrors the authenticated M2 signing identity, keeps bounded retired signing-key history, records authenticated contact time, and uses `.tmp` + `.bak` persistence recovery. Protocol version and ports remain unchanged. See `docs/GNP1_MILESTONE2_4_1_TRUSTED_IDENTITY_REGISTRY.md`.

## GNP/1 development checkpoint: M2.4.2 Trusted Key Rotation

M2.4.2 adds cryptographically authenticated signing-key rotation without changing the persistent Device ID, ECDH pairing anchor, ports, or protocol version 3. A replacement signing key is accepted only through a continuous `GLR1` certificate chain signed by the previously trusted signing key; each certificate advances generation exactly by one. Before the first rotation the binding remains legacy-compatible `GLI1`; after rotation the peer presents the bounded continuity chain in `GLI2`. Update every device in a trust group to M2.4.2 before rotating any key. See `docs/GNP1_MILESTONE2_4_2_TRUSTED_KEY_ROTATION.md`.

## GNP/1 development checkpoint: M2.5 Authenticated Rename Propagation

The first M2.5 Trusted Identity State Management checkpoint allows a trusted device name to change without creating a new identity. M2.5 originally accepted a new name from verified `GLS1` when Device ID, paired ECDH fingerprint, pinned ECDSA Signing Key ID, identity version and key generation all matched the current trusted identity. M2.5.3 supersedes that mutation rule with replay-protected `GLS2`: legacy `GLS1` remains compatible for discovery/authentication but can no longer change the saved trusted name on an M2.5.3 node. Device ID, keys, pairing trust, key history and `FirstTrustedAtUtc` are preserved. See `docs/GNP1_MILESTONE2_5_AUTHENTICATED_RENAME.md`.

## GNP/1 development checkpoint: M2.5.2 Trusted Identity Lifecycle

M2.5.2 separates cryptographic binding integrity (`Trusted / Changed`) from administrative lifecycle (`Active / Retired / Revoked`). Retired identities remain stored but cannot participate until explicitly reactivated; Revoked is terminal until explicit Forget + new SAS pairing and also removes the legacy `trusted-devices.json` trust record as downgrade defense in depth. Normal trusted lookup, discovery presentation, endpoint refresh, rename, signing-key binding/rotation and pairing replacement all fail closed for inactive identities. M2.5.2 introduced registry schema v3 with bounded local identity-event history and a trust-relationship identifier used by M2.5.2.1 session enforcement; M2.5.3 upgrades the registry to schema v4 by adding the highest accepted signed identity revision. Windows settings exposes Retire/reactivate/Revoke/Forget; Android enforces the same persisted lifecycle but does not yet expose management UI. Lifecycle decisions are local to the node in this checkpoint and are not propagated as network-wide administrative commands. Once a local installation writes the current registry schema, downgrading that same app-data state to an older build is unsupported. See `docs/GNP1_MILESTONE2_5_2_TRUSTED_IDENTITY_LIFECYCLE.md`.


## GNP/1 development checkpoint: M2.5.2.1 Revocation Session Enforcement

M2.5.2.1 hardens `Revoked` and explicit Forget against already-authenticated transfer sessions. Each trusted record now has a local `TrustRelationshipId`; live Windows/Android transfers are linked to that relationship lifetime, so Revoked/Forget cancels the active session immediately. Resumable partial state is now keyed by remote Device ID plus the current trust relationship as well as file metadata. A fresh SAS pairing after Forget therefore cannot automatically inherit the old resume offset, while rename, signing-key rotation and Retired/reactivation preserve normal continuity. The wire protocol remains v3. See `docs/GNP1_MILESTONE2_5_2_1_REVOCATION_SESSION_ENFORCEMENT.md`.

### M2.5.2.1 fix2 build correction

Android transfer-server cancellation handling now explicitly references `System.OperationCanceledException`, avoiding the name collision with `Android.OS.OperationCanceledException` during `net10.0-android` compilation. No protocol, trust, lifecycle, or resume semantics changed from fix1.

## GNP/1 development checkpoint: M2.5.3 Identity History & Replay Hardening

M2.5.3 adds replay-protected signed discovery `GLS2`. It carries the same authenticated device identity as `GLS1` plus a positive monotonic `IdentityRevision` inside the ECDSA-signed payload. Each node persists its local assertion revision and advances it when the signed public assertion changes (device name/kind or signing key generation/key). Trusted Identity Registry schema v4 stores `LastAcceptedIdentityRevision`; a lower revision is rejected as rollback and a different name at the same revision is rejected as a conflict. Once an M2.5.3 peer establishes ordered state, unordered legacy `GLS1` may still prove/sign the peer for compatibility but cannot mutate its saved trusted name. `GLS1` and `GLD2` are still broadcast for older peers and the transfer protocol remains version 3. Lifecycle decisions remain local policy; M2.5.3 does not invent a network revocation authority. See `docs/GNP1_MILESTONE2_5_3_IDENTITY_REPLAY_HARDENING.md`.


## GNP/1 development checkpoint: M2.6.1 Roles & Capabilities

M2.6.1 adds persistent local role profiles (`Client`, `Server`, `Relay`, `Backup`, `Custom`) and an explicit capability/dependency model. Existing installations migrate safely to the Client preset. Role changes do not alter Device ID, keys, trust, lifecycle, TrustRelationshipId or M2.5.3 IdentityRevision. Server/Relay/Backup presets configure their required/recommended capabilities; future services such as Network Events, Sync and Relay routing are not activated by this checkpoint. See `docs/GNP1_MILESTONE2_6_1_ROLES_CAPABILITIES.md`.

## GNP/1 development checkpoint: M2.6.2 Authenticated Capability Advertisement

M2.6.2 adds additive signed discovery `GLC1`, carrying the replay-protected identity assertion together with a separate monotonic `CapabilityRevision` and the device capability bitset. Capabilities are accepted only after the packet matches the already trusted Device ID, ECDH pairing anchor and current pinned ECDSA signing identity; self-declaration alone never grants permissions. Trusted Identity Registry schema v5 persists the last authenticated capability set/revision and rejects rollback or same-revision conflicts. `GLS2`, `GLS1` and `GLD2` remain broadcast for compatibility and protocol version stays 3. Windows now derives the role profile from the exact capability set: preset matches resolve automatically to Client/Server/Relay/Backup, otherwise Custom. See `docs/GNP1_MILESTONE2_6_2_AUTHENTICATED_CAPABILITIES.md`.
