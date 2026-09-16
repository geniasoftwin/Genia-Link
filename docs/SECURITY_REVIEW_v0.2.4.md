# Security / stability review — Genia Link v0.2.4

Дата: 2026-08-20

## Цель релиза

v0.2.4 закрепляет результаты реального теста Windows ↔ HONOR с файлом 1.4 ГБ и устраняет два класса отказов: остановку Android-transfer при сворачивании/гашении экрана и зависание progress после потери Wi‑Fi.

Wire-format protocol остаётся version 2. Pairing, trusted-device identity, ECDH P-256, AES-256-GCM, frame sequence authentication и SHA-256 целого файла не ослаблялись.

## Android foreground transfer

Во время активной передачи запускается foreground service типа `dataSync`. Service существует только на время пользовательской file-transfer операции и показывает ongoing notification с progress и действием Cancel.

На время transfer берётся `PARTIAL_WAKE_LOCK`, чтобы CPU мог продолжить локальную TCP-передачу при погашенном экране. Wake lock имеет 6-часовой hard timeout и освобождается при success/error/cancel/service teardown. Экран не удерживается включённым фоновым wake lock: `FLAG_KEEP_SCREEN_ON` используется отдельно только пока Activity видима и transfer активен.

Разрешения Android v0.2.4 ограничены:

- `INTERNET` — TCP/UDP sockets;
- `ACCESS_NETWORK_STATE` — только уведомления `ConnectivityManager` о потере/возврате Wi‑Fi для безопасного пересоздания локальных sockets; runtime prompt не требуется;
- `POST_NOTIFICATIONS` — progress notification Android 13+;
- `FOREGROUND_SERVICE` — foreground service;
- `FOREGROUND_SERVICE_DATA_SYNC` — корректный service type для file transfer;
- `WAKE_LOCK` — partial CPU wake lock только во время активной передачи.

Storage permission не используется. Исходящие файлы читаются через Storage Access Framework, входящие публикуются через MediaStore Downloads.

## Обрыв сети

`IdleTimeout` и `TransferIoTimeout` ограничены 30 секундами. Каждый transfer frame отправляется с linked cancellation token. После потери Wi‑Fi операция должна перейти в timeout/error вместо бесконечного ожидания.

При незавершённом приёме:

- Windows удаляет `.part`;
- Android удаляет непубликованный `is_pending=1` MediaStore item;
- UI получает явное событие завершения с ошибкой и сбрасывает progress;
- foreground notification/wake lock завершаются.

Успешно проверенный и уже опубликованный файл не удаляется только из-за потери финального ACK.

При видимой Android Activity Wi‑Fi recovery дополнительно отслеживается через `ConnectivityManager.NetworkCallback`. При потере Wi‑Fi локальные receiver/pairing/discovery services останавливаются, а после возвращения Wi‑Fi и короткой DHCP-задержки sockets создаются заново. Это не расширяет сетевой trust boundary: `LocalNetworkPolicy` и protocol v2 остаются без изменений.

## Windows UX

Добавлена единственная разрешённая точка `Process.Start`: пользовательская кнопка `Открыть папку` для `%USERPROFILE%\Downloads\Genia Link`. `UseShellExecute=true` открывает уже известный локальный каталог; имя процесса/команда не принимаются из сети. `SecurityCheck.ps1` требует, чтобы `Process.Start` встречался ровно один раз и только в `MainWindow.xaml.cs`.

## Supply chain / offline

- сторонних `PackageReference` нет;
- HTTP/HTTPS clients, cloud SDK, telemetry и analytics отсутствуют;
- `allowBackup=false` и `usesCleartextTraffic=false` сохраняются;
- security/analyzer warnings остаются errors;
- Android-specific manifest/permission/foreground-service checks выполняются `scripts\SecurityCheck-Android.ps1`.


### Background availability follow-up

Local LAN services were moved out of the Android Activity lifecycle into a foreground service declared as `connectedDevice`. The manifest adds `FOREGROUND_SERVICE_CONNECTED_DEVICE` and `CHANGE_NETWORK_STATE`; both are normal permissions and no cloud/Internet endpoint is introduced. The service remains restricted by the existing `LocalNetworkPolicy`, uses the same trusted-device key store, and stops/rebuilds sockets on Wi-Fi loss/return. Pairing still requires a visible Activity for SAS confirmation; background pairing requests are rejected.
