# Genia Link Android v0.2.4 — Wi‑Fi stability

Дата: 2026-08-20

## Что входит

Android-клиент остаётся native `.NET for Android` (`net10.0-android`) и использует тот же protocol v2, что Windows v0.2.4.

- UDP 47502 — discovery в локальной сети.
- TCP 47501 — безопасное pairing с 6-значным SAS.
- TCP 47500 — зашифрованная передача файлов в обе стороны.
- Android Keystore — неэкспортируемый ECDH P-256 private key.
- Trusted-device store — только public key и метаданные peer.
- AES-256-GCM secure channel и replay/tamper protection из `GeniaLink.Core`.
- SHA-256 целого файла перед подтверждением успешного приёма.
- Android Storage Access Framework для выбора локальных файлов без storage permission.
- MediaStore Downloads для входящих файлов: `Загрузки/Genia Link`.
- Повторные имена не перезаписывают существующий файл: выбирается уникальное имя.
- Незавершённый/повреждённый входящий файл остаётся pending и удаляется при отказе/обрыве.
- Никаких PackageReference, HTTP/HTTPS клиентов, облачных SDK, аналитики или телеметрии.

## Интерфейс

Главный экран разделён на четыре понятных блока:

1. состояние локальной сети и портов;
2. найденные устройства с состоянием trust/identity;
3. выбор и отправка файлов с прогрессом, скоростью и отменой;
4. информация о входящих файлах и переход к Downloads.

Технический журнал убран с главного экрана и доступен через кнопку `Диагностика`.

Application label задан через `@string/app_name` и manifest, launcher icon — adaptive Android icon. Это устраняет ситуацию, когда пакет устанавливался без нормального отображаемого имени/значка в launcher.

Интерфейс учитывает `WindowInsets` для system bars и display cutout, поэтому элементы управления не должны уходить под статус-бар, навигационную панель или вырез экрана на Android 15/16.

## Android storage

Выбор файлов использует `ACTION_OPEN_DOCUMENT`, `CATEGORY_OPENABLE`, multi-select, `EXTRA_LOCAL_ONLY` и только временный read-grant. Долговременные URI-разрешения не сохраняются: список выбранных файлов тоже не переживает перезапуск приложения. URI читаются напрямую через `ContentResolver`; файл не копируется целиком во временный cache перед отправкой.

Входящие данные записываются через `MediaStore.Downloads` с `relative_path=Download/Genia Link/` и `is_pending=1`. Для resume точный app-owned `content://` URI сохраняется в приватном `resume-index.json`; файловый менеджер и `adb shell` могут не показывать pending row. После полного размера и SHA-256 проверки запись публикуется (`is_pending=0`) и индекс удаляется. При сетевом обрыве partial сохраняется до 7 дней; при повреждении/SHA-256 mismatch удаляется.

Дополнительные storage permissions не требуются для файлов, создаваемых самим приложением через MediaStore на Android 10+.

## Lifecycle и фоновые передачи

При активной отправке или уже начавшемся входящем файле Android запускает foreground service типа `dataSync`. В шторке отображаются имя/направление/progress и действие `Отменить`. На время transfer service удерживает только `PARTIAL_WAKE_LOCK`, поэтому CPU продолжает передавать данные при погашенном экране, но экран не принудительно включается. Wake lock всегда освобождается при успехе, ошибке, отмене или системном timeout.

Если Activity уходит в фон во время transfer, TCP-сессия не отменяется. Discovery/pairing/listener остаются живы только до завершения текущей операции, после чего фоновые локальные службы останавливаются. Если transfer не активен, прежняя экономная модель сохраняется: при уходе Activity в фон sockets закрываются.

`FLAG_KEEP_SCREEN_ON` применяется только пока интерфейс Genia Link видим и идёт transfer. Пользователь может вручную погасить экран — foreground service + partial wake lock продолжают работу.

Потеря Wi‑Fi больше не должна оставлять UI бесконечно в промежуточном состоянии: transfer I/O и idle timeout ограничены 30 секундами; после ошибки progress переводится в состояние `Передача прервана`/`Тайм-аут`, сокет закрывается, а частичные данные сохраняются для безопасной докачки. Повреждённый partial удаляется после неуспешной проверки.

## Проверка

```powershell
.\scripts\SecurityCheck-Android.ps1
```

После успешной проверки и подключения телефона:

```powershell
.\scripts\Install-Android.ps1
```

Скрипт сам ищет `adb.exe`, выбирает единственное устройство в состоянии `device`, выполняет `-t:Install` и запускает Genia Link. Если подключено несколько Android-устройств:

```powershell
.\scripts\Install-Android.ps1 -Serial AR5FVB6326004703
```

## Ручной тест Windows ↔ HONOR

1. Запустить оба приложения; discovery должен появиться примерно за один интервал broadcast.
2. Убедиться, что уже сопряжённые устройства показываются как доверенные.
3. Android → Windows: выбрать доверенный ПК, выбрать 1–3 файла и отправить.
4. Проверить Windows `Downloads\Genia Link` и SHA-256/успешный статус.
5. Windows → Android: отправить те же файлы обратно.
6. Проверить `Загрузки/Genia Link` на телефоне.
7. Повторить файл с тем же именем — существующий файл не должен перезаписаться.
8. Передать файл 0 Б, небольшой файл, файл 100+ МБ и по возможности 1+ ГБ.
9. На середине передачи выключить Wi‑Fi — приложение не должно падать, частичный Android download не должен публиковаться.
10. Повторно включить Wi‑Fi — discovery должен восстановиться после возврата приложения на экран.
11. Нажать `Отмена` на исходящей Android-передаче — сокет должен закрыться без зависания UI.
12. Перезапустить оба приложения — trust должен сохраниться без нового SAS.

## Wi-Fi recovery (v0.2.4 fix3)

Пока Activity открыта, приложение подписывается на Wi-Fi network callback (`ACCESS_NETWORK_STATE`). После `Wi-Fi OFF → ON` локальные TCP/UDP services пересоздаются автоматически после короткой задержки для обновления DHCP/route state. Callback снимается в `OnStop`, поэтому этот fix не является постоянным background-availability режимом; такой режим планируется отдельным foreground `connectedDevice` service.


## Background availability (v0.2.4 stability fix4)

After the user opens Genia Link, Android runs a foreground `connectedDevice` service for LAN availability. Discovery UDP 47502, pairing TCP 47501 and trusted receiver TCP 47500 are no longer tied to the Activity lifecycle. Opening the system file browser, minimizing Genia Link or turning the screen off must not make the phone disappear from Windows. The persistent notification is intentional and provides an explicit `Stop` action. Active file transfer still uses the separate `dataSync` foreground service and partial wake lock only for the duration of the transfer.
