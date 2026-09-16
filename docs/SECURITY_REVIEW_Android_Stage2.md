# Security review — Android stage 2

Дата: 2026-08-20

## Границы доверия

- Internet/cloud endpoints: отсутствуют.
- Разрешённый transport: local/private IPv4 по policy `LocalNetworkPolicy`.
- Discovery не является authentication: доверие определяется сохранённым ECDH public key и trusted-session handshake.
- Передача файла разрешается только устройству, которое прошло pairing и сохранилось как trusted peer.

## Защита данных

- ECDH P-256 private key хранится в Android Keystore и не сериализуется.
- Каждая transfer session получает свежий session key из общего ECDH секрета и nonce обеих сторон.
- SecureChannel использует AES-256-GCM и аутентифицирует sequence number.
- FileOffer содержит SHA-256; получатель публикует файл только после полного размера и fixed-time hash comparison.

## Android storage

- Нет `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE`.
- Исходящие файлы выбираются пользователем через Storage Access Framework.
- Приложение запрашивает только временный read-grant на выбранные URI и не сохраняет долгоживущие URI permissions.
- `EXTRA_LOCAL_ONLY=true` просит system picker отдавать только данные, уже находящиеся на устройстве.
- Входящие файлы создаются как app-owned pending entries в MediaStore Downloads.
- Pending entry удаляется при timeout, disconnect, protocol error, hash mismatch или cancel.
- Имя проходит `FileSafety`; path traversal и format/control characters отклоняются.
- Existing Downloads item не перезаписывается.

## Lifecycle / resource safety

- TCP listeners, UDP discovery и pending pairing привязаны к Activity foreground lifecycle.
- Первый fault одного local-service loop отменяет соседние loops; частично работающая network state не остаётся.
- Send cancellation закрывает network/file streams через `using`/`await using`.
- ECDH/session/public/hash secrets очищаются через `CryptographicOperations.ZeroMemory` там, где материал представлен managed byte arrays.
- Диагностический log ограничен 64 KiB, чтобы не расти бесконечно.
- UI применяет `WindowInsets.Type.SystemBars()` + `DisplayCutout()` к корневому content padding, чтобы tappable controls оставались вне системных перекрытий при обязательном edge-to-edge.

## Manifest

- `allowBackup=false`.
- `usesCleartextTraffic=false`.
- v0.2.4 permissions: `INTERNET`, `POST_NOTIFICATIONS`, `FOREGROUND_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`, `WAKE_LOCK`. Storage permission по-прежнему не требуется.
- Label и adaptive launcher icon заданы явно.

`scripts\SecurityCheck-Android.ps1` после build/self-tests дополнительно проверяет эти manifest-инварианты.

## Осознанные ограничения stage 2

- Активная передача теперь защищена foreground `dataSync` service + progress notification; постоянный фоновый discovery без активной пользовательской операции не включается.
- Protocol v2 IPv4-only.
- File transfer server обслуживает одну TCP transfer session за раз; это ограничивает concurrency и упрощает resource bounds.
