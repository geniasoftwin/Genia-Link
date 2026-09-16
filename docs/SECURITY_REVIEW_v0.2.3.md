# Security / build review — Genia Link v0.2.3 source candidate

Дата ревью: 2026-08-19

## Причина выпуска v0.2.3

На реальной Visual Studio 2026 / .NET 10 сборка v0.2.2 остановилась только на одном analyzer-as-error:

- `CA1513` в `GeniaLink.SelfTest/Program.cs`: анализатор потребовал использовать `ObjectDisposedException.ThrowIf(...)` вместо ручного `throw new ObjectDisposedException(...)`.

Production-код Genia Link при этом уже собирался; ошибка находилась исключительно во вспомогательном in-memory stream, используемом SelfTest.

## Исправлено

1. `InMemoryDuplexStream.ThrowIfDisposed()` теперь вызывает `ObjectDisposedException.ThrowIf(_disposed, this)`.
2. `TreatWarningsAsErrors` и .NET analyzers оставлены включёнными — правило CA1513 не подавляется через `NoWarn`/`pragma`.
3. Production discovery/pairing/transfer/crypto код не менялся; wire protocol остаётся version 2, поэтому v0.2.3 совместима с v0.2.1/v0.2.2 по сетевому протоколу. Для тестов всё равно рекомендуется использовать одинаковую сборку на обоих ПК.
4. SelfTest pairing/trusted-handshake по-прежнему работает через in-memory duplex stream без открытия TCP-портов.
5. Облачные/HTTP-функции не добавлялись, сторонних `PackageReference` нет.

## Статическая проверка в текущей среде

В контейнере отсутствует .NET SDK/MSBuild, поэтому реальный `dotnet build` здесь не выполнялся. Проверено статически:

- исправленный вызов `ObjectDisposedException.ThrowIf`: присутствует;
- ручных `throw new ObjectDisposedException` в исходниках: 0;
- XML/XAML/project files: корректно разбираются;
- `.slnLaunch`: корректный JSON;
- third-party `PackageReference`: 0;
- `HttpClient`, `HttpWebRequest`, `WebClient`, cloud/telemetry SDK markers, `Process.Start`, P/Invoke и hard-coded HTTP(S) URL в runtime C# исходниках не обнаружены.

## Что проверить на Windows

Из корня v0.2.3:

```powershell
.\scripts\Publish-Portable.ps1
```

Ожидается: чистая Release-сборка, 10 `[PASS]`, `SELF-TEST PASSED`, `SECURITY CHECK PASSED`, затем `artifacts\portable-win-x64\GeniaLink.exe`.

## Security posture

v0.2.3 остаётся полностью локальным Windows↔Windows прототипом: runtime использует только прямые локальные TCP/UDP соединения Genia Link ↔ Genia Link. Облачных сервисов, аккаунтов, телеметрии, аналитики и внешних API нет.
