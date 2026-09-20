# Genia Link

<p align="center">
  <img src="branding/web/readme-hero.svg" alt="Genia Link — доверенная локальная сеть между Windows и Android" width="100%" />
</p>

<p align="center"><a href="README.md">English</a> · <strong>Русский</strong></p>

<p align="center">
  <a href="https://github.com/geniasoftwin/Genia-Link/actions/workflows/ci.yml"><img src="https://github.com/geniasoftwin/Genia-Link/actions/workflows/ci.yml/badge.svg?branch=main" alt="Genia Link CI" /></a>
</p>

Genia Link — локальная система связи между доверенными устройствами для прямого обмена файлами между Windows и Android. Текущий публичный снимок исходного кода в `main`: **v0.3.1 RC4 / GNP/1 M2.6.2 Authenticated Capabilities**. Активная разработка дошла до этапа **GNP/1 M2.7**: ограниченные параллельные доверенные передачи, живые роли/возможности устройств, локальные псевдонимы, масштабируемые динамические фильтры/действия и отдельное окно диагностики.

> **Статус разработки:** release candidate / промежуточный этап развития протокола. До стабильного релиза интерфейсы, упаковка и детали GNP/1 могут изменяться.

## Основные возможности

- Прямая передача устройство ↔ устройство внутри локальной IPv4-сети.
- Автоматическое обнаружение устройств без ручного ввода IP в обычном сценарии.
- Явное SAS-сопряжение и постоянная криптографическая идентичность доверенного устройства.
- ECDH P-256 для согласования ключей и отдельные ключи каждой сессии.
- AES-256-GCM для защищённых кадров передачи.
- SHA-256-проверка файла и продолжение прерванных передач.
- Trusted Identity Registry с аутентифицированной привязкой signing key и проверяемой цепочкой смены ключей.
- Защищённые от replay подписанные утверждения идентичности.
- Локальные состояния доверия Active / Retired / Revoked.
- GNP/1 M2.6.2 — аутентифицированное объявление возможностей устройства.
- GNP/1 M2.7 — этап разработки с bounded per-peer concurrency, service-ready UI, локальными псевдонимами, живым отображением аутентифицированных ролей, динамическими фильтрами/действиями и отдельной диагностикой.
- Общая протокольная/core-часть для Windows и Android.
- Опциональный Android-режим **«Всегда готов к приёму»** для длительного простоя.
- В этом снимке исходников нет сторонних NuGet `PackageReference`.

## Локальная сетевая модель

Genia Link рассчитан на передачу пользовательских файлов напрямую между доверенными устройствами в локальной сети. В исходном коде пути передачи нет HTTP-клиентов, облачных relay API, SDK аналитики, рекламы или внешнего сервера приложения.

TCP listener может слушать локальные интерфейсы, но входящие адреса дополнительно ограничиваются `LocalNetworkPolicy`: допускаются IPv4 loopback/private/link-local/shared-local диапазоны. Действия, связанные с доверием, дополнительно проходят механизм pairing/session authentication Genia Link.

Android использует системное разрешение `INTERNET`, потому что оно требуется Android для TCP/UDP-сокетов. Само наличие этого разрешения не означает использование интернет-сервиса Genia Link.

## Структура репозитория

```text
src/
  GeniaLink.Core/       Общая логика протокола, identity, session и transfer
  GeniaLink.Windows/    Windows WPF-клиент
  GeniaLink.Android/    Android-клиент
  GeniaLink.SelfTest/   Офлайн self-tests
scripts/                Сборка, публикация, установка и security-check скрипты
docs/                   Документация протокола, этапов и безопасности
branding/               Графика и заметки по брендингу
```

## Сборка

Проекты рассчитаны на **.NET 10**. Для Windows нужна Windows Desktop toolchain, для Android — workload .NET for Android.

Подробности текущего рабочего процесса:

- [Подробные заметки разработки](docs/DEVELOPMENT_NOTES_RU.md)
- [Описание протокола](docs/PROTOCOL.md)
- [GNP/1 M2.6.2](docs/GNP1_MILESTONE2_6_2_AUTHENTICATED_CAPABILITIES.md)
- [GNP/1 M2.7](docs/GNP1_MILESTONE2_7_SERVICE_CONCURRENCY_DEVICE_UI.md)
- [Финальный RC4 regression-чеклист](docs/RC4_FINAL_TEST.md)
- [Технические заметки по безопасности](docs/SECURITY_IMPLEMENTATION.md)

## Релизы и changelog

Заметки о публичных снимках исходного кода ведутся в [CHANGELOG.md](CHANGELOG.md). M2.7 фиксируется как этап разработки без отдельного GitHub Release и без тега; готовые бинарные релизы в сам репозиторий не включены.

## Безопасность

К security-sensitive частям относятся pairing, trusted-session authentication, device/signing identity, смена signing key, подлинность/replay-защита discovery, transfer framing, resume state и ограничение файловых путей.

В рабочем пакете есть офлайн self-tests и PowerShell security-check скрипты. Перед выпуском релизной сборки их следует запускать на целевой Windows/.NET/Android toolchain.

Для сообщения об уязвимости см. [SECURITY.md](SECURITY.md). Не публикуйте в открытом issue закрытые ключи, credentials, реальные идентификаторы устройств или детали эксплуатации уязвимости.

## Приватность

Для передачи файлов Genia Link не требует аккаунта Genia Link или облачного ретранслятора. Операционная система, менеджеры пакетов, GitHub, инфраструктура сертификатов или будущие опциональные функции могут независимо использовать Интернет вне протокола передачи Genia Link.

## Лицензия и права

Исходный код доступен для просмотра, однако репозиторий **не распространяется по open-source лицензии**. Если для отдельного файла или стороннего компонента явно не указано иное, материалы проекта распространяются как All Rights Reserved.

См. [LICENSE](LICENSE) и [NOTICE.md](NOTICE.md).

---

**Genia Link** находится в активной разработке Genia Soft.
