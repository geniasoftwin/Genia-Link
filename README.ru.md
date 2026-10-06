## Текущий checkpoint разработки — GNP/1 M2.8.4.5 Cancel / Retry (физически проверен 06.10.2026)

Рабочая линия Genia Link продвинулась дальше публичного снимка M2.6.2. Текущий проверенный пакет: **v0.3.1 RC4 · GNP/1 M2.8.4.5 Cancel / Retry**.

На связке Android → доверенный Windows Print Gateway → Samsung SCX-4300 подтверждены:
- аутентифицированное получение принтеров и отправка заданий;
- явные аутентифицированные Cancel / Retry с привязкой к JobId и владельцу-устройству;
- ранняя отмена JPG/PNG и PDF до передачи в Windows spooler;
- отмена DOCX во время Office-подготовки и в полном 3000-мс окне после подготовки;
- повторные циклы **Cancel → Retry → Cancel** с сохранением документа и настроек печати;
- fail-closed поведение поздней отмены: если точное задание spooler уже нельзя доказать, отмена не подтверждается, а Retry блокируется;
- сохранение консервативной M2.8.4.4 lifecycle-логики для legacy-драйверов;
- Windows и Android security/build gates, включая проверки fix7/fix8, прошли успешно.

Подробности: [checkpoint M2.8.4.5 Cancel / Retry](docs/GNP1_MILESTONE2_8_4_5_CANCEL_RETRY.md) и [Development Status](docs/DEVELOPMENT_STATUS.md).

**Следующий шаг:** продолжаем линию M2.8 от этой проверенной базы и расширяем физическую совместимость, не меняя уже подтверждённый контракт Cancel / Retry без отдельной причины.

> Примечание по публикации: эта отметка фиксирует проверенное состояние разработки. Публичное дерево исходников в `main` пока остаётся снимком M2.6.2 до отдельной полной синхронизации и повторной проверки всего пакета.

# Genia Link

<p align="center">
  <img src="branding/web/readme-hero.svg" alt="Genia Link — доверенная локальная сеть между Windows и Android" width="100%" />
</p>

<p align="center"><a href="README.md">English</a> · <strong>Русский</strong></p>

<p align="center">
  <a href="https://github.com/geniasoftwin/Genia-Link/actions/workflows/ci.yml"><img src="https://github.com/geniasoftwin/Genia-Link/actions/workflows/ci.yml/badge.svg?branch=main" alt="Genia Link CI" /></a>
</p>

Genia Link — локальная система связи между доверенными устройствами для прямого обмена файлами между Windows и Android. Текущий публичный снимок исходного кода: **v0.3.1 RC4 / GNP/1 M2.6.2 Authenticated Capabilities**.

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
- Общая протокольная/core-часть для Windows и Android.
- Опциональный Android-режим **«Всегда готов к приёму»** для длительного простоя.
- В этом снимке исходников нет сторонних NuGet `PackageReference`.

## Текущий прогресс разработки

Публичный снимок исходного кода в `main` по-прежнему соответствует **v0.3.1 RC4 / GNP/1 M2.6.2**. В рабочей ветке разработки проект уже продвинулся дальше и проходит проверку перед следующей синхронизацией исходников.

По состоянию на **6 октября 2026 года**:

- **GNP/1 M2.7** — в рабочей линии завершён этап large-batch/concurrent transfer и UX продолжения/истории передач.
- **GNP/1 M2.8.1 Print Service Foundation** — подтверждена физическая сквозная печать: Android → аутентифицированная GNP/1-сессия → Windows Print Gateway → реальный принтер.
- **GNP/1 M2.8.2 PDF Printing** — подтверждена печать PDF на **Samsung SCX-4300 Series**; исправленный масштаб PDF теперь совпадает с физическим масштабом при прямой печати того же документа из Windows.
- **GNP/1 M2.8.3 Windows Remote Print Client** — подтверждена физическая печать Windows → authenticated GNP/1 → Windows Print Gateway → Samsung SCX-4300; режим изображения «Фактический размер» дополнительно проверен калибровочным квадратом **50 × 50 мм** и совпал с прямой печатью из Windows.
- **GNP/1 M2.8.4 Office Document Print Bridge** — Microsoft Office path физически проверен для macro-free Office-документов; fallback LibreOffice/OpenOffice реализован, но ещё не проходил отдельную физическую проверку.
- **GNP/1 M2.8.4.3 TXT backend** — физически подтверждены UTF-8, реальные TAB-стопы, перенос строк и многостраничная пагинация.
- **GNP/1 M2.8.4.4 Lifecycle / Error Recovery** — физически проверены консервативная lifecycle-семантика и cleanup Android-уведомлений fix23.
- **GNP/1 M2.8.4.5 Cancel / Retry** — **PHYSICAL + SECURITY PASS**: ранняя отмена image/PDF, Office preparation-aware отмена DOCX, явный Retry с сохранением настроек и fail-closed поздняя отмена.
- Печать использует существующую trusted GNP/1-сессию; отдельный неаутентифицированный порт печати не добавляется.
- Обнаружение `PrinterGateway` само по себе не означает доверия и не даёт разрешения на печать.

Подробно различие между публичным снимком и текущими проверенными этапами описано в [Development Status](docs/DEVELOPMENT_STATUS.md).

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
- [Финальный RC4 regression-чеклист](docs/RC4_FINAL_TEST.md)
- [Технические заметки по безопасности](docs/SECURITY_IMPLEMENTATION.md)

## Релизы и changelog

Заметки о публичных снимках исходного кода ведутся в [CHANGELOG.md](CHANGELOG.md). Текущий RC4/M2.6.2 — предварительный снимок исходников; готовые бинарные релизы в сам репозиторий не включены.

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
