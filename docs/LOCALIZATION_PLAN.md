# Genia Link Localization / Unified UI Roadmap

_Last updated: 2026-10-10_

**Status: PLANNED.** These are agreed product requirements, not features currently claimed to be shipped.

## Initial languages

- `auto` — default: detect operating-system UI locale.
- `ru` — Russian.
- `en` — English.
- On unsupported system languages, use English fallback.
- The user may override auto-detection explicitly on **each device**.
- Persist this preference across restarts and application upgrades.

## Architectural requirements

1. Localize all user-visible UI: main window, discovery, pairing, device cards, transfer/history, print, scan, errors, confirmations, tray/notifications, settings and accessibility text.
2. Make localization independent from GNP/1 on-wire semantics, security decisions and serialized error identifiers. Protocol fields, hashes, signatures and keys are locale-invariant.
3. Use resource keys instead of scattered conditional string literals. Keep a single reviewed terminology glossary for Windows and Android.
4. Prefer structured error codes plus localized messages; log invariant diagnostic codes and preserve actionable support information.
5. Keep number/date/measurement presentation culture-aware while network/storage numeric representation stays invariant. Changing UI language must not change the system locale.
6. Support pluralization, long text, small displays, accessibility scaling, right label alignment as appropriate, and avoid fixed-width assumptions.
7. Language changes should update visible screens/dialogs without losing job state; if a full hot-switch proves unsafe on a given screen, defer its refresh safely rather than reset transfers or print jobs.
8. Remember Windows PowerShell 5.1 encoding guards: preserve required UTF-8 BOM on protected source/scripts when editing.

## UI design direction

One coherent design system for both Windows and Android, adapted to native platform conventions:

- compact device cards and consistent window/dialog rhythm;
- stable spacing, typography, icons, button hierarchy and status language;
- no duplicate 'Search' entry if the devices screen already offers automatic discovery and a manual refresh action;
- primary screens show essential actions; deeper capability/status information is behind 'Details';
- color alone never communicates trust, scanning/printing status or errors.

**Future scanner UI** and **future language toggle** should be built as reusable components, rather than separately restyling every platform screen twice.

## Planned order

1. Complete and freeze the current print settings/lifecycle checkpoint after its outstanding verification.
2. Implement M2.9.1 scanner foundation; proceed through remote scan MVP.
3. Introduce resource catalogs, explicit `auto/ru/en` preference and terminology keys.
4. Apply a unified design system incrementally to Windows and Android, with regression tests for long labels and small layouts.

## Acceptance checklist

- Fresh RU-system installation opens in Russian by default.
- Fresh EN-system installation opens in English by default.
- Unsupported locale opens in English.
- Manual RU/EN overrides persist after restart/update.
- RU/EN switching does not alter active trust keys, discovery, transfer, print or scan state.
- Every dialog and notification uses the selected UI language or a documented fallback.
- Existing security/build checks remain green.

## Non-goals for this draft

- Translating protocol message IDs or cryptographic metadata.
- Shipping an unimplemented scanner or localization feature as if already present.
- Requiring a cloud translation service or third-party account.
