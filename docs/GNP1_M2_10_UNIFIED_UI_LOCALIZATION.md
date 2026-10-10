# GNP/1 M2.10 — Unified UI & Localization (RU/EN)

**Status: APPROVED FOR DEVELOPMENT — NOT IMPLEMENTED OR PHYSICALLY VALIDATED.** Kickoff: 2026-10-10.

This is a separate presentation-layer milestone. **M2.9.3 remains reserved for Scan Job Management.** The physically tested M2.9.2 combination (Windows ScannerGateway **build7** + two Android clients **build8**) is the regression and rollback baseline.

> The public source on `main` remains v0.3.1 RC4 / GNP/1 M2.6.2. M2.10 has neither published source nor a binary release. This plan is not a claim of implementation.

## Goals

1. Introduce a consistent visual language for Windows (WPF) and Android (native UI), preserving platform-specific navigation, keyboard and touch conventions.
2. Localize user-visible device discovery, pairing, transfer/history, print, scan, menus, settings, dialogs, errors, notifications and accessibility descriptions into **Russian and English**.
3. Add a persistent, **per-device** UI language preference: `auto` (initial default), `ru`, `en`. Auto follows the system UI language for Russian and English; other languages fall back to English.
4. Keep active trusted sessions, device keys, transfers, print/scan jobs and other runtime state intact when changing language.

## Engineering boundaries

- UI locale is local presentation state, not a GNP/1 message or an input to cryptographic identity, SAS, signing, network framing, transfer resume, capability advertisements or job ownership.
- Use reviewed resource keys and a shared RU/EN terminology glossary, not language conditionals scattered across business logic. Keep diagnostic error codes and on-wire values invariant.
- Display formatting may reflect UI culture, but stored/network values must remain invariant. Never change the operating-system locale.
- Language selection must not restart local services, lose transfer state or modify permissions. Refresh open views safely; if instant refresh cannot be guaranteed, defer it until an appropriate safe boundary.
- Preserve app identity/signing for in-place Android upgrades and the existing Windows `settings.json` migration behavior; keep the pairing and trusted history untouched.
- No cloud translation, new Internet dependency or unrelated mandatory packages.
- Preserve PowerShell 5.1 BOM/encoding assumptions and existing build/security checks.

## Shared UI design, platform-native implementation

| Area | Shared direction |
| --- | --- |
| Device cards | Compact identity/status layout, trust represented by icon + text, capabilities only after authentication |
| Navigation | Clear Devices / Transfers / Services / Settings destinations; avoid a redundant Search section |
| Primary actions | Send, print and scan only when locally supported and authenticated by the remote device |
| Advanced settings | Secondary detail panels; keep original driver-reported limits and explicit Unknown/Busy states |
| Visual language | Consistent brand palette, spacing, typography, button hierarchy and icon semantics; retain native interaction styles |
| Accessibility | Responsive long labels, font scaling, keyboard/touch targets, semantic labels; color alone never conveys security/status |

## Implementation sequence and checkpoints

1. **Foundation:** RU/EN keyed catalogs and glossary; language preference `auto/ru/en` persisted per-device; locale fallback and migration tests. Begin in separate development sources based on physically tested M2.9.2 build8.
2. **First-screen pilot:** localize main navigation, device cards, peer status and settings for Windows/Android; apply unified visual tokens; test switching/restart/in-place upgrade without re-pairing.
3. **Workflow coverage:** pairing, file selection, transfer/history, print, scan, notifications and confirmation/error flows. Use stable state-based localizations rather than parsing Russian status text.
4. **Hardening:** verify long labels, layout scaling, accessibility, full target-toolchain build/security gates, and real-device regression for file transfer, remote print, scan Busy handling and scan screen-on protection.
5. **GitHub presentation:** capture authentic screenshots/video only after validation and removal of private documents, network details and device identifiers.

The source review found the Windows UI primarily in WPF/XAML and a substantial programmatically built Android UI in `MainActivity.cs`; incremental migration is preferable to rewriting all screens simultaneously.

## Acceptance checklist

- [ ] Fresh RU-system installation uses Russian in Auto; EN uses English; other locales use English fallback.
- [ ] Explicit RU/EN overrides survive restarts and in-place upgrades on Windows and Android.
- [ ] Main windows, device lists, pairing, transfer, print, scan, notifications, errors and accessibility descriptions are localized or explicitly document fallback.
- [ ] Switching language does not touch trust, discovery, cryptographic identity, transfers, jobs or resource permissions.
- [ ] Long labels, compact layouts and large accessibility font sizes are usable.
- [ ] Existing Windows and Android security/build checks pass on the real development toolchain.
- [ ] M2.9.2 physical regression (Windows build7 + Android build8 baseline) is preserved in the M2.10 candidate.

See [Localization Plan](LOCALIZATION_PLAN.md), [Development Status](DEVELOPMENT_STATUS.md) and [M2.9.2 Remote Scan checkpoint](GNP1_M2_9_2_REMOTE_SCAN_BUILD8.md).
