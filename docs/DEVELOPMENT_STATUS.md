# Genia Link Development Status

_Last updated: 2026-10-10_

This page separates the **public source snapshot currently stored on `main`** from newer development packages that have been physically validated before a deliberate source synchronization.

## Public source snapshot

The current public source snapshot on `main` remains:

**v0.3.1 RC4 / GNP/1 M2.6.2 — Authenticated Capabilities**

It includes trusted device identity, authenticated capability advertisement, local-only encrypted transfer, resumable transfers, Windows/Android clients, and the security/self-test tooling documented in this repository.

## Current development progress

The active development line has advanced beyond the public M2.6.2 snapshot.

| Milestone | Status | Verified behavior |
| --- | --- | --- |
| GNP/1 M2.7 | Development checkpoint completed | Large-batch scheduling, concurrent trusted transfer handling, resume/history UX and related stability fixes |
| GNP/1 M2.8.1 | Physical end-to-end test passed | Android → authenticated GNP/1 session → Windows Print Gateway → physical printer |
| GNP/1 M2.8.2 | Physical PDF test passed | PDF printing and corrected physical scale on Samsung SCX-4300 Series |
| GNP/1 M2.8.3 | Physical Windows remote-print test passed | Windows → authenticated GNP/1 → Windows Print Gateway → Samsung SCX-4300; image ActualSize calibration matched direct Windows printing |
| GNP/1 M2.8.4 | Microsoft Office path physically validated | Macro-free DOCX/XLSX/PPTX local Office-to-PDF bridge; Microsoft Office path exercised physically. LibreOffice/OpenOffice fallback remains implemented but not physically validated |
| GNP/1 M2.8.4.1 | Check passed | Excel print options remain bounded and authenticated |
| GNP/1 M2.8.4.2 | Physical/checkpoint validation passed | Print layout and image alignment behavior retained |
| GNP/1 M2.8.4.3 | Physical TXT backend passed | UTF-8, real TAB stops, wrapping and multi-page pagination |
| GNP/1 M2.8.4.4 | Physical lifecycle/error-recovery passed | Conservative Queued/Printing/Unknown lifecycle semantics; fix23 Android foreground-notification cleanup |
| GNP/1 M2.8.4.5 | **Physical + security PASS** | Authenticated Cancel / Retry; pre-spool cancel for image/PDF; Office preparation-aware DOCX cancel; explicit retry with preserved settings; fail-closed late cancel |
| GNP/1 M2.8.5.1 | Functional + physical regression observed in dev | Printer Capability V3 inventory on Samsung SCX-4300, PDF print and Cancel / Retry smoke test |
| GNP/1 M2.8.5.2 | Functional UI observed in dev | Read-only detailed printer capability profile displayed in Android |
| GNP/1 M2.8.5.3 | Partial physical validation in dev | Actual copies and DPI changes verified on SCX-4300; paper-format test and final security/build confirmation remain outstanding |

Detailed M2.8.4.5 checkpoint: [Cancel / Retry](GNP1_MILESTONE2_8_4_5_CANCEL_RETRY.md).

Public product/design/security context: [Product & Dependency Principles](PRODUCT_PRINCIPLES.md) · [User Flow](USER_FLOW.md) · [Validation & Compatibility Matrix](VALIDATION_MATRIX.md) · [Architecture overview](ARCHITECTURE.md) · [GNP/1 Specification](GNP1_SPEC.md) · [Threat model](THREAT_MODEL.md) · [Protocol notes](PROTOCOL.md).

## Print Service security model

The printing path remains built on the existing Genia Link trust model:

- No separate unauthenticated print port is introduced.
- `PrinterGateway` is an authenticated capability advertisement; seeing it during discovery does not by itself authorize printing.
- Printer discovery, print submission and print-control messages use an authenticated trusted GNP/1 session.
- Cancel ownership is bound to the accepted JobId and authenticated remote device.
- Retry is manual; an unconfirmed cancellation does not enable retry.
- Windows remains the print gateway and uses the locally installed Windows printer/driver stack.
- The tested path remains local-network-first; no Genia Link cloud relay is required.

## M2.8.4.5 validation summary

The validated checkpoint provides a bounded cancellation window before Windows spooler handoff. For Office documents, cancellation remains available during preparation and a full 3000 ms pre-spool window starts after Office preparation completes. If a job has already left the spooler and the exact Genia Link marker/Windows JobId cannot be proven, cancellation is reported as not confirmed and retry is suppressed.

Physical tests covered repeated Cancel → Retry → Cancel cycles on DOCX, PDF and image/JPG/PNG paths. Windows and Android security/build gates also passed on the target toolchain.

## Planned next steps

1. Finish the outstanding M2.8.5.3 print settings checks and freeze the actual selected source package (do not infer full security PASS from UI screenshots).
2. Start [M2.9 Scanner Service Foundation](GNP1_M2_9_SCANNER_PLAN.md) with a read-only WIA scanner-driver probe and a locally initiated single-page scan.
3. After the scanner MVP, implement authenticated remote scanning and preview; only then multipage / ADF / PDF support where observed.
4. Add [Russian/English localization](LOCALIZATION_PLAN.md) with system-default selection, persistent manual override and a unified Windows/Android design system.
5. Broaden compatibility tests and prepare a deliberate public source synchronization beyond M2.6.2 only after packaging and revalidating a complete development checkpoint.

## Roadmap boundary

Scanner, localization, peer-assisted reachability and related future capabilities remain **PLANNED** unless explicitly implemented and validated. They are not included in the public M2.6.2 source snapshot.

The scanner plan explicitly requires a locally installed WIA-compatible scanner driver on the Windows gateway where appropriate, but no Microsoft Office or Genia Link cloud service.

## Publication note

The milestones above describe **validated development progress**, not a claim that the corresponding M2.7/M2.8 source has already been synchronized to the public `main` branch.

The documentation checkpoint is intentionally separate from source synchronization so the public source tree is never partially replaced.
