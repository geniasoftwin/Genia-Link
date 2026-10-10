# Genia Link Validation & Compatibility Matrix

_Last updated: 2026-10-10_

This matrix answers a simple question: **what is actually public, what has been physically validated, and what still needs testing?**

## Status definitions

| Status | Meaning |
| --- | --- |
| **PUBLIC** | Included in the source snapshot currently stored on `main` |
| **PHYSICAL PASS** | Exercised successfully on real hardware in the development line |
| **SECURITY PASS** | Development security/build gate passed on the target toolchain |
| **IMPLEMENTED / NOT PHYSICALLY VALIDATED** | Code path exists but the stated real-hardware path still needs validation |
| **PLANNED** | Accepted next-step direction; no implementation claim |

## Core / transport

| Area | Windows | Android | Status |
| --- | --- | --- | --- |
| Local UDP discovery | Yes | Yes | **PUBLIC** |
| SAS pairing | Yes | Yes | **PUBLIC** |
| Persistent trusted identity | Yes | Yes | **PUBLIC** |
| Authenticated trusted transport | Yes | Yes | **PUBLIC** |
| AES-256-GCM protected frames | Yes | Yes | **PUBLIC** |
| Resumable file transfer + SHA-256 verification | Yes | Yes | **PUBLIC** |
| Trusted Identity Registry / lifecycle | Yes | Yes | **PUBLIC** |
| Replay-hardened signed identity assertions | Yes | Yes | **PUBLIC** |
| Authenticated capability advertisement | Yes | Yes | **PUBLIC M2.6.2** |

## Print development line

| Path / feature | Validation | Notes |
| --- | --- | --- |
| Android → Windows Print Gateway | **PHYSICAL PASS** | Real physical printer path |
| Windows → Windows Print Gateway | **PHYSICAL PASS** | Real physical printer path |
| Image JPG/PNG | **PHYSICAL PASS** | Includes pre-spool cancellation testing |
| PDF | **PHYSICAL PASS** | Physical scale correction verified |
| TXT | **PHYSICAL PASS** | UTF-8, TAB stops, wrapping, multipage |
| DOCX via Microsoft Office | **PHYSICAL PASS** | Macro-free Office bridge |
| XLSX/PPTX Microsoft Office bridge | **PHYSICALLY VALIDATED PATH** | Office bridge validated; per-document layout still depends on source content/Office rendering |
| LibreOffice/OpenOffice fallback | **IMPLEMENTED / NOT PHYSICALLY VALIDATED** | Must not be presented as physically verified yet |
| Lifecycle / Error Recovery | **PHYSICAL PASS** | Conservative Unknown semantics on legacy driver |
| Cancel / Retry | **PHYSICAL + SECURITY PASS** | M2.8.4.5 |
| Office-preparation-aware early cancel | **PHYSICAL PASS** | DOCX repeated Cancel → Retry → Cancel |
| Late cancel after exact job is no longer provable | **PHYSICAL PASS** | Fail-closed; Retry suppressed |

## Remote Scan development line — M2.9.2

**Tested configuration:** trusted Windows ScannerGateway **build7** and **two Android clients build8**. The public `main` branch does **not** yet include this source.

| Path / feature | Validation | Notes |
| --- | --- | --- |
| Authenticated Windows scanner inventory from Android | **PHYSICAL PASS** | Both phones found the scanner via the trusted gateway |
| One-page 300 dpi WIA → bounded BMP-to-JPEG → Android | **PHYSICAL PASS** | Verified JPEG reception in device logs |
| Repeated scans | **PHYSICAL PASS** | Multiple sequential verified JPEG results without observed gateway restart |
| Two clients / exclusive scanner access | **PHYSICAL PASS** | One WIA acquisition at a time; overlapping requests receive `Busy` |
| Android busy-message UX | **PHYSICAL PASS** | Clear “Сканер занят другим заданием” message shown in UI |
| Android scan display wake protection | **PHYSICAL PASS** | Screen remained on through active scans, with system timeouts 15 and 30 seconds |
| Manual screen lock / app backgrounding | **NOT VALIDATED** | No foreground-service/background-scanning guarantee |
| Scan cancellation, automatic job queue | **NOT VALIDATED** | Candidate for later milestone, not part of this PASS |
| ADF/multipage and PDF output | **NOT VALIDATED** | No compatibility claim from one-page JPEG testing |
| Full M2.9.2 Windows + Android security/build gate | **NOT CONFIRMED** | Physical success and one reported Android Share/Resume check do not establish the full gate |

Checkpoint report: [M2.9.2 Remote Scan build8](GNP1_M2_9_2_REMOTE_SCAN_BUILD8.md).

## Physical printer baseline

| Device / driver class | Status | What it proves |
| --- | --- | --- |
| Samsung SCX-4300 Series | **PHYSICAL PASS** | Conservative legacy Windows printer baseline; file/Office/PDF/image/TXT and lifecycle/cancel behavior |
| Additional modern office printers/MFPs | **PLANNED** | M2.8.5 compatibility/capability expansion |
| Label printers using normal Windows drivers | **PLANNED** | Small/custom media and driver compatibility |
| Receipt/POS printers using normal Windows drivers | **PLANNED** | 58/80 mm and continuous-media behavior |

No generic claim of compatibility with every Windows printer is made from the single-device baseline.

## Build / security validation

The M2.8.4.5 checkpoint has passed the project's Windows and Android build/security gates on the target development toolchain.

The public repository still contains the older M2.6.2 source snapshot. The validation statements above describe newer development checkpoints and are not a claim that all M2.8 or M2.9 source has been published on `main`.

## Next compatibility checkpoint

The next print milestone is intended to formalize printer capability reporting rather than assuming that every driver exposes the same state or features.

Expected M2.8.5 work includes discovery of driver-reported properties such as paper/media support, color/mono, duplex, resolution and reliability of lifecycle/status reporting.

Unsupported or unavailable information should remain **Unknown/Unavailable**, not be guessed.
