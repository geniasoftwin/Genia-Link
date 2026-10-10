# GNP/1 M2.9 — Scanner Service Roadmap (Design Draft)

_Last updated: 2026-10-10_

**Status: PLANNED.** This is an implementation design, not a claim that scanner functionality is currently present in the published source or validated development builds.

**Publication boundary:** public `main` remains v0.3.1 RC4 / GNP/1 M2.6.2. The newer M2.8 print checkpoints were tested separately and are not yet fully synchronized to `main`.

## Goal

Add trusted local scanning from a Windows-connected scanner/MFP to Windows and Android clients, without a cloud service or required Office installation. The first candidate device is the Samsung SCX-4300 connected to a Windows machine, **only if its installed scanner driver exposes a compatible WIA scanner**.

## M2.9.1 — Windows Scanner Service Foundation

First implement locally, without remote GNP/1 scan messages:

1. Read-only WIA 2.0 scanner enumeration and driver capability inventory.
2. Distinguish device detected / WIA not available / scanner not configured / device busy, without guessing.
3. Query capabilities individually: flatbed vs ADF, optical/available DPI, color modes, paper/area and output formats if driver exposes them.
4. Acquire one page on user command. Start with a bounded raster output and controlled local staging.
5. Reliable cancellation, timeouts, cleanup and error reporting; do not claim cancellation when device execution cannot be confirmed.
6. Physical tests with the actual driver before labelling the milestone PASS.

**Process boundary:** use an appropriately isolated Windows user-session STA COM worker/broker for WIA; do not require scan acquisition in Session 0, and do not block the main WPF UI thread. The WIA acquisition runs under a suitable user context, distinct from the GNP/1 parser boundary.

**Dependency policy:** Windows WIA is a system API, not a requirement to install a third-party Office or document suite. Some devices nevertheless require a compatible vendor-supplied scanner driver. WIA support must be discovered, never assumed.

## M2.9.2 — Authenticated remote scan and preview

After local WIA acquisition is validated:

- Add an **authenticated ScannerGateway** capability; advertisement alone does not authorize a scan.
- Offer scanner list/capabilities through the existing encrypted trusted GNP/1 session (TCP 47500), with explicitly negotiated additive messages.
- Authorize a scan request against the authenticated remote DeviceId and a gateway policy, with explicit initiation rather than unattended acquisition.
- Return a bounded scan artifact through the trusted channel; verify integrity and save atomically in a user-approved destination.
- Add Android and Windows client preview (first page first, then more pages on request).
- Handle disconnects, session revocation, malformed parameters, busy devices and scan cancellation conservatively.

Do **not** reserve or publish protocol message numbers until implementation and compatibility review. No scanner listener/port should be exposed without authenticated GNP/1 authority.

## M2.9.3 — Multipage / ADF / PDF

Only after basic single-page remote scanning is physically validated:

- ADF or flatbed selection where confirmed by the scanner driver.
- Multipage acquisition and bounded page/byte counts.
- Local PDF assembly, preview and user-controlled destination naming.
- Duplex scan options only where the scanner actually supports them.
- Driver-specific compatibility matrix and fallback/error reporting.

## Safety and reliability requirements

- Untrusted peers cannot enumerate or actuate the scanner.
- No transitive trust: permissions never flow from a trusted intermediary.
- Each job belongs to an authenticated request context; concurrency is bounded.
- Scanner readback does not reveal arbitrary local files or memory.
- Enforce bounds on dimensions, page count, bytes, image decoding, metadata, temporary files and job lifetime.
- No automatic scanning or silent camera/ADF activation.
- Scan output is kept local unless the authorized user explicitly transfers it.
- Clean staging files on success, abort and failure, with conservative reporting on device ambiguity.
- No dependence on cloud OCR, remote APIs or third-party accounts.

## First physical readiness test

Before adding scanning to Genia Link, on the Windows gateway:

1. Verify a scanner driver is installed and the Windows scan application (or another WIA client) can enumerate the device.
2. Run a read-only WIA probe; if the device is not listed, distinguish missing WIA driver from unsupported hardware or service restrictions.
3. If listed, execute a locally initiated one-page test scan using an existing WIA-compatible app.
4. Record the actual driver model, bed/ADF behavior and supported modes without claiming support for unobserved capabilities.

A read-only Windows PowerShell probe is a diagnostic tool, **not** a scanner-service implementation. The real M2.9.1 coding starts from a deliberately selected, physically/security-checked M2.8 baseline and must preserve the existing transfer and print contracts.

## Validation gates

- Windows build with analyzers/warnings as errors.
- Offline security/self-tests unchanged and extended for scan ownership/bounds.
- Existing Android and Windows GNP/1 regression gates green.
- Confirmed real single-page scan with the actual scanner driver.
- Remote GNP/1 path is a **separate** M2.9.2 physical validation, not part of M2.9.1 PASS.
