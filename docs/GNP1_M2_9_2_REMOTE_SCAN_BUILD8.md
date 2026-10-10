# GNP/1 M2.9.2 — Remote Scan / Android Scan Stability build8

**Development checkpoint:** Genia Link v0.3.1 RC4 · GNP/1 M2.9.2 · **PHYSICAL PASS for the scenarios below on 2026-10-10**.

> **Publication boundary:** This is a documentation-only report about a separate, physically tested development package. The public source tree on `main` remains **v0.3.1 RC4 / GNP/1 M2.6.2**. Neither the build7 Windows gateway nor the build8 Android implementation is being published by this checkpoint. **PHYSICAL PASS** does not mean a full release certification or an independently verified complete Windows/Android security/build gate.

## Physically tested configuration

- Windows laptop with a locally installed scanner/MFP driver, acting as a trusted **ScannerGateway**: **M2.9.2 Remote Scan build7**.
- **Two trusted Android phones**: **M2.9.2 Android Scan Stability build8**.
- Direct local-network transport over existing authenticated GNP/1 sessions. No cloud path or unauthenticated scanner listener was introduced for this tested workflow.
- Single-page **300 dpi** scan, scanner acquisition through Windows WIA, conversion of the device-returned BMP to bounded JPEG, and verified JPEG receipt on the requesting Android phone.

## Test evidence and outcomes

| Scenario | Physical result | Scope |
| --- | --- | --- |
| Repeated single-page scan requests | **PASS** | Several sequential successful `Ready` / verified JPEG results; no Windows gateway restart needed in the observed test |
| Two Android clients, one scanner | **PASS** | Only one acquisition accepted at a time; competing client receives `Busy`; after completion the other phone can receive its own JPEG |
| Busy message on Android | **PASS** | UI displays “Сканер занят другим заданием. Повторите после его завершения.” instead of a generic scan failure |
| Screen timeout set to 30 s and 15 s | **PASS** | During active scanning, the Android display remained on until the scan completed |
| Verified result delivery | **PASS** | Logs record `verified JPEG scan received` after authenticated scan requests |
| Manual device lock / backgrounding | **NOT VALIDATED** | Auto screen-on protection is not evidence of background scanning support |
| Explicit cancel, server-side wait queue, ADF/multipage, PDF output | **NOT VALIDATED** | No support or physical-pass claim from these tests |

A two-device timing sequence observed in the test:

- 20:10:19 — Android client A requested a trusted scan; 20:10:50 — client A received a verified JPEG.
- 20:10:26 through 20:10:50 — Android client B's competing requests received `Busy`.
- 20:10:50 — client B's subsequent scan request was accepted; 20:11:32 — client B received a verified JPEG.
- 20:10:58 — client A's competing request received `Busy` while client B was using the scanner.

This establishes **exclusive scanner access**, not an automatic queue. The observed rejected requests were safe, but repeated button presses produced repeated `Busy` responses; rate limiting/UX is a possible improvement.

## Boundaries and follow-up

1. Keep the known-good build7 Windows WIA path intact while validating Android-specific changes.
2. Separately test manual screen lock, app backgrounding, network interruption, cancellation, and recovery.
3. Design optional queued jobs with explicit user confirmation/document ownership before any automatic second acquisition; never mix results between authenticated requesting devices.
4. Repeat the project's full target-toolchain security/build gates and package validation before any public source synchronization or release claim.

**No sensitive logs, pairing identifiers, private keys, device IDs, or IP addresses are attached.**
