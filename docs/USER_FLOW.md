# Genia Link User Flow

_Last updated: 2026-10-07_

This page explains the product flow at a user level. It deliberately distinguishes **current/public behavior**, **physically validated development behavior**, and **concept UI**.

> The visual below is a **concept UI direction**, not a screenshot of the current application build. It illustrates the intended information hierarchy without claiming that every control or layout is already implemented exactly as shown.

<p align="center">
  <img src="../branding/web/print-flow-concept.svg" alt="Concept UI showing Genia Link discovery, SAS pairing, trusted capabilities, remote printing and fail-closed Cancel / Retry" width="100%" />
</p>

## Status legend

| Label | Meaning |
| --- | --- |
| **PUBLIC** | Source is currently present on `main` |
| **VALIDATED DEV** | Implemented in the development line and physically/security validated, but full source is not yet synchronized to `main` |
| **IMPLEMENTED / UNVALIDATED** | Implemented in the development line but still needs the stated physical compatibility test |
| **PLANNED** | Accepted engineering direction; implementation has not been claimed |
| **CONCEPT** | Product/UI exploration only |

## 1. Discover a device — PUBLIC

Genia Link discovers peers on the local IPv4 network using its own UDP discovery on port 47502.

Discovery makes a peer visible. It does **not** make that peer trusted.

For an already trusted sleeping peer, a previously cryptographically confirmed local endpoint may be retained as a route hint. The remembered IP still does not authorize the device.

## 2. Pair with SAS — PUBLIC

Initial trust is explicit:

1. select the peer;
2. compare the same six-digit SAS on both devices;
3. confirm on both sides;
4. persist the cryptographic peer identity.

A name or IP address never replaces this trust decision.

## 3. Use authenticated capabilities — PUBLIC

After pairing, the peer authenticates as the expected persistent identity.

The M2.6.2 public source snapshot includes authenticated capability advertisements. Capabilities describe what a trusted device can provide; they do not create trust by themselves.

## 4. Transfer files — PUBLIC

File transfer uses the authenticated encrypted transport and includes bounded filenames/paths, resume state and final SHA-256 verification.

Unsafe paths and integrity mismatch are rejected.

## 5. Remote printing — VALIDATED DEV

The M2.8 development line adds a Windows Print Gateway over the existing trusted GNP/1 transport.

Physically validated paths include Android → Windows gateway and Windows → Windows gateway. The current physical baseline is Samsung SCX-4300 Series.

Validated document paths include image/JPG/PNG, PDF, TXT and the Microsoft Office bridge for macro-free Office documents.

## 6. Cancel / Retry — VALIDATED DEV

M2.8.4.5 binds cancellation to the accepted JobId and authenticated remote device.

- Before spooler handoff, cancellation can stop preparation/staging.
- Office preparation remains cancellation-aware.
- A full bounded pre-spool window exists after Office preparation.
- After spooler submission, only the exact correlated Windows job may be cancelled.
- If exact cancellation cannot be proven, Genia Link reports **not confirmed** and suppresses Retry.

Retry is explicit and receives a new JobId while preserving the selected document/settings.

## 7. Driver limitations are visible — VALIDATED DEV

Genia Link does not fabricate printer state.

The legacy Samsung SCX-4300 driver can remove a job from the Windows queue before physical paper completion can be proven. In that situation the client uses conservative lifecycle wording instead of claiming physical completion.

## Why the concept UI is useful

The proposed UI direction makes the trust model visible to ordinary users:

- device visibility and device trust are shown as different states;
- available capabilities are shown after trust;
- print settings stay attached to the job;
- Cancel / Retry state is explicit;
- unknown physical status remains unknown rather than being presented as success.

The design can evolve without changing the underlying GNP/1 security contract.
