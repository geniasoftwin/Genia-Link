# Genia Link Product & Dependency Principles

_Last updated: 2026-10-07_

This document records product-level engineering principles. It does **not** claim that every future edition or module described here is already implemented.

## 1. Minimal mandatory dependencies

Genia Link should minimize mandatory external dependencies.

A core advertised capability should not require the user to install unrelated helper applications, create third-party accounts, or depend on a cloud service unless there is no reasonable way to implement that capability safely, locally and maintainably.

> **Dependency policy:** a mandatory external dependency is acceptable only when the function cannot reasonably be implemented safely, locally and maintainably without it.

## 2. Optional integrations enhance; they do not define the baseline

Optional integrations may improve fidelity, compatibility, performance or convenience.

They should not be the only way to unlock a core capability that the product itself advertises.

> **Optional integration should enhance capability, not unlock the basic capability.**

Examples:

- Microsoft Office may be used as a high-fidelity renderer for its own document formats when present.
- A self-contained document-preparation engine may provide the baseline path for a future Pro-class edition.
- Platform-native printing, scanning, keystore and cryptographic APIs remain valid dependencies because they are part of the target operating system rather than separately deployed helper products.

## 3. Local-first and self-contained direction

The preferred architecture is:

- local processing where practical;
- authenticated GNP/1 transport;
- no required Genia Link cloud relay;
- no required third-party account for core local functions;
- bounded local caches and staging;
- explicit, inspectable fallback behavior.

This is a design direction, not a claim that every planned future feature is already dependency-free.

## 4. Future Pro-class principle

A future **Genia Link Pro** direction is intended to be self-contained for its advertised professional capabilities.

That means, conceptually:

```text
Genia Link Pro
├── GNP/1 Core
├── File Transfer
├── Printer Gateway
├── Print Preview
├── Document Preparation Engine
├── Local PDF/Image/TXT rendering
├── Scanner Gateway
└── Local job/cache management
```

Microsoft Office or another external renderer may still be detected and used as an **optional high-fidelity backend**, but the future Pro product direction should not make such software an unconditional requirement for the capability itself.

## 5. Prepared-artifact principle for document printing

For complex office documents, the preferred future printing model is:

```text
source document
    ↓
document preparation backend
    ↓
immutable prepared artifact (for example PDF)
    ↓
preview + SHA-256 identity
    ↓
explicit user confirmation
    ↓
print the same prepared artifact
```

This avoids a misleading flow where one renderer is used for preview and a different renderer is used for actual printing.

If a compatibility renderer is used, the UI should disclose that fact and allow the user to inspect the prepared result before printing.

## 6. No hidden fidelity claims

Genia Link should not claim that every document backend reproduces every Microsoft Office layout identically.

When the renderer or printer driver cannot prove fidelity or physical completion, the product should expose that uncertainty rather than inventing confidence.

This follows the broader Genia Link fail-closed / fail-conservative design philosophy.

## 7. Edition philosophy

Potential product editions should differ by real engineering scope rather than artificial feature locks:

| Direction | Intended role |
| --- | --- |
| Genia Link Mini | lightweight trusted transfer client |
| Genia Link | general trusted local device link |
| Genia Link Pro | self-contained professional gateway/workstation direction |
| Genia Link TV | trusted media/presentation receiver direction |

These names describe product direction only. They are not release claims unless separately marked as implemented and published.

## 8. Short form

The preferred product direction can be summarized as:

**Local. Trusted. Self-contained.**

with one additional engineering rule:

**Use external integrations when they improve the product, not because the product cannot function without them.**
