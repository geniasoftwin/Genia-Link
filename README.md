# Genia Link

**English** · [Русский](README.ru.md)

Genia Link is a local-network device link for trusted file exchange between Windows and Android devices. The core transfer path is designed to work directly over the LAN without a cloud relay.

> **Status:** development preview. The current development line is **v0.3.1 RC4 / GNP/1 M2.6.x**. Interfaces, protocol details, packaging, and compatibility requirements may change before a stable release.

## What Genia Link is designed to provide

- local device discovery on the LAN;
- explicit trusted pairing with verification;
- authenticated and encrypted file transfer between trusted devices;
- transfer resume for interrupted files;
- protected browsing/requesting of files exposed through the Genia Link folder workflow;
- trusted-device identity tracking and protection against silent identity replacement;
- replay/tamper checks for authenticated discovery data;
- safe destination/path handling for received files;
- Windows integration such as **Send to** workflows;
- Windows and Android clients built around a shared protocol/core.

## Security model

Genia Link treats device identity and pairing state as security boundaries. A previously trusted device is not supposed to become trusted again merely because another endpoint appears under the same display name. Identity/key changes require a new explicit trust decision.

The project also uses defensive checks around transfer paths, authenticated discovery/control messages, replay handling, and trusted peer state. Security-sensitive behavior is covered by automated self-tests in the development package.

## Privacy and networking

Genia Link is intended for direct communication between devices on a local network. The transfer design does not require a Genia Link cloud service to relay user files.

Operating systems, package managers, GitHub, certificate infrastructure, or future optional features may still use Internet connectivity independently of the Genia Link transfer protocol.

## Platforms

Current development targets include:

- **Windows** — .NET desktop client;
- **Android** — .NET for Android client.

Exact OS/runtime requirements will be documented with public release packages.

## Repository scope

This repository is being prepared as the public home of Genia Link. Public source, documentation, test material, and release artifacts may be added incrementally.

Sensitive material such as signing keys, certificates, private keys, credentials, local machine configuration, and private infrastructure data must never be committed.

## License and rights

No open-source license is granted by the mere publication of this repository. Unless a file or component explicitly states otherwise, the project content is **All Rights Reserved**. Third-party components remain subject to their own licenses and notices.

See [LICENSE](LICENSE) and [NOTICE.md](NOTICE.md).

## Security reporting

Please read [SECURITY.md](SECURITY.md) before reporting a potential vulnerability.

---

**Genia Link** is under active development by Genia Soft.
