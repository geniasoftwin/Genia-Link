# GNP/1 M2.7 — Service Availability, Concurrent Transfers and Device UI

> **Status of this document:** this is a development/design and validation record for M2.7 work performed in a separate local development build. The implementation described below is **not included in this pull request or in the current public source snapshot**. The public source tree remains M2.6.2. Statements below must therefore not be read as claims about the behavior of the source currently visible in this repository.

## Goal

M2.7 is intended to turn the authenticated capability state introduced in M2.6.2 into visible application behavior while keeping the trust model unchanged.

The development checkpoint combines three areas:

1. service availability derived from authenticated capability sets;
2. bounded concurrent file-transfer sessions;
3. a scalable device/user interface built around stable device identity, local aliases, live authenticated roles and real available actions.

M2.7 does **not** create trust from capabilities and does not introduce network-wide administrative authorization.

## Service availability

Capability-gated service availability is an **M2.7 design requirement**, not behavior provided by the current public M2.6.2 source tree.

Before a future M2.7 source snapshot is published, service entry points must enforce the required authenticated capability on both initiating and receiving paths.

Planned examples:

- File Transfer requires `FileTransfer`;
- Shared Resources requires `SharedResources`.

The service layer is intended to support future capabilities such as Print, Scan, Storage and Messaging, but the UI must not expose an action merely because it is planned. Filters and actions should be generated only from states, authenticated roles and authenticated services that actually exist.

A signed LAN capability advertisement is not sufficient by itself to establish trust. Pairing, Trusted Identity Registry state, pinned signing identity, lifecycle state and the trusted-session handshake remain authoritative.

## Concurrent trusted transfers

A separately tested M2.7 development build used bounded file-level parallelism. It deliberately did not split one file into multiple transport streams.

Development policy used during testing:

- up to **3 outgoing file sessions per peer**;
- up to **4 concurrent incoming trusted sessions** per receiver;
- each file session kept an independent trusted handshake, secure channel, transfer ID, resume offset and SHA-256 integrity verification;
- duplicate transfers of the same source file to the same peer were serialized to avoid resume-state races;
- a file was shown as completed only after the trusted transfer returned successfully after receiver-side integrity verification.

This development approach used multiple ordinary trusted transfer sessions, so protocol version 3 and the existing transfer wire format did not need to change.

The current public source tree does not contain this scheduler/receiver concurrency implementation.

## Per-peer scheduler

In the separately tested M2.7 development build, separate Windows Send To requests shared the same bounded per-peer pool. When three trusted sessions were active, the next transfer waited until a slot became available.

This behavior is recorded here as development validation and is not implemented by the current public source snapshot.

## Device identity UI

The M2.7 UI design uses two distinct presentation names:

- **Original name** — the name announced by the remote device;
- **Local alias** — an optional name chosen only on the local device.

The intended alias model stores aliases by stable Device ID and does not modify:

- Device ID;
- pairing/trust state;
- ECDH identity;
- signing key or signing-key generation;
- capability advertisements;
- remote metadata.

The original name remains available even when a local alias is set.

The alias editor/storage path is not present in the current public source snapshot.

## Authenticated roles and live refresh

The M2.7 development UI derives Client / Server / Relay / Backup / Custom presentation from capabilities already accepted into the Trusted Identity Registry.

A merely signed but not yet trusted capability advertisement does not by itself produce a trusted role.

Local M2.7 testing recorded live role/profile refresh after accepted capability revisions without restart or re-pairing. This observation refers to the separate development build, not the current public source tree.

Device type, role and availability remain separate concepts.

## Scalable device list

The separately developed M2.7 Windows UI included:

- `Devices — N`;
- search;
- dynamic filters generated from states, authenticated roles and authenticated services present in the development build;
- no empty future filters such as Print, Scan or Relay when those capabilities were absent;
- a selected-device header with common Files access and a dynamic `Actions` menu.

These controls are not present in the current public source snapshot.

## Transfer activity UI

The separately developed M2.7 UI represented concurrent transfers with independent activity rows rather than one shared progress bar.

Its Completed section was designed with:

- bounded recent history;
- consistent full-width rows;
- filename, direction/peer and completion time aligned predictably;
- ellipsis for long names;
- constrained Explorer opening/selection for completed local files;
- UI-history clearing that does not delete transfer files.

These activity/history controls are not present in the current public source snapshot.

## Diagnostics

The separately developed M2.7 UI moved technical diagnostics out of the main work surface into a dedicated Diagnostics window with:

- bounded live log history;
- Copy;
- Clear;
- wrapped long lines;
- no horizontal scrollbar.

The current public source snapshot still uses the earlier in-window diagnostics presentation.

Diagnostics presentation does not alter transfer state or trust state.

## Future service UI decisions

M2.7 is intended to lay the UI foundation for service-driven actions without pretending that unfinished services already exist.

Planned rules:

- Print and Scan appear under `Actions` only when real authenticated implementations/capabilities exist;
- the same principle applies to Storage and other device services;
- Chat is planned as a separate user window rather than a permanently reserved area in the main Files workspace;
- a Chat affordance is added only when a real authenticated messaging service exists.

## Compatibility

The M2.7 development work was designed around these compatibility constraints:

- Protocol version remains 3.
- M2.6.2 `GLC1` signed capability advertisement format remains compatible.
- Pairing is unchanged.
- Existing trusted devices do not require re-pairing.
- Existing Device IDs and signing keys remain unchanged.
- Single-file transfer remains compatible with the existing trusted transfer protocol.

## Local validation record

Real-device testing performed on separate M2.7 development builds recorded:

- simultaneous Windows → Android trusted sessions;
- simultaneous Android → Windows trusted sessions;
- three active outgoing slots with refill when one completed;
- successful integrity completion across parallel batches;
- safe failure when a stale/sleeping endpoint did not accept a connection, followed by successful transfer after fresh signed discovery/authenticated contact;
- live role/profile updates in the M2.7 development UI;
- dynamic role/service/state filters in that development UI;
- diagnostics separated from the main UI in that development UI;
- transfer-history and multi-progress behavior under concurrent load.

These observations are development test notes. They **cannot be reproduced from the current public source snapshot**, because the corresponding M2.7 implementation is not part of this pull request.

No raw live logs are published because they can contain device identifiers, signing-key identifiers, IP addresses and local device names.

## Development status

M2.7 remains a development checkpoint in the existing v0.3.1 RC4 line. This pull request publishes documentation only and does **not** publish the M2.7 implementation, create a GitHub Release, or create a tag. A future source publication should include the implementation and re-run the repository build/security checks against that exact tree.
