# GNP/1 M2.7 — Service Availability, Concurrent Transfers and Device UI

## Goal

M2.7 turns the authenticated capability state introduced in M2.6.2 into visible application behavior while keeping the trust model unchanged.

The checkpoint combines three areas:

1. service availability derived from authenticated capability sets;
2. bounded concurrent file-transfer sessions;
3. a scalable device/user interface built around stable device identity, local aliases, live authenticated roles and real available actions.

M2.7 does **not** create trust from capabilities and does not introduce network-wide administrative authorization.

## Service availability

A service is considered mutually available only when the required capability is present in valid authenticated capability state.

Examples:

- File Transfer requires `FileTransfer`;
- Shared Resources requires `SharedResources`.

The service layer is intentionally prepared for future capabilities such as Print, Scan, Storage and Messaging, but the UI must not expose an action merely because it is planned. Filters and actions are generated only from states, authenticated roles and authenticated services that actually exist.

A signed LAN capability advertisement is not sufficient by itself to establish trust. Pairing, Trusted Identity Registry state, pinned signing identity, lifecycle state and the trusted-session handshake remain authoritative.

## Concurrent trusted transfers

M2.7 adds bounded file-level parallelism. It deliberately does not split one file into multiple transport streams.

Default policy:

- up to **3 outgoing file sessions per peer**;
- up to **4 concurrent incoming trusted sessions** per receiver;
- each file keeps an independent trusted handshake, secure channel, transfer ID, resume offset and SHA-256 integrity verification;
- duplicate transfers of the same source file to the same peer are serialized to avoid resume-state races;
- a file is shown as completed only after the trusted transfer returns successfully after receiver-side integrity verification.

Parallelism is implemented as multiple ordinary trusted transfer sessions, so protocol version 3 and the existing transfer wire format remain unchanged.

## Per-peer scheduler

Separate Windows Send To requests share the same bounded per-peer pool. When three trusted sessions are active, the next transfer waits until a slot becomes available.

This keeps concurrency local to a peer and avoids unbounded fan-out while still allowing independent files to make progress simultaneously.

## Device identity UI

A device has two distinct presentation names:

- **Original name** — the name announced by the remote device;
- **Local alias** — an optional name chosen only on the local device.

Aliases are stored by stable Device ID and never modify:

- Device ID;
- pairing/trust state;
- ECDH identity;
- signing key or signing-key generation;
- capability advertisements;
- remote metadata.

The original name remains available even when a local alias is set.

## Authenticated roles and live refresh

Client / Server / Relay / Backup / Custom presentation is derived from capabilities already accepted into the Trusted Identity Registry.

A merely signed but not yet trusted capability advertisement does not by itself produce a trusted role.

Accepted capability revisions update the visible role/profile without requiring restart or re-pairing. Live testing confirmed that role changes propagate to the remote UI effectively immediately after the updated profile is saved and accepted.

Device type, role and availability remain separate concepts.

## Scalable device list

The Windows device pane now includes:

- `Devices — N`;
- search;
- dynamic filters generated only from states, authenticated roles and authenticated services currently present;
- no empty future filters such as Print, Scan or Relay when those capabilities are absent;
- a selected-device header with common Files access and a dynamic `Actions` menu.

This is intended to remain usable as the trusted-device list grows from a few devices to dozens.

## Transfer activity UI

Concurrent transfers are represented by independent activity rows instead of sharing one global progress bar.

Successfully verified transfers move into a compact Completed section:

- bounded recent history;
- consistent full-width rows;
- filename, direction/peer and completion time aligned predictably;
- long names use ellipsis;
- clicking a completed item opens/selects the local file through a constrained Explorer launcher;
- clearing the UI history never deletes transfer files.

The Completed area uses the available Files-workspace height rather than reserving blank space for unrelated future features.

## Diagnostics

Technical diagnostics are intentionally removed from the normal work surface.

They are available only from the overflow menu in a dedicated Diagnostics window with:

- bounded live log history;
- Copy;
- Clear;
- wrapped long lines;
- no horizontal scrollbar.

Diagnostics presentation does not alter transfer state or trust state.

## Future service UI decisions

M2.7 lays the UI foundation for service-driven actions without pretending that unfinished services already exist.

Planned rules:

- Print and Scan appear under `Actions` only when real authenticated implementations/capabilities exist;
- the same principle applies to Storage and other device services;
- Chat is planned as a separate user window, similar to Diagnostics being a separate technical window, rather than a permanently reserved area in the main Files workspace;
- a Chat affordance is added only when a real authenticated messaging service exists.

## Compatibility

- Protocol version remains 3.
- M2.6.2 `GLC1` signed capability advertisement format remains compatible.
- Pairing is unchanged.
- Existing trusted devices do not require re-pairing.
- Existing Device IDs and signing keys remain unchanged.
- Single-file transfer remains compatible with the existing trusted transfer protocol.

## Live validation completed

Real-device testing completed during M2.7 development confirmed:

- true simultaneous Windows → Android trusted sessions;
- true simultaneous Android → Windows trusted sessions;
- three active outgoing slots with immediate refill when one completes;
- successful SHA-256/integrity completion across parallel batches;
- safe failure when a stale/sleeping endpoint does not accept a connection, followed by successful transfer after fresh signed discovery/authenticated contact;
- live authenticated role/profile updates in the UI;
- dynamic role/service/state filters based on what is actually present;
- diagnostics separated from the main UI;
- transfer-history and multi-progress UI behavior under real concurrent load.

No raw live logs are published because they can contain device identifiers, signing-key identifiers, IP addresses and local device names.

## Development status

M2.7 is a development checkpoint in the existing v0.3.1 RC4 line. It is documented through normal commits/PR history and is **not** intended to create a separate GitHub Release or tag.
