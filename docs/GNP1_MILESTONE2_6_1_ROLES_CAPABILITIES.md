# GNP/1 M2.6.1 — Roles & Capabilities Foundation

## Goal

M2.6.1 adds a local, persistent device-role profile above the completed M2.5 trusted identity state model. Roles do **not** create a new identity and do not alter Device ID, ECDH pairing trust, ECDSA signing identity, key generation, TrustRelationshipId, lifecycle state or M2.5.3 IdentityRevision.

The model is deliberately split into:

- **Role profile** — a user-facing preset such as Client, Server, Relay or Backup.
- **Capability set** — explicit functions required/recommended by that profile.
- **Dependencies** — capabilities that cannot be disabled while a role requires them.

## Profiles

### Client

Required:
- Trusted Discovery
- Trusted Transport

Preset also enables:
- File Transfer
- Shared Resources

### Server

Required:
- Trusted Discovery
- Trusted Transport
- Background Availability

Preset also enables:
- File Transfer
- Shared Resources
- Network Events
- Genia Sync

`Network Events` and `Genia Sync` are configuration foundations in this checkpoint; their network services are intentionally not activated yet.

### Relay

Required:
- Trusted Discovery
- Trusted Transport
- Background Availability
- Relay

The actual relay-routing protocol is a later checkpoint.

### Backup

Required:
- Trusted Discovery
- Trusted Transport
- Background Availability
- Backup

Preset also enables File Transfer and Genia Sync. The backup service/protocol is a later checkpoint.

### Custom

The user can select the optional capability set manually, but Trusted Discovery and Trusted Transport remain mandatory GNP/1 core dependencies.

## Persistence and migration

Windows stores the selected `DeviceRoleProfile` and `DeviceCapability` flags in the existing bounded `settings.json`. Existing settings from M2.5.3 have no role fields; a missing/zero capability set migrates safely to the Client preset. Unknown role values normalize to Client and unknown capability bits are stripped.

Selecting an infrastructure profile (Server, Relay, Backup) also proposes Windows autostart + minimized startup. These ordinary Windows startup settings remain user-adjustable in M2.6.1.

## Security boundaries

M2.6.1 is intentionally **local configuration only**:

- roles/capabilities are not yet advertised over discovery;
- a peer cannot grant itself permissions by selecting a role;
- role changes do not mutate trusted identity state;
- lifecycle `Active / Retired / Revoked` remains authoritative for whether an identity may participate;
- protected administrative capabilities/password authorization are future M2.6 checkpoints.

This avoids conflating a self-declared service role with network authorization.

## Acceptance test

1. Upgrade an existing M2.5.3 Windows node without deleting app data.
2. Confirm normal trusted discovery and transfers still work.
3. Open Settings → Role and functions; existing installation should be Client with core + File Transfer + Shared Resources.
4. Select Server. Required Background Availability becomes checked/locked; Network Events and Sync are selected by the preset; Windows autostart/minimized startup are proposed.
5. Save and restart. Startup log must restore `Server` and the persisted capability set without new pairing or identity revision changes.
6. Return to Client and verify Device ID, signing key/generation, trusted peers and M2.5.3 rename state are unchanged.
