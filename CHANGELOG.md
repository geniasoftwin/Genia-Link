## GNP/1 M2.8.4.4 fix23 — physical validation checkpoint — 2026-10-03

- Physically validated Android → trusted Windows PrinterGateway → Samsung SCX-4300 remote printing on the fix23 package.
- M2.8.4.3 TXT printing remains intact, including UTF-8, 8-character monospace TAB stops, wrapping and multi-page pagination.
- Lifecycle monitoring remains conservative: a spooler job disappearing is not treated as proof of physical completion.
- Legacy SCX-4300 testing confirmed that standard System.Printing, Win32 queue/job status and Bidi may expose no paper-feed/jam completion state after the driver hands the job off. The Android UI therefore uses the honest terminal fallback **«Передано принтеру · физический статус принтера недоступен»**.
- fix21 prevents the native `PRINTED + DELETING` combination from being classified as a user cancellation.
- fix23 routes terminal Android transfer/print cleanup through an ordered `TRANSFER_STOP` command owned by the foreground service. Physical testing confirmed that the temporary print/transfer notification is removed after completion while the independent Always Ready notification remains.
- Compact icon/tile print settings are retained for image and Excel options.
- No cloud, HTTP, analytics, third-party package, new unauthenticated listener, printer mutation, Bidi Set, or automatic job cancellation was added.
- Next planned checkpoint: **M2.8.4.5 Cancel / Retry**.
- Additional physical testing on older and newer printer models remains planned.

# Changelog

All notable public source snapshots of Genia Link will be documented here.

## Unreleased

### M2.8.4 Office Document Print Bridge development — 2026-09-27

- Added development support for validated macro-free DOCX/XLSX/PPTX over the existing authenticated print session; no new GNP/1 print message range or unauthenticated listener is introduced.
- Office documents render locally to temporary PDF and then reuse the physically validated Genia Link PDF print renderer.
- Backend preference is Microsoft Office → LibreOffice → Apache OpenOffice.
- The LibreOffice/OpenOffice fallback is restricted to known Program Files `soffice` binaries, structured arguments, `UseShellExecute=false`, headless conversion, isolated per-job user profiles, and a bounded conversion lifetime.
- The compatible-suite fallback is implemented in the development package and still requires build/runtime/physical validation before M2.8.4 is marked passed.
- Public `main` source remains the M2.6.2 snapshot; this changelog entry records development progress only.

### M2.8.3 Windows Remote Print physical validation — 2026-09-27

- Verified Windows → authenticated GNP/1 → Windows Print Gateway → Samsung SCX-4300 physical printing.
- Verified the physical/virtual printer picker path from the Windows client.
- Verified image scaling modes with a calibration image; `ActualSize` produced a measured 50 × 50 mm target and matched direct Windows printing on the same printer.
- Existing M2.7 file-transfer behavior remained functional during the remote-print tests.

### M2.8.2 Print/PDF validation — 2026-09-26

- Development has progressed beyond the public M2.6.2 source snapshot through the M2.7 transfer/resume UX checkpoint and into the M2.8 print-service line.
- Verified physical end-to-end image printing over the trusted GNP/1 path: Android → Windows Print Gateway → Samsung SCX-4300 Series.
- Verified PDF printing over the same authenticated trusted path.
- Corrected PDF page geometry so the physical output scale matches direct Windows printing on the tested printer.
- Print-service discovery keeps `PrinterGateway` as an authenticated capability statement; discovery alone does not imply trust or authorize a print job.
- Printing reuses the existing trusted GNP/1 session rather than opening a separate unauthenticated print service port.
- The public `main` source snapshot still remains M2.6.2 until the newer development source is synchronized and revalidated for publication.
- See `docs/DEVELOPMENT_STATUS.md` for the current checkpoint matrix and publication boundary.

### M2.6.2 Android Keystore validation — 2026-09-18

- Fixed Android ECDSA signing to use the existing non-exportable Android Keystore `PrivateKeyEntry`.
- Confirmed live M2.6.2 signed capability advertisement from Android without legacy GLD2 fallback.
- Confirmed authenticated Android capability acceptance and automatic `Client` profile resolution on Windows.
- Confirmed Windows Server capability revision advertisement is verified on Android.
- Existing Device IDs, pairings and signing-key generations remain unchanged.
- No release or tag is created for this development checkpoint.

## v0.3.1 RC4 / GNP/1 M2.6.2 — 2026-09-16

Initial public source snapshot of Genia Link.

### Highlights

- Windows and Android clients with a shared protocol/core implementation.
- Local IPv4 device discovery and direct device-to-device transfer.
- Explicit SAS pairing and persistent trusted device identity.
- ECDH P-256 key agreement with per-session keys.
- AES-256-GCM protected transfer frames.
- SHA-256 file verification and resumable partial transfers.
- Trusted Identity Registry with signing-key binding and continuity-verified key rotation.
- Replay-hardened signed identity assertions.
- Active / Retired / Revoked trusted-identity lifecycle.
- GNP/1 M2.6.2 authenticated capability advertisement (`GLC1`).
- Automatic role/profile resolution from authenticated capability sets.
- Windows Send To integration and Android share workflow.
- Optional Android Always Ready mode for long-idle availability.
- Offline self-tests and PowerShell security-check scripts included in the source tree.

### Notes

- This is a release-candidate / protocol-development checkpoint, not a stable release.
- The repository is source-available for inspection and is not released under an open-source license.
- No release binaries are included with this source snapshot.
- Protocol, packaging, UI and compatibility details may change before a stable release.

### Documentation

- `docs/GNP1_MILESTONE2_6_2_AUTHENTICATED_CAPABILITIES.md`
- `docs/RC4_FINAL_TEST.md`
- `docs/SECURITY_IMPLEMENTATION.md`
- `docs/PROTOCOL.md`
