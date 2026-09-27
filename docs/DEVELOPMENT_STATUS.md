# Genia Link Development Status

_Last updated: 2026-09-27_

This page separates the **public source snapshot currently stored on `main`** from newer development packages that are still being validated before source synchronization.

## Public source snapshot

The current public source snapshot on `main` is:

**v0.3.1 RC4 / GNP/1 M2.6.2 — Authenticated Capabilities**

It includes trusted device identity, authenticated capability advertisement, local-only encrypted transfer, resumable transfers, Windows/Android clients, and the security/self-test tooling documented in this repository.

## Current development progress

The active development line has advanced beyond the public M2.6.2 snapshot.

| Milestone | Status | Verified behavior |
| --- | --- | --- |
| GNP/1 M2.7 | Development checkpoint completed | Large-batch scheduling, concurrent trusted transfer handling, resume/history UX and related stability fixes |
| GNP/1 M2.8.1 | Physical end-to-end test passed | Android → authenticated GNP/1 session → Windows Print Gateway → physical printer |
| GNP/1 M2.8.2 | Physical PDF test passed | PDF sent from Android through the trusted Windows Print Gateway and printed on a Samsung SCX-4300 Series |
| M2.8.2 PDF scaling fix | Verified | PDF physical scale now matches printing the same PDF directly from Windows on the tested printer |
| GNP/1 M2.8.3 | Physical end-to-end test passed | Windows → authenticated GNP/1 → Windows Print Gateway → Samsung SCX-4300; image ActualSize also matched a 50 × 50 mm calibration target and direct Windows printing |
| GNP/1 M2.8.4 | Implemented; validation in progress | Macro-free DOCX/XLSX/PPTX → local PDF → verified PDF renderer, with Microsoft Office → LibreOffice → Apache OpenOffice backend preference |

## Print Service security model

The printing path is intentionally built on the existing Genia Link trust model:

- No separate unauthenticated print port is introduced.
- `PrinterGateway` is an authenticated capability advertisement; seeing it during discovery does not by itself authorize printing.
- Printer discovery and print-job submission use an authenticated trusted GNP/1 session.
- Windows remains the print gateway and uses the locally installed Windows printer/driver stack.
- The tested path remains local-network-first; no Genia Link cloud relay is required for the print job.

## Current print scope

The development print path currently covers:

- JPEG/PNG image printing through a trusted Windows Print Gateway.
- PDF printing through the same trusted path.
- Real Windows printer enumeration, including physical and virtual printers.
- PDF page-size handling corrected so the physical output scale matches direct Windows printing on the tested device.
- Windows Remote Print Client physically verified through a second trusted Windows Print Gateway.
- Image scaling modes `Fit / ActualSize / Fill` physically verified; `ActualSize` produced an exact 50 × 50 mm calibration square on the tested printer.
- Office-document development path for macro-free DOCX/XLSX/PPTX renders locally to PDF. Microsoft Office is preferred; LibreOffice and Apache OpenOffice are available as tightly scoped local fallbacks from known Program Files locations.

The M2.8.4 compatible-suite fallback is implemented in the local development package and is awaiting build/runtime/physical validation.

## Planned next steps

Near-term work includes:

1. Complete M2.8.4 build/runtime validation with Microsoft Office and at least one compatible-suite fallback (LibreOffice/OpenOffice).
2. Physically compare DOCX/XLSX/PPTX output against direct local printing on the same printer.
3. Continue keeping printing additive to the existing trusted transport rather than weakening discovery, pairing, identity, or transfer security.
4. After the print branch is stable, prepare the next public source synchronization beyond M2.6.2.

## Publication note

The milestones above describe **validated development progress**, not a claim that the corresponding M2.7/M2.8 source has already been synchronized to the public `main` branch.

When that source synchronization is ready, the public snapshot/version references in the README and changelog will be advanced together.
