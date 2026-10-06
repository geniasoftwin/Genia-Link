# GNP/1 M2.8.4.5 — Cancel / Retry

**Current tested checkpoint:** v0.3.1 RC4 · M2.8.4.5 Cancel / Retry · physically validated 2026-10-06.

M2.8.4.5 adds explicit, authenticated print-job cancellation and manual retry to the existing trusted GNP/1 print path. The implementation preserves the fail-closed behavior of M2.8.4.4 and does not introduce an unauthenticated listener, cloud path, HTTP endpoint, automatic retry, queue purge, or broad printer mutation.

## Protocol and ownership

- PrintJobCancelRequest = 69 and PrintJobCancelResult = 70 are additive authenticated control messages.
- Cancellation remains bound to the active lifecycle JobId and the authenticated remote DeviceId that owns the job.
- Retry is always explicit and creates a new JobId while reusing the previously selected document and print settings.
- Retry is suppressed when cancellation cannot be confirmed, preventing accidental duplicate printing.

## Cancellation phases

M2.8.4.5 handles cancellation conservatively across the print pipeline:

1. **Before Windows spooler submission** — the job is cancelled locally and staging is cleaned.
2. **During Office preparation** — DOCX/XLSX/PPTX cancellation remains eligible while local conversion/render preparation is still running.
3. **Guaranteed pre-spool window** — after Office preparation completes, a full bounded 3000 ms cancellation window is provided before Windows spooler handoff.
4. **After spooler submission** — cancellation targets only the exact Genia Link job marker/Windows JobId. No queue-wide cancellation is used.
5. **If the exact job can no longer be proven** — cancellation returns not-confirmed and retry is suppressed.

The Windows helper resolves the bounded Genia Link marker, requires exactly one matching spooler job, rechecks the same Windows JobId immediately before cancellation, and fails closed if ownership/correlation is uncertain.

## Physical validation

The Android → trusted Windows Print Gateway → Samsung SCX-4300 path was physically exercised with repeated cancel/retry cycles.

Verified behavior:

- early cancel before spooler handoff on image/JPG/PNG jobs;
- early cancel before spooler handoff on PDF jobs;
- DOCX cancel during Office preparation;
- DOCX cancel inside the post-preparation 3000 ms pre-spool window;
- repeated **Cancel → Retry → Cancel** cycles with preserved print settings;
- normal printing when the cancellation window is allowed to expire;
- late cancellation after the legacy driver has already removed the job from the spooler returns **not confirmed**;
- retry remains disabled after an unconfirmed late cancellation.

The Samsung SCX-4300 remains a useful legacy-driver baseline: it can remove a job from the Windows spooler before physical completion can be proven. M2.8.4.5 therefore keeps the conservative M2.8.4.4 lifecycle semantics and does not synthesize successful physical completion.

## Validation gates

The checkpoint package passed the Windows and Android security/build gates on the target toolchain:

- .NET analyzers with warnings-as-errors;
- protocol/security self-tests;
- zero third-party PackageReference dependency check;
- offline cloud/risky-API static scan;
- M2.8.4.5 Cancel / Retry checks;
- early-cancel UX checks;
- pre-spool cancel-window checks;
- Office preparation-aware cancel checks;
- Android build and Android Cancel / Retry checks.

## Publication boundary

This document records the physically validated development state. The public source tree on main remains the older **v0.3.1 RC4 / GNP/1 M2.6.2** snapshot until a deliberate full source synchronization is prepared and revalidated. The checkpoint is documentation-only and does not partially replace the public source tree.
