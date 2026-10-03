# GNP/1 M2.8.4.4 — Print Job Lifecycle / Error Recovery

**Current tested checkpoint:** v0.3.1 RC4 · fix23 · physically validated 2026-10-03.

M2.8.4.4 extends the authenticated M2.8 print path with bounded, opt-in lifecycle status. It does not add a listener, cloud service, HTTP endpoint, shell print handler, or automatic printer control.

## Protocol and compatibility

- `PrintJobStatus = 67` carries bounded lifecycle state/message/page counters.
- `PrintJobOfferV5 = 68` explicitly opts an updated client into lifecycle frames.
- Older V1–V4 behavior remains available through negotiation fallback; updated clients do not require old gateways to understand V5.
- Trusted GNP/1 authentication, PrinterGateway capability enforcement, SHA-256 staging and the 50 MiB print-job limit remain in force.

Normalized lifecycle states are `Queued`, `Spooling`, `Printing`, `Paused`, `AttentionRequired`, `Completed`, `Cancelled`, `Failed`, and `Unknown`.

## Read-only Windows observation

The gateway correlates each lifecycle-aware spooler job with a bounded `[GL-xxxxxxxx]` marker and observes status through multiple local read-only channels:

- System.Printing queue/job state;
- Win32 `GetPrinter(PRINTER_INFO_6)`;
- bounded `EnumJobs` level 2;
- `FindFirstPrinterChangeNotification` / `FindNextPrinterChangeNotification`;
- bounded Windows Bidi status probing for documented printer State / StateReason when the installed provider supports it.

No Bidi `Set`, `SetPrinter`, `SetJob` or automatic cancellation is used by M2.8.4.4.

## Conservative completion semantics

A job disappearing from the Windows spooler is **not** proof that paper was physically printed. After handoff, Genia Link performs a bounded post-spool observation window. If Windows/driver exposes no explicit physical completion or fault, the client uses the user-facing fallback:

**Передано принтеру · физический статус принтера недоступен**

Raw diagnostics remain in the diagnostic log instead of being copied into the normal status card.

fix21 also corrects native job-status precedence: `PRINTED + DELETING` is treated as a driver/spooler teardown combination rather than evidence that the user pressed Cancel.

## Android foreground notification — fix23

Terminal transfer/print cleanup is ordered through an explicit `TRANSFER_STOP` service command after `TRANSFER_START`. The foreground service that owns notification 47500 performs `StopForeground(Remove)`, explicit notification cancellation and `StopSelfResult(startId)`; `OnDestroy` repeats idempotent cleanup as a final safety net.

Physical testing confirmed that the temporary **«Отправка файла / Печать…»** notification disappears after the terminal print result. The separate Always Ready notification **«Genia Link · Готов к приёму»** remains intentionally active.

## Physical Samsung SCX-4300 checkpoint

The Android → trusted Windows gateway → Samsung SCX-4300 path has been physically exercised with successful printing and with a paper-feed failure.

The legacy driver can remove the spooler job while the device still cannot physically feed paper, while System.Printing/Win32/Bidi expose no reliable paper-out/jam completion signal. This is recorded as a driver/device reporting limitation, not as print success. Genia Link therefore keeps the conservative physical-status fallback instead of synthesizing `Completed`.

M2.8.4.3 TXT printing remains physically validated with UTF-8, real TAB stops, wrapping and multi-page pagination. Image/PDF/Office paths and the compact icon/tile print settings remain part of the current development package.

## Next checkpoint

**M2.8.4.5 Cancel / Retry**: explicit user cancellation and convenient retry while preserving the selected document and print settings. Additional physical compatibility testing on older and newer printer models is planned.
