---
title: Understanding Clock Status
type: concept
description: Interpret timed's state, source selection, and accuracy estimates.
related:
  - peios/time/overview
  - peios/time/configuring-sources
  - peios/time/time-zone-and-setting-the-clock
---

`clock` reports what timed knows about the machine's time. Its status and
source views help distinguish a display-zone problem from a failure to obtain
usable time. `clock(1)` owns the command syntax and exit-status reference.

## Status

Read `clock status` starting with **state**, **following**, **accuracy**, and
the age of the last update. The state labels retain their wire spelling:

| State | Meaning |
|---|---|
| `synchronised` | The clock is being kept from usable measurements. |
| `settling` | The frequency estimate is still converging. |
| `spike` | A large offset is being checked before changing the clock. |
| `unsynchronised` | The clock has no accepted synchronization. |

Manual operation adds `Automatic is 0: the clock is set by hand`. That is
not evidence of network synchronization.

**Accuracy** combines uncertainty reported by the selected measurements.
It helps assess clock quality, but does not independently prove the time.
**Frequency** estimates the hardware clock's error in parts per million.
The saved drift estimate lets later starts reuse what timed has learned.

**Stepped** records cumulative steps since startup. Unexpected changes call
for inspection of `timed.clock.stepped` events. Manual changes, automatic
corrections, and the boot floor have distinct operation names.

**Floor** is the recorded build epoch, used as a lower bound. Remaining near
the floor does not establish correct time or certificate validity.

**Time zone** is timed's recorded zone for `/etc/localtime`. An unidentified
file is displayed as `UTC (none chosen)`. A failed copy can also leave the
reported name without valid corresponding data. Resolve errors using the
[zone procedure](~peios/time/time-zone-and-setting-the-clock#in-a-terminal).

## Sources

`clock sources` shows each source's state, authentication, reach history,
measurements, and age. The leading markers summarize selection:

| Mark | State | Meaning |
|---|---|---|
| `*` | `system-peer` | Selected source for the system's reference figures. |
| `+` | `candidate` | Agrees and contributes to the combined measurement. |
| `-` | `outlier` | Agrees but is excluded because of measurement quality. |
| `x` | `falseticker` | Disagrees with the selected set. |
| `?` | `unusable` | Has answered but cannot supply usable time. |
| blank | `unreachable` | Has no usable reply history. |

**Auth** distinguishes authenticated NTS from plain time. **Reach** is an
octal mask of the last eight polls, newest in the lowest bit. `377` means
all eight answered; `376` means the latest poll failed; `0` means none
answered. Stale measurements stop contributing when reach is lost.

**Last** is the age of the last answer. Read any note below a source before
changing policy: a connection failure and a certificate failure need
different investigation.

## Setting the clock

`clock set` requests a coordinated manual step. It requires manual mode and
timed's control right. The
[manual-time
procedure](~peios/time/time-zone-and-setting-the-clock#in-a-terminal)
covers prerequisites, local-zone interpretation, and checks afterward.

## Exit statuses

An unsuccessful query does not establish the state of the clock. In
particular, a failed connection differs from a successful source query
finding no sources. Scripts should use the exit statuses documented in
`clock(1)` instead of inferring success from partial output.

## When reload is refused

Reloading and setting time require timed's control right. Querying status
and sources is public under the default policy. The control descriptor is
`Machine\System\Time ControlSecurity`; SYSTEM and Administrators receive
control access by default.

Registry write access is a separate check. A successful policy write does
not prove that the caller can reload, and a refused reload does not undo
the write. A configuration-read failure also makes reload fail while timed
retains its last complete configuration.
