---
title: The clock command
type: reference
description: Every verb of the clock command, what each field of its output means, and what its exit statuses tell a script.
related:
  - peios/time/overview
  - peios/time/configuring-sources
  - peios/time/time-zone-and-setting-the-clock
---

`clock` reads over timed's socket and prints. It **writes no policy** —
time policy is registry configuration, and `reg` is how a registry value is
set. Registry writes and timed's control requests have separate access
checks. The two verbs that act are `reload`, and `set`, which asks timed
to set the clock while it isn't being set automatically; see [when reload
is refused](#when-reload-is-refused).

It is called `clock` and not `time` because `time` is a shell keyword:
`time status` would run `status` and report how long it took.

## Verbs

| Command | Reads | Acts |
|---|---|---|
| `clock status` | socket | — |
| `clock sources` | socket | — |
| `clock reload` | — | asks timed to re-read `Machine\System\Time` |
| `clock set TIME` | — | asks timed to set the clock, while `Automatic` is 0 |

`status` is the default, so bare `clock` is `clock status`.

## Status

```
$ clock status
generation   118
time zone    Europe/London
state        synchronised
following    1.time.peios.org (stratum 3)
offset       -412.0us
frequency    -12.750 ppm
jitter       +180.3us
accuracy     within 31.4ms
  root delay      28.2ms
  root dispersion 4.10ms
sources      4 configured, 3 contributing
updates      118 (last 22s ago)
stepped      +2.1d in total since start
floor        1788142329 (the build timestamp; the clock is never set below it)
```

**time zone** is the name timed has recorded for `/etc/localtime`. In the
inspected timed 0.1.10 source, [restart identification](https://github.com/peios/timed/blob/c1db503a60108542c8586c574802e5f2339dbcb4/timed/src/localtime.rs#L94-L118)
requires the saved name and zone data to match that file. If identification
fails, the [command prints `UTC (none chosen)`](https://github.com/peios/timed/blob/c1db503a60108542c8586c574802e5f2339dbcb4/clock/src/main.rs#L140-L144)
even though the file may contain another zone. A later successful apply
restores the reported name. After a copy failure, the retained name is not
a fresh verification of the file either. Check timed's log and the
[time-zone procedure](~peios/time/time-zone-and-setting-the-clock#in-a-terminal)
before relying on an unexpected display. This is source inspection, not
installed-image validation.

**state** is the field to read first:

| State | Meaning |
|---|---|
| `synchronised` | Normal. |
| `settling` | Being steered, but the frequency estimate is still converging. Usual for the first few minutes after boot. |
| `spike` | A large offset has appeared and is being timed to see whether it is real. The clock is deliberately untouched meanwhile. |
| `unsynchronised` | Nothing is believed and the clock is free-running. With `Automatic is 0: the clock is set by hand` after it, nothing is being asked: the clock is set by hand. |

**accuracy** is timed's estimate of how wrong this machine's time might
be, combining the reported uncertainties between here and the reference
clock. Check it when investigating Kerberos clock skew. It depends on the
source measurements and is not independent proof that the time is right.

**frequency** is what the crystal is doing, in parts per million, and it is
persistent — it is written to `/var/state/timed/drift` and read back at the
next boot. Tens of ppm is an ordinary machine. Approaching ±500 means the
hardware is at the edge of what the discipline can correct.

**stepped** can be non-zero after a boot on a machine whose clock was
wrong. Later growth means there have been further steps; check whether
these followed a manual set or re-enabling automatic time. Unexpected or
repeated growth warrants investigation. The [clock-step event
reference](~peios/events/timed/timed-clock-stepped) explains how to tell
manual, automatic and boot-floor steps apart.

**floor** is the build timestamp, the lower bound timed will use. If the
clock remains there after boot, it may not yet have acquired real time.
The floor does not establish synchronisation or guarantee a successful
TLS handshake; inspect the source notes and see [the bootstrap
explanation](~peios/time/overview).

## Sources

```
$ clock sources
  source                   state        auth   str reach     offset     delay     last
* 1.time.peios.org         system-peer  nts      2   377   -0.918ms   22.7ms       44s
+ 0.time.peios.org         candidate    nts      3   377   -1.204ms   14.2ms       31s
- 3.time.peios.org         outlier      nts      2   377   +8.221ms   61.0ms       58s
x 2.time.peios.org         falseticker  nts      2   377   +4.102s    18.1ms       12s

* system peer  + candidate  - outlier  x falseticker  ? unusable
```

| Mark | State | Meaning |
|---|---|---|
| `*` | `system-peer` | Chosen. The machine takes its stratum and root figures from this one. |
| `+` | `candidate` | Agrees with the majority and contributes to the combined answer. |
| `-` | `outlier` | Agrees, but too noisy to be worth including. |
| `x` | `falseticker` | **Disagrees with the majority.** Go and look at this one. |
| `?` | `unusable` | Answering, but saying it is not synchronised itself. |
| ` ` | `unreachable` | Not answering. |

**auth** is `nts` or `none`. `none` means anyone on the path can forge that
source's replies.

**reach** is the last eight polls as an octal bitmask, newest in the low
bit — the classic NTP display. `377` is eight for eight; `376` means the
most recent poll was missed; `0` means nothing for eight polls, at which
point the source's stored measurements are discarded rather than left to
vote with stale numbers.

**last** is how long ago the source answered. It exceeding the poll
interval by much is the first sign of trouble.

A source that is not contributing prints a note underneath saying why.

## Setting the clock

```
$ clock set 2026-10-04 14:05
the clock is set
$ clock set 2026-10-04T14:05:30
$ clock set @1791122700
```

The time is local, in the machine's time zone, to the minute or the
second, or `@` and a number of seconds since 1970 in UTC. timed sets the
clock only while `Machine\System\Time Automatic` is 0; otherwise it keeps
the clock from its sources, the next poll would put it back, and it
refuses:

```
$ clock set 2026-10-04 14:05
clock: the clock is kept from its sources; set Automatic to 0 to set it by hand
```

Like `reload`, it needs the control right. Changing `Automatic` needs
registry write access separately. A manual set jumps the clock and changes
the basis of later timestamps. Check the zone and plan for that jump
before setting it, then inspect `clock status`; see [the complete
procedure](~peios/time/time-zone-and-setting-the-clock#in-a-terminal).

## Exit statuses

| Status | Meaning |
|---|---|
| `0` | Done. |
| `2` | Asked about something that is not there — no sources are configured. |
| `1` | It went wrong: timed is unreachable, or refused. |
| `64` | The command line was not understood. |

The separation of `2` from `1` is what lets a script tell "this machine has
no time sources" from "I could not find out".

## When reload is refused

```
$ clock reload
clock: not permitted
```

`reload` and `set` need the control right on timed's control object.
Reading does not: what time the machine thinks it is, and how well it knows, is not a
secret, and a program deciding whether the clock is trustworthy enough to
validate a certificate should not need a privilege to find out.

The descriptor is `Machine\System\Time ControlSecurity`; by default SYSTEM
and Administrators may control, and everybody may query. This is distinct
from write access to the registry key: a successful policy write does not
prove that the caller may reload or set the clock, and a refused reload
does not undo that write.
