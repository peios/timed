---
title: Keeping the time
type: concept
description: Inspect clock status and time sources, choose the right correction, and understand how timed keeps the machine clock.
related:
  - peios/time/configuring-sources
  - peios/time/time-zone-and-setting-the-clock
  - peios/time/the-clock-command
  - peios/trust/overview
---

Start by asking **timed**, the service that keeps the machine's clock,
what it is doing:

```
$ clock status
$ clock sources
```

These commands inspect the clock; they do not change it. In `clock status`,
read **state**, **time zone**, **following**, **accuracy** and the age of the
last update. In `clock sources`, look for a chosen source, contributing
candidates, authentication and any failure notes. [The clock command
reference](~peios/time/the-clock-command) explains each field and the
command's exit statuses.

Choose the next step from what you find:

- **The displayed time is in the wrong zone:** check the effective **time
  zone** before changing the machine clock. The clock runs in UTC; a zone
  changes how programs show it. Follow [the time-zone
  procedure](~peios/time/time-zone-and-setting-the-clock).
- **The machine is unsynchronised or sources are failing:** inspect the
  configured policy and each source's state in [configuring time
  sources](~peios/time/configuring-sources). If status says
  `Automatic is 0: the clock is set by hand`, automatic time is disabled.
- **The state is `settling` or `spike`:** timed is still converging or
  checking a large change. Read the [status
  meanings](~peios/time/the-clock-command#status) before intervening.
- **There is no suitable time server:** use the [manual-time
  procedure](~peios/time/time-zone-and-setting-the-clock#in-a-terminal).
  Check the zone and the consequences of a clock jump first.

After a change, run both inspection commands again. A saved setting or a
successful reload does not by itself establish synchronisation. Check the
effective zone, source list, authentication, state, accuracy and fresh
updates rather than relying only on the displayed wall time.

Setting the clock needs `SeSystemtimePrivilege`. timed's service identity
holds it, and so do Administrators. timed runs from boot and keeps the
clock from network time servers. Changing it behind timed's back can lead
to a correction or a refusal of an excessive offset; see [why not just set
the clock](~peios/time/time-zone-and-setting-the-clock#why-not-just-set-the-clock).
Registry changes and timed control requests have [separate permission
checks](~peios/time/the-clock-command#when-reload-is-refused).

## Why this is worth caring about

A wrong clock does not look like a wrong clock. It looks like:

- certificates that are expired, or not yet valid, and TLS that fails for
  reasons that make no sense;
- Kerberos tickets refused across a domain, because Kerberos treats a
  clock skew as evidence of a replay;
- logs from two machines that cannot be put in order, which is exactly
  when you most need them to be.

So time is not a convenience. It is something several other things quietly
depend on, and an attacker who can move it has more than a wrong clock.

## Sources are not trusted individually

timed compares several servers. Each one reports not just a time but an
*interval* in which it estimates the true time lies, and timed looks for
the largest set of intervals that overlap. A server outside that overlap
is a **falseticker** and is discarded, however confident it sounded.

This can reject a wrong source whose narrow interval disagrees with the
others. It is not a guarantee that the agreeing sources are correct:
shared upstream clocks, operators or network failures can give several
sources the same error. Authentication identifies a source; it does not
prove that source's clock is right.

Configure at least three sources with independent failure modes. With one,
there is nothing to compare it against. With two that disagree, timed
reports itself unsynchronised rather than choosing between them. Three
can let an agreeing, correct majority exclude one wrong source, provided
those assumptions hold. Counting three names alone does not establish
that independence.

## Every source is authenticated

By default timed will not use a source that cannot prove who it is. That
is **NTS** (RFC 8915): a TLS handshake on port 4460 establishes a pair of
keys, and every NTP packet afterwards carries a tag computed with them.
Forging a reply requires the key.

The certificate is validated against [the machine's trust
store](~peios/trust/overview), over trustd's socket — so a certificate
authority you distrust is distrusted here too, immediately, without timed
needing to be restarted.

When timed needs a new NTS handshake, a network that blocks port 4460
prevents that exchange. Cached cookies can avoid a fresh handshake, as
explained below; blocking the port does not by itself mean existing
authenticated time is lost. If no usable sources remain, the machine
reports itself unsynchronised. `AllowUnauthenticated` exists for networks
where that is not acceptable; see [configuring
sources](~peios/time/configuring-sources) for what you give up.

## The default sources

The documented shipped fallback set uses four names in our own zone,
when no earlier [source selection](~peios/time/configuring-sources#precedence-is-first-match-not-merge)
supplies a list:

```
0.time.peios.org    →  time.cloudflare.com
1.time.peios.org    →  nts.netnod.se
2.time.peios.org    →  ptbtime1.ptb.de
3.time.peios.org    →  ptbtime2.ptb.de
```

The list is intended to span three operators in three jurisdictions: a
commercial network, a Swedish national infrastructure operator, and
Germany's national metrology institute. Two of the names are from the
same operator; four names are not four independent sources. Operator
variety reduces a shared failure risk, but is not proof of independent
upstream clocks or correct time. Check `clock sources` for what the
machine actually selected and can reach.

The indirection through `time.peios.org` is deliberate. If an operator
withdraws its service, that is a DNS change rather than a new image for
every machine.

## Two circles, and how they are broken

Both are worth knowing about, because both look like bugs when you meet
them.

**NTS needs TLS; TLS needs a clock.** A machine with a dead RTC battery
may boot reading 1970. Otherwise valid certificates can then appear
"not yet valid", blocking the handshake that would obtain authenticated
time. timed sets a lower bound at **its own build timestamp**, reported as `floor`
in `clock status`. The [clock-step event
reference](~peios/events/timed/timed-clock-stepped) calls this `boot-floor`
and explicitly says the real time is not yet known.

The floor is a bootstrap aid, not current time or a guarantee that TLS
will succeed. A remote server's certificate still has to be valid at the
clock's reading and trusted by the machine. Reachability, authentication
and source agreement still matter, so do not assume the first poll will
fix the clock. If it remains on the floor, inspect the source failure
notes rather than treating the build date as a verified time.

**A fresh handshake needs a clock too.** So the cookies from the last one
are kept under `/var/state/timed`, and a reboot usually needs no handshake
at all. The startup hook establishes a complete protected, inheritable
descriptor before creating the cookie directory: SYSTEM, Administrators and
timed's service SID have access. Inherited public read grants are removed from
the state directory; a Unix mode on a cookie file is not the security boundary.

## Steering, not jumping

Once the time is known, timed **slews** the clock: it changes the rate
slightly so the error is absorbed over the next few minutes. A great deal
of software quietly assumes the clock only goes forwards, and stepping it
backwards breaks timers, file timestamps and anything measuring a
duration.

The documented automatic discipline permits steps in these situations:

- **at startup**, once, however large the correction, when usable sources
  agree;
- **after fifteen minutes of consistent disagreement**, when the offset is
  too large to slew away. Fifteen minutes because a congested network or a
  server having a moment looks exactly like a genuine step until time
  passes, and stepping the clock on a transient is worse than being slow
  to correct a real one.

An offset larger than a thousand seconds appearing *after* the machine was
synchronised is refused outright and logged loudly. A machine that far out
has a problem a time client should not paper over.

Manual sets and the boot floor are also clock steps. Turning automatic
time back on starts the sources afresh and can cause an initial
correction of any size. Plan for that jump before re-enabling it; source
changes and reloads are not a promise of uninterrupted wall-clock time.

Every step is recorded in the event log as a `timed.clock.stepped` event,
with the clock's reading just before and just after it, so a jump in the
times of other records can be explained. Its `operation.name` says which
step it was: `automatic` for timed's own, `manual` for a [clock set by
hand](~peios/time/time-zone-and-setting-the-clock), and `boot-floor` for
the clock raised to the build's timestamp at startup (see [Two circles, and
how they are broken](#two-circles-and-how-they-are-broken)). Its
`subject.token.sid` is whoever acted: the person who asked, for a manual
set, and timed's own service SID for the other two. Slewing is
not recorded. The event is `essential`, so the emission policy cannot
switch it off.

## Learning the crystal

The clock is a crystal running at the wrong rate — consistently wrong, by
some tens of parts per million. timed learns that rate and writes it to
`/var/state/timed/drift`, so the next boot starts with the previously
learned rate rather than learning it entirely from scratch. This can
shorten settling time; it does not guarantee a particular accuracy after
one poll.

The rate estimate also helps when the network goes away. Holdover still
depends on how stable the crystal remains and how accurate that estimate
was. Use the reported state and accuracy rather than assuming a fixed
period of correct time without sources.

## What timed does not do

**It is not a time server.** It listens on no network port and initiates
every conversation it takes part in. Serving time to other machines will
be a separate, unprivileged package — the client holds the dangerous
privilege, and a server is exposed to the whole network and needs no
privilege at all. Keeping them apart is the point.

**It does not touch the hardware clock directly.** Once timed reports the
clock as synchronised, the kernel writes it back to the RTC every eleven
minutes on its own.

**It does not decide how the time is shown.** The clock runs in UTC.
The time zone, `Machine\System\Time TimeZone`, sets the machine's default
local zone; timed copies the chosen zone into `/etc/localtime` as the
default local-zone data. For command-specific UTC or `TZ` choices, see
[the time-zone guide](~peios/time/time-zone-and-setting-the-clock).
