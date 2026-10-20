---
title: Keeping the Time
type: concept
description: How timed obtains authenticated time and corrects the machine clock.
related:
  - peios/time/configuring-sources
  - peios/time/time-zone-and-setting-the-clock
  - peios/time/the-clock-command
  - peios/trust/overview
---

timed keeps the machine clock aligned with network time sources. Certificate
validation, authentication, and the ordering of records depend on that clock.
A time zone changes how programs display time; it does not correct the clock.

The service compares measurements from several sources, rejects conflicting
measurements, and adjusts the clock's rate. Its reported accuracy estimates
uncertainty from those measurements. It is not independent proof of the time.

## Sources are not trusted individually

Each server supplies an interval in which it estimates the true time lies.
timed selects an overlapping set and rejects sources outside that agreement.
A rejected source is called a **falseticker**.

Three sources with independent failure modes can let an agreeing majority
exclude one incorrect source. One source has no independent comparison. Two
disagreeing sources do not establish which one is correct. Several names
can still share an operator, upstream clock, or network failure.

Authentication proves the identity of a source. It does not prove that the
source reports the correct time.

## Every source is authenticated

By default, timed requires Network Time Security (NTS). A Transport Layer
Security (TLS) exchange on port 4460 establishes keys for authenticated
Network Time Protocol (NTP) messages.

timed checks the certificate against the **configured server name**, using
roots supplied by [trustd](~peios/trust/overview) for server authentication.
A DNS alias can change the address used for the connection; it cannot choose
a different trusted certificate identity.

Roots are loaded at startup and refreshed after handshake failures. timed
does not subscribe to trust-store changes. A distrust change therefore does
not immediately invalidate an established NTS session or its cached cookies.

A blocked key-exchange port prevents new handshakes. Cached cookies can keep
an existing source usable without another handshake. If no usable source
remains, timed reports that the clock is unsynchronized. Allowing plain NTP
is an explicit policy choice described in
[Configuring Time Sources](~peios/time/configuring-sources).

## The default sources

When neither configured sources nor eligible network-provided sources supply
a list, timed uses these operator hostnames:

- `time.cloudflare.com`
- `nts.netnod.se`
- `ptbtime1.ptb.de`

These names identify three operators. They do not guarantee independent
upstream clocks, reachability, or correct time. Replacing a fallback operator
requires a configuration or software update; changing a Peios DNS alias does
not change the authenticated identity.

## Two circles, and how they are broken

A machine with an incorrect hardware clock can reject valid certificates
as not yet valid. timed raises a clock below its recorded build epoch to
that lower bound. The epoch is stored in the source tree so that rebuilding
the same source does not change the bound.

The floor is a bootstrap aid, not verified time. Certificates still have to
be valid at the resulting clock reading. A machine can remain unable to
complete a handshake after the floor is applied.

NTS cookies from successful exchanges are saved under `/var/state/timed`.
They can let a restarted service obtain authenticated time before another
TLS exchange. The startup hook protects this state for SYSTEM,
Administrators, and timed's service identity. Cookie files contain secrets.

## Steering, not jumping

Ordinary correction changes the clock's rate gradually, called **slewing**.
A clock step changes the wall-clock reading immediately and can affect
file timestamps, log ordering, and software that uses wall-clock deadlines.

The automatic discipline permits an initial correction of any size when
usable sources agree. After synchronization, a persistent large offset can
cause a step after 15 minutes. An offset above 1000 seconds is refused rather
than automatically accepted after synchronization.

Manual changes and the boot floor also step the clock. Turning automatic
time back on restarts source acquisition and permits another initial
correction. A reload is not a guarantee of uninterrupted wall-clock time.

Each step emits `timed.clock.stepped`. Its `operation.name` distinguishes
`automatic`, `manual`, and `boot-floor`. See the
installed `evman timed.clock.stepped` definition and the
`timed.clock.stepped` evman entry for the recorded fields. Slewing does not
emit a step event.

## Learning the crystal

timed estimates the machine clock's frequency error and saves it in
`/var/state/timed/drift`. Reusing that estimate can shorten settling after a
restart. Accuracy without network measurements depends on the clock's
stability and the quality of the saved estimate.

## What timed does not do

timed is a client, not a network time server. It does not serve time to
other machines or directly write the hardware clock. The kernel periodically
updates the hardware clock when the system clock is marked synchronized.

The machine clock represents UTC. timed applies the selected local-zone data
to `/etc/localtime`; individual programs can choose a different display zone.
See [Changing the Time Zone and
Clock](~peios/time/time-zone-and-setting-the-clock)
for the distinction and the operational checks.
