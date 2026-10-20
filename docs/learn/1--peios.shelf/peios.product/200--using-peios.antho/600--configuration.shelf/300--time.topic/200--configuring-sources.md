---
title: Configuring Time Sources
type: how-to
description: Choose time sources and check that timed can use them.
related:
  - peios/time/overview
  - peios/time/the-clock-command
  - peios/using-peios/registry/regman
---

Configure time sources when the machine needs a particular operator or a
network's time service. Check the effective sources after applying policy:
a saved setting does not establish synchronization.

## Before you start

- Install and start timed and its `clock` command.
- Obtain write access to `Machine\System\Time` to change policy.
- Obtain timed's control right to request a reload. Registry write access
  and the control right are separate permissions.
- Choose sources with independent failure modes. Prefer authenticated
  sources and check that their certificates cover the configured names.

The regman entry for `Machine\System\Time` owns the complete configuration
reference. `clock(1)` describes the command interface.

## Naming your own servers

1. Inspect the existing state and policy:

   ```sh
   clock status
   clock sources
   reg get Machine/System/Time
   ```

2. Set the source list. This example selects the shipped public operators
   explicitly, so network-provided time servers cannot replace the list:

   ```sh
   reg set Machine/System/Time Servers \
       multi:'time.cloudflare.com,nts.netnod.se,ptbtime1.ptb.de'
   ```

3. Reload and check the result using the procedure below.

An entry names a host, optionally a port, followed by supported option words.
`prefer` breaks ties between agreeing sources. It does not make a disagreeing
source valid. A malformed entry is logged and omitted.

### Precedence is first match, not merge

timed selects the first nonempty list in this order:

1. Successfully parsed `Servers` entries.
2. Network-provided time servers, when `UseFromDHCP` permits them.
3. The shipped fallback set.

The selected list replaces later choices. A domain policy can write
`Servers`; the selector has no separate domain-discovery stage.

Authentication filtering happens after selection. An explicit list containing
only plain-NTP sources produces no usable sources when
`AllowUnauthenticated` is `0`; it does not fall through to public servers.
If every explicit entry is malformed, selection continues to the next list.

To remove an explicit override:

```sh
reg del Machine/System/Time Servers
clock reload
```

This restores the selection order. It does not necessarily select the public
fallbacks because network-provided sources can take precedence.

## Turning authentication off

Plain Network Time Protocol (NTP) does not authenticate replies. Someone who
can observe and alter the exchange can supply false time. Certificate
validation and authentication systems can be affected by an incorrect clock.

For an explicitly configured plain-NTP source, both settings are required:

- The entry includes `unauthenticated` or `noauth`.
- `AllowUnauthenticated` is `1`.

Use this policy only after accepting the trust placed in the server and its
network path. Changing `AllowUnauthenticated` back to `0` excludes all plain
sources, including those explicitly marked unauthenticated.

## DHCP time servers

Dynamic Host Configuration Protocol (DHCP) time servers are eligible when
`UseFromDHCP` is `1` and no valid explicit list takes precedence. They are
plain-NTP sources, so `AllowUnauthenticated` must also be `1`.

Before allowing them, account for every network the machine can join. A
network controls the time-server addresses it offers. This machine-wide
setting follows the machine between networks.

netd publishes DHCP option 42 independently of whether its offered DNS
configuration is accepted. See
[The Resolver Channel](~peios/netd/what-netd-publishes/the-resolver-channel).
timed applies its own time-source policy to that information.

## Poll intervals

`MinPoll` and `MaxPoll` are powers of two seconds. Their defaults are 6 and
10, giving intervals from 64 seconds through about 17 minutes. Values are
clamped to the range documented in regman.

Shorter intervals increase server traffic. Longer intervals help estimate
frequency error. Keep the defaults unless measurements justify a change.

## Doing it from a domain

Distribute time policy through registry policy using the same values. The
policy must still produce sources that pass authentication and selection.
A successful registry update does not establish correct time on each machine.

## Reload and verify

1. Request a reload:

   ```sh
   clock reload
   ```

2. Inspect the source list and clock state:

   ```sh
   clock sources
   clock status
   ```

3. Check the source names, authentication, failure notes, selected source,
   accuracy estimate, and age of the last update. Repeat after further polls
   if the clock is still settling.

A failed configuration read retains the last complete configuration and
returns a reload error. A registry notification triggers another read.
Malformed individual server entries remain warnings and are omitted.
A successful reload means the configuration was read, not that sources have
answered or agreed.

## When something is wrong

A source marked `falseticker` disagrees with the selected set. Investigate
that source and the agreement among the others; the label alone does not
prove which clock is correct. An unreachable source includes a failure note
when timed has one.

If no source is selected, compare `Servers`, `UseFromDHCP`, and
`AllowUnauthenticated` with the reported list. Check whether `Automatic` is
`0`. A wrong local-zone display needs a zone correction, not necessarily a
change of time source.

If reload is refused, check the separate
[control permission](~peios/time/the-clock-command#when-reload-is-refused).
A refused reload does not undo a registry write. If `clock` cannot contact
timed, it has not established whether sources are usable.

## Changing an active source list

Reordering sources preserves each unchanged source's session and pending
work. Removing a source discards results that arrive for that old source.
Changing its port or authentication mode starts a new association. A source
removed and later added again does not inherit an earlier pending result.
