---
title: Configuring time sources
type: how-to
description: Inspect effective time sources, choose and apply source policy, and verify synchronisation without hiding authentication or clock-jump risks.
related:
  - peios/time/overview
  - peios/time/the-clock-command
  - peios/registry-administration/regman
---

Inspect the clock and the sources before changing policy:

```
$ clock status
$ clock sources
$ reg get Machine/System/Time
```

`clock` shows timed's current state; [reg get](~peios/registry-administration/reg)
reads the effective registry values. Check
`Automatic`, `Servers`, `AllowUnauthenticated` and `UseFromDHCP` against the
sources actually shown. If status says
`Automatic is 0: the clock is set by hand`, follow [the manual and automatic
time procedure](~peios/time/time-zone-and-setting-the-clock#in-a-terminal)
before expecting source updates. A wrong displayed zone is a [time-zone
setting](~peios/time/time-zone-and-setting-the-clock), not by itself a
reason to replace sources.

Everything about where a machine gets its time is under
`Machine\System\Time`. There is no configuration file, and `clock` writes
no policy. Change it with `reg`, or System Settings' **Time Servers** group
in **Time & Date**, which writes the same values.

Policy changes need registry write access to `Machine\System\Time`.
`clock reload` and `clock set` separately need the control right on timed's
control object. Having one does not imply the other; see [when reload is
refused](~peios/time/the-clock-command#when-reload-is-refused). Inspection
through `clock` is available to everyone under the default descriptor.

## When something is wrong

```
$ clock sources
  source                   state        auth   str reach     offset     delay     last
* 0.time.peios.org         system-peer  nts      3   377   -1.204ms   14.2ms       31s
+ 1.time.peios.org         candidate    nts      2   377   -0.918ms   22.7ms       44s
x 2.time.peios.org         falseticker  nts      2   377   +4.102s    18.1ms       12s
  3.time.peios.org         unreachable  nts     16     0       +0ns       0ns         -
    NTS-KE failed: connecting to 192.0.2.9:4460: Connection refused
```

- `falseticker` — this server disagrees with the others. Investigate it
  and the agreement among the other sources; disagreement is not by itself
  proof of which clock is correct.
- `unreachable` — no reply for eight polls. The note says why.
- `reach` is the last eight polls in octal, newest in the low bit:
  `377` is eight for eight, `376` means the newest poll was missed, and
  `0` means no replies in that window.

In the example, the final source failed to connect for NTS key exchange on
port 4460. Investigate the reported failure before changing authentication
policy. A source missing from the list may have a malformed configuration
entry; check the log for a warning. [The clock
reference](~peios/time/the-clock-command#sources) describes the other
states, authentication, poll history and failure notes.

If `clock` cannot reach timed, the command failed to inspect the clock;
that is different from a successful query reporting no usable sources.
Keep the error and check the [exit
status](~peios/time/the-clock-command#exit-statuses) before deciding what
to change.

## Naming your own servers

Each entry is a host, optionally `host:port`, optionally followed by
option words:

| Option | Meaning |
|---|---|
| `prefer` | Lead with this one when several agree. |
| `unauthenticated` (or `noauth`) | This source speaks plain NTP, not NTS. |

`prefer` breaks ties and nothing more. A preferred source that disagrees
with the majority is still discarded — a preference is a statement about
which server to lean on, not a licence to be wrong.

A misspelled option is an error and the entry is ignored with a warning in
the log, rather than silently doing nothing. `clock sources` will show the
entry missing.

> [!IMPORTANT]
> **Name at least three, with independent failure modes.** One source has
> nothing to check it against. Two that disagree cannot be told apart, and
> the machine reports itself unsynchronised rather than picking one.
> Three can reject one wrong source when the other two are correct and
> agree; names alone do not guarantee independent or correct clocks.

Choose NTS-capable servers unless you have deliberately accepted the
tradeoff in [turning authentication off](#turning-authentication-off).
Source changes affect future corrections, so plan for their effect on
work that depends on timestamps. A successful reload does not guarantee
that the clock will only slew; see [steering, not
jumping](~peios/time/overview#steering-not-jumping).

For example, to replace the source list with three servers you operate,
pass `multi:` one comma-separated data token, as in [reg's value
syntax](~peios/registry-administration/reg#value-literals-and-types):

```
$ reg set Machine/System/Time Servers multi:'dc01.corp.example,dc02.corp.example,ntp3.corp.example'
$ clock reload
```

### Precedence is first match, not merge

```
Servers  →  DHCP, if enabled and offered  →  the shipped fallback set
```

That is the selection order in the inspected
[timed 0.1.10 source](https://github.com/peios/timed/blob/c1db503a60108542c8586c574802e5f2339dbcb4/timed/src/main.rs#L367-L402).
A separate domain-discovery tier is mentioned as a future version in its
configuration comments; it is not implemented in this selector. A domain
policy that writes `Servers` still takes effect as registry configuration.
This is a pinned source finding, not verification of an installed image.

The first nonempty list is the *whole* list. `Servers` means entries that
parsed successfully; if all are malformed, there is no explicit list and
selection continues. A valid explicit list replaces the fallback set.
Authentication filtering happens after selection: if the selected list
contains only plain-NTP sources and `AllowUnauthenticated` is `0`, those
sources are excluded without falling through to public NTS servers.

To remove an explicit override, delete the value. This restores selection
by the chain above: DHCP can take precedence when enabled and offered, and
the shipped fallback is used only if no earlier choice supplies a list.
Deletion does not necessarily select public servers:

```
$ reg del Machine/System/Time Servers
$ clock reload
```

## Turning authentication off

`AllowUnauthenticated` is `0` by default: a source must prove who it is or
it is not used.

What you give up is worth being clear about. Without NTS, the only thing
standing between you and a forged reply is that the server must echo the
exact 64 bits timed put in its request — a random number, so an attacker
who cannot *see* the request cannot guess it. An attacker who can see it
can forge freely and move your clock wherever they like.

The reason to think twice is that a wrong clock is not a self-contained
problem: certificate validity, Kerberos, and the ordering of your logs all
rest on it.

Reasonable uses: an isolated network with its own stratum-1 appliance; a
lab; a machine behind a firewall that blocks port 4460 where you control
the path anyway.

For an explicitly configured plain-NTP source, both the per-source
`unauthenticated` (or `noauth`) word and the machine-wide
`AllowUnauthenticated` value are needed. The word identifies the plain
source; the value permits its use. Setting `AllowUnauthenticated` back to
`0` excludes all unauthenticated sources, including per-source exceptions;
it does not disable authenticated sources.

The following example replaces the entire source list with **one**
unauthenticated server. Use it only if that is the intended policy; it
provides no comparison against independent sources:

```
$ reg set Machine/System/Time AllowUnauthenticated dword:1
$ reg set Machine/System/Time Servers multi:'ntp.lan unauthenticated'
$ clock reload
```

## DHCP time servers

`UseFromDHCP` is `0` by default, as on Windows. DHCP sources are eligible
only when no successfully parsed explicit `Servers` list supplies names,
according to the source-qualified precedence above. They are unauthenticated, so they also
require `AllowUnauthenticated` to be `1`. Enabling `UseFromDHCP` alone does
not meet that authentication policy.

Before enabling this, decide whether you trust the network's time
servers. On a network you do not control, a DHCP server can offer an
attacker's time source. The setting follows the machine to other networks;
it is most appropriate for a machine that only attaches to networks you
run. The [authentication tradeoff](#turning-authentication-off) applies.

```
$ reg set Machine/System/Time UseFromDHCP dword:1
```

This changes eligibility; it does not override a valid `Servers` list,
enable unauthenticated time by itself, or prove DHCP offered a usable
source. [netd's resolver
channel](~peios/netd/what-netd-publishes/the-resolver-channel) reports DHCP
option 42 time servers independently of `Dns.Offered`; timed decides
whether to use them under its own policy. Reload after the intended
policy changes and verify the selected list and `auth` column. Do not
delete a working explicit list merely to make DHCP take precedence.

## Poll intervals

```
MinPoll   default 6    64 seconds
MaxPoll   default 10   about 17 minutes
```

Both are powers of two seconds, and both are clamped to the range 4 to 17.
timed lengthens the interval towards `MaxPoll` while the clock is being
held steadily and shortens it when the offset starts moving.

There is rarely a reason to change either. Lowering `MinPoll` makes
recovery from a disturbance faster and costs the servers more traffic; a
long interval measures the crystal's *rate* better than a short one
measures its phase, and it is the rate estimate that holds the clock right
between polls anyway.

The floor of 4 is not negotiable. A configuration error must not be able
to turn a machine into a nuisance at somebody else's public server.

## Doing it from a domain

Every value here is an ordinary registry write, so distributing time
policy to a fleet is an ordinary policy push. There is no separate
mechanism and nothing timed-specific to learn.

## Reload and verify

After the intended registry changes, ask timed to reread them and inspect
the result:

```
$ clock reload
$ clock status
$ clock sources
```

Check that the expected sources are present, their authentication matches
the policy, and the failure notes are resolved. Then check the state,
following source, accuracy and age of the last update. `settling` can be
normal while the frequency estimate converges; inspect again as polls
arrive rather than treating a successful reload as synchronisation.

If reload is refused, preserve the exact error and check the separate
[control permission](~peios/time/the-clock-command#when-reload-is-refused).
Do not assume a failed reload undid a registry write. If sources are
missing or still rejected, return to [when something is
wrong](#when-something-is-wrong) and compare stored policy with timed's
reported state before making another change.
