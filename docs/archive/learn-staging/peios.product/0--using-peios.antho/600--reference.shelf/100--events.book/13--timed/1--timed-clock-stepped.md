---
title: "timed.clock.stepped"
description: "timed moved the system clock at once by an arbitrary amount, rather than adjusting its rate."
---

- **Event type:** `timed.clock.stepped`
- **Defined in:** `timed.evman`
- **Tier:** essential
- **Gating:** none — every step timed makes is recorded
- **Cardinality:** one record per occurrence

timed moved the system clock at once by an arbitrary amount, rather than
adjusting its rate. Every timestamp written after this record is on the new
clock, including the times of every other event in the store, so this is
the record that explains a jump in them.

timed slews small errors by adjusting the clock's rate after each poll, and
those corrections are not recorded. Only a step is.

## Fields

| Field | Type | Presence | Meaning |
|---|---|---|---|
| [`operation.name`](~peios/events/field-index/fields-operation#operation.name) | `str.enum` | required | Why timed stepped the clock. `automatic` is its own decision: its sources agreed the clock was further off than it is willing to slew. `manual` is a request on its control socket (`clock set`), which timed accepts only while `Automatic` is 0. `boot-floor` is the clock raised to the build's timestamp at startup, because it read earlier than that; the real time is not yet known when this is written.<br><br>Values here (closed set): `automatic` · `manual` · `boot-floor`. |
| [`clock.time`](~peios/events/field-index/fields-clock#clock.time) | `uint.time` | required | Never before the build's timestamp: timed refuses a step that would land there. |
| [`clock.time-previous`](~peios/events/field-index/fields-clock#clock.time-previous) | `uint.time` | optional | The wall clock's reading just before timed moved it, the counterpart of `clock.time`. |
| [`subject.token.sid`](~peios/events/field-index/fields-subject#subject.token.sid) | `bin.sid` | required | The principal that acted. On a `manual` step, the user of the token that asked for the clock to be set; timed refuses a request whose user it cannot read. On an `automatic` step and the `boot-floor`, which timed decides on its own authority, timed's own user: its service SID. Search `operation.name`, not this field, to tell timed's own steps from a person's. |

Every record also carries the header fields of [the envelope](~peios/events/introduction/the-envelope), which no payload repeats.

*Generated from `timed.evman` by `pkm/tools/gen-events-book.py`. Edit the fragment, not this page.*
