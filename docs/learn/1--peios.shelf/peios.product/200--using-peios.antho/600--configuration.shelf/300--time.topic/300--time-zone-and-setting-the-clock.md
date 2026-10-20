---
title: Changing the Time Zone and Clock
type: how-to
description: Choose the machine's local time zone or set its clock manually.
related:
  - peios/time/overview
  - peios/time/configuring-sources
  - peios/time/the-clock-command
---

Change the time zone when the clock is correct but local time is displayed
incorrectly. Set the clock manually when no suitable time source is available.
The machine clock represents UTC; the zone controls its local display.

## Before you start

- Install timed, `clock`, and the time-zone database.
- Obtain registry write access to `Machine\System\Time` to change settings.
- Obtain timed's control right to reload or set the clock.
- Before a manual change, account for its effect on timestamps and software
  that uses wall-clock deadlines.

`clock(1)` owns the command syntax. The regman entry for
`Machine\System\Time` describes the settings and access checks.

## Using the graphical settings {#in-system-settings}

Open **System Settings** and select **Time & Date** to inspect the machine's
zone, automatic-time policy, and sources. Changing machine time is separate
from choosing a 12- or 24-hour desktop display; see
[Desktop Settings](~peios/desktop-settings/wallpaper-clock-and-dock#clock).

Verify the effective zone and clock state after a change. A saved setting
does not prove that the zone data was applied or that sources agree.

## In a terminal

### Change the time zone

1. Check the reported zone:

   ```sh
   clock status
   ```

2. Select an installed zone, for example:

   ```sh
   reg set Machine/System/Time TimeZone sz:Europe/London
   clock reload
   ```

3. Read `clock status` again and check timed's log for zone errors.

The name identifies data under `/usr/share/zoneinfo`. An invalid or missing
zone is refused before copying, leaving the previous file in place. timed
retries a refused name after configuration changes and every 10 minutes.
Deleting `TimeZone` requests UTC.

On restart, timed identifies the zone only when its saved name and installed
zone data match `/etc/localtime`. If identification fails, `clock` reports
`UTC (none chosen)`, even if the existing file contains another zone.

A copy failure after `/etc/localtime` is truncated can leave incomplete data.
The retained status name is not a fresh verification of the file. Resolve
copy or saved-name errors before interpreting or setting local time.

### Set the clock manually

1. Confirm the zone and resolve any errors described above.

2. Turn off automatic time and reload:

   ```sh
   reg set Machine/System/Time Automatic dword:0
   clock reload
   ```

3. Run `clock set` with the intended local date and time. For example, the
   syntax for 14:05 on October 19, 2026 is:

   ```sh
   clock set 2026-10-19 14:05
   ```

4. Check `clock status`. It should report manual operation and the intended
   zone. Manual time is not network synchronization.

Use `@SECONDS` instead of a local date to specify a UTC Unix timestamp.
timed refuses manual setting while `Automatic` is `1`.

### Return to automatic time

1. Account for a possible clock step when sources agree. Reacquisition
   permits an initial correction of any size.

2. Restore automatic operation:

   ```sh
   reg set Machine/System/Time Automatic dword:1
   clock reload
   ```

3. Check `clock sources` and `clock status` as measurements arrive. Confirm
   authentication, agreement, accuracy, and fresh updates.

<!-- Preserve the published heading anchor. -->
<!-- lint-disable-next-line spelling -->
## Coordinating changes with timed {#why-not-just-set-the-clock}

Changing the clock outside timed leaves the service measuring an unexpected
error. It can correct the change or refuse a sufficiently large offset.
Using `clock set` coordinates the change with the service and emits
`timed.clock.stepped` with operation `manual` and the requesting identity.
Read the installed definition with `evman timed.clock.stepped`.

Individual programs can display UTC with `date -u` or use a `TZ` environment
setting where supported. Those choices do not change the machine clock.

## File validation

Zone files and metadata must be regular files of at most 16 MiB. Aliases to
regular files are supported. Timed checks the opened zone file and copies
that same data, so validation and copying cannot select different files.

Timed updates the pre-created `/etc/localtime` file in place. Readers can
observe an empty or partial copy, and a write failure can leave a partial
copy. Its directory permissions do not allow an atomic rename by the service.
