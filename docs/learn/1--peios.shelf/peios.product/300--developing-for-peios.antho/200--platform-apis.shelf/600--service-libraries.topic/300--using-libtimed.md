---
title: Using libtimed
type: reference
description: Operations, ownership, errors, and Rust access for libtimed ABI 1.
---

`libtimed.so.1` provides the public C interface for timed. The
`timed-client` crate wraps the same shared library and returns owned Rust
values. Internal implementation crates do not replace this public boundary.

## Operations

The library reads status and sources, subscribes to clock snapshots, requests
configuration reloads, and requests manual time changes. The daemon checks
permissions and whether its operating mode allows a manual change.

Configuration helpers parse a server entry, check zone-name syntax, verify an
installed zone, and read zone and country lists. Zone-name syntax alone does
not establish that the zone is installed. Zone files and metadata must be
regular files of at most 16 MiB; aliases to regular files are supported.
Missing or unreadable metadata produces an empty list. These helpers do not
change the registry or the system clock.

## Linking and ownership

Include `<peios/timed.h>` and use the `timed` pkg-config module. The
installed header and `libtimed(3)` describe individual functions and data
layouts. `peios_timed_abi_version()` returns the ABI major version, 1.

Each operation returns an owned result, including failures. Check
`peios_timed_result_error()` before reading a view, and release the result
exactly once with `peios_timed_result_free()`. Error codes are POSIX numbers;
human-readable diagnostic wording is not a stable identifier. Reading the
stored error does not set thread-local `errno`.

Strings are UTF-8 spans with explicit byte lengths, without terminating NUL
bytes. Input spans are borrowed for the call and must remain live, aligned,
and initialized. A null pointer with zero length represents absent optional
text; a non-null pointer with zero length represents present empty text.
Returned strings, arrays, and nested views belong to the result. Copy what
you need before freeing it. Handles from another library are not valid here.

## Connections and failure

Each ordinary daemon operation opens its own filesystem Unix socket. The
system default is `/run/timed/time.sock`; clients can select another socket
for a
private service instance or a test.

A positive timeout in milliseconds bounds connection, sending, and receiving
together. A full connection queue can fail immediately. A transport error
does not establish whether a requested change was applied. The library does
not automatically replay operations after an uncertain failure.

## Rust access

Use `Client::system(Duration)` for the installed daemon or
`Client::new(path, Duration)` for an explicit socket. The wrapper copies
result views into Rust values and releases C results through `Drop`.
Select a matching source revision of `timed-client` and link the installed
shared library; the crate is not a precompiled Rust ABI package.

## Subscriptions

A subscription is owned separately from each returned snapshot. Calls and
freeing on one subscription must not overlap. A receive timeout retains
partial framing so a later call can continue. Other transport or protocol
errors close the stream; create a new subscription explicitly if needed.
The Rust wrapper requires mutable access to receive the next snapshot.
