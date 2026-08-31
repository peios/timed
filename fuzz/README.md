# Fuzzing timed

Everything that reads bytes a stranger chose. Six targets, in rough order
of how exposed each is:

| Target | Reads |
|---|---|
| `ntp_packet` | A UDP datagram from anyone on the path. The most exposed surface there is: authentication happens *after* parsing and cannot happen before it. |
| `source_accept` | The whole reply-validation path against a real `Source` — origin echo, NTS identifier, authenticator, kiss handling, sample reduction — where the interactions between those checks live. |
| `nts_authenticator` | The authenticator extension field, with two attacker-chosen 16-bit lengths indexing into a buffer. |
| `nts_ke` | The NTS-KE record stream, over TLS from a server whose certificate we validated — so a defence against one that is broken or has turned hostile. |
| `time_wire` | The control socket, connectable by every program on the machine. |
| `engine_ops` | Selection and discipline as a state machine. |

Run one with `cargo +nightly fuzz run <target>`; artefacts land in
`fuzz/artifacts/`.

## The invariants that matter

Not panicking is the floor. Three others are asserted, and each of them is
a real bug if it ever stops holding:

**A source is never marked reachable, and never produces a sample, from a
datagram that did not echo the nonce it was sent** (`source_accept`). If
that fails, an off-path attacker can move the machine's clock. The nonce is
64 bits the fuzzer would have to guess, so the assertion is exercised on
every input that does *not* guess it — which is all of them.

**Nothing produces a NaN, and the discipline never asks the kernel for a
rate outside the tolerance** (`engine_ops`). A NaN frequency reaches the
drift file and is read back at every future boot, so it is permanent.

**The extension-field walk never exceeds the datagram** (`ntp_packet`).
This is the offset arithmetic the authenticator's associated data depends
on; getting it wrong means verifying a tag over the wrong bytes.

`engine_ops` is structure-aware rather than byte-oriented, because the
interesting failures in selection and discipline are not malformed input,
they are *sequences* — a source that answers, vanishes, returns with a
wild offset, is outvoted, comes back. Those cost nothing to reach from a
derived `Arbitrary` and are nearly unreachable from random bytes.

## Deliberately not asserted

`ntp_packet` does **not** assert that decode/encode round-trips
byte-identically. Extension-field padding is not kept, so a field whose
declared length exceeds its value re-encodes shorter. That is precisely
why the NTS authenticator verifies against the bytes as received rather
than a re-encoding of the parsed form — a re-encoding would establish that
we can reproduce the packet, not that the server sent it.
