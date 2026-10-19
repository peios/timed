/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_PKM_NET_H
#define _UAPI_PKM_NET_H

#include <linux/types.h>
#include <pkm/sd.h>

/*
 * KACS port reservations — who may claim a TCP/UDP port.
 *
 * Ports are a shared, unowned namespace; the only thing KACS authorises is
 * the claim: bind(2) to a non-zero port. A reservation is a (protocol set,
 * port range) selector mapped to a security descriptor, held as one value
 * under the registry key
 *
 *   Machine\System\Network\TcpIp\PortReservations\
 *
 * where the value name is the selector ("tcp,udp:1-1023", "tcp:80",
 * "*:8080") and the data is a self-relative security descriptor. The key's
 * unnamed default value is the default reservation, consulted when no
 * selector contains the requested port. The address family is deliberately
 * not part of the selector: one reservation covers IPv4 and IPv6, or
 * dual-stack squatting bypasses it.
 *
 * At bind(2) KACS finds the most specific selector containing
 * (protocol, port) and evaluates the caller's token against its descriptor
 * for KACS_PORT_BIND. Binding port 0 (ephemeral allocation) is never
 * checked. Rebinding onto an already-bound port (SO_REUSEADDR /
 * SO_REUSEPORT) additionally requires the caller's user SID to equal the
 * existing binder's, or SeTcbPrivilege.
 *
 * A port descriptor carries only KACS_PORT_BIND and READ_CONTROL. Editing
 * a reservation is a registry value write, governed by the key's own
 * descriptor; WRITE_DAC / WRITE_OWNER inside a port descriptor are
 * meaningless and never honoured.
 *
 * CAP_NET_BIND_SERVICE is in KACS's always-allow set: the Linux privileged-
 * port floor never refuses a bind, so every claim reaches the reservation
 * check.
 */
#define KACS_PORT_BIND 0x00000001U /* bind(2) to a port the selector contains */

#define KACS_PORT_ALL_ACCESS (KACS_PORT_BIND | KACS_ACCESS_READ_CONTROL)

/* Protocol bits in a reservation selector. */
#define KACS_PORT_PROTO_TCP 0x01U
#define KACS_PORT_PROTO_UDP 0x02U
#define KACS_PORT_PROTO_ALL (KACS_PORT_PROTO_TCP | KACS_PORT_PROTO_UDP)

/* Longest accepted selector name, in bytes: "tcp,udp:65535-65535". */
#define KACS_PORT_SELECTOR_MAX_LEN 19U

#endif /* _UAPI_PKM_NET_H */
