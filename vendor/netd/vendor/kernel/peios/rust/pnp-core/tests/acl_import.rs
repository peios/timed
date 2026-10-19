//! ACL-completeness: a first-match ACL imports as flat siblings with
//! descending priority and reproduces first-match semantics exactly
//! (the "each ACL line is just given descending priority" theorem from the
//! design session, checked packet by packet).

mod common;

use common::*;
use pnp_core::{Snapshot, Verdict};

/// A tiny first-match ACL interpreter: the ground truth.
struct AclLine {
    matches: fn(&Snapshot) -> bool,
    verdict: Verdict,
}

fn first_match(acl: &[AclLine], snap: &Snapshot, default: Verdict) -> Verdict {
    for line in acl {
        if (line.matches)(snap) {
            return line.verdict;
        }
    }
    default
}

#[test]
fn descending_priority_reproduces_first_match_semantics() {
    // A deliberately overlap-heavy ACL:
    //   1. src 10.0.0.0/8         -> PASS
    //   2. dstport 22             -> DROP
    //   3. proto tcp              -> PASS
    //   (default)                 -> DROP
    let acl = [
        AclLine {
            matches: |s| {
                matches!(s.src_addr, Some(a) if match a {
                    core::net::IpAddr::V4(v4) => v4.octets()[0] == 10,
                    _ => false,
                })
            },
            verdict: Verdict::Pass,
        },
        AclLine {
            matches: |s| s.dst_port == Some(22),
            verdict: Verdict::Drop,
        },
        AclLine {
            matches: |s| s.protocol == Some(6),
            verdict: Verdict::Pass,
        },
    ];

    // The mechanical import: one sibling per line, descending priority.
    let imported = || {
        vec![
            rb("line-1")
                .s("SrcAddr.Equal", "10.0.0.0/8")
                .int("Priority", 30)
                .actions(&["PASS"]),
            rb("line-2")
                .int("DstPort.Equal", 22)
                .int("Priority", 20)
                .actions(&["DROP"]),
            rb("line-3")
                .s("Protocol.Equal", "tcp")
                .int("Priority", 10)
                .actions(&["PASS"]),
        ]
    };

    // Packets chosen to hit every overlap: lines {1,2,3}, {2,3}, {1,3},
    // {3}, {1}, {} .
    let packets = [
        tcp_in("10.0.0.7", 5555, "10.0.0.5", 22),  // 1 beats 2: PASS
        tcp_in("192.0.2.9", 5555, "10.0.0.5", 22), // 2 beats 3: DROP
        tcp_in("10.9.9.9", 5555, "10.0.0.5", 80),  // 1: PASS
        tcp_in("192.0.2.9", 5555, "10.0.0.5", 80), // 3: PASS
        icmp_in("10.0.0.7"),                       // 1: PASS
        icmp_in("192.0.2.9"),                      // default: DROP
    ];

    for (i, snap) in packets.iter().enumerate() {
        let want = first_match(&acl, snap, Verdict::Drop);
        let got = judge(imported(), snap);
        assert_eq!(got.verdict, want, "packet #{i} diverged from the ACL");
    }
}
