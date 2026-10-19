use netd_core::policy;
use netd_core::raw::{RawKey, RawValue};
use pnp_core::Snapshot;

fn rule(name: &str, action: &str) -> RawKey {
    RawKey {
        name: name.into(),
        values: vec![("Actions".into(), RawValue::List(vec![action.into()]))],
        children: Vec::new(),
    }
}

#[test]
fn profile_case_aliases_do_not_create_a_policy_conflict() {
    let rules = RawKey {
        name: "Interface".into(),
        values: Vec::new(),
        children: vec![
            rule("first", "JOIN(office)"),
            rule("second", "JOIN(OFFICE)"),
        ],
    };
    let profiles = RawKey {
        name: "Profiles".into(),
        values: Vec::new(),
        children: vec![RawKey {
            name: "Office".into(),
            values: Vec::new(),
            children: Vec::new(),
        }],
    };
    let policy = policy::build(Some(&rules), Some(&profiles)).unwrap();
    let judgment = policy.judge(&Snapshot::default());
    assert!(!judgment.conflict, "{judgment:?}");
    assert_eq!(judgment.outcome.profile().unwrap().path, "Office");
}

#[test]
fn non_ascii_action_is_rejected_without_panicking() {
    let rules = RawKey {
        name: "Interface".into(),
        values: Vec::new(),
        children: vec![rule("bad", "ééé")],
    };
    assert!(policy::build(Some(&rules), None).is_err());
}
