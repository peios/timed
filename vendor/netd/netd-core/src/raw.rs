//! A registry key as the pure modules read it: lowered to a neutral tree of
//! values and subkeys, so that everything with a law in it is testable
//! without a registry. netd lowers `Rules\Interface` and `Profiles` to this
//! shape; so does any program that checks a change to them before making it.

/// A registry value, lowered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawValue {
    Int(i64),
    Str(String),
    List(Vec<String>),
    /// A type the vocabulary has no use for (binary, none). Kept so the
    /// builder can refuse it by name rather than silently drop it.
    Other,
}

/// A registry key, lowered: its name, values and subkeys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawKey {
    pub name: String,
    pub values: Vec<(String, RawValue)>,
    pub children: Vec<RawKey>,
}
