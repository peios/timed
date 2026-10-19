/// Error returned by fallible PKM allocation helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocError;

impl core::fmt::Display for AllocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "allocation failed")
    }
}

/// Fallible clone trait used by PKM-owned container helpers in kernel mode.
pub trait TryClone: Sized {
    /// Attempts to clone `self`, returning `AllocError` on allocation failure.
    fn try_clone(&self) -> Result<Self, AllocError>;
}

#[cfg(not(feature = "kernel"))]
impl<T: Clone> TryClone for T {
    fn try_clone(&self) -> Result<Self, AllocError> {
        Ok(self.clone())
    }
}

#[cfg(feature = "kernel")]
mod try_clone_prims {
    use super::{AllocError, TryClone};

    macro_rules! impl_try_clone_copy {
        ($($t:ty),* $(,)?) => {
            $(impl TryClone for $t {
                fn try_clone(&self) -> Result<Self, AllocError> {
                    Ok(*self)
                }
            })*
        };
    }

    impl_try_clone_copy!(
        u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, bool, char
    );

    impl<T: TryClone> TryClone for Option<T> {
        fn try_clone(&self) -> Result<Self, AllocError> {
            match self {
                Some(value) => Ok(Some(value.try_clone()?)),
                None => Ok(None),
            }
        }
    }

    impl<T: Copy, const N: usize> TryClone for [T; N] {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(*self)
        }
    }
}

#[cfg(not(feature = "kernel"))]
mod vec_inner {
    use super::{AllocError, TryClone};
    use alloc::vec;

    /// Fallible vector wrapper used by the slow-track core outside kernel mode.
    #[derive(Clone, Eq, PartialEq)]
    pub struct Vec<T>(vec::Vec<T>);

    impl<T> Vec<T> {
        /// Creates an empty vector.
        pub const fn new() -> Self {
            Self(vec::Vec::new())
        }

        /// Creates an empty vector with the requested capacity.
        pub fn with_capacity(capacity: usize) -> Result<Self, AllocError> {
            Ok(Self(vec::Vec::with_capacity(capacity)))
        }

        /// Appends one element.
        pub fn push(&mut self, value: T) -> Result<(), AllocError> {
            self.0.push(value);
            Ok(())
        }

        /// Extends the vector from an iterator.
        pub fn extend<I>(&mut self, iter: I) -> Result<(), AllocError>
        where
            I: IntoIterator<Item = T>,
        {
            for value in iter {
                self.push(value)?;
            }
            Ok(())
        }

        /// Extends the vector by fallibly cloning elements from a slice.
        pub fn extend_from_slice(&mut self, slice: &[T]) -> Result<(), AllocError>
        where
            T: TryClone,
        {
            for value in slice {
                self.push(value.try_clone()?)?;
            }
            Ok(())
        }

        /// Pops one element from the end of the vector.
        pub fn pop(&mut self) -> Option<T> {
            self.0.pop()
        }

        /// Truncates the vector to `len` elements.
        pub fn truncate(&mut self, len: usize) {
            self.0.truncate(len);
        }

        /// Returns the current length.
        pub fn len(&self) -> usize {
            self.0.len()
        }

        /// Returns whether the vector is empty.
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        /// Returns an immutable iterator.
        pub fn iter(&self) -> core::slice::Iter<'_, T> {
            self.0.iter()
        }

        /// Returns a mutable iterator.
        pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
            self.0.iter_mut()
        }

        /// Returns the vector as a slice.
        pub fn as_slice(&self) -> &[T] {
            &self.0
        }

        /// Returns a mutable raw pointer to the backing storage.
        pub fn as_mut_ptr(&mut self) -> *mut T {
            self.0.as_mut_ptr()
        }
    }

    impl<T> Default for Vec<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<T: core::fmt::Debug> core::fmt::Debug for Vec<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(self.as_slice(), f)
        }
    }

    impl<T: core::hash::Hash> core::hash::Hash for Vec<T> {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            self.as_slice().hash(state);
        }
    }

    impl<T: PartialEq> PartialEq<alloc::vec::Vec<T>> for Vec<T> {
        fn eq(&self, other: &alloc::vec::Vec<T>) -> bool {
            self.as_slice() == other.as_slice()
        }
    }

    impl<T> core::ops::Deref for Vec<T> {
        type Target = [T];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<T> core::ops::DerefMut for Vec<T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl<'a, T> IntoIterator for &'a Vec<T> {
        type Item = &'a T;
        type IntoIter = core::slice::Iter<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            self.iter()
        }
    }

    impl<'a, T> IntoIterator for &'a mut Vec<T> {
        type Item = &'a mut T;
        type IntoIter = core::slice::IterMut<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            self.iter_mut()
        }
    }

    impl<T> IntoIterator for Vec<T> {
        type Item = T;
        type IntoIter = alloc::vec::IntoIter<T>;

        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }

    impl<T> From<alloc::vec::Vec<T>> for Vec<T> {
        fn from(value: alloc::vec::Vec<T>) -> Self {
            Self(value)
        }
    }

    impl<T> From<Vec<T>> for alloc::vec::Vec<T> {
        fn from(value: Vec<T>) -> Self {
            value.0
        }
    }
}

#[cfg(feature = "kernel")]
mod vec_inner {
    use super::{AllocError, TryClone};

    /// Fallible vector wrapper used inside the kernel.
    ///
    /// PNP divergence from the kacs-core original: allocations use
    /// GFP_ATOMIC, not GFP_KERNEL. Evaluation runs in the netfilter hook
    /// path (softirq context), where sleeping allocation is illegal; the
    /// other allocating path, policy ingestion, is rare and its
    /// allocations are small, so paying the atomic tax there too is
    /// cheaper than plumbing per-call flags through every signature.
    /// Evaluation handles AllocError by failing closed (the glue drops).
    pub struct Vec<T>(kernel::alloc::KVec<T>);

    impl<T> Vec<T> {
        /// Creates an empty vector.
        pub const fn new() -> Self {
            Self(kernel::alloc::KVec::new())
        }

        /// Creates an empty vector with the requested capacity.
        pub fn with_capacity(capacity: usize) -> Result<Self, AllocError> {
            let inner =
                kernel::alloc::KVec::with_capacity(capacity, kernel::alloc::flags::GFP_ATOMIC)
                    .map_err(|_| AllocError)?;
            Ok(Self(inner))
        }

        /// Appends one element.
        pub fn push(&mut self, value: T) -> Result<(), AllocError> {
            self.0
                .push(value, kernel::alloc::flags::GFP_ATOMIC)
                .map_err(|_| AllocError)
        }

        /// Extends the vector from an iterator.
        pub fn extend<I>(&mut self, iter: I) -> Result<(), AllocError>
        where
            I: IntoIterator<Item = T>,
        {
            for value in iter {
                self.push(value)?;
            }
            Ok(())
        }

        /// Extends the vector by fallibly cloning elements from a slice.
        pub fn extend_from_slice(&mut self, slice: &[T]) -> Result<(), AllocError>
        where
            T: TryClone,
        {
            for value in slice {
                self.push(value.try_clone()?)?;
            }
            Ok(())
        }

        /// Pops one element from the end of the vector.
        pub fn pop(&mut self) -> Option<T> {
            self.0.pop()
        }

        /// Truncates the vector to `len` elements.
        pub fn truncate(&mut self, len: usize) {
            self.0.truncate(len);
        }

        /// Returns the current length.
        pub fn len(&self) -> usize {
            self.0.len()
        }

        /// Returns whether the vector is empty.
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }

        /// Returns an immutable iterator.
        pub fn iter(&self) -> core::slice::Iter<'_, T> {
            self.0.iter()
        }

        /// Returns a mutable iterator.
        pub fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
            self.0.iter_mut()
        }

        /// Returns the vector as a slice.
        pub fn as_slice(&self) -> &[T] {
            &self.0
        }

        /// Returns a mutable raw pointer to the backing storage.
        pub fn as_mut_ptr(&mut self) -> *mut T {
            self.0.as_mut_ptr()
        }
    }

    impl<T> Default for Vec<T> {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<T: core::fmt::Debug> core::fmt::Debug for Vec<T> {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(self.as_slice(), f)
        }
    }

    impl<T: core::hash::Hash> core::hash::Hash for Vec<T> {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            self.as_slice().hash(state);
        }
    }

    impl<T: PartialEq> PartialEq for Vec<T> {
        fn eq(&self, other: &Self) -> bool {
            self.as_slice() == other.as_slice()
        }
    }

    impl<T: Eq> Eq for Vec<T> {}

    impl<T> core::ops::Deref for Vec<T> {
        type Target = [T];

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl<T> core::ops::DerefMut for Vec<T> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    impl<'a, T> IntoIterator for &'a Vec<T> {
        type Item = &'a T;
        type IntoIter = core::slice::Iter<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            self.iter()
        }
    }

    impl<'a, T> IntoIterator for &'a mut Vec<T> {
        type Item = &'a mut T;
        type IntoIter = core::slice::IterMut<'a, T>;

        fn into_iter(self) -> Self::IntoIter {
            self.iter_mut()
        }
    }

    impl<T> IntoIterator for Vec<T> {
        type Item = T;
        type IntoIter = <kernel::alloc::KVec<T> as IntoIterator>::IntoIter;

        fn into_iter(self) -> Self::IntoIter {
            self.0.into_iter()
        }
    }

    impl<T: TryClone> TryClone for Vec<T> {
        fn try_clone(&self) -> Result<Self, AllocError> {
            let mut cloned = Self::with_capacity(self.len())?;
            for value in self.iter() {
                cloned.push(value.try_clone()?)?;
            }
            Ok(cloned)
        }
    }
}

pub use vec_inner::Vec;

#[cfg(not(feature = "kernel"))]
mod string_inner {
    use super::AllocError;

    /// Owned UTF-8 string wrapper used outside kernel mode.
    #[derive(Clone, Default, Eq, PartialEq, Hash)]
    pub struct String(alloc::string::String);

    impl String {
        /// Creates an empty string.
        pub fn new() -> Self {
            Self(alloc::string::String::new())
        }

        /// Appends one Unicode scalar value.
        pub fn push(&mut self, character: char) -> Result<(), AllocError> {
            self.0.push(character);
            Ok(())
        }

        /// Returns the string as `&str`.
        pub fn as_str(&self) -> &str {
            &self.0
        }

        /// Returns the UTF-8 bytes.
        pub fn as_bytes(&self) -> &[u8] {
            self.0.as_bytes()
        }

        /// Returns the string length in bytes.
        pub fn len(&self) -> usize {
            self.0.len()
        }

        /// Returns whether the string is empty.
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
    }

    impl core::fmt::Debug for String {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(self.as_str(), f)
        }
    }

    impl core::fmt::Display for String {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Display::fmt(self.as_str(), f)
        }
    }

    impl core::ops::Deref for String {
        type Target = str;

        fn deref(&self) -> &Self::Target {
            self.as_str()
        }
    }

    impl PartialEq<str> for String {
        fn eq(&self, other: &str) -> bool {
            self.as_str() == other
        }
    }

    impl PartialEq<&str> for String {
        fn eq(&self, other: &&str) -> bool {
            self.as_str() == *other
        }
    }

    impl From<&str> for String {
        fn from(value: &str) -> Self {
            Self(value.into())
        }
    }

    impl From<alloc::string::String> for String {
        fn from(value: alloc::string::String) -> Self {
            Self(value)
        }
    }
}

#[cfg(feature = "kernel")]
mod string_inner {
    use super::{AllocError, TryClone, Vec};

    /// Owned UTF-8 string wrapper used inside the kernel.
    pub struct String(Vec<u8>);

    impl String {
        /// Creates an empty string.
        pub fn new() -> Self {
            Self(Vec::new())
        }

        /// Appends one Unicode scalar value.
        ///
        /// All-or-nothing: `extend_from_slice` pushes the encoded bytes one at a
        /// time, so a mid-character allocation failure would otherwise leave a
        /// truncated (invalid) UTF-8 sequence behind while still returning `Err`.
        /// `as_str`'s `from_utf8_unchecked` trusts the buffer, so on failure we
        /// roll the buffer back to its pre-push length.
        pub fn push(&mut self, character: char) -> Result<(), AllocError> {
            let mut buf = [0u8; 4];
            let encoded = character.encode_utf8(&mut buf);
            let saved_len = self.0.len();
            match self.0.extend_from_slice(encoded.as_bytes()) {
                Ok(()) => Ok(()),
                Err(err) => {
                    self.0.truncate(saved_len);
                    Err(err)
                }
            }
        }

        /// Returns the string as `&str`.
        pub fn as_str(&self) -> &str {
            unsafe { core::str::from_utf8_unchecked(self.0.as_slice()) }
        }

        /// Returns the UTF-8 bytes.
        pub fn as_bytes(&self) -> &[u8] {
            self.0.as_slice()
        }

        /// Returns the string length in bytes.
        pub fn len(&self) -> usize {
            self.0.len()
        }

        /// Returns whether the string is empty.
        pub fn is_empty(&self) -> bool {
            self.0.is_empty()
        }
    }

    impl TryClone for String {
        fn try_clone(&self) -> Result<Self, AllocError> {
            Ok(Self(self.0.try_clone()?))
        }
    }

    impl Default for String {
        fn default() -> Self {
            Self::new()
        }
    }

    impl core::fmt::Debug for String {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Debug::fmt(self.as_str(), f)
        }
    }

    impl core::fmt::Display for String {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            core::fmt::Display::fmt(self.as_str(), f)
        }
    }

    impl core::hash::Hash for String {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            self.as_str().hash(state);
        }
    }

    impl PartialEq for String {
        fn eq(&self, other: &Self) -> bool {
            self.as_str() == other.as_str()
        }
    }

    impl Eq for String {}

    impl PartialEq<str> for String {
        fn eq(&self, other: &str) -> bool {
            self.as_str() == other
        }
    }

    impl PartialEq<&str> for String {
        fn eq(&self, other: &&str) -> bool {
            self.as_str() == *other
        }
    }

    impl core::ops::Deref for String {
        type Target = str;

        fn deref(&self) -> &Self::Target {
            self.as_str()
        }
    }
}

pub use string_inner::String;

/// Fallibly clones a slice into a PKM vector.
pub fn slice_to_vec<T: TryClone>(slice: &[T]) -> Result<Vec<T>, AllocError> {
    let mut values = Vec::with_capacity(slice.len())?;
    for value in slice {
        values.push(value.try_clone()?)?;
    }
    Ok(values)
}

/// Collects an iterator into a PKM vector using fallible pushes.
pub fn vec_collect<T>(iter: impl IntoIterator<Item = T>) -> Result<Vec<T>, AllocError> {
    let mut values = Vec::new();
    for value in iter {
        values.push(value)?;
    }
    Ok(values)
}
