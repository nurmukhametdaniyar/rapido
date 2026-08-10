//! Canonical encoding for everything that gets signed or hashed.
//!
//! Rule: a hashed message is the concatenation of length-prefixed fields, with
//! a length-prefixed DST first. Length prefixes make the encoding injective, so
//! two different field decompositions can never produce the same byte string
//! (which would otherwise be a signature-substitution bug).

use crate::dst::Dst;

/// Builder for a canonical, injective byte encoding.
#[derive(Debug, Clone)]
pub struct Transcript {
    buf: Vec<u8>,
}

impl Transcript {
    /// Start a transcript bound to a domain separation tag.
    pub fn new(dst: Dst) -> Self {
        let mut t = Transcript { buf: Vec::with_capacity(128) };
        t.push_bytes(dst.as_bytes());
        t
    }

    /// Append a length-prefixed byte field (u64 big-endian length).
    pub fn push_bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(&(b.len() as u64).to_be_bytes());
        self.buf.extend_from_slice(b);
        self
    }

    pub fn push_u64(&mut self, v: u64) -> &mut Self {
        self.push_bytes(&v.to_be_bytes())
    }

    pub fn push_u32(&mut self, v: u32) -> &mut Self {
        self.push_bytes(&v.to_be_bytes())
    }

    pub fn push_usize(&mut self, v: usize) -> &mut Self {
        self.push_u64(v as u64)
    }

    /// Append a sequence of byte fields, itself length-prefixed by element count.
    pub fn push_seq<'a, I: IntoIterator<Item = &'a [u8]>>(&mut self, items: I) -> &mut Self {
        let v: Vec<&[u8]> = items.into_iter().collect();
        self.push_usize(v.len());
        for item in v {
            self.push_bytes(item);
        }
        self
    }

    pub fn finish(&self) -> Vec<u8> {
        self.buf.clone()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dst;

    #[test]
    fn encoding_is_injective_across_field_splits() {
        // ("ab", "c") and ("a", "bc") must not collide.
        let a = Transcript::new(dst::PRESENT).push_bytes(b"ab").push_bytes(b"c").finish();
        let b = Transcript::new(dst::PRESENT).push_bytes(b"a").push_bytes(b"bc").finish();
        assert_ne!(a, b);
    }

    #[test]
    fn dst_changes_the_encoding() {
        let a = Transcript::new(dst::PRESENT).push_bytes(b"x").finish();
        let b = Transcript::new(dst::CRED).push_bytes(b"x").finish();
        assert_ne!(a, b);
    }
}
