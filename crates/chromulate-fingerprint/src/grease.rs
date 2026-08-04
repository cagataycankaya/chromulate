//! The reserved GREASE code points (RFC 8701).

use rand::rngs::StdRng;
// `random_range` moved from `Rng` to `RngExt` in rand 0.10; `RngExt` is
// blanket-implemented for every `Rng`, so the bounds below are unchanged and
// only the import is needed.
use rand::{Rng, RngExt as _, SeedableRng};
use serde::{Deserialize, Serialize};

/// One of the sixteen reserved GREASE code points, `0x?A?A`.
///
/// GREASE values are advertised by a client purely so that servers stay
/// tolerant of unknown code points. They carry no meaning, they are redrawn on
/// every connection, and both JA3 and JA4 strip them before hashing — which is
/// exactly why a profile has to model *where* they go rather than which value
/// was seen once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct GreaseValue(u16);

impl GreaseValue {
    /// Every legal GREASE value, in ascending order.
    pub const ALL: [Self; 16] = [
        Self(0x0a0a),
        Self(0x1a1a),
        Self(0x2a2a),
        Self(0x3a3a),
        Self(0x4a4a),
        Self(0x5a5a),
        Self(0x6a6a),
        Self(0x7a7a),
        Self(0x8a8a),
        Self(0x9a9a),
        Self(0xaaaa),
        Self(0xbaba),
        Self(0xcaca),
        Self(0xdada),
        Self(0xeaea),
        Self(0xfafa),
    ];

    /// Returns `true` when a raw code point is one of the reserved GREASE values.
    #[must_use]
    pub const fn is_grease_value(value: u16) -> bool {
        (value >> 8) == (value & 0x00ff) && (value & 0x000f) == 0x000a
    }

    /// Wraps a raw code point, returning `None` when it is not a GREASE value.
    #[must_use]
    pub const fn new(value: u16) -> Option<Self> {
        if Self::is_grease_value(value) {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Returns the raw code point.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Returns the index of this value within [`GreaseValue::ALL`].
    #[must_use]
    pub const fn index(self) -> usize {
        (self.0 >> 12) as usize
    }

    /// Draws one GREASE value uniformly.
    pub fn draw<R: Rng>(rng: &mut R) -> Self {
        Self::ALL[rng.random_range(0..Self::ALL.len())]
    }

    /// Draws one GREASE value from a seed, so tests can pin the result.
    #[must_use]
    pub fn draw_seeded(seed: u64) -> Self {
        Self::draw(&mut StdRng::seed_from_u64(seed))
    }

    /// Draws the two distinct values a ClientHello needs for its extension edges.
    ///
    /// RFC 8701 section 3.1 requires a client that sends two GREASE extensions
    /// to send two *different* values, so the second draw is taken as a non-zero
    /// offset from the first rather than as an independent sample.
    pub fn draw_pair<R: Rng>(rng: &mut R) -> (Self, Self) {
        let first = Self::draw(rng);
        let offset = rng.random_range(1..Self::ALL.len());
        (first, Self::ALL[(first.index() + offset) % Self::ALL.len()])
    }

    /// Draws a distinct pair from a seed, so tests can pin the result.
    #[must_use]
    pub fn draw_pair_seeded(seed: u64) -> (Self, Self) {
        Self::draw_pair(&mut StdRng::seed_from_u64(seed))
    }
}

impl From<GreaseValue> for u16 {
    fn from(value: GreaseValue) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_sixteen_reserved_values_are_recognised_as_grease() {
        assert_eq!(GreaseValue::ALL.len(), 16);
        for value in GreaseValue::ALL {
            assert!(
                GreaseValue::is_grease_value(value.get()),
                "{:#06x} should be GREASE",
                value.get()
            );
        }
    }

    #[test]
    fn real_code_points_are_not_mistaken_for_grease() {
        for value in [0x1301_u16, 0x0000, 0x002b, 0x0a0b, 0x0b0b, 0xff01, 0x44cd] {
            assert!(
                !GreaseValue::is_grease_value(value),
                "{value:#06x} should not be GREASE"
            );
        }
    }

    #[test]
    fn index_round_trips_through_the_value_table() {
        for (index, value) in GreaseValue::ALL.iter().enumerate() {
            assert_eq!(value.index(), index);
        }
    }

    #[test]
    fn the_same_seed_draws_the_same_value() {
        assert_eq!(GreaseValue::draw_seeded(7), GreaseValue::draw_seeded(7));
    }

    #[test]
    fn a_drawn_pair_is_always_two_different_values() {
        for seed in 0..512 {
            let (first, second) = GreaseValue::draw_pair_seeded(seed);
            assert_ne!(
                first, second,
                "seed {seed} produced a repeated GREASE value"
            );
        }
    }
}
