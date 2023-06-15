use std::{
    cmp::Ordering,
    fmt::Display,
    ops::{Add, AddAssign, Sub, SubAssign},
};

type Width = u16;

/// for efficient math in the partialord impl
const HALF_MAX: Width = Width::MAX / 2;

/// A packet sequence number with wrapping addition/subtraction/ordering.
#[derive(Debug, Default, bytemuck::Pod, bytemuck::Zeroable, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct SeqNum(pub Width);

impl From<Width> for SeqNum {
    #[inline]
    fn from(value: Width) -> Self {
        Self(value)
    }
}

impl Display for SeqNum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}seq", self.0)
    }
}

/// Ordering implementation taking into account that sequence values wrap around. As a
/// consequences, this cannot implement [Ord](std::cmp::Ord), which requires [total ordering](https://en.wikipedia.org/wiki/Total_order).
/// A total order requires that, for all `a`, `b`, `c` in `X`, if `a` <= `b` && `b` <= `c`, then `a` <= `c`. Wrapping values break that condition.
/// I.E. where `w` is the width of a `SeqNum`, `SeqNum(0)` <= `SeqNum(2^w / 2 - 1)` && `SeqNum(2^w / 2 - 1)` <= `SeqNum(2^w - 1)`, but `SeqNum(0)` > `SeqNum(2^w - 1)`.
impl PartialOrd for SeqNum {
    fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
        if self.0 == o.0 {
            Some(Ordering::Equal)
        } else if self.gt(o) {
            Some(Ordering::Greater)
        } else {
            Some(Ordering::Less)
        }
    }

    fn lt(&self, o: &Self) -> bool {
        (self.0 < o.0 && o.0 - self.0 <= HALF_MAX) || (self.0 > o.0 && self.0 - o.0 > HALF_MAX)
    }

    fn gt(&self, o: &Self) -> bool {
        (self.0 > o.0 && self.0 - o.0 <= HALF_MAX) || (self.0 < o.0 && o.0 - self.0 > HALF_MAX)
    }

    fn ge(&self, other: &Self) -> bool {
        self.0 == other.0 || self.gt(other)
    }

    fn le(&self, other: &Self) -> bool {
        self.0 == other.0 || self.lt(other)
    }
}

/// Wrapping addition.
impl Add<Width> for SeqNum {
    type Output = Self;

    fn add(self, rhs: Width) -> Self::Output {
        Self(self.0.wrapping_add(rhs))
    }
}

/// Wrapping addition.
impl Add<SeqNum> for SeqNum {
    type Output = Self;

    fn add(self, rhs: SeqNum) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
    }
}

/// Wrapping subtraction.
impl Sub<Width> for SeqNum {
    type Output = Self;

    fn sub(self, rhs: Width) -> Self::Output {
        Self(self.0.wrapping_sub(rhs))
    }
}

/// Wrapping subtraction.
impl Sub<SeqNum> for SeqNum {
    type Output = Self;

    fn sub(self, rhs: SeqNum) -> Self::Output {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

/// Wrapping addition.
impl AddAssign<Width> for SeqNum {
    fn add_assign(&mut self, rhs: Width) {
        self.0 = self.0.wrapping_add(rhs);
    }
}

/// Wrapping addition.
impl AddAssign<SeqNum> for SeqNum {
    fn add_assign(&mut self, rhs: SeqNum) {
        self.0 = self.0.wrapping_add(rhs.0);
    }
}

/// Wrapping subtraction.
impl SubAssign<Width> for SeqNum {
    fn sub_assign(&mut self, rhs: Width) {
        self.0 = self.0.wrapping_sub(rhs);
    }
}

/// Wrapping addition.
impl SubAssign<SeqNum> for SeqNum {
    fn sub_assign(&mut self, rhs: SeqNum) {
        self.0 = self.0.wrapping_sub(rhs.0);
    }
}
