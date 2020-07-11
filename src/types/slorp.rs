pub trait Parsable {
    type Parsed;
    /// Parses the fields of the object
    fn parse(&self) -> Self::Parsed;
    /// Returns the inner slice
    fn slice(&self) -> &[u8];
}

/// Slice or Parsed
///
/// An enum that could contain either an object parsed from a &[u8] slice or an object
/// containing the slice itself
pub enum Slorp<P, S: Parsable<Parsed = P>> {
    Parsed(P),
    Slice(S),
}

impl<P, S: Parsable<Parsed = P>> Slorp<P, S> {
    /// Parses the inner value (if it's a slice, else it just returns the value)
    pub fn parse(self) -> P {
        match self {
            Self::Parsed(val) => val,
            Self::Slice(val) => val.parse(),
        }
    }
    /// If there is one, returns the contained slice object
    pub fn slice(self) -> Option<S> {
        match self {
            Self::Parsed(_) => None,
            Self::Slice(val) => Some(val),
        }
    }
    /// If there is one, returns a reference to the contained slice object
    pub fn slice_ref<'a>(&'a self) -> Option<&'a S> {
        match self {
            Self::Parsed(_) => None,
            Self::Slice(ref val) => Some(val),
        }
    }
}

// One day
// impl<P, S: Parsable<Parsed=P>> From<S> for Slorp<P, S> {
// 	fn from(val: S) -> Self {
// 		Self::Slice(val)
// 	}
// }

// impl<P, S: Parsable<Parsed=P>> From<P> for Slorp<P, S> {
// 	fn from(val: P) -> Self {
// 		Self::Parsed(val)
// 	}
// }
