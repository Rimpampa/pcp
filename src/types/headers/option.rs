//! # Format
//!
//! The RFC defines the following format for the option header:
/*!

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Option Code  |  Reserved     |       Option Length           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                       (optional) Data                         :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
//! **Option Code**:
//!     8 bits. Its most significant bit indicates if this option is
//!     mandatory (0) or optional (1) to process.
//!
//! **Reserved**: 8 bits. MUST be set to 0 on transmission and MUST be ignored on reception.
//!
//! **Option Length**:
//!     16 bits. Indicates the length of the enclosed data,
//!     in octets.  Options with length of 0 are allowed.  Options that
//!     are not a multiple of 4 octets long are followed by one, two, or
//!     three 0 octets to pad their effective length in the packet to be a
//!     multiple of 4 octets.  The Option Length reflects the semantic
//!     length of the option, not including any padding octets.
//!
//! **Data**:  Option data.

use crate::types::{
    FilterOptionPayload, OptionCode, Parsable, ParsingError, ThirdPartyOptionPayload,
};
use std::convert::{TryFrom, TryInto};

// TODO: length field might be unnecessary

/// A correctly formed PCP `OptionHeader` containing the specific `OptionCode` and the length of the payload
#[derive(PartialEq, Debug)]
pub struct OptionHeader {
    pub code: OptionCode,
    pub length: u16,
}

impl OptionHeader {
    /// Size of the PCP option header (in bytes)
    pub const SIZE: usize = 4;

    /// Constructs a new filter option header
    pub const fn filter() -> Self {
        Self {
            code: OptionCode::Filter,
            length: FilterOptionPayload::SIZE as u16,
        }
    }

    /// Constructs a new third party option header
    pub const fn third_party() -> Self {
        Self {
            code: OptionCode::ThirdParty,
            length: ThirdPartyOptionPayload::SIZE as u16,
        }
    }

    /// Constructs a new prefer failure option header
    pub const fn prefer_failure() -> Self {
        Self {
            code: OptionCode::PreferFailure,
            length: 0,
        }
    }

    /// Creates a correctly formatted byte array representing the header
    pub fn bytes(&self) -> [u8; Self::SIZE] {
        let len = self.length.to_be_bytes();
        [self.code as u8, 0, len[0], len[1]]
    }
}

/// A zero-copy type containing a valid PCP option header. It can be obtained via the
/// `try_from` method (from the `std::TryFrom` trait) from a slice containing
/// a valid sequence of bytes.
pub struct OptionHeaderSlice<'a> {
    slice: &'a [u8],
}

impl OptionHeaderSlice<'_> {
    /// Returns the option code
    pub fn code(&self) -> OptionCode {
        // The option cose has already been proven valid
        self.slice[0].try_into().unwrap()
    }
    /// Returns the length of the option payload
    pub fn length(&self) -> u16 {
        // There is no way a slice of 2 elements cannot be made into an array of two elements
        u16::from_be_bytes(self.slice[2..4].try_into().unwrap())
    }
    /// Returns the inner slice
    pub fn slice(&self) -> &[u8] {
        self.slice
    }
}

impl Parsable for OptionHeaderSlice<'_> {
    type Parsed = OptionHeader;

    fn parse(&self) -> Self::Parsed {
        OptionHeader {
            code: self.code(),
            length: self.length(),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for OptionHeaderSlice<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<OptionHeaderSlice<'a>, Self::Error> {
        // The size of the slice must be at least 4
        if slice.len() < OptionHeader::SIZE {
            Err(ParsingError::InvalidSliceLength(OptionHeader::SIZE))
        }
        // Check that the length specified in the header is correct
        else {
            let length = u16::from_be_bytes(slice[2..4].try_into().unwrap());
            // This is done by looking for the size of the payload of that specific option code
            match OptionCode::try_from(slice[0])? {
                OptionCode::Filter if length != FilterOptionPayload::SIZE as u16 => {
                    Err(ParsingError::InvalidOptionLength(
                        OptionCode::Filter,
                        FilterOptionPayload::SIZE,
                    ))
                }
                OptionCode::PreferFailure if length != 0 => Err(ParsingError::InvalidOptionLength(
                    OptionCode::PreferFailure,
                    0,
                )),
                OptionCode::ThirdParty if length != ThirdPartyOptionPayload::SIZE as u16 => {
                    Err(ParsingError::InvalidOptionLength(
                        OptionCode::ThirdParty,
                        ThirdPartyOptionPayload::SIZE,
                    ))
                }
                // The option header is valid
                _ => Ok(OptionHeaderSlice {
                    slice: &slice[..OptionHeader::SIZE],
                }),
            }
        }
    }
}
