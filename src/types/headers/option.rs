/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Option Code  |  Reserved     |       Option Length           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                       (optional) Data                         :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
use crate::types::{
    FilterOptionPayload, OptionCode, Parsable, ParsingError, ThirdPartyOptionPayload,
};
use std::convert::{TryFrom, TryInto};

// pub type OptionHeaderType<'a> = Slorp<OptionHeader, OptionHeaderSlice<'a>>;

// impl OptionHeaderType<'_> {
//     pub fn code(&self) -> OptionCode {
//         match self {
//             Self::Parsed(val) => val.code,
//             Self::Slice(val) => val.code(),
//         }
//     }

//     pub fn length(&self) -> u16 {
//         match self {
//             Self::Parsed(val) => val.length,
//             Self::Slice(val) => val.length(),
//         }
//     }
// }

#[derive(PartialEq, Debug)]
pub struct OptionHeader {
    pub code: OptionCode,
    pub length: u16,
}

impl OptionHeader {
    /// Size of the PCP option header (in bytes)
    pub const SIZE: usize = 4;

    pub const fn filter() -> Self {
        Self::new(OptionCode::Filter, FilterOptionPayload::SIZE as u16)
    }

    pub const fn third_party() -> Self {
        Self::new(OptionCode::ThirdParty, ThirdPartyOptionPayload::SIZE as u16)
    }

    pub const fn prefer_failure() -> Self {
        Self::new(OptionCode::PreferFailure, 0)
    }

    /// Creates a new option header
    const fn new(code: OptionCode, length: u16) -> Self {
        Self { code, length }
    }
    /// Returns the bytes of the header
    pub fn bytes(&self) -> [u8; Self::SIZE] {
        let len = self.length.to_be_bytes();
        [self.code as u8, 0, len[0], len[1]]
    }
}

pub struct OptionHeaderSlice<'a> {
    slice: &'a [u8],
}

impl OptionHeaderSlice<'_> {
    /// Returns the code number of the option
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
            // There is no way a slice of two elements cannot be made into an array of two elements
            let length = u16::from_be_bytes(match slice[2..4].try_into() {
                Ok(arr) => arr,
                _ => unreachable!(),
            });
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
                OptionCode::ThirdParty if length != FilterOptionPayload::SIZE as u16 => {
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
