/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Version = 2  |R|   Opcode    |   Reserved    |  Result Code  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Lifetime (32 bits)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Epoch Time (32 bits)                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                      Reserved (96 bits)                       |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    :             (optional) Opcode-specific response data          :
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :             (optional) Options                                :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
use crate::types::{OpCode, Parsable, ParsingError, ResultCode};
use std::convert::{TryFrom, TryInto};

// impl ResponseHeaderType<'_> {
//     /// Returns the version number of the protocol being used
//     pub fn version(&self) -> u8 {
//         match self {
//             Self::Parsed(val) => val.version,
//             Self::Slice(val) => val.version(),
//         }
//     }
//     /// Returns the operation code number (relative to the request previously made)
//     pub fn opcode(&self) -> OpCode {
//         match self {
//             Self::Parsed(val) => val.opcode,
//             Self::Slice(val) => val.opcode(),
//         }
//     }
//     /// Returns the result code number of the request
//     pub fn result_code(&self) -> ResultCode {
//         match self {
//             Self::Parsed(val) => val.result,
//             Self::Slice(val) => val.result_code(),
//         }
//     }
//     /// Returns the lifetime of the request. That is for how long it will remain valid.
//     /// When it's an error it indicates for how long the same request will lead to an error
//     pub fn lifetime(&self) -> u32 {
//         match self {
//             Self::Parsed(val) => val.lifetime,
//             Self::Slice(val) => val.lifetime(),
//         }
//     }

//     pub fn epoch(&self) -> u32 {
//         match self {
//             Self::Parsed(val) => val.epoch,
//             Self::Slice(val) => val.epoch(),
//         }
//     }
// }

#[derive(PartialEq, Debug)]
pub struct ResponseHeader {
    pub version: u8,
    pub opcode: OpCode,
    pub result: ResultCode,
    pub lifetime: u32,
    pub epoch: u32,
}

impl ResponseHeader {
    /// Size of the PCP response header (in bytes)
    pub const SIZE: usize = 24; // 192 bit
}

pub struct ResponseHeaderSlice<'a> {
    // slice: &'a [u8; ResponseHeader::SIZE],
    slice: &'a [u8],
}

impl ResponseHeaderSlice<'_> {
    /// Returns the version number of the protocol being used
    pub fn version(&self) -> u8 {
        self.slice[0]
    }
    /// Returns the operation code number (relative to the request previously made)
    pub fn opcode(&self) -> OpCode {
        // The opcode has already been proven valid
        match (self.slice[1] & 0b_0111_1111).try_into() {
            Ok(opcode) => opcode,
            _ => unreachable!(),
        }
    }
    /// Returns the result code number of the request
    pub fn result_code(&self) -> ResultCode {
        // The result code has already been proven valid
        self.slice[3].try_into().unwrap()
    }
    /// Returns the lifetime of the request. That is for how long it will remain valid.
    /// When it's an error it indicates for how long the same request will lead to an error
    pub fn lifetime(&self) -> u32 {
        u32::from_be_bytes(self.slice[4..8].try_into().unwrap())
    }
    /// [TODO]
    pub fn epoch(&self) -> u32 {
        u32::from_be_bytes(self.slice[8..12].try_into().unwrap())
    }
    /// Returns the inner slice
    pub fn slice(&self) -> &[u8] {
        self.slice
    }
}

impl Parsable for ResponseHeaderSlice<'_> {
    type Parsed = ResponseHeader;

    fn parse(&self) -> Self::Parsed {
        ResponseHeader {
            version: self.version(),
            opcode: self.opcode(),
            result: self.result_code(),
            lifetime: self.lifetime(),
            epoch: self.epoch(),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ResponseHeaderSlice<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<ResponseHeaderSlice<'a>, Self::Error> {
        // The length of the slice must be at least 24
        if slice.len() < ResponseHeader::SIZE {
            Err(ParsingError::InvalidSliceLength(ResponseHeader::SIZE))
        }
        // Versions below 2 are not supported (0 is NAT-PMP)
        else if slice[0] < 2 {
            Err(ParsingError::VersionNotSupported(slice[0]))
        }
        // The MSb of the opcode must not be considered as it indicates whether
        // the packet is a response or a request
        else if slice[1] & 0b_1000_0000 == 0 {
            Err(ParsingError::NotAResponse)
        }
        // It's a valid header
        else {
            // Check if the opcode is valid
            OpCode::try_from(slice[1] & 0b_0111_1111)?;
            // Check if the result code is valid
            ResultCode::try_from(slice[3])?;
            Ok(ResponseHeaderSlice {
                slice: &slice[..ResponseHeader::SIZE],
            })
        }
    }
}
