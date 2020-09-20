//! # Format
//!
//! The RFC defines the following format for the response header:
/*!

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
//! **Version**: Only version 2 is supported.
//!
//! **R**: Indicates Request (0) or Response (1). All Responses MUST use 1.
//!
//! **Opcode**: The 7-bit Opcode value. The server copies this value from the request.
//!
//! **Reserved**: 8 reserved bits, MUST be sent as 0, MUST be ignored when received.
//!
//! **Result Code**: The result code for this response.
//!
//! **Lifetime**:
//!     An unsigned 32-bit integer, in seconds, ranging from 0 to
//!     2^32-1 seconds. On an error response, this indicates how long
//!     clients should assume they'll get the same error response from
//!     that PCP server if they repeat the same request. On a success
//!     response for the PCP Opcodes that create a mapping (MAP and PEER),
//!     the Lifetime field indicates the lifetime for this mapping.
//!
//! **Epoch Time**: The server's Epoch Time value.
//!
//! **Reserved**:
//!     96 reserved bits. For requests that were successfully
//!     parsed, this MUST be sent as 0, MUST be ignored when received.
//!     For requests that were not successfully parsed, the server copies
//!     the last 96 bits of the PCP Client's IP Address field from the request
//!     message into this corresponding 96-bit field of the response.
//!
//! **Opcode-specific information**:
//!     Payload data for this Opcode. The length of
//!     this data is determined by the Opcode definition.
//!
//! **PCP Options**:
//!     Zero, one, or more options that are legal for both a
//!     PCP response and for this Opcode.

use crate::types::{OpCode, Parsable, ParsingError, ResultCode};
use std::convert::{TryFrom, TryInto};

/// A correctly formed PCP `ResponseHeader` containing a version number, an `OpCode`,
/// the `ResultCode` of the request, a lifetime duration (in seconds) and the epoch
/// of the server
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

/// A zero-copy type containing a valid PCP response header. It can be obtained via the
/// `try_from` method (from the `std::TryFrom` trait) from a slice containing
/// a valid sequence of bytes.
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

    /// Returns the epoch time field
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
        // The R field tells if the packet is a response or a request
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
