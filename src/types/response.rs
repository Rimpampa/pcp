use crate::types::headers::{ResponseHeader, ResponseHeaderSlice};
use crate::types::payloads::{
    MapResponsePayloadSlice, PeerResponsePayloadSlice, ResponsePayload, ResponsePayloadSlice,
};
use crate::types::{OpCode, PacketOption, PacketOptionSlice, Parsable, ParsingError};
use std::convert::TryFrom;

///   A PCP `ResponsePacket` containing a `ResponseHeader`, a `ResponsePayload`
///   and some `PacketOption`s.
///
///   This type cannot be constructed directly as it is meant to be received from a
///   UDP socket. The only way to get it is to `parse` (see `Parsable`) a `ResponsePacketSlice`.
pub struct ResponsePacket {
    pub header: ResponseHeader,
    pub payload: ResponsePayload,
    pub options: Vec<PacketOption>,
}

/// A zero-copy type containing a valid PCP response packet. It can be obtained via the
/// `try_from` method (from the std `TryFrom` trait) from a slice containing
/// a valid sequence of bytes.
pub struct ResponsePacketSlice<'a> {
    header: ResponseHeaderSlice<'a>,
    payload: ResponsePayloadSlice<'a>,
    options: Vec<PacketOptionSlice<'a>>,
}

impl<'a> ResponsePacketSlice<'a> {
    /// Returns a reference to the options in the packets
    pub const fn options(&self) -> &Vec<PacketOptionSlice<'a>> {
        &self.options
    }

    /// Returns a reference to the payload data of the packet
    pub const fn payload(&self) -> &ResponsePayloadSlice<'a> {
        &self.payload
    }

    /// Returns a reference to the header data of the packet
    pub const fn header(&self) -> &ResponseHeaderSlice<'a> {
        &self.header
    }
}

impl Parsable for ResponsePacketSlice<'_> {
    type Parsed = ResponsePacket;

    fn parse(&self) -> Self::Parsed {
        Self::Parsed {
            header: self.header().parse(),
            payload: self.payload.parse(),
            options: self.options().parse(),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ResponsePacketSlice<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        // Check if the header is valid
        let header = ResponseHeaderSlice::try_from(slice)?;

        let mut at = ResponseHeader::SIZE;

        let opcode = header.opcode();
        // Check if the payload is valid
        let payload = match opcode {
            OpCode::Map => MapResponsePayloadSlice::try_from(&slice[at..])?.into(),
            OpCode::Peer => PeerResponsePayloadSlice::try_from(&slice[at..])?.into(),
            OpCode::Announce => ResponsePayloadSlice::Announce,
        };
        let mut options = Vec::new();
        at += payload.size();

        // Check for possible options
        while at < slice.len() {
            let option = PacketOptionSlice::try_from(&slice[at..])?;
            // Check if the option is valid for this opcode
            // As I'm parsing this slice, there is no way it could be
            let option_code = &option.header().code();
            if !opcode.valid_option(option_code) {
                return Err(ParsingError::InvalidOption(opcode, *option_code));
            }
            at += option.size();
            options.push(option);
        }
        Ok(Self {
            header,
            payload,
            options,
        })
    }
}
