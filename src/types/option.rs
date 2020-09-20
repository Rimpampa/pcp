use crate::types::headers::{OptionHeader, OptionHeaderSlice};
use crate::types::payloads::{
    FilterOptionPayloadSlice, OptionPayload, OptionPayloadSlice, ThirdPartyOptionPayloadSlice,
};
use crate::types::{OptionCode, Parsable, ParsingError};
use std::convert::TryFrom;
use std::net::IpAddr;

/// A correctly formed `PacketOption` containing an `OptionHeader` and an `OptionPayload`.
#[derive(PartialEq, Debug)]
pub struct PacketOption {
    pub header: OptionHeader,
    pub payload: OptionPayload,
}

impl PacketOption {
    // TODO: I might be missing something (on the docs)

    /// Constructs a filter option
    ///
    /// This option is used to filter the address of remote peers using the mapping
    pub fn filter(prefix: u8, remote_port: u16, remote_address: IpAddr) -> Self {
        Self {
            header: OptionHeader::filter(),
            payload: OptionPayload::filter(prefix, remote_port, remote_address),
        }
    }

    /// Constructs a third party option
    ///
    /// This options informs the PCP server that the packet is creating a mapping
    /// on behalf of another host
    pub fn third_party(address: IpAddr) -> Self {
        Self {
            header: OptionHeader::third_party(),
            payload: OptionPayload::third_party(address),
        }
    }

    /// Constructs a prefer failure option.
    ///
    /// This option tell the PCP server to fail in the case it can't use the specified
    /// public address and port
    pub fn prefer_failure() -> Self {
        Self {
            header: OptionHeader::prefer_failure(),
            payload: OptionPayload::PreferFailure,
        }
    }
    /// Returns the size of the option
    pub fn size(&self) -> usize {
        OptionHeader::SIZE + self.payload.size()
    }
}

/// A zero-copy type containing a valid PCP option. It can be obtained via the
/// `try_from` method (from the std `TryFrom` trait) from a slice containing
/// a valid sequence of bytes.
pub struct PacketOptionSlice<'a> {
    header: OptionHeaderSlice<'a>,
    payload: OptionPayloadSlice<'a>,
}

impl<'a> PacketOptionSlice<'a> {
    /// Returns the size of the option
    pub fn size(&self) -> usize {
        OptionHeader::SIZE + self.payload.size()
    }
    /// Returns a reference to the payload data of the packet
    pub fn payload(&self) -> &OptionPayloadSlice<'a> {
        &self.payload
    }
    /// Returns a reference to the header data of the packet
    pub fn header(&self) -> &OptionHeaderSlice<'a> {
        &self.header
    }
}

impl Parsable for PacketOptionSlice<'_> {
    type Parsed = PacketOption;

    fn parse(&self) -> Self::Parsed {
        Self::Parsed {
            header: self.header().parse(),
            payload: self.payload().parse(),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for PacketOptionSlice<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        let header = OptionHeaderSlice::try_from(slice)?;
        let payload = match header.code() {
            // try to parse the filter option payload
            OptionCode::Filter => {
                FilterOptionPayloadSlice::try_from(&slice[OptionHeader::SIZE..])?.into()
            }
            // try to parse the third party option payload
            OptionCode::ThirdParty => {
                ThirdPartyOptionPayloadSlice::try_from(&slice[OptionHeader::SIZE..])?.into()
            }
            // there is no payload, so just return the enum value
            OptionCode::PreferFailure => OptionPayloadSlice::PreferFailure,
        };
        Ok(PacketOptionSlice { header, payload })
    }
}
