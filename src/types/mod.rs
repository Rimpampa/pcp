mod headers;
mod op_code;
mod option_code;
mod parsing_error;
mod payloads;
mod protocols;
mod result_code;
mod slorp;

pub use op_code::OpCode;
pub use option_code::OptionCode;
pub use parsing_error::ParsingError;
pub use protocols::ProtocolNumber;
pub use result_code::ResultCode;

pub use headers::*;
pub use payloads::*;

// use headers::*;
// use payloads::*;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub trait Parsable {
    type Parsed;
    /// Parses the fields of the object
    fn parse(&self) -> Self::Parsed;
    // /// Returns the inner slice
    // pub fn slice(&self) -> &[u8];
}

impl<P, S> Parsable for Vec<S>
where
    S: Parsable<Parsed = P>,
{
    type Parsed = Vec<P>;

    fn parse(&self) -> Self::Parsed {
        self.iter().map(|v| v.parse()).collect()
    }
}

pub trait Ipv6Address {
    fn is_ipv6_mapped(&self) -> bool;
    fn true_form(self) -> IpAddr;
}

impl Ipv6Address for Ipv6Addr {
    fn is_ipv6_mapped(&self) -> bool {
        match self.octets() {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, _, _, _, _] => true,
            _ => false,
        }
    }
    fn true_form(self) -> IpAddr {
        match self.octets() {
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => {
                IpAddr::V4(Ipv4Addr::new(a, b, c, d))
            }
            _ => IpAddr::V6(self),
        }
    }
}

#[derive(PartialEq)]
pub struct PacketOption {
    pub header: OptionHeader,
    pub payload: OptionPayload,
}

impl PacketOption {
    const fn new(header: OptionHeader, payload: OptionPayload) -> Self {
        Self { header, payload }
    }

    pub fn filter(prefix: u8, remote_port: u16, remote_address: IpAddr) -> Self {
        Self::new(
            OptionHeader::filter(),
            OptionPayload::filter(prefix, remote_port, remote_address),
        )
    }
    pub fn third_party(address: IpAddr) -> Self {
        Self::new(
            OptionHeader::third_party(),
            OptionPayload::third_party(address),
        )
    }
    pub fn prefer_failure() -> Self {
        Self::new(OptionHeader::prefer_failure(), OptionPayload::PreferFailure)
    }
    /// Returns the size of the option
    pub fn size(&self) -> usize {
        OptionHeader::SIZE + self.payload.size()
    }
}

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
        Ok(PacketOptionSlice {
            header: header,
            payload,
        })
    }
}

pub struct RequestPacket {
    pub header: RequestHeader,
    pub payload: RequestPayload,
    pub options: Vec<PacketOption>,
}

impl RequestPacket {
    fn new(header: RequestHeader, payload: RequestPayload, options: Vec<PacketOption>) -> Self {
        Self {
            header,
            payload,
            options,
        }
    }

    // pub fn map<Ip: IpAddress>(
    pub fn map(
        version: u8,
        lifetime: u32,
        internal_address: IpAddr,
        nonce: [u8; 12],
        protocol: Option<ProtocolNumber>,
        internal_port: u16,
        external_port: u16,
        external_address: IpAddr,
        options: Vec<PacketOption>,
    ) -> Result<Self, ParsingError> {
        // Check that the provided options are supported
        if let Some(o) = options
            .iter()
            .map(|o| o.header.code)
            .find(|o| !OpCode::Map.valid_option(o))
        {
            Err(ParsingError::InvalidOption(OpCode::Map, o))
        }
        // Check that the version is supported
        else if version < 2 {
            Err(ParsingError::VersionNotSupported(version))
        } else {
            Ok(Self::new(
                RequestHeader::new(version, OpCode::Map, lifetime, internal_address),
                MapRequestPayload::new(
                    nonce,
                    protocol,
                    internal_port,
                    external_port,
                    external_address,
                )
                .into(),
                options,
            ))
        }
    }

    pub fn peer(
        version: u8,
        lifetime: u32,
        internal_address: IpAddr,
        nonce: [u8; 12],
        protocol: Option<ProtocolNumber>,
        internal_port: u16,
        external_port: u16,
        external_address: IpAddr,
        remote_port: u16,
        remote_address: IpAddr,
        options: Vec<PacketOption>,
    ) -> Result<Self, ParsingError> {
        // Check that the provided options are supported
        if let Some(o) = options
            .iter()
            .map(|o| o.header.code)
            .find(|o| !OpCode::Peer.valid_option(o))
        {
            Err(ParsingError::InvalidOption(OpCode::Peer, o))
        }
        // Check that the version is supported
        else if version < 2 {
            Err(ParsingError::VersionNotSupported(version))
        } else {
            Ok(Self::new(
                RequestHeader::new(version, OpCode::Peer, lifetime, internal_address),
                PeerRequestPayload::new(
                    nonce,
                    protocol,
                    internal_port,
                    external_port,
                    external_address,
                    remote_port,
                    remote_address,
                )
                .into(),
                options,
            ))
        }
    }

    pub fn announce(version: u8, address: IpAddr) -> Self {
        Self::new(
            RequestHeader::new(version, OpCode::Announce, 0, address),
            RequestPayload::announce(),
            Vec::new(),
        )
    }
}

pub struct ResponsePacket {
    pub header: ResponseHeader,
    pub payload: ResponsePayload,
    pub options: Vec<PacketOption>,
}

pub struct ResponsePacketSlice<'a> {
    header: ResponseHeaderSlice<'a>,
    payload: ResponsePayloadSlice<'a>,
    options: Vec<PacketOptionSlice<'a>>,
}

impl<'a> ResponsePacketSlice<'a> {
    /// Returns a reference to the options in the packets
    pub fn options(&self) -> &Vec<PacketOptionSlice<'a>> {
        &self.options
    }
    /// Returns a reference to the payload data of the packet
    pub fn payload(&self) -> &ResponsePayloadSlice<'a> {
        &self.payload
    }
    /// Returns a reference to the header data of the packet
    pub fn header(&self) -> &ResponseHeaderSlice<'a> {
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
