// TODO: questi non dovrebbero essere pubblici
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
pub use slorp::{Parsable, Slorp};

pub use headers::{OptionHeaderType, RequestHeader, ResponseHeaderType};
pub use payloads::{OptionPayload, RequestPayload, ResponsePayload};

use headers::*;
use payloads::*;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// /// Trait used in order to have mulitple parameters that are address of the same version (both IPv4
// /// or both IPv6).
// pub trait IpAddress: Into<IpAddr> {}
// impl IpAddress for Ipv4Addr {}
// impl IpAddress for Ipv6Addr {}

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

pub struct PacketOption<'a> {
    header: OptionHeaderType<'a>,
    payload: OptionPayload<'a>,
}

impl<'a> PacketOption<'a> {
    fn new(header: OptionHeaderType<'a>, payload: OptionPayload<'a>) -> Self {
        Self { header, payload }
    }

    pub fn filter(prefix: u8, remote_port: u16, remote_address: IpAddr) -> Self {
        Self::new(
            Slorp::Parsed(OptionHeader::filter()),
            OptionPayload::filter(prefix, remote_port, remote_address),
        )
    }
    pub fn third_party(address: IpAddr) -> Self {
        Self::new(
            Slorp::Parsed(OptionHeader::third_party()),
            OptionPayload::third_party(address),
        )
    }
    pub fn prefer_failure() -> Self {
        Self::new(
            Slorp::Parsed(OptionHeader::prefer_failure()),
            OptionPayload::PreferFailure,
        )
    }
    /// Returns the size of the option
    pub fn size(&self) -> usize {
        OptionHeader::SIZE + self.payload.size()
    }
    /// Returns a reference to the payload data of the packet
    pub fn payload(&self) -> &OptionPayload<'a> {
        &self.payload
    }
    /// Returns a reference to the header data of the packet
    pub fn header(&self) -> &OptionHeaderType<'a> {
        &self.header
    }
}

impl<'a> TryFrom<&'a [u8]> for PacketOption<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        let header = OptionHeaderSlice::try_from(slice)?;
        let payload = match header.code() {
            // try to parse the filter option payload
            OptionCode::Filter => Slorp::Slice(FilterOptionPayloadSlice::try_from(
                &slice[OptionHeader::SIZE..],
            )?)
            .into(),
            // try to parse the third party option payload
            OptionCode::ThirdParty => Slorp::Slice(ThirdPartyOptionPayloadSlice::try_from(
                &slice[OptionHeader::SIZE..],
            )?)
            .into(),
            // there is no payload, so just return the enum value
            OptionCode::PreferFailure => OptionPayload::PreferFailure,
        };
        Ok(Self {
            header: Slorp::Slice(header),
            payload,
        })
    }
}

pub struct RequestPacket<'a> {
    pub header: RequestHeader,
    pub payload: RequestPayload,
    // maybe use Vec<PacketOption<'a>>
    pub options: &'a[PacketOption<'a>],
}

impl<'a> RequestPacket<'a> {
    fn new(header: RequestHeader, payload: RequestPayload, options: &'a[PacketOption<'a>]) -> Self {
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
        options: &'a[PacketOption<'a>],
    ) -> Result<Self, ParsingError> {
		// Check that the provided options are supported
        if let Some(o) = options
            .iter()
            .map(|o| o.header().code())
            .find(|o| !OpCode::Map.valid_option(o))
        {
            ParsingError::InvalidOption(OpCode::Map, o).into()
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
		options: &'a[PacketOption<'a>]
	) -> Result<Self, ParsingError> {
		// Check that the provided options are supported
        if let Some(o) = options
            .iter()
            .map(|o| o.header().code())
            .find(|o| !OpCode::Peer.valid_option(o))
        {
            ParsingError::InvalidOption(OpCode::Peer, o).into()
		}
		// Check that the version is supported
		else if version < 2 {
			Err(ParsingError::VersionNotSupported(version))
		} else {
			Ok(Self::new(
				RequestHeader::new(version, OpCode::Peer, lifetime, internal_address),
				PeerRequestPayload::new(nonce, protocol, internal_port, external_port, external_address, remote_port, remote_address).into(),
				options
			))
		}
	}

	pub fn announce(version: u8, address: IpAddr) -> Self {
		Self::new(
			RequestHeader::new(version, OpCode::Announce, 0, address),
			RequestPayload::announce(),
			&[]
		)
	}
}

pub struct ResponsePacket<'a> {
    header: ResponseHeaderType<'a>,
    payload: ResponsePayload<'a>,
    options: Vec<PacketOption<'a>>,
}

impl<'a> ResponsePacket<'a> {
    /// Returns a reference to the options in the packets
    pub fn options(&self) -> &Vec<PacketOption<'a>> {
        &self.options
    }
    /// Returns a reference to the payload data of the packet
    pub fn payload(&self) -> &ResponsePayload<'a> {
        &self.payload
    }
    /// Returns a reference to the header data of the packet
    pub fn header(&self) -> &ResponseHeaderType<'a> {
        &self.header
    }
}

impl<'a> TryFrom<&'a [u8]> for ResponsePacket<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<Self, Self::Error> {
        // Check if the header is valid
        let header = ResponseHeaderSlice::try_from(slice)?;

        let mut at = ResponseHeader::SIZE;

        let opcode = header.opcode();
        // Check if the payload is valid
        let payload = match opcode {
            OpCode::Map => Slorp::Slice(MapResponsePayloadSlice::try_from(&slice[at..])?).into(),
            OpCode::Peer => Slorp::Slice(PeerResponsePayloadSlice::try_from(&slice[at..])?).into(),
            OpCode::Announce => ResponsePayload::Announce,
        };
        let mut options = Vec::new();
        at += payload.size();

        // Check for possible options
        while at < slice.len() {
            let option = PacketOption::try_from(&slice[at..])?;
            // Check if the option is valid for this opcode
            let option_code = &option.header().slice_ref().unwrap().code();
            if !opcode.valid_option(option_code) {
                return ParsingError::InvalidOption(opcode, *option_code).into();
            }
            at += option.size();
            options.push(option);
        }
        Ok(Self {
            header: Slorp::Slice(header),
            payload,
            options,
        })
    }
}
