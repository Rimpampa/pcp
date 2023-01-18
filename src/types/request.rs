use super::*;
use crate::{types::util::Serialize, ProtocolNumber};
use std::convert::{TryFrom, TryInto};

/// Maximum size a PCP packet can have
pub const MAX_PACKET_SIZE: usize = 1100;

const MAX_REQUEST_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - RequestHeader::SIZE;

const MAX_RESPONSE_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - ResponseHeader::SIZE;

/// Generic payload + options data strcuture
///
/// This struct contains the payload as a parsed value of type `T`
/// and the options as an array of `SIZE` bytes.
///
/// The options are not parsed because it cannot be known how many of
/// them there will be and of what type, use the [`options()`] method
/// to parse them.
#[derive(PartialEq, Debug)]
pub struct Payload<T, const SIZE: usize> {
    /// Parsed payload data
    pub data: T,
    /// Raw options
    pub raw_options: ([u8; SIZE], usize),
}

pub type MapPayload =
    Payload<MapRequestPayload, { MAX_REQUEST_PAYLOAD_SIZE - MapRequestPayload::SIZE }>;

pub type PeerPayload =
    Payload<PeerRequestPayload, { MAX_REQUEST_PAYLOAD_SIZE - PeerRequestPayload::SIZE }>;

pub type AnnouncePayload = Payload<(), MAX_REQUEST_PAYLOAD_SIZE>;

/// PCP request payload
///
/// This enum has a discriminant for each [`OpCode`]
/// which contains the payload and the options requested.
///
/// The tag of this _tagged enum_ could be compared to the `Opcode`
/// field of the request header (check [`RequestPacket`])
#[derive(PartialEq, Debug)]
pub enum RequestPayload {
    /// Payload data for a **map** request
    Map(MapPayload),
    /// Payload data for a **peer** request
    Peer(PeerPayload),
    /// Payload data for a **announce** request
    Announce(AnnouncePayload),
}

/// PCP request packet
///
/// # Format
///
/// ```plain
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Version = 2  |R|   Opcode    |         Reserved              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Requested Lifetime (32 bits)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |            PCP Client's IP Address (128 bits)                 |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                                                               :
/// :             (optional) Opcode-specific information            :
/// :                                                               :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                                                               :
/// :             (optional) PCP Options                            :
/// :                                                               :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub struct RequestPacket {
    /// The version of the PCP protocol
    ///
    /// This field is used for version negotiation,
    /// PCP clients and servers compliant with the RFC 6887
    /// use the value 2
    pub version: u8,
    /// Requested lifetime, in seconds
    pub lifetime: u32,
    /// The source IP address used by the PCP client when
    /// sending this PCP request
    ///
    /// An IPv4 address is represented using an IPv4-mapped IPv6 address,
    /// check [`Ipv4Addr::to_ipv6_mapped()`](std::net::Ipv4Addr::to_ipv6_mapped()).
    ///
    /// The PCP Client IP Address in the PCP message header is used to
    /// detect an unexpected NAT on the path between the PCP client and
    /// the PCP-controlled NAT or firewall device.
    pub address: Ipv6Addr,
    /// Wrapper around the payload and the options
    pub payload: RequestPayload,
}

impl RequestPacket {
    /// Fills the byte array with the request packet formatted correctly
    pub fn serialize(&self, mut s: &mut [u8]) {
        assert!(s.len() >= self.size());

        self.header.serialize(&mut s);
        s = &mut s[self.header.size()..];

        match &self.payload {
            RequestPayload::Map(p) => p.se(s),
            RequestPayload::Peer(p) => p.se(s),
            RequestPayload::Announce => (),
        };
        s = &mut s[self.payload.size()..];

        for option in &self.options {
            match &option.payload {
                OptionPayload::PreferFailure => (),
                OptionPayload::Filter(p) => p.serialize(s),
                OptionPayload::ThirdParty(p) => p.serialize(s),
            };
            s = &mut s[option.size()..];
        }
    }

    /// Constructs a PCP map request
    pub fn map(
        version: u8,
        lifetime: u32,
        internal_addr: Ipv6Addr,
        nonce: [u8; 12],
        protocol: ProtocolNumber,
        internal_port: u16,
        external_port: u16,
        external_addr: Ipv6Addr,
        options: Vec<PacketOption>,
    ) -> Result<Self, Error> {
        // Check that the provided options are supported by the opcode
        for option in &options {
            let code = option.header.code;
            if !OpCode::Map.is_option_valid(code) {
                return Err(Error::InvalidOption(OpCode::Map, code));
            }
        }
        // Check that the version is supported
        if version < 2 {
            return Err(Error::VersionNotSupported(version));
        }
        let payload = MapRequestPayload {
            nonce,
            protocol,
            internal_port,
            external_port,
            external_addr,
        };

        Self {
            header: RequestHeader::map(version, lifetime, internal_addr),
            payload: RequestPayload::Map(payload),
            options,
        }
        .check_size()
    }

    /// Constructs a PCP peer request
    pub fn peer(
        version: u8,
        lifetime: u32,
        internal_addr: Ipv6Addr,
        nonce: [u8; 12],
        protocol: ProtocolNumber,
        internal_port: u16,
        external_port: u16,
        external_addr: Ipv6Addr,
        remote_port: u16,
        remote_addr: Ipv6Addr,
        options: Vec<PacketOption>,
    ) -> Result<Self, Error> {
        // Check that the provided options are supported by the opcode
        for option in &options {
            let code = option.header.code;
            if !OpCode::Map.is_option_valid(code) {
                return Err(Error::InvalidOption(OpCode::Map, code));
            }
        }
        // Check that the version is supported
        if version < 2 {
            return Err(Error::VersionNotSupported(version));
        }
        let payload = PeerRequestPayload {
            nonce,
            protocol,
            internal_port,
            external_port,
            external_addr,
            remote_port,
            remote_addr,
        };
        Self {
            header: RequestHeader::peer(version, lifetime, internal_addr),
            payload: RequestPayload::Peer(payload),
            options,
        }
        .check_size()
    }

    /// Constructs a PCP announce request
    pub fn announce(version: u8, address: Ipv6Addr) -> Self {
        Self {
            header: RequestHeader::announce(version, address),
            payload: RequestPayload::Announce,
            options: Vec::new(),
        }
    }
}

// ========================================== RESPONESES ==========================================

/// TODO
#[derive(PartialEq, Debug)]
pub enum ResponsePayload {
    Map(MapResponsePayload),
    Peer(PeerResponsePayload),
    Announce,
}

impl ResponsePayload {
    pub fn size(&self) -> usize {
        match self {
            ResponsePayload::Map(_) => MapResponsePayload::SIZE,
            ResponsePayload::Peer(_) => PeerResponsePayload::SIZE,
            ResponsePayload::Announce => 0,
        }
    }
}

/// A correctly formed PCP response packet.
#[derive(PartialEq, Debug)]
pub struct ResponsePacket {
    pub header: ResponseHeader,
    pub payload: ResponsePayload,
    pub options: Vec<PacketOption>,
}

impl TryFrom<&[u8]> for ResponsePacket {
    type Error = Error;

    fn try_from(mut slice: &[u8]) -> Result<Self, Self::Error> {
        // Check if the header is valid
        let header = ResponseHeader::try_from(slice)?;

        slice = &slice[ResponseHeader::SIZE..];

        // Check if the payload is valid
        let payload = match header.opcode {
            OpCode::Map => ResponsePayload::Map(slice.try_into()?),
            OpCode::Peer => ResponsePayload::Peer(slice.try_into()?),
            OpCode::Announce => ResponsePayload::Announce,
        };
        slice = &slice[payload.size()..];

        let mut options = Vec::new();
        // Check for possible options
        while !slice.is_empty() {
            let option = PacketOption::try_from(slice)?;
            slice = &slice[option.size()..];
            // Check if the option is valid for this opcode
            // As I'm parsing this slice, there is no way it could be
            let code = option.header.code;
            if !header.opcode.is_option_valid(code) {
                return Err(Error::InvalidOption(header.opcode, code));
            }
            options.push(option);
        }
        Ok(Self {
            header,
            payload,
            options,
        })
    }
}

impl PartialEq<RequestPacket> for ResponsePacket {
    fn eq(&self, other: &RequestPacket) -> bool {
        use RequestPayload as Req;
        use ResponsePayload as Res;

        let check_payload = match (&self.payload, &other.payload) {
            (Res::Announce, Req::Announce) => true,
            (Res::Map(res), Req::Map(req)) => {
                // Do not check the external address as the server can choose anything
                res.protocol == req.protocol
                    && (res.external_port == req.external_port || req.external_port == 0)
                    && res.internal_port == req.internal_port
                    && res.nonce == req.nonce
            }
            (Res::Peer(res), Req::Peer(req)) => {
                res.protocol == req.protocol
                    && (res.external_port == req.external_port || req.external_port == 0)
                    && res.internal_port == req.internal_port
                    && res.nonce == req.nonce
                    && res.remote_addr == req.remote_addr
                    && res.remote_port == req.remote_port
            }
            _ => false,
        };

        self.header.opcode == other.header.opcode
            && self.header.version == other.header.version
            && check_payload
    }
}

impl PartialEq<ResponsePacket> for RequestPacket {
    fn eq(&self, other: &ResponsePacket) -> bool {
        other == self
    }
}
