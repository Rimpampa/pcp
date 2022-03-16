use super::*;
use crate::ProtocolNumber;
use std::{
    convert::{TryFrom, TryInto},
    net::Ipv6Addr,
};

/// Maximum size a PCP packet can have
pub const MAX_PACKET_SIZE: usize = 1100;

// =========================================== OPTIONS ============================================

#[derive(PartialEq, Debug)]
pub enum OptionPayload {
    Filter(FilterOptionPayload),
    ThirdParty(ThirdPartyOptionPayload),
    PreferFailure,
}

impl OptionPayload {
    fn size(&self) -> usize {
        match self {
            Self::Filter(_) => FilterOptionPayload::SIZE,
            Self::ThirdParty(_) => ThirdPartyOptionPayload::SIZE,
            Self::PreferFailure => 0,
        }
    }
}

/// A correctly formed PCP packet option
#[derive(PartialEq, Debug)]
pub struct PacketOption {
    pub header: OptionHeader,
    pub payload: OptionPayload,
}

impl PacketOption {
    /// Constructs a filter option
    ///
    /// This option is used to filter the address of remote peers using the mapping
    pub fn filter(prefix: u8, remote_port: u16, remote_addr: Ipv6Addr) -> Self {
        Self {
            header: OptionHeader::filter(),
            payload: OptionPayload::Filter(FilterOptionPayload {
                prefix,
                remote_port,
                remote_addr,
            }),
        }
    }

    /// Constructs a third party option
    ///
    /// This options informs the PCP server that the packet is creating a mapping
    /// on behalf of another host
    pub fn third_party(address: Ipv6Addr) -> Self {
        Self {
            header: OptionHeader::third_party(),
            payload: OptionPayload::ThirdParty(ThirdPartyOptionPayload { address }),
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

impl TryFrom<&[u8]> for PacketOption {
    type Error = ParsingError;

    fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
        let header = OptionHeader::try_from(slice)?;
        let slice = &slice[OptionHeader::SIZE..];
        let payload = match header.code {
            OptionCode::Filter => OptionPayload::ThirdParty(slice.try_into()?),
            OptionCode::ThirdParty => OptionPayload::ThirdParty(slice.try_into()?),
            OptionCode::PreferFailure => OptionPayload::PreferFailure,
        };
        Ok(Self { header, payload })
    }
}

// =========================================== REQUESTS ===========================================

/// TODO
#[derive(PartialEq, Debug)]
pub enum RequestPayload {
    Map(MapRequestPayload),
    Peer(PeerRequestPayload),
    Announce,
}

impl RequestPayload {
    fn size(&self) -> usize {
        match self {
            RequestPayload::Map(_) => MapRequestPayload::SIZE,
            RequestPayload::Peer(_) => PeerRequestPayload::SIZE,
            RequestPayload::Announce => 0,
        }
    }
}

/// A properly constructed PCP request packet.
#[derive(PartialEq, Debug)]
pub struct RequestPacket {
    pub header: RequestHeader,
    pub payload: RequestPayload,
    pub options: Vec<PacketOption>,
}

impl RequestPacket {
    /// PCP packets cannot be bigger than [`MAX_PACKET_SIZE`]
    fn check_size(self) -> Result<Self, ParsingError> {
        if self.size() > MAX_PACKET_SIZE {
            return Err(ParsingError::PacketTooBig(self.size()));
        }
        Ok(self)
    }

    /// Returns the size in bytes of the request
    pub fn size(&self) -> usize {
        RequestHeader::SIZE
            + self.payload.size()
            + self.options.iter().map(PacketOption::size).sum::<usize>()
    }

    /// Fills the byte array with the request packet formatted correctly
    pub fn copy_to(&self, mut s: &mut [u8]) {
        assert!(s.len() >= self.size());

        self.header.copy_to(&mut s);
        s = &mut s[self.header.size()..];

        match &self.payload {
            RequestPayload::Map(p) => p.copy_to(s),
            RequestPayload::Peer(p) => p.copy_to(s),
            RequestPayload::Announce => (),
        };
        s = &mut s[self.payload.size()..];

        for option in &self.options {
            match &option.payload {
                OptionPayload::PreferFailure => (),
                OptionPayload::Filter(p) => p.copy_to(s),
                OptionPayload::ThirdParty(p) => p.copy_to(s),
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
        protocol: Option<ProtocolNumber>,
        internal_port: u16,
        external_port: u16,
        external_addr: Ipv6Addr,
        options: Vec<PacketOption>,
    ) -> Result<Self, ParsingError> {
        // Check that the provided options are supported by the opcode
        for option in &options {
            let code = option.header.code;
            if !OpCode::Map.is_option_valid(code) {
                return Err(ParsingError::InvalidOption(OpCode::Map, code));
            }
        }
        // Check that the version is supported
        if version < 2 {
            return Err(ParsingError::VersionNotSupported(version));
        }
        let payload =
            MapRequestPayload::new(nonce, protocol, internal_port, external_port, external_addr);

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
        protocol: Option<ProtocolNumber>,
        internal_port: u16,
        external_port: u16,
        external_addr: Ipv6Addr,
        remote_port: u16,
        remote_addr: Ipv6Addr,
        options: Vec<PacketOption>,
    ) -> Result<Self, ParsingError> {
        // Check that the provided options are supported by the opcode
        for option in &options {
            let code = option.header.code;
            if !OpCode::Map.is_option_valid(code) {
                return Err(ParsingError::InvalidOption(OpCode::Map, code));
            }
        }
        // Check that the version is supported
        if version < 2 {
            return Err(ParsingError::VersionNotSupported(version));
        }
        let payload = PeerRequestPayload::new(
            nonce,
            protocol,
            internal_port,
            external_port,
            external_addr,
            remote_port,
            remote_addr,
        );
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
    type Error = ParsingError;

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
                return Err(ParsingError::InvalidOption(header.opcode, code));
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
                /*
                    After performing common PCP response processing, the response is
                    further matched with a previously sent MAP request by comparing the
                    internal IP address (the destination IP address of the PCP response,
                    or other IP address specified via the THIRD_PARTY option), the
                    protocol, the internal port, and the mapping nonce.  Other fields are
                    not compared, because the PCP server sets those fields.  The PCP
                    server will send a Mapping Update (Section 14.2) if the mapping
                    changes (e.g., due to IP renumbering).
                */
                (res.protocol == req.protocol || res.protocol == ProtocolNumber::Hopopt)
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
