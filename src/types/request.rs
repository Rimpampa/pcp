use crate::types::headers::RequestHeader;
use crate::types::payloads::{
    MapRequestPayload, OptionPayload, PeerRequestPayload, RequestPayload,
};
use crate::types::{OpCode, PacketOption, ParsingError, ProtocolNumber};
use std::net::IpAddr;

/// A properly constructed PCP `RequestPacket` containing a `RequestHeader`
/// a `RequestPayload` and some `PacketOption`s.
///
/// There is a limit on the number of options (more specifically on the size
/// of the packet) but on this struct you can add as many of them as you want,
/// the check will be done once the request is submitted.
///
/// There are three types of requests: `map`, `peer` and `announce`.
pub struct RequestPacket {
    pub header: RequestHeader,
    pub payload: RequestPayload,
    pub options: Vec<PacketOption>,
}

impl RequestPacket {
    /// Returns the size in bytes of the request
    pub fn size(&self) -> usize {
        RequestHeader::SIZE
            + self.payload.size()
            + self.options.iter().map(PacketOption::size).sum::<usize>()
    }

    /// Returns the byte array containing the request packet formatted correctly
    pub fn bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.size());
        buf.extend_from_slice(&self.header.bytes());
        match &self.payload {
            RequestPayload::Map(p) => buf.extend_from_slice(&p.bytes()),
            RequestPayload::Peer(p) => buf.extend_from_slice(&p.bytes()),
            RequestPayload::Announce => (),
        };
        self.options.iter().for_each(|o| {
            buf.extend_from_slice(&o.header.bytes());
            match &o.payload {
                OptionPayload::PreferFailure => (),
                OptionPayload::Filter(p) => buf.extend_from_slice(&p.bytes()),
                OptionPayload::ThidParty(p) => buf.extend_from_slice(&p.bytes()),
            }
        });
        buf
    }

    /// Constructs a PCP map request
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
            Ok(Self {
                header: RequestHeader::new(version, OpCode::Map, lifetime, internal_address),
                payload: MapRequestPayload::new(
                    nonce,
                    protocol,
                    internal_port,
                    external_port,
                    external_address,
                )
                .into(),
                options,
            })
        }
    }

    /// Constructs a PCP peer request
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
            Ok(Self {
                header: RequestHeader::new(version, OpCode::Peer, lifetime, internal_address),
                payload: PeerRequestPayload::new(
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
            })
        }
    }

    /// Constructs a PCP announce request
    pub fn announce(version: u8, address: IpAddr) -> Self {
        Self {
            header: RequestHeader::new(version, OpCode::Announce, 0, address),
            payload: RequestPayload::announce(),
            options: Vec::new(),
        }
    }
}
