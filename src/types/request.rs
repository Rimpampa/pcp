use std::net::Ipv6Addr;

use crate::types::{util, ProtocolNumber};
use util::{Deserialize, DeserializeSkip, Serialize};

use super::{Error, OpCode};

/// Maximum size a PCP packet can have
pub const MAX_PACKET_SIZE: usize = 1100;

const MAX_REQUEST_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - Request::HEADER_SIZE;

// const MAX_RESPONSE_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - ResponseHeader::SIZE;

pub type Nonce = [u8; 12];

/// PCP map request payload
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                 Mapping Nonce (96 bits)                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Protocol    |          Reserved (24 bits)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Internal Port          |    Suggested External Port    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |           Suggested External IP Address (128 bits)            |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub struct Map {
    /// Random value chosen by the PCP client
    pub mapping_nonce: Nonce,
    /// Upper-layer protocol associated with this mapping
    ///
    /// The value [`ProtocolNumber::Hopopt`] (0) has a special
    /// meaning for _all protocols_.
    pub protocol: ProtocolNumber,
    /// Internal port for the mapping
    ///
    /// The value `0` indicates _all ports_, and is legal when the lifetime
    /// is zero (a delete request), if the protocol does not use 16-bit
    /// port numbers, or the client is requesting _all ports_.
    ///
    /// If the `protocol` is [`ProtocolNumber::Hopopt`] (zero, meaning _all protocols_),
    /// then internal port **must** be zero on transmission and **must** be
    /// ignored on reception.
    pub internal_port: u16,
    /// Suggested external port for the mapping
    ///
    /// This is useful for refreshing a mapping, especially after the PCP
    /// server loses state.
    ///
    /// If the PCP client does not know the external
    /// port, or does not have a preference, it **must** use 0.
    pub suggested_external_port: u16,
    /// Suggested external IPv4 or IPv6 address
    ///
    /// This is useful for refreshing a mapping, especially
    /// after the PCP server loses state.
    ///
    /// If the PCP client does not know
    /// the external address, or does not have a preference, it **must** use
    /// the address-family-specific all-zeros address, which is
    /// [`Ipv4Addr::UNSPECIFIED`](std::net::Ipv4Addr::UNSPECIFIED) for IPv4 and
    /// [`Ipv6Addr::UNSPECIFIED`](std::net::Ipv6Addr::UNSPECIFIED) for IPv6
    pub suggested_external_addr: Ipv6Addr,
}

impl Map {
    pub const SIZE: usize = 36;
}

impl Serialize<Map> for [u8] {
    fn se(self: &mut Self, map: Map) -> util::Result<&mut Self> {
        self.se(map.mapping_nonce)?
            .se(map.protocol as u8)?
            .se([0; 3])?
            .se(map.internal_port)?
            .se(map.suggested_external_port)?
            .se(map.suggested_external_addr)
    }
}

impl Deserialize<Map> for &[u8] {
    fn de(&mut self) -> util::Result<Map> {
        Ok(Map {
            mapping_nonce: self.de()?,
            protocol: self.de()?,
            internal_port: self.skip(3)?.de()?,
            suggested_external_port: self.de()?,
            suggested_external_addr: self.de()?,
        })
    }
}

/// PCP peer request payload
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                 Mapping Nonce (96 bits)                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Protocol    |          Reserved (24 bits)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Internal Port          |    Suggested External Port    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |           Suggested External IP Address (128 bits)            |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Remote Peer Port        |     Reserved (16 bits)        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |               Remote Peer IP Address (128 bits)               |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub struct Peer {
    /// Random value chosen by the PCP client
    pub mapping_nonce: Nonce,
    /// Upper-layer protocol associated with this mapping
    ///
    /// The value [`ProtocolNumber::Hopopt`] (0) has a special
    /// meaning for _all protocols_.
    pub protocol: ProtocolNumber,
    /// Internal port for the mapping
    ///
    /// The value `0` indicates _all ports_, and is legal when the lifetime
    /// is zero (a delete request), if the protocol does not use 16-bit
    /// port numbers, or the client is requesting _all ports_.
    ///
    /// If the `protocol` is [`ProtocolNumber::Hopopt`] (zero, meaning _all protocols_),
    /// then internal port **must** be zero on transmission and **must** be
    /// ignored on reception.
    pub internal_port: u16,
    /// Suggested external port for the mapping
    ///
    /// This is useful for refreshing a mapping, especially after the PCP
    /// server loses state.
    ///
    /// If the PCP client does not know the external
    /// port, or does not have a preference, it **must** use 0.
    pub suggested_external_port: u16,
    /// Suggested external IPv4 or IPv6 address
    ///
    /// This is useful for refreshing a mapping, especially
    /// after the PCP server loses state.
    ///
    /// If the PCP client does not know
    /// the external address, or does not have a preference, it **must** use
    /// the address-family-specific all-zeros address, which is
    /// [`Ipv4Addr::UNSPECIFIED`](std::net::Ipv4Addr::UNSPECIFIED) for IPv4 and
    /// [`Ipv6Addr::UNSPECIFIED`](std::net::Ipv6Addr::UNSPECIFIED) for IPv6
    pub suggested_external_addr: Ipv6Addr,
    pub remote_peer_port: u16,
    pub remote_peer_addr: Ipv6Addr,
}

impl Peer {
    pub const SIZE: usize = 56;
}

impl Serialize<Peer> for [u8] {
    fn se(self: &mut Self, peer: Peer) -> util::Result<&mut Self> {
        self.se(peer.mapping_nonce)?
            .se(peer.protocol as u8)?
            .se([0; 3])?
            .se(peer.internal_port)?
            .se(peer.suggested_external_port)?
            .se(peer.suggested_external_addr)?
            .se(peer.remote_peer_port)?
            .se([0; 2])?
            .se(peer.remote_peer_addr)
    }
}

impl Deserialize<Peer> for &[u8] {
    fn de(&mut self) -> util::Result<Peer> {
        Ok(Peer {
            mapping_nonce: self.de()?,
            protocol: self.de()?,
            internal_port: self.skip(3)?.de()?,
            suggested_external_port: self.de()?,
            suggested_external_addr: self.de()?,
            remote_peer_port: self.de()?,
            remote_peer_addr: self.skip(2)?.de()?,
        })
    }
}

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

pub type MapPayload = Payload<Map, { MAX_REQUEST_PAYLOAD_SIZE - Map::SIZE }>;

pub type PeerPayload = Payload<Peer, { MAX_REQUEST_PAYLOAD_SIZE - Peer::SIZE }>;

pub type AnnouncePayload = Payload<[u8; 0], MAX_REQUEST_PAYLOAD_SIZE>;

impl<T, const SIZE: usize> Serialize<Payload<T, SIZE>> for [u8]
where
    [u8]: Serialize<T> + for<'a> Serialize<&'a [u8]>,
{
    fn se(&mut self, payload: Payload<T, SIZE>) -> util::Result<&mut Self> {
        let (opt, len) = &payload.raw_options;
        self.se(payload.data)?.se(&opt[..*len])
    }
}

impl<T, const SIZE: usize> Deserialize<Payload<T, SIZE>> for [u8]
where
    [u8]: Deserialize<T>,
{
    fn de(&mut self) -> util::Result<Payload<T, SIZE>> {
        let data = self.de()?;
        if self.len() > SIZE {
            return Err(Error::InvalidSliceSize(self.len(), SIZE))
        }
        let mut array = [0; SIZE];
        array[..self.len()].copy_from_slice(self);
        Ok({
            Payload {
                data,
                raw_options: (array, self.len()),
            }
        })
    }
}

/// PCP request payload
///
/// This enum has a discriminant for each [`OpCode`]
/// which contains the payload and the options requested.
///
/// The tag of this enum could be compared to the `Opcode`
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

impl RequestPayload {
    pub const fn opcode(&self) -> OpCode {
        match self {
            Self::Map(_) => OpCode::Map,
            Self::Peer(_) => OpCode::Peer,
            Self::Announce(_) => OpCode::Announce,
        }
    }
}

/// PCP request packet
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
pub struct Request {
    /// The version of the PCP protocol
    ///
    /// This field is used for version negotiation,
    /// PCP clients and servers compliant with the RFC 6887
    /// use the value `2`
    pub version: u8,
    /// Requested lifetime of this mapping, in seconds
    ///
    /// The value 0 indicates _delete_
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

impl Request {
    pub const HEADER_SIZE: usize = 24;
}

impl Serialize<Request> for [u8] {
    fn se(mut self: &mut Self, req: Request) -> util::Result<&mut Self> {
        self = self
            .se(req.version)?
            .se(req.payload.opcode() as u8 & 0b01111111)?
            .se([0; 2])?
            .se(req.lifetime)?
            .se(req.address)?;
        match req.payload {
            RequestPayload::Map(p) => self.se(p),
            RequestPayload::Peer(p) => self.se(p),
            RequestPayload::Announce(p) => self.se(p),
        }
    }
}

impl Deserialize<Request> for &[u8] {
    fn de(&mut self) -> util::Result<Request> {
        let version = self.de()?;
        let opcode = self.de()?;
        let lifetime = self.skip(2)?.de()?;
        let address = self.de()?;
        let payload = match opcode {
            OpCode::Map => RequestPayload::Map(self.de()?),
            OpCode::Peer => RequestPayload::Peer(self.de()?),
            OpCode::Announce => RequestPayload::Announce(self.de()?),
        };
        Ok(Request {
            version,
            lifetime,
            address,
            payload,
        })
    }
}
