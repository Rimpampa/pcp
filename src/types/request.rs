use std::{net::Ipv6Addr, num::NonZeroU16};

use crate::types::{util, ProtocolNumber};
use util::{Deserialize, DeserializeSkip, Serialize};

use super::{Error, OpCode};

/// Maximum size a PCP packet can have
pub const MAX_PACKET_SIZE: usize = 1100;

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
    /// [`Ipv4Addr::UNSPECIFIED`] for IPv4 and [`Ipv6Addr::UNSPECIFIED`] for IPv6.
    ///
    /// An IPv6 address is represented directly, and an IPv4 address is represented
    /// using the IPv4-mapped address syntax, check [`Ipv4Addr::to_ipv6_mapped`].
    ///
    /// [`Ipv4Addr::UNSPECIFIED`]: std::net::Ipv4Addr::UNSPECIFIED
    /// [`Ipv6Addr::UNSPECIFIED`]: std::net::Ipv6Addr::UNSPECIFIED
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
    /// [`Ipv4Addr::UNSPECIFIED`] for IPv4 and [`Ipv6Addr::UNSPECIFIED`] for IPv6.
    ///
    /// An IPv6 address is represented directly, and an IPv4 address is represented
    /// using the IPv4-mapped address syntax, check [`Ipv4Addr::to_ipv6_mapped`].
    ///
    /// [`Ipv4Addr::UNSPECIFIED`]: std::net::Ipv4Addr::UNSPECIFIED
    /// [`Ipv6Addr::UNSPECIFIED`]: std::net::Ipv6Addr::UNSPECIFIED
    pub suggested_external_addr: Ipv6Addr,
    /// Remote peer's port for the mapping
    pub remote_peer_port: NonZeroU16,
    /// Remote peer's IP address.
    /// 
    /// This is from the perspective of the PCP client,
    /// so that the PCP client does not need to concern itself with
    /// NAT64 or NAT46 (which both cause the client's idea of the
    /// remote peer's IP address to differ from the remote peer's actual
    /// IP address).
    /// 
    /// This field allows the PCP client and PCP server to disambiguate multiple
    /// connections from the same port on the internal host to different servers.
    /// 
    /// An IPv6 address is represented directly, and an IPv4 address is represented
    /// using the IPv4-mapped address syntax, check [`Ipv4Addr::to_ipv6_mapped`].
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
            .se(u16::from(peer.remote_peer_port))?
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
            remote_peer_port: NonZeroU16::new(self.de()?).ok_or(Error::ZeroRemotePeerPort)?,
            remote_peer_addr: self.skip(2)?.de()?,
        })
    }
}

/// Payload + raw options pair
///
/// This struct contains the payload as a parsed value of type `T`
/// and the options as an array of bytes that should be big enough to
/// hold the maximum size of the options given the [`MAX_PACKET_SIZE`]
/// limit.
///
/// The options are not parsed because it cannot be known how many of
/// them there will be and of what type, use the [`options()`] method
/// to get an iterator of parsed options.
#[derive(PartialEq, Debug)]
pub struct Payload<T, const SIZE: usize> {
    /// Parsed payload data
    pub data: T,
    /// Raw options
    pub raw_options: heapless::Vec<u8, SIZE>,
}

/// Returns the maximum size the options can take up in the packet,
/// considering the given payload size and the constant header size
const fn max_options_size(payload_size: usize) -> usize {
    MAX_PACKET_SIZE - Request::HEADER_SIZE - payload_size
}

/// [`Payload`] for a PCP map request
pub type MapPayload = Payload<Map, { max_options_size(Map::SIZE) }>;

/// [`Payload`] for a PCP peer request
pub type PeerPayload = Payload<Peer, { max_options_size(Peer::SIZE) }>;

/// [`Payload`] for a PCP announce request
pub type AnnouncePayload = Payload<(), { max_options_size(0) }>;

impl<T, const SIZE: usize> Serialize<Payload<T, SIZE>> for [u8]
where
    [u8]: Serialize<T> + for<'a> Serialize<&'a [u8]>,
{
    fn se(&mut self, payload: Payload<T, SIZE>) -> util::Result<&mut Self> {
        self.se(payload.data)?.se(payload.raw_options.as_slice())
    }
}

impl<T, const SIZE: usize> Deserialize<Payload<T, SIZE>> for &[u8]
where
    for<'a> &'a [u8]: Deserialize<T> + Deserialize<heapless::Vec<u8, SIZE>>,
{
    fn de(&mut self) -> util::Result<Payload<T, SIZE>> {
        Ok({
            Payload {
                data: self.de()?,
                raw_options: self.de()?,
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
    /// Returns the [`OpCode`] of this request
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
    /// Size of the PCP request header in bytes
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
