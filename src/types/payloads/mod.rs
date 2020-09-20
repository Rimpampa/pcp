//! This module contains all the payloads described in the RFC

mod filter_option;
mod map_request;
mod map_response;
mod peer_request;
mod peer_response;
mod third_party_option;

pub use filter_option::{FilterOptionPayload, FilterOptionPayloadSlice};
pub use map_request::MapRequestPayload;
pub use map_response::{MapResponsePayload, MapResponsePayloadSlice};
pub use peer_request::PeerRequestPayload;
pub use peer_response::{PeerResponsePayload, PeerResponsePayloadSlice};
pub use third_party_option::{ThirdPartyOptionPayload, ThirdPartyOptionPayloadSlice};

use super::{Parsable, ProtocolNumber};
use std::net::IpAddr;

/// An enum containing a PCP option payload
///
/// Currently supported option payloads are: filter, third party and prefer failure.
#[derive(PartialEq, Debug)]
pub enum OptionPayload {
    Filter(FilterOptionPayload),
    ThidParty(ThirdPartyOptionPayload),
    PreferFailure,
}

impl OptionPayload {
    /// Returns the size in bytes of the payload
    pub const fn size(&self) -> usize {
        match self {
            Self::Filter(_) => FilterOptionPayload::SIZE,
            Self::ThidParty(_) => ThirdPartyOptionPayload::SIZE,
            Self::PreferFailure => 0,
        }
    }

    /// Constructs a new filter option payload (see `FilterOptionPayload`)
    pub const fn filter(prefix: u8, remote_port: u16, remote_address: IpAddr) -> Self {
        Self::Filter(FilterOptionPayload::new(
            prefix,
            remote_port,
            remote_address,
        ))
    }

    /// Constructs a new third party option payload (see `ThirdPartyOptionPayload`)
    pub const fn third_party(address: IpAddr) -> Self {
        Self::ThidParty(ThirdPartyOptionPayload::new(address))
    }

    /// Constructs a new prefer failure option payload
    pub const fn prefer_failure() -> Self {
        Self::PreferFailure
    }
}

impl From<FilterOptionPayload> for OptionPayload {
    fn from(val: FilterOptionPayload) -> Self {
        Self::Filter(val)
    }
}

impl From<ThirdPartyOptionPayload> for OptionPayload {
    fn from(val: ThirdPartyOptionPayload) -> Self {
        Self::ThidParty(val)
    }
}

/// A zero-copy type containing a valid PCP option payload. It can be obtained via the
/// `try_from` method (from the `std::TryFrom` trait) from a slice containing
/// a valid sequence of bytes.
pub enum OptionPayloadSlice<'a> {
    Filter(FilterOptionPayloadSlice<'a>),
    ThidParty(ThirdPartyOptionPayloadSlice<'a>),
    PreferFailure,
}

impl OptionPayloadSlice<'_> {
    /// Returns the size in bytes of the option payload
    pub const fn size(&self) -> usize {
        match self {
            Self::Filter(_) => FilterOptionPayload::SIZE,
            Self::ThidParty(_) => ThirdPartyOptionPayload::SIZE,
            Self::PreferFailure => 0,
        }
    }

    /// Returns the inner slice
    pub const fn slice(&self) -> &[u8] {
        match self {
            Self::Filter(p) => p.slice(),
            Self::PreferFailure => &[],
            Self::ThidParty(p) => p.slice(),
        }
    }
}

impl Parsable for OptionPayloadSlice<'_> {
    type Parsed = OptionPayload;

    fn parse(&self) -> Self::Parsed {
        match self {
            Self::Filter(p) => OptionPayload::Filter(p.parse()),
            Self::ThidParty(p) => OptionPayload::ThidParty(p.parse()),
            Self::PreferFailure => OptionPayload::PreferFailure,
        }
    }
}

impl<'a> From<FilterOptionPayloadSlice<'a>> for OptionPayloadSlice<'a> {
    fn from(val: FilterOptionPayloadSlice<'a>) -> Self {
        Self::Filter(val)
    }
}

impl<'a> From<ThirdPartyOptionPayloadSlice<'a>> for OptionPayloadSlice<'a> {
    fn from(val: ThirdPartyOptionPayloadSlice<'a>) -> Self {
        Self::ThidParty(val)
    }
}

/// An enum containing a PCP request payload
///
/// Currently supported request payloads are: map, peer and announce
pub enum RequestPayload {
    Map(MapRequestPayload),
    Peer(PeerRequestPayload),
    Announce,
}

impl RequestPayload {
    /// Returns the size in bytes of the request payload
    pub const fn size(&self) -> usize {
        match self {
            Self::Map(_) => MapRequestPayload::SIZE,
            Self::Peer(_) => PeerRequestPayload::SIZE,
            Self::Announce => 0,
        }
    }

    /// Constructs a new map request payload (see `MapRequestPayload`)
    pub fn map(
        nonce: [u8; 12],
        protocol: Option<ProtocolNumber>,
        internal_port: u16,
        external_port: u16,
        external_address: IpAddr,
    ) -> Self {
        MapRequestPayload::new(
            nonce,
            protocol,
            internal_port,
            external_port,
            external_address,
        )
        .into()
    }

    /// Constructs a new peer request payload (see `PeerRequestPayload`)
    pub fn peer(
        nonce: [u8; 12],
        protocol: Option<ProtocolNumber>,
        internal_port: u16,
        external_port: u16,
        external_address: IpAddr,
        remote_port: u16,
        remote_address: IpAddr,
    ) -> Self {
        PeerRequestPayload::new(
            nonce,
            protocol,
            internal_port,
            external_port,
            external_address,
            remote_port,
            remote_address,
        )
        .into()
    }

    /// Constructs a new announce request payload
    pub fn announce() -> Self {
        Self::Announce
    }
}

impl From<MapRequestPayload> for RequestPayload {
    fn from(val: MapRequestPayload) -> Self {
        Self::Map(val)
    }
}

impl From<PeerRequestPayload> for RequestPayload {
    fn from(val: PeerRequestPayload) -> Self {
        Self::Peer(val)
    }
}

/// An enum containing a PCP response payload
///
/// Currently supported response payloads are: map, peer and announce.
pub enum ResponsePayload {
    Map(MapResponsePayload),
    Peer(PeerResponsePayload),
    Announce,
}

impl ResponsePayload {
    /// Returns the size in bytes of the response payload
    pub const fn size(&self) -> usize {
        match self {
            Self::Map(_) => MapRequestPayload::SIZE,
            Self::Announce => 0,
            Self::Peer(_) => PeerRequestPayload::SIZE,
        }
    }
}

/// A zero-copy type containing a valid PCP response payload. It can be obtained via the
/// `try_from` method (from the `std::TryFrom` trait) from a slice containing
/// a valid sequence of bytes.
pub enum ResponsePayloadSlice<'a> {
    Map(MapResponsePayloadSlice<'a>),
    Peer(PeerResponsePayloadSlice<'a>),
    Announce,
}

impl ResponsePayloadSlice<'_> {
    /// Returns the size in bytes of the response payload
    pub const fn size(&self) -> usize {
        match self {
            Self::Map(_) => MapResponsePayload::SIZE,
            Self::Announce => 0,
            Self::Peer(_) => PeerResponsePayload::SIZE,
        }
    }
    /// Returns the inner slice
    pub fn slice(&self) -> &[u8] {
        match self {
            Self::Map(p) => p.slice(),
            Self::Announce => &[],
            Self::Peer(p) => p.slice(),
        }
    }
}

impl Parsable for ResponsePayloadSlice<'_> {
    type Parsed = ResponsePayload;

    fn parse(&self) -> Self::Parsed {
        match self {
            Self::Map(p) => ResponsePayload::Map(p.parse()),
            Self::Announce => ResponsePayload::Announce,
            Self::Peer(p) => ResponsePayload::Peer(p.parse()),
        }
    }
}

impl<'a> From<MapResponsePayloadSlice<'a>> for ResponsePayloadSlice<'a> {
    fn from(val: MapResponsePayloadSlice<'a>) -> Self {
        Self::Map(val)
    }
}

impl<'a> From<PeerResponsePayloadSlice<'a>> for ResponsePayloadSlice<'a> {
    fn from(val: PeerResponsePayloadSlice<'a>) -> Self {
        Self::Peer(val)
    }
}
