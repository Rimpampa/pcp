mod filter_option;
mod map_request;
mod map_response;
mod peer_request;
mod peer_response;
mod third_party_option;

pub use filter_option::{FilterOptionPayload, FilterOptionPayloadSlice, FilterOptionType};
pub use map_request::MapRequestPayload;
pub use map_response::{MapResponsePayload, MapResponsePayloadSlice, MapResponseType};
pub use peer_request::PeerRequestPayload;
pub use peer_response::{PeerResponsePayload, PeerResponsePayloadSlice, PeerResponseType};
pub use third_party_option::{
    ThirdPartyOptionPayload, ThirdPartyOptionPayloadSlice, ThirdPartyOptionType,
};

use super::{ProtocolNumber, Slorp};
use std::net::IpAddr;

/// An enum containing a PCP option payload
pub enum OptionPayload<'a> {
    Filter(FilterOptionType<'a>),
    ThidParty(ThirdPartyOptionType<'a>),
    PreferFailure,
}

impl OptionPayload<'_> {
    pub fn filter(prefix: u8, remote_port: u16, remote_address: IpAddr) -> Self {
        Slorp::Parsed(FilterOptionPayload::new(
            prefix,
            remote_port,
            remote_address,
        ))
        .into()
    }

    pub fn third_party(address: IpAddr) -> Self {
        Slorp::Parsed(ThirdPartyOptionPayload::new(address)).into()
    }
    // [TODO: do i need it? (moka! am I under control?...)]
    pub fn prefer_failure() -> Self {
        Self::PreferFailure
    }

    pub fn size(&self) -> usize {
        match self {
            Self::Filter(_) => FilterOptionPayload::SIZE,
            Self::ThidParty(_) => ThirdPartyOptionPayload::SIZE,
            Self::PreferFailure => 0,
        }
    }
}

impl<'a> From<FilterOptionType<'a>> for OptionPayload<'a> {
    fn from(val: FilterOptionType<'a>) -> Self {
        Self::Filter(val)
    }
}

impl<'a> From<ThirdPartyOptionType<'a>> for OptionPayload<'a> {
    fn from(val: ThirdPartyOptionType<'a>) -> Self {
        Self::ThidParty(val)
    }
}

/// An enum containing a PCP request payload
pub enum RequestPayload {
    Map(MapRequestPayload),
    Peer(PeerRequestPayload),
    Announce,
}

impl RequestPayload {
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
pub enum ResponsePayload<'a> {
    Map(MapResponseType<'a>),
    Peer(PeerResponseType<'a>),
    Announce,
}

impl ResponsePayload<'_> {
    pub fn size(&self) -> usize {
        match self {
            Self::Map(_) => MapRequestPayload::SIZE,
            Self::Announce => 0,
            Self::Peer(_) => PeerRequestPayload::SIZE,
        }
    }
}

impl<'a> From<MapResponseType<'a>> for ResponsePayload<'a> {
    fn from(val: MapResponseType<'a>) -> Self {
        Self::Map(val)
    }
}

impl<'a> From<PeerResponseType<'a>> for ResponsePayload<'a> {
    fn from(val: PeerResponseType<'a>) -> Self {
        Self::Peer(val)
    }
}
