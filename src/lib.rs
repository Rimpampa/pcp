//! This crate is a client implementation of the Port Control Protocol (RFC 6887).
//!
//! It is used to instruct the NAT device on the your network to create inbound and outbound
//! mappings

// TODO: finisici la documentazione

#![allow(unused)]
mod client;
mod event;
mod handle;
mod map;
mod state;
pub mod types;

pub use client::Client;
pub use handle::{Error, Handle, Request};
pub use map::{InboundMap, OutboundMap};
pub use state::{Alert, MapHandle, State};
pub use types::ProtocolNumber;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
pub trait IpAddress: std::fmt::Debug + Send + Copy + Into<IpAddr> + 'static {
    const MAX_PREFIX_LENGTH: u8;
    const UNSPECIFIED: Self;
}
impl IpAddress for Ipv4Addr {
    const MAX_PREFIX_LENGTH: u8 = 32;
    const UNSPECIFIED: Self = Self::UNSPECIFIED;
}
impl IpAddress for Ipv6Addr {
    const MAX_PREFIX_LENGTH: u8 = 128;
    const UNSPECIFIED: Self = Self::UNSPECIFIED;
}
