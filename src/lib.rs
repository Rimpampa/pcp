//! A PCP client implementation written in Rust.
//!
//! > The Port Control Protocol allows an IPv6 or IPv4 host to control how
//! incoming IPv6 or IPv4 packets are translated and forwarded by a
//! Network Address Translator (NAT) or simple firewall.
//! The aim of this protocol is to replace the older NAT-PMP by allowing
//! a host to optimize its outgoing NAT keepalive messages.
//! >
//! >~ *from [RFC 6887](https://tools.ietf.org/html/rfc6887)*
//!
//! # Getting Started
//!
//! To start requesting mappings you first have to start the `Client` and get an
//! `Handle` to it. Once you have the `Handle` you can start creating requests.
//!
//! ```rust
//! use std::net::Ipv4Addr;
//!
//! // This is the address of your host in your local network
//! let pcp_client = Ipv4Addr::new(192, 168, 1, 101);
//!
//! // Most of the times it's the default gateway address
//! let pcp_server = Ipv4Addr::new(192, 168, 1, 1);
//!
//! // Start the PCP client service
//! let handle = Client::<Ipv4Addr>::start(pcp_client, pcp_server).unwrap();
//! ```
//!
//! There are two types of mappings you can request: `InboundMapping`s and
//! `OutboundMapping`s (The difference is explained later). Both of them can be
//! contructed with the `new` method and support a various number of options that
//! can be added with chaining methods.
//!
//! ```rust
//! // This allows any host from outside the local network to send requests to
//! // your computer using the TCP protocol on the port 6000.
//! // Once requested, it will last for 20 seconds
//! let mapping = InboundMap::new(6000, 20).protocol(ProtocolNumber::Tcp);
//! ```
//!
//! After you have a mapping you can request it by calling the `request` method on
//! the `Handle` which also returns an handle to that specific mapping. When
//! requesting a mapping you also specifiy how you want the `Client` to handle it:
//! you can choose to make it last for only the duration of it's lifetime or to
//! keeping it alive until it gets blocked explicitly. A `MappingHandle` can be
//! used to control the mapping and, also, to check its state.
//!
//! ```rust
//! // Request the mapping to the server and instruct the client to keeping
//! // it alive for as long as I want
//! let map_handle = handle.request(mapping, RequestType::KeepAlive);
//!
//! // do stuff...
//!
//! map_handle.revoke(); // stop the mapping
//! ```
//!
//! # Difference Between Mappings
//!
//! The [RFC](https://tools.ietf.org/html/rfc6887) explains:
//! > While all mappings are, by necessity, bidirectional (most Internet
//! communication requires information to flow in both directions for successful
//! operation), when talking about mappings, it can be helpful to identify them
//! loosely according to their *primary* purpose.
//! >
//! > - **Outbound mappings** exist primarily to enable outbound communication.
//! For example, when a host calls connect() to make an outbound connection, a NAT
//! gateway will create an implicit dynamic outbound mapping to facilitate that
//! outbound communication.
//! >
//! > -  **Inbound mappings** exist primarily to enable listening servers to
//! receive inbound connections.  Generally, when a client calls listen() to listen
//! for inbound connections, a NAT gateway will not implicitly create any mapping
//! to facilitate that inbound communication.  A PCP MAP request can be used
//! explicitly to create a dynamic inbound mapping to enable the desired inbound
//! communication.

// TODO: expand documentation

mod client;
mod event;
mod handle;
mod map;
mod state;
pub mod types;

pub use client::Client;
pub use handle::{Error, Handle, RequestType, Requester};
pub use map::{InboundMap, OutboundMap};
pub use state::{Alert, /* MapHandle, */ State};
pub use types::ProtocolNumber;

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6, ToSocketAddrs, UdpSocket},
};

/// Common trait for IPv4 and IPv6 addresses
pub trait IpAddress: std::fmt::Debug + Send + Copy + Into<IpAddr> + 'static {
    type SockAddr: ToSocketAddrs;

    /// Number of bits of the address
    const LENGTH: u8;
    /// Unspeficied address
    const UNSPECIFIED: Self;
    /// The link local scope multicast all nodes address
    const ALL_NODES: Self;
    /// The IPv6 representation of this address
    fn to_ipv6(self) -> Ipv6Addr;
    /// Associate a port with this address
    fn to_sockaddr(self, port: u16) -> Self::SockAddr;
    /// Joins the [`UdpSocket`] `sock` to the multicast group with this address
    fn join_muliticast_group(&self, sock: &UdpSocket) -> io::Result<()>;
}

impl IpAddress for Ipv4Addr {
    type SockAddr = SocketAddrV4;

    const LENGTH: u8 = 32;
    const UNSPECIFIED: Self = Self::UNSPECIFIED;
    const ALL_NODES: Self = Self::new(224, 0, 0, 1);

    fn to_ipv6(self) -> Ipv6Addr {
        self.to_ipv6_mapped()
    }

    fn to_sockaddr(self, port: u16) -> Self::SockAddr {
        Self::SockAddr::new(self, port)
    }

    fn join_muliticast_group(&self, sock: &UdpSocket) -> io::Result<()> {
        sock.join_multicast_v4(self, &Self::UNSPECIFIED)
    }
}

impl IpAddress for Ipv6Addr {
    type SockAddr = SocketAddrV6;

    const LENGTH: u8 = 128;
    const UNSPECIFIED: Self = Self::UNSPECIFIED;
    const ALL_NODES: Self = Self::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

    fn to_ipv6(self) -> Ipv6Addr {
        self
    }

    fn to_sockaddr(self, port: u16) -> Self::SockAddr {
        Self::SockAddr::new(self, port, 0, 0)
    }

    fn join_muliticast_group(&self, sock: &UdpSocket) -> io::Result<()> {
        sock.join_multicast_v6(self, 0)
    }
}
