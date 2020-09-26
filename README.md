# pcp-rs

A PCP client implementation written in Rust.

> The Port Control Protocol allows an IPv6 or IPv4 host to control how
incoming IPv6 or IPv4 packets are translated and forwarded by a
Network Address Translator (NAT) or simple firewall.
The aim of this protocol is to replace the older NAT-PMP by allowing
a host to optimize its outgoing NAT keepalive messages.
>
>~ *from [RFC 6887](https://tools.ietf.org/html/rfc6887)*

# Getting Started

To start requesting mappings you first have to start the `Client` and get an
`Handle` to it. Once you have the `Handle` you can start creating requests.

```rust
use std::net::Ipv4Addr;

// This is the address of your host in your local network
let pcp_client = Ipv4Addr::new(192, 168, 1, 101);

// Most of the times it's the default gateway address
let pcp_server = Ipv4Addr::new(192, 168, 1, 1);

// Start the PCP client service
let handle = Client::<Ipv4Addr>::start(pcp_client, pcp_server).unwrap();
```

There are two types of mappings you can request: `InboundMapping`s and
`OutboundMapping`s (The difference is explained later). Both of them can be
contructed with the `new` method and support a various number of options that
can be added with chaining methods.

```rust
// This allows any host from outside the local network to send requests to
// your computer using the TCP protocol on the port 6000.
// Once requested, it will last for 20 seconds
let mapping = InboundMap::new(6000, 20).protocol(ProtocolNumber::Tcp);
```

After you have a mapping you can request it by calling the `request` method on
the `Handle` which also returns an handle to that specific mapping. When
requesting a mapping you also specifiy how you want the `Client` to handle it:
you can choose to make it last for only the duration of it's lifetime or to
keeping it alive until it gets blocked explicitly. A `MappingHandle` can be
used to control the mapping and, also, to check its state.

```rust
// Request the mapping to the server and instruct the client to keeping
// it alive for as long as I want
let map_handle = handle.request(mapping, RequestType::KeepAlive);

// do stuff...

map_handle.revoke(); // stop the mapping
```

# Difference Between Mappings

The [RFC](https://tools.ietf.org/html/rfc6887) explains:
> While all mappings are, by necessity, bidirectional (most Internet
communication requires information to flow in both directions for successful
operation), when talking about mappings, it can be helpful to identify them
loosely according to their *primary* purpose.
>
> - **Outbound mappings** exist primarily to enable outbound communication.
For example, when a host calls connect() to make an outbound connection, a NAT
gateway will create an implicit dynamic outbound mapping to facilitate that
outbound communication.
>
> -  **Inbound mappings** exist primarily to enable listening servers to
receive inbound connections.  Generally, when a client calls listen() to listen
for inbound connections, a NAT gateway will not implicitly create any mapping
to facilitate that inbound communication.  A PCP MAP request can be used
explicitly to create a dynamic inbound mapping to enable the desired inbound
communication.