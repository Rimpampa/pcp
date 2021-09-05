//! The `Client` is the heart of the system, it operates on an independent thread
//! and it's what implements the actual protocol.
//!
//! # Initialization
//!
//! A `Client` operates on a single stack, that means only with IPv4 addresses or
//! only with IPv6 ones. It's created by calling the `start` method, and, once is
//! called, the main thread is started but also other two threads get created,
//! each will wait for incoming packets form the specified address: one will listen
//! on the unicast address of the PCP server and the other on the _all hosts_
//! multicast group (224.0.0.1). The latter one is used by the PCP server to
//! communicate a failure in the system and/or a reboot of the device.
//! The `start` function then returns an `Handle` which will then be used to
//! request mappings and the state of the client.
//!
//! The newly created `Client` state is made of:
//! - an empty vector which will be used to store the state of the requested
//! mappings;
//! - the thread local RNG that will be used for some timings calculation and nonce
//! generation;
//! - a `Reciever` for the events and a `Sender` for notifying the `Handle`;
//! - a copy of the event sender for creating delayied events;
//! - the socket and the address to send the requests;
//!
//! # Internal Workings
//!
//! Once it's started the main thread waits for events incoming from the listening
//! threads or from the `Handle`, or from the client itself. At the start nothing
//! is expected to come from the listening threads as no request has been made
//! (only in the case the server has some issues this will happen) so the only
//! source of events is the `Handle`.
//!
//! When a mapping is request the client constructs a new `MappingState` containing
//! the informations of that mapping and adds it to it's list, while also sending
//! the request to the server. The list may have some empty spots in it left by
//! dropped mappings, so when adding a new mapping, those places are filled first,
//! otherwise the list is expanded.
//!
//! > **Side Note**
//! >
//! > The list of the mappings never shrinks, and that might be a problem so I
//! > might want to change it to an `HashMap`
//!
//! Another thing is done while reqesting a new maping, and that is to start a
//! timer that waits for a specific amount of time (defined by the RFC) after which
//! the request is sended again and another timer is started with a longer
//! duration. This process repeats until the server responds or a maximum number of
//! times is reached, after which the request is considered to be `Expired`. Before
//! becoming `Running` once the server responds, or `Expired` when it doesn't, the
//! mapping is in the `Starting` state.
//!
//! _(maybe move this to the State module)_
//!
//! When the mapping is finally `Running` another timer is started that lasts for
//! it's lifetime. The duration of this timer depends on the requested amount of
//! times it has to leave, which can be finate (`Repeat(n)` or `Once`) or endelss
//! (`KeepAlive`). In the latter two cases the time to wait has to be smaller than
//! the actual lifetime has the renewal is not immidiate.
//!
//! _(maybe remove `Once` as it's the same as Repeat(1))_
//!
//! # The Epoch and Recovery
//!
//! Every time a response is received a check is made on the server epoch to verify
//! that the server didn't lose it's state. In the case that the check fails the
//! state of the server has to be updated, thus all the currently active mappings
//! have to be resent. The correct thing to do might be to send the requests with
//! the lifetime decreased to the amount left before the error, but in reality it
//! can't be determined the exact moment of failure thus they are sent again with
//! their full lifetime.
//!
//! The recovery procedure is actuated, also, when an _unsolicited announce response_
//! arrives, which means that the server had some problems and lost it's state.

use super::event::{Delay, Event};
use super::handle::{Error, RequestType};
use crate::state::MappingState;
use crate::types::{
    Epoch, MapResponsePayload, PacketOption, PeerResponsePayload, RequestPacket, ResponsePacket,
    ResponsePayload, ResultCode, MAX_PACKET_SIZE,
};
use crate::State;
use rand::rngs::ThreadRng;
use rand::Rng;
use std::convert::TryFrom;
use std::io;
use std::net::{IpAddr, Ipv6Addr, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

// TODO: allow modifying those values

/// Initial Retrasmission Time
const IRT: f32 = 3.0;
/// Maximum Restrasmission Time
const MRT: f32 = 1024.0;
/// Maximum Retrasmission Count (0 = infinite)
const MRC: usize = 0;

/// A daemon thread that implements the PCP protocol (client-side).
///
/// After `start`ing a `Client` an `Handle` is returned that can be used
/// to submit requests and check its state
///
/// A `Client` works only with IPv4 addresses or only with IPv6 addresses
///
/// **Note**: RFC 7488 explains a procedure to follow for the address selection
/// of the PCP client address and the PCP server one, but it's not (yet)
/// implemented and those adderesses have to be set manually.
///
/// # Examples
///
/// Creating a `Client` is as spimple as:
/**

    use std::net::Ipv4Addr;

    // This is the address of your host in your local network
    let pcp_client = Ipv4Addr::new(192, 168, 1, 101);

    // Most of the times it's the default gateway address
    let pcp_server = Ipv4Addr::new(192, 168, 1, 1);

    // Start the PCP client service
    let handle = Client::<Ipv4Addr>::start(pcp_client, pcp_server).unwrap();

*/
pub struct Client {
    /// IP Address (or addresses) of the client
    addr: IpAddr,
    /// Socket connected to the PCP server
    socket: UdpSocket,
    /// Receiver where the events come from
    event_receiver: mpsc::Receiver<Event>,
    /// Event source used for initializing `Delay`s
    event_source: mpsc::Sender<Event>,
    /// Sender connected to this client's handler, used for notifying eventual errors
    to_handle: mpsc::Sender<Error>,
    /// Vector containing the data of each mapping
    mappings: Vec<MappingState>,
    /// Thread local RNG, used for generating RTs and mapping nonces
    rng: ThreadRng,
    /// Value of the current epoch time, paired with the instant of when it was received
    epoch: Option<Epoch>,
}

impl Client {
    /// Creates a new `Client` and starts it on a different thread; the return value is the `Sender`
    /// of `Event`s connected to the client's `Receiver` from which the client will listen for
    /// incoming events
    fn open(
        socket: UdpSocket,
        addr: IpAddr,
        to_handle: mpsc::Sender<Error>,
    ) -> mpsc::Sender<Event> {
        let (tx, event_receiver) = mpsc::channel();
        let event_source = tx.clone();
        std::thread::spawn(move || {
            Self {
                addr,
                socket,
                event_receiver,
                event_source,
                mappings: Vec::new(),
                rng: rand::thread_rng(),
                epoch: None,
                to_handle,
            }
            .handle_errors()
        });
        tx
    }

    /// Returns the next available index to which a new mapping can be stored; if the vector is
    /// full it'll return None, if there is an empty space it'll return its index
    fn next_index(&self) -> Option<usize> {
        // A dropped mapping has no reason to exist anymore, thus it's index can be reused
        self.mappings.iter().position(|m| m.state == State::Dropped)
    }

    /// Generate the noce of the mapping randomly
    fn generate_nonce(&mut self) -> [u8; 12] {
        self.rng.gen()
    }

    /// Validate the epoch according to the previous one and time elapsed since then
    fn validate_epoch(&mut self, curr_epoch: Epoch) -> Result<bool, Error> {
        let res = curr_epoch.validate_epoch(self.epoch);
        match res {
            true => self.epoch = Some(curr_epoch),
            false => self.server_lost_state()?,
        }
        Ok(res)
    }

    /// When the epoch is invalid or an announce response is received it means that the server has
    /// lost it's internal state, so all of the mappings will have to be resent
    fn server_lost_state(&mut self) -> Result<(), Error> {
        // Ignore all the active delays
        self.mappings.iter_mut().for_each(|map| {
            map.delay.ignore();
        });

        let sock = &self.socket;
        // Resend the data for each mapping
        self.mappings
            .iter_mut()
            .try_for_each(|map| -> io::Result<()> { sock.send(map.bytes()).map(|_| ()) })?;

        let rng = &mut self.rng;
        let event_source = &self.event_source;
        // Reset the state and start the new timer for each mapping
        self.mappings.iter_mut().enumerate().for_each(|(id, map)| {
            map.state = State::Starting(0);
            map.delay = Delay::by(Self::generate_irt(rng), id, event_source.clone());
        });
        Ok(())
    }

    fn update_mapping(
        rng: &mut ThreadRng,
        map: &mut MappingState,
        id: usize,
        times: usize,
        sock: &UdpSocket,
        tx: mpsc::Sender<Event>,
    ) -> Result<(), Error> {
        match Self::jitter_lifetime(rng, map.request.header.lifetime, times) {
            Some(delay) => {
                // Resend the request
                sock.send(map.bytes())?;
                map.state = State::Updating(times, map.request.header.lifetime);
                map.delay = Delay::by(delay, id, tx);
            }
            None => map.state = State::Expired,
        }
        Ok(())
    }

    /// Generates the 1 + RAND factor used in the IRT and RT functions
    fn one_plus_rand(rng: &mut ThreadRng) -> f32 {
        // RAND sould be a value between -0.1 and 0.1, but by subtracting it from one the range
        // becomes from 0.9 to 1.1, thus I can generate a number between 0 as 0.2 and add it to 0.9
        0.9 + rng.gen::<f32>() * 0.2
    }

    /// Generates the Initial Retrasmission Time (IRT) using the following formula:
    ///
    /// RT = (1 + RAND) * IRT
    fn generate_irt(rng: &mut ThreadRng) -> Duration {
        Duration::from_secs_f32(Self::one_plus_rand(rng) * IRT)
    }

    /// Generates the Retrasmission Time (RT) using the following formula:
    ///
    /// RT = (1 + RAND) * MIN (2 * RTprev, MRT)
    fn generate_rt(rng: &mut ThreadRng, rt_prev: Duration) -> Duration {
        Duration::from_secs_f32(Self::one_plus_rand(rng) * MRT.min(2.0 * rt_prev.as_secs_f32()))
    }

    /// Computes the duration needed to wait for the retrasmission of a keepalive request
    fn jitter_lifetime(rng: &mut ThreadRng, lifetime: u32, times: usize) -> Option<Duration> {
        let ftime = lifetime as f32
            * if times == 0 {
                // (1/2)~(5/8) --> 1/2 + 0~1 * 1/8
                0.5 + rng.gen::<f32>() * 0.125
            } else {
                // Not sure of this formula, it's not explicitly written in the specification
                // n = number of attempts (subsequent to the first)
                // (2^(n+1)-1)/2^(n+1) + 0~1 * 1/(2^(n+3))
                let denom = 4 << times;
                let base = (denom - 1) as f32 / denom as f32;
                base + rng.gen::<f32>() / (8 << times) as f32
            };
        if ftime < 4.0 {
            None
        } else {
            Some(Duration::from_secs_f32(ftime))
        }
    }

    /// Function used as a catch for the errors that might be generated while running the client
    fn handle_errors(mut self) {
        loop {
            match self.run() {
                // Ok(()) is returned only when the shoutdown event is received
                Ok(()) => break,
                Err(error) => match error {
                    err @ Error::Parsing(_) => {
                        self.to_handle.send(err).ok();
                    }
                    err @ Error::Socket(_) | err @ Error::Channel(_) => {
                        self.to_handle.send(err).ok();
                        break;
                    }
                },
            }
        }
    }

    fn run(&mut self) -> Result<(), Error> {
        loop {
            match self.event_receiver.recv()? {
                // The handler request an inbound mapping
                Event::InboundMap(map, kind, handle_id, handle_alert) => {
                    // Get the index of this mapping
                    let opt_idx = self.next_index();
                    let idx = opt_idx.unwrap_or(self.mappings.len());

                    // Count the number of options
                    let mut cap = map.filters.len();
                    if map.prefer_failure {
                        cap += 1
                    };
                    if map.third_party.is_some() {
                        cap += 1
                    };

                    // Insert all the options in one vector
                    let mut options = Vec::with_capacity(cap);
                    map.filters.into_iter().for_each(|f| {
                        options.push(PacketOption::filter(
                            // TODO: sposta questo all'interno
                            f.prefix,
                            f.remote_port,
                            f.remote_addr,
                        ))
                    });
                    if map.prefer_failure {
                        options.push(PacketOption::prefer_failure())
                    };
                    if let Some(addr) = map.third_party {
                        options.push(PacketOption::third_party(addr))
                    }

                    // Construct the request
                    let request = RequestPacket::map(
                        2,
                        map.lifetime,
                        match self.addr {
                            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                            IpAddr::V6(v6) => v6,
                        },
                        self.generate_nonce(),
                        map.protocol,
                        map.internal_port,
                        map.external_port.unwrap_or(0),
                        map.external_addr.unwrap_or(Ipv6Addr::UNSPECIFIED),
                        options,
                    )
                    .unwrap();

                    let delay = Delay::by(
                        Self::generate_irt(&mut self.rng),
                        idx,
                        self.event_source.clone(),
                    );
                    // Construct the mapping
                    let mut mapping = MappingState::new(request, delay, kind);

                    // Send the packet
                    self.socket.send(mapping.bytes()).map_err(|err| {
                        handle_id.send(None).ok();
                        Error::from(err)
                    })?;
                    handle_id.send(Some(idx)).ok();

                    // Insert the mapping in the list
                    match opt_idx {
                        Some(i) => self.mappings[i] = mapping,
                        None => self.mappings.push(mapping),
                    }
                }
                // The handler request an outbound mapping
                Event::OutboundMap(map, kind, handle_id, handle_alert) => {
                    // Get the index of this mapping
                    let opt_idx = self.next_index();
                    let idx = opt_idx.unwrap_or(self.mappings.len());

                    // Construct a vector with all the options
                    let options = match map.third_party {
                        Some(addr) => vec![PacketOption::third_party(addr)],
                        None => Vec::new(),
                    };

                    // Construct the request
                    let request = RequestPacket::peer(
                        2,
                        map.lifetime,
                        match self.addr {
                            IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                            IpAddr::V6(v6) => v6,
                        },
                        self.generate_nonce(),
                        map.protocol,
                        map.internal_port,
                        map.external_port.unwrap_or(0),
                        map.external_addr.unwrap_or(Ipv6Addr::UNSPECIFIED),
                        map.remote_port,
                        map.remote_addr,
                        options,
                    )
                    .unwrap();

                    let delay = Delay::by(
                        Self::generate_irt(&mut self.rng),
                        idx,
                        self.event_source.clone(),
                    );
                    // Construct the mapping
                    let mut mapping = MappingState::new(request, delay, kind);

                    // Send the packet
                    self.socket.send(mapping.bytes()).map_err(|err| {
                        handle_id.send(None).ok();
                        Error::from(err)
                    })?;
                    handle_id.send(Some(idx)).ok();

                    // Insert the mapping in the vector
                    match opt_idx {
                        Some(i) => self.mappings[i] = mapping,
                        None => self.mappings.push(mapping),
                    }
                }
                // The relative handle of this mapping has been dropped or
                // the handler requests to revoke a mapping
                ev @ Event::Drop(_) | ev @ Event::Revoke(_) => {
                    // TODO: accertarsi che sia davvero avvenuto
                    let mapping = &mut self.mappings[match ev {
                        Event::Revoke(id) | Event::Drop(id) => id,
                        _ => unreachable!(),
                    }];
                    // Delete the lifetime and reset the buffer
                    mapping.request.header.lifetime = 0;
                    mapping.clear();
                    mapping.delay.ignore();
                    // Send the packet with the 0 lifetime
                    let mut buffer = vec![0u8; mapping.request.size()];
                    mapping.request.copy_to(&mut buffer);
                    self.socket.send(&buffer)?;

                    mapping.state = match ev {
                        Event::Revoke(_) => State::Revoked,
                        Event::Drop(_) => State::Dropped,
                        _ => unreachable!(),
                    };
                }
                // The handler requests to renew a mapping
                Event::Renew(id, lifetime) => {
                    let mapping = &mut self.mappings[id];
                    // Update the lifetime
                    mapping.request.header.lifetime = lifetime;
                    mapping.delay.ignore();
                    // Update the buffer and send the packet
                    self.socket.send(mapping.bytes())?;

                    mapping.state = State::Starting(0);
                    mapping.delay = Delay::by(
                        Self::generate_irt(&mut self.rng),
                        id,
                        self.event_source.clone(),
                    );
                }
                // A delay has ended
                Event::Delay(id, waited) => self.delay_expired(id, waited)?,
                Event::ServerResponse(when, packet) => self.server_response(packet, when)?,
                Event::Shutdown => return Ok(()),
                Event::ListenError(error) => return Err(error),
            }
        }
    }

    fn delay_expired(&mut self, id: usize, waited: Duration) -> Result<(), Error> {
        let mapping = &mut self.mappings[id];
        let update = match mapping.state {
            // The mapping was in a starting state, this means that the packet was
            // already been sent n times but the server, still, didn't respond, thus
            // the client will try to send it again
            State::Starting(n) => {
                mapping.state = State::Starting(n + 1);
                self.socket.send(mapping.bytes())?;
                // Restart the timer
                mapping.delay = Delay::by(
                    Self::generate_rt(&mut self.rng, waited),
                    id,
                    self.event_source.clone(),
                );
                None
            }
            // If it's running it means that the lifetime has ended
            State::Running => match mapping.kind {
                RequestType::Once | RequestType::Repeat(0) => {
                    mapping.state = State::Expired;
                    None
                }
                RequestType::Repeat(n) => {
                    mapping.kind = RequestType::Repeat(n - 1);
                    Some(0)
                }
                RequestType::KeepAlive => Some(0),
            },
            State::Updating(n, lifetime) => Some(n + 1),
            _ => None,
        };
        if let Some(times) = update {
            Self::update_mapping(
                &mut self.rng,
                mapping,
                id,
                times,
                &self.socket,
                self.event_source.clone(),
            )?;
        }
        Ok(())
    }

    fn server_response(&mut self, packet: ResponsePacket, when: Instant) -> Result<(), Error> {
        use ResponsePayload::*;

        let curr_epoch = Epoch::new_when(packet.header.epoch, when);
        if !self.validate_epoch(curr_epoch)? {
            return Ok(());
        }
        match packet.payload {
            // Announce error responses shouldn't even be sent, but if one still arrives
            // it gets ignored
            Announce if packet.header.result != ResultCode::Success => (),
            Announce => self.server_lost_state()?,
            Map(MapResponsePayload {
                external_addr: addr,
                external_port: port,
                ..
            })
            | Peer(PeerResponsePayload {
                external_addr: addr,
                external_port: port,
                ..
            }) => {
                if let Some(idx) = self.mappings.iter().position(|v| v.request == packet) {
                    let mapping = &mut self.mappings[idx];

                    if packet.header.result != ResultCode::Success {
                        mapping.delay.ignore();
                        mapping.state = State::Error(packet.header.result);
                        return Ok(());
                    }

                    let m_lifetime = mapping.request.header.lifetime;
                    let p_lifetime = packet.header.lifetime;

                    mapping.delay.ignore();
                    // It's not granted that the requested lifetime matches the
                    // assigned one
                    if m_lifetime != p_lifetime {
                        mapping.request.header.lifetime = p_lifetime;
                        mapping.clear();
                    }
                    // After a success response the mapping is running
                    mapping.state = State::Running;

                    // let alert = Alert::Assigned(addr.into(), port, p_lifetime);
                    // mapping.alert(alert);

                    let wait = match mapping.kind {
                        RequestType::Once | RequestType::Repeat(0) => {
                            Duration::from_secs(m_lifetime as u64)
                        }
                        RequestType::KeepAlive | RequestType::Repeat(_) => {
                            Self::jitter_lifetime(&mut self.rng, m_lifetime, 0).unwrap_or_default()
                        }
                    };
                    // Set the delay for when it expires
                    mapping.delay = Delay::by(wait, idx, self.event_source.clone())
                }
            }
        };
        Ok(())
    }

    fn listen(socket: UdpSocket, to_client: mpsc::Sender<Event>) {
        let mut buf = [0; MAX_PACKET_SIZE];
        std::thread::spawn(move || loop {
            if let Ok(bytes) = socket.recv(&mut buf) {
                if bytes < 1011 {
                    match ResponsePacket::try_from(&buf[..bytes]) {
                        Ok(packet) => to_client.send(Event::packet_event(packet)).ok(),
                        Err(error) => to_client.send(Event::ListenError(error.into())).ok(),
                    };
                }
            }
        });
    }
}

// // TODO: check if multicast packets are received
// /// Starts the PCP client and returns it's `Handle` which is used to request mappings.
// pub fn start(client: Ipv4Addr, server: Ipv4Addr) -> io::Result<Handle<Ipv4Addr>> {
//     let server_sockaddr = SocketAddrV4::new(server, 5351);

//     let client_socket = UdpSocket::bind(SocketAddrV4::new(client, 0))?;
//     client_socket.connect(server_sockaddr)?;
//     // One part will be used only for sending, the other only for receiving
//     let server_socket = client_socket.try_clone()?;

//     let (to_handle, from_client) = mpsc::channel();
//     let tx = Client::open(client_socket, client, to_handle);

//     let announce_socket = UdpSocket::bind(SocketAddrV4::new(client, 5350))?;
//     announce_socket.join_multicast_v4(&Ipv4Addr::new(224, 0, 0, 1), &client)?;
//     announce_socket.connect(server_sockaddr)?;

//     Self::listen(announce_socket, tx.clone());
//     Self::listen(server_socket, tx.clone());

//     Ok(Handle::new(tx, from_client))
// }

// impl Client<Ipv6Addr> {
//     /// Starts the PCP client and returns it's `Handle` which is used to request mappings.
//     pub fn start(client: Ipv6Addr, server: Ipv6Addr) -> io::Result<Handle<Ipv6Addr>> {
//         let server_sockaddr = SocketAddrV6::new(server, 5351, 0, 0);

//         let client_socket = UdpSocket::bind(SocketAddrV6::new(client, 0, 0, 0))?;
//         client_socket.connect(server_sockaddr)?;
//         // One part will be used only for sending, the other only for receiving
//         let server_socket = client_socket.try_clone()?;

//         let (to_handle, from_client) = mpsc::channel();
//         let tx = Client::open(client_socket, client, to_handle);

//         let announce_socket = UdpSocket::bind(SocketAddrV6::new(client, 5350, 0, 0))?;
//         announce_socket.join_multicast_v6(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 0)?;
//         announce_socket.connect(server_sockaddr)?;

//         Self::listen(announce_socket, tx.clone());
//         Self::listen(server_socket, tx.clone());

//         Ok(Handle::new(tx, from_client))
//     }
// }
