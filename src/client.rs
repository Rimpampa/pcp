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

use super::event::{Delay, ServerEvent};
use super::handle::{Error, RequestKind};
use crate::event::{ClientEvent, MapEvent, MapEventKind};
use crate::state::MappingState;
use crate::types::{
    Epoch, MapRequestPayload, MapResponsePayload, PacketOption, PeerRequestPayload,
    PeerResponsePayload, RequestPacket, RequestPayload, ResponsePacket, ResponsePayload,
    ResultCode, MAX_PACKET_SIZE, MULTICAST_PORT, UNICAST_PORT,
};
use crate::{Handle, InboundMap, IpAddress, OutboundMap, State};
use rand::rngs::ThreadRng;
use rand::Rng;
use std::io;
use std::net::{Ipv6Addr, UdpSocket};
use std::sync::mpsc;
use std::time::{Duration, Instant};

// TODO: allow modifying those values

mod timeout {
    use std::time::Duration;

    use rand::{distributions::Uniform, prelude::Distribution};

    /// Initial Retrasmission Time
    pub const IRT: f32 = 3.0;
    /// Maximum Restrasmission Time
    pub const MRT: f32 = 1024.0;
    /// Maximum Retrasmission Count (0 = infinite)
    pub const MRC: usize = 0;
    /// The maximum jitter used for timouts
    pub const RAND: f32 = 0.2;
    /// A reasonable lifetime length for when the lifetime recevied seems to big
    pub const REASONABLE_LIFETIME: u32 = 60 * 60 * 24;

    /// **O**ne **P**lus **R**and:
    /// generates the `1 + RAND` factor used in some of the time releated functions
    pub fn opr<R: rand::Rng>(rng: &mut R) -> f32 {
        const BASE: f32 = 1.0 - RAND * 0.5;
        Uniform::new(BASE, BASE + RAND).sample(rng)
    }

    /// Generates the **I**nitial **R**etrasmission **T**ime (IRT):
    /// `RT = (1 + RAND) * IRT`
    pub fn irt<R: rand::Rng>(rng: &mut R) -> Duration {
        Duration::from_secs_f32(opr(rng) * IRT)
    }

    /// Generates the Retrasmission Time (RT) using the following formula:
    ///
    /// RT = (1 + RAND) * MIN (2 * RTprev, MRT)
    pub fn rt<R: rand::Rng>(rng: &mut R, rt_prev: Duration) -> Duration {
        Duration::from_secs_f32(opr(rng) * MRT.min(2.0 * rt_prev.as_secs_f32()))
    }

    /// Returns the duration it has to wait for the trasmission (or retrasmission) of a
    /// keepalive request, where `times` is the number of previous attempts (thus 0 the first
    /// time) and `rem` is the remaining lifetime of the mapping.
    ///
    /// From the RFC:
    /// > The PCP client SHOULD renew the mapping before its expiry time;
    /// > otherwise, it will be removed by the PCP server. To reduce the risk of inadvertent
    /// > synchronization of renewal requests, a random jitter component should
    /// > be included.  It is RECOMMENDED that PCP clients send a single
    /// > renewal request packet at a time chosen with uniform random
    /// > distribution in the range 1/2 to 5/8 of expiration time.  If no
    /// > SUCCESS response is received, then the next renewal request should be
    /// > sent 3/4 to 3/4 + 1/16 to expiration, and then another 7/8 to 7/8 +
    /// > 1/32 to expiration, and so on, subject to the constraint that renewal
    /// > requests MUST NOT be sent less than four seconds apart (a PCP client
    /// > MUST NOT send a flood of ever-closer-together requests in the last
    /// > few seconds before a mapping expires).
    pub fn renew<R: rand::Rng>(rng: &mut R, rem: Duration, times: usize) -> Option<Duration> {
        let times = times.try_into().ok()?;
        let pr = 0.5f32.powi(times);
        Some(Uniform::new(1.0 - pr, 1.0 - 1.25 * pr).sample(rng) * rem.as_secs_f32())
            .filter(|&t| t >= 4.0)
            .map(Duration::from_secs_f32)
    }
}

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
/// ```
/// use std::net::Ipv4Addr;
/// // This is the address of your host in your local network
/// let pcp_client = Ipv4Addr::new(192, 168, 1, 101);
/// // Most of the times it's the default gateway address
/// let pcp_server = Ipv4Addr::new(192, 168, 1, 1);
/// // Start the PCP client service
/// let handle = Client::<Ipv4Addr>::start(pcp_client, pcp_server).unwrap();
/// ```
pub struct Client<Ip: IpAddress> {
    /// IP Address (or addresses) of the client
    addr: Ip,
    /// Socket connected to the PCP server
    socket: UdpSocket,
    /// Receiver where the events come from
    event_receiver: mpsc::Receiver<ServerEvent<Ip>>,
    /// Event source used for initializing `Delay`s
    event_source: mpsc::Sender<ServerEvent<Ip>>,
    /// Sender connected to this client's handler, used for notifying eventual errors
    to_handle: mpsc::Sender<ClientEvent<Ip>>,
    /// Vector containing the data of each mapping
    mappings: Vec<MappingState>,
    /// Thread local RNG, used for generating RTs and mapping nonces
    rng: ThreadRng,
    /// Value of the current epoch time, paired with the instant of when it was received
    epoch: Option<Epoch>,
}

impl<Ip: IpAddress> Client<Ip> {
    /// Creates a new [`Client`] that will comunicate with the PCP server connected to `socket`,
    /// from the local interface with address `addr`.
    ///
    /// The created [`Client`] will run on a separate thread and any interaction with it is made
    /// through the returned [`Sender`] of [`Event`]s.
    fn open(
        socket: UdpSocket,
        addr: Ip,
        to_handle: mpsc::Sender<ClientEvent<Ip>>,
    ) -> mpsc::Sender<ServerEvent<Ip>> {
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
    /// full it'll return [`None`], if there is an empty space it'll return its index
    fn next_index(&self) -> usize {
        // A dropped mapping has no reason to exist anymore, thus it's index can be reused
        self.mappings
            .iter()
            .position(|m| m.state == State::Dropped)
            .unwrap_or(self.mappings.len())
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
            .try_for_each(|map| sock.send(map.bytes()).map(|_| ()))?;

        let event_source = &self.event_source;
        // Reset the state and start the new timer for each mapping
        let mappings = self.mappings.iter_mut().enumerate();
        for (id, map) in mappings {
            use State::*;
            if matches!(map.state, Error(_) | Expired | Revoked | Dropped) {
                continue;
            }
            map.state = Starting(0);
            map.delay = Delay::by(timeout::irt(&mut self.rng), id, event_source.clone());
        }
        Ok(())
    }

    fn update_mapping(&mut self, id: usize, times: usize) -> Result<(), Error> {
        let map = &mut self.mappings[id];
        map.rem -= map.renew;
        match timeout::renew(&mut self.rng, map.rem, times) {
            Some(delay) => {
                map.renew = delay;
                // Resend the request
                self.socket.send(map.bytes())?;
                map.state = State::Updating(times, map.request.header.lifetime);
                map.delay = Delay::by(delay, id, self.event_source.clone());
            }
            None => map.state = State::Expired,
        }
        Ok(())
    }

    /// Function used as a catch for the errors that might be generated while running the client
    fn handle_errors(mut self) {
        loop {
            // TODO: better error handling and recovery
            match self.run() {
                // Ok(()) is returned only when the shoutdown event is received
                Ok(()) => break,
                Err(err @ Error::Parsing(_)) => {
                    self.to_handle.send(ClientEvent::Service(err)).ok();
                }
                Err(err @ Error::Socket(_)) | Err(err @ Error::Channel(_)) => {
                    self.to_handle.send(ClientEvent::Service(err)).ok();
                    break;
                }
            }
        }
    }

    fn run(&mut self) -> Result<(), Error> {
        use ServerEvent as Ev;

        loop {
            match self.event_receiver.recv()? {
                // The handler request an inbound mapping
                Ev::InboundMap { map, kind, id } => self.new_inbound(map, kind, id)?,
                // The handler request an outbound mapping
                Ev::OutboundMap { map, kind, id } => self.new_outbound(map, kind, id)?,
                // The relative handle of this mapping has been dropped or
                // the handler requests to revoke a mapping
                // NOTE:
                // This means a MAP or PEER request with lifetime of 0 will only set the assigned
                // lifetime to 0 (i.e., delete the mapping) if the internal host had not sent a
                // packet using that mapping for the idle-timeout time, otherwise the assigned
                // lifetime will be the remaining idle-timeout time.
                Ev::Revoke(id) => {
                    let mapping = &mut self.mappings[id];
                    // Delete the lifetime and reset the buffer
                    mapping.request.header.lifetime = 0;
                    mapping.clear();
                    mapping.delay.ignore();
                    // Send the packet with the 0 lifetime
                    let mut buffer = vec![0u8; mapping.request.size()];
                    mapping.request.copy_to(&mut buffer);
                    self.socket.send(&buffer)?;

                    mapping.state = State::Revoked;
                }
                // The handler requests to renew a mapping
                Ev::Renew(id, lifetime) => {
                    let mapping = &mut self.mappings[id];
                    // Update the lifetime
                    mapping.rem = Duration::from_secs(lifetime as u64);
                    mapping.request.header.lifetime = lifetime;
                    mapping.delay.ignore();
                    // Update the buffer and send the packet
                    self.socket.send(mapping.bytes())?;

                    mapping.state = State::Starting(0);
                    mapping.delay =
                        Delay::by(timeout::irt(&mut self.rng), id, self.event_source.clone());
                }
                // A delay has ended
                Ev::Delay(id, waited) => self.delay_expired(id, waited)?,
                Ev::ServerResponse(when, packet) => self.server_response(packet, when)?,
                Ev::Shutdown => return Ok(()),
            }
        }
    }

    fn new_mapping(
        &mut self,
        request: RequestPacket,
        kind: RequestKind,
        id: usize,
    ) -> Result<(), Error> {
        // TODO: I may want to override the selected mapping

        // Get the index of this mapping
        let new_id = self.next_index();
        if new_id != id {
            let ev = ClientEvent::Map(MapEvent::new(id, MapEventKind::NewId(new_id)));
            self.to_handle.send(ev).ok();
        }

        let delay = Delay::by(
            timeout::irt(&mut self.rng),
            new_id,
            self.event_source.clone(),
        );
        // Construct the mapping
        let mapping = MappingState::new(request, delay, kind);

        // Insert the mapping in the list
        self.mappings.insert(new_id, mapping);
        Ok(())
    }

    fn new_inbound(
        &mut self,
        map: InboundMap<Ip>,
        kind: RequestKind,
        id: usize,
    ) -> Result<(), Error> {
        // Count the number of options
        let cap =
            map.filters.len() + map.prefer_failure as usize + map.third_party.is_some() as usize;

        // Insert all the options in one vector
        let mut options = Vec::with_capacity(cap);
        map.filters.into_iter().for_each(|f| {
            options.push(PacketOption::filter(
                f.prefix,
                f.remote_port,
                f.remote_addr.to_ipv6(),
            ))
        });
        if map.prefer_failure {
            options.push(PacketOption::prefer_failure())
        }
        if let Some(addr) = map.third_party {
            options.push(PacketOption::third_party(addr.to_ipv6()))
        }
        // Construct the request
        let request = RequestPacket::map(
            2,
            map.lifetime,
            self.addr.to_ipv6(),
            self.rng.gen(),
            map.protocol,
            map.internal_port,
            map.external_port.unwrap_or(0),
            map.external_addr.unwrap_or(Ip::UNSPECIFIED).to_ipv6(),
            options,
        )
        .unwrap();

        self.new_mapping(request, kind, id)?;
        Ok(())
    }

    fn new_outbound(
        &mut self,
        map: OutboundMap<Ip>,
        kind: RequestKind,
        id: usize,
    ) -> Result<(), Error> {
        // Construct a vector with all the options
        let options = match map.third_party {
            Some(addr) => vec![PacketOption::third_party(addr.to_ipv6())],
            None => Vec::new(),
        };

        // Construct the request
        let request = RequestPacket::peer(
            2,
            map.lifetime,
            self.addr.to_ipv6(),
            self.rng.gen(),
            map.protocol,
            map.internal_port,
            map.external_port.unwrap_or(0),
            map.external_addr.unwrap_or(Ip::UNSPECIFIED).to_ipv6(),
            map.remote_port,
            map.remote_addr.to_ipv6(),
            options,
        )
        .unwrap();

        self.new_mapping(request, kind, id)?;
        Ok(())
    }

    fn delay_expired(&mut self, id: usize, waited: Duration) -> Result<(), Error> {
        let mapping = &mut self.mappings[id];
        match mapping.state {
            State::Starting(n) if n == timeout::MRC => {
                todo!("the mapping failed, server didn't respond")
            }
            // The mapping was in a starting state, this means that the packet was
            // already been sent n times but the server, still, didn't respond, thus
            // the client will try to send it again
            // TODO: manage the MRD timeout
            State::Starting(n) => {
                mapping.state = State::Starting(n + 1);
                self.socket.send(mapping.bytes())?;
                // Restart the timer
                mapping.delay = Delay::by(
                    timeout::rt(&mut self.rng, waited),
                    id,
                    self.event_source.clone(),
                );
            }
            // If it's running it means that the lifetime has ended
            State::Running => match mapping.kind {
                RequestKind::Repeat(0) => mapping.state = State::Expired,
                RequestKind::Repeat(n) => {
                    mapping.kind = RequestKind::Repeat(n - 1);
                    self.update_mapping(id, 0)?;
                }
                RequestKind::KeepAlive => self.update_mapping(id, 0)?,
            },
            State::Updating(n, _) => self.update_mapping(id, n + 1)?,
            _ => (),
        }
        Ok(())
    }

    fn mapping_response(
        &mut self,
        packet: ResponsePacket,
        addr: Ipv6Addr,
        port: u16,
    ) -> Result<(), Error> {
        if let Some(idx) = self.mappings.iter().position(|v| v.request == packet) {
            let mapping = &mut self.mappings[idx];

            match mapping.request.payload {
                RequestPayload::Map(MapRequestPayload {
                    ref mut external_addr,
                    ref mut external_port,
                    ..
                })
                | RequestPayload::Peer(PeerRequestPayload {
                    ref mut external_addr,
                    ref mut external_port,
                    ..
                }) => {
                    *external_addr = addr;
                    *external_port = port;
                }
                RequestPayload::Announce => unreachable!(),
            }

            if packet.header.result != ResultCode::Success {
                mapping.delay.ignore();
                mapping.state = State::Error(packet.header.result);
                return Ok(());
            }

            let m_lifetime = mapping.request.header.lifetime;
            let p_lifetime = packet.header.lifetime;
            mapping.rem = Duration::from_secs(packet.header.lifetime as u64);

            mapping.delay.ignore();
            // It's not granted that the requested lifetime matches the assigned one
            mapping.request.header.lifetime = p_lifetime.min(timeout::REASONABLE_LIFETIME);
            mapping.clear();
            // After a success response the mapping is running
            mapping.state = State::Running;

            let wait = match mapping.kind {
                RequestKind::Repeat(0) => Duration::from_secs(m_lifetime as u64),
                RequestKind::KeepAlive | RequestKind::Repeat(_) => {
                    timeout::renew(&mut self.rng, mapping.rem, 0).unwrap_or_default()
                }
            };
            mapping.renew = wait;
            // Set the delay for when it expires
            mapping.delay = Delay::by(wait, idx, self.event_source.clone())
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
            }) => self.mapping_response(packet, addr, port)?,
        };
        Ok(())
    }

    fn listen(socket: UdpSocket, to_client: mpsc::Sender<ServerEvent<Ip>>) {
        let mut buf = [0; MAX_PACKET_SIZE];
        std::thread::spawn(move || loop {
            let response = socket.recv(&mut buf).map_err(Error::from);
            let _ = match response.and_then(|bytes| Ok(buf[..bytes].try_into()?)) {
                Ok(packet) => to_client.send(ServerEvent::ServerResponse(Instant::now(), packet)),
                Err(_) => todo!(),
            };
        });
    }

    /// Starts the PCP client and returns it's [`Handle`] which is used to request mappings.
    pub fn start(client: Ip, server: Ip) -> io::Result<Handle<Ip>> {
        let server_sockaddr = server.to_sockaddr(UNICAST_PORT);

        let client_socket = UdpSocket::bind(client.to_sockaddr(0))?;
        client_socket.connect(&server_sockaddr)?;
        // One part will be used only for sending, the other only for receiving
        let server_socket = client_socket.try_clone()?;

        let (to_handle, from_client) = mpsc::channel();
        let tx = Client::open(client_socket, client, to_handle);

        let announce_socket = UdpSocket::bind(Ip::ALL_NODES.to_sockaddr(MULTICAST_PORT))?;
        Ip::ALL_NODES.join_muliticast_group(&announce_socket)?;
        announce_socket.connect(server_sockaddr)?;

        Self::listen(announce_socket, tx.clone());
        Self::listen(server_socket, tx.clone());

        Ok(Handle::new(tx, from_client))
    }
}
