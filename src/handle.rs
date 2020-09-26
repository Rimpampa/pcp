use super::event::Event;
use super::map::{InboundMap, Map, OutboundMap};
use super::state::{AtomicState, MapHandle, State};
use super::IpAddress;
use crate::types::ParsingError;
use std::sync::mpsc::{self, RecvError};
use std::sync::Arc;
use std::{fmt, io};

/// Error generated by PCP operations
#[derive(Debug)]
pub enum Error {
    /// Error generated by an I/O operation related to the UDP sockets used for
    /// communication with the PCP server
    Socket(io::Error),

    /// Error generated by one of the channels used for the communication
    /// between the running threads
    Channel(RecvError),

    /// Warning generated when the server responds with a packet with an unknown
    /// format or some invalid values
    Parsing(ParsingError),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Socket(err)
    }
}

impl From<RecvError> for Error {
    fn from(err: RecvError) -> Self {
        Self::Channel(err)
    }
}

impl From<ParsingError> for Error {
    fn from(err: ParsingError) -> Self {
        Self::Parsing(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket(err) => write!(f, "Socket error: {:?}", err),
            Self::Channel(err) => write!(f, "Inner threads communication error: {:?}", err),
            Self::Parsing(err) => write!(f, "Response parsing error: {:?}", err),
        }
    }
}

/// An handle to a PCP client service
///
/// When a `Client` is started its `Handle` is returned and can be used to
/// `request` mappings and to query its state.
///
/// # Examples
///
/// ### Submitting a request
///
/// Request an inbound mapping to the port 120 TCP:
/**

    // Start the PCP client service
    let handle = Client::<Ipv4Addr>::start(client, server).unwrap();

    // Allows for any host to connect on the TCP port number 120
    // (see map module)
    let map = InboundMap::new(6000, 120).protocol(ProtocolNumber::Tcp);

    // Submit the request to the client, it will live one time
    let map_handle = handle.request(map, RequestType::Once).unwrap();

*/
/// ### Querying the state
///
/// Check if the `Client` reported any errors:
/**

    // Start the PCP client service
    let handle = Client::<Ipv4Addr>::start(client, server).unwrap();

    // Do stuff...

    // Non blocking, use wait_err to block until a new error arrives
    if let Some(err) = handle.poll_err() {
        println!("The client reported an error: {}", err);
    }
*/
pub struct Handle<Ip: IpAddress> {
    to_client: mpsc::Sender<Event<Ip>>,
    from_client: mpsc::Receiver<Error>,
}

impl<Ip: IpAddress> Handle<Ip> {
    pub(crate) fn new(
        to_client: mpsc::Sender<Event<Ip>>,
        from_client: mpsc::Receiver<Error>,
    ) -> Self {
        Handle {
            to_client,
            from_client,
        }
    }

    /// Waits for an error to arrive
    pub fn wait_err(&self) -> Error {
        self.from_client.recv().unwrap_or_else(Error::from)
    }

    /// Returns `Some(Error)` if an error has been received, `None` otherwise
    pub fn poll_err(&self) -> Option<Error> {
        self.from_client.try_recv().ok()
    }

    /// Signals the `Client` to end execution
    pub fn shutdown(self) {
        self.to_client.send(Event::Shutdown).ok();
    }
}

/// The number of times a request has to be submitted:
///
/// - `Once`: send only one time
/// - `Repeat(n)`: repeats for `n` times
/// - `KeepAlive`: continues to resend until it gets stopped manually
#[derive(Debug, PartialEq)]
pub enum RequestType {
    Once,
    Repeat(usize),
    KeepAlive,
}

// TODO: modify this trait to be implemented on the Requestable items instead that on the Handle

/// Allows an `Handler` to request mappings via a `Client`
pub trait Request<Ip: IpAddress, M: Map<Ip>> {
    /// Send the request to the `Client` that will then send it to the server
    fn request(&self, map: M, kind: RequestType) -> Result<MapHandle<Ip>, Error>;
}

impl<Ip: IpAddress> Request<Ip, InboundMap<Ip>> for Handle<Ip> {
    fn request(&self, map: InboundMap<Ip>, kind: RequestType) -> Result<MapHandle<Ip>, Error> {
        let (id_tx, id_rx) = mpsc::channel();
        let (alert_tx, alert_rx) = mpsc::channel();
        let state = Arc::new(AtomicState::new(State::Requested));
        self.to_client
            .send(Event::InboundMap(
                map,
                kind,
                Arc::clone(&state),
                id_tx,
                alert_tx,
            ))
            .unwrap();
        if let Some(id) = id_rx.recv().unwrap() {
            Ok(MapHandle::new(id, state, self.to_client.clone(), alert_rx))
        } else {
            Err(self.wait_err())
        }
    }
}

impl<Ip: IpAddress> Request<Ip, OutboundMap<Ip>> for Handle<Ip> {
    fn request(&self, map: OutboundMap<Ip>, kind: RequestType) -> Result<MapHandle<Ip>, Error> {
        let (id_tx, id_rx) = mpsc::channel();
        let (alert_tx, alert_rx) = mpsc::channel();
        let state = Arc::new(AtomicState::new(State::Requested));
        self.to_client
            .send(Event::OutboundMap(
                map,
                kind,
                Arc::clone(&state),
                id_tx,
                alert_tx,
            ))
            .unwrap();
        if let Some(id) = id_rx.recv().unwrap() {
            Ok(MapHandle::new(id, state, self.to_client.clone(), alert_rx))
        } else {
            Err(self.wait_err())
        }
    }
}

impl<Ip: IpAddress> Drop for Handle<Ip> {
    fn drop(&mut self) {
        self.to_client.send(Event::Shutdown).ok();
    }
}
