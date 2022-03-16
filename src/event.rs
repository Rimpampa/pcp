use super::handle::Error;
use super::map::{InboundMap, OutboundMap};
use crate::types::ResponsePacket;
use crate::{IpAddress, RequestKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[derive(Debug)]
/// Events that a PCP has to process
pub enum ServerEvent<Ip: IpAddress> {
    /// The handler requests an inbound mapping; the first Sender tells the map handler the id of
    /// the mapping
    InboundMap {
        map: InboundMap<Ip>,
        kind: RequestKind,
        id: usize,
    },
    /// The handler requests an outbound mapping; the first Sender tells the map handler the id of
    /// the mapping
    OutboundMap {
        map: OutboundMap<Ip>,
        kind: RequestKind,
        id: usize,
    },
    /// The handler of the mapping requests to revoke a mapping
    Revoke(usize),
    /// The handler of the mapping requests to renew a mapping for the specified lifetime
    Renew(usize, u32),
    /// The handler of the client has dropped or has requested to shutdown the service
    Shutdown,
    /// The server sent a respone packet
    ServerResponse(Instant, ResponsePacket),
    /// A delay has ended
    Delay(usize, Duration),
}

/// An handle to a waiting thread: one the thread wait ends an event is sent
pub struct Delay {
    signal: Arc<AtomicBool>,
}

impl Delay {
    /// Creates a `Delay` event that will be sent through the event `channel` after the secified
    /// amount of `time`
    pub fn by<Ip: IpAddress>(
        time: Duration,
        id: usize,
        channel: mpsc::Sender<ServerEvent<Ip>>,
    ) -> Self {
        let signal = Arc::new(AtomicBool::new(true));
        let cloned = Arc::clone(&signal);
        tokio::spawn(async move {
            tokio::time::sleep(time).await;
            if cloned.load(Ordering::Relaxed) {
                let _ = channel.send(ServerEvent::Delay(id, time)).await;
            }
        });
        Self { signal }
    }

    /// Ignores this delay, once
    pub fn ignore(&mut self) {
        self.signal.store(false, Ordering::Relaxed);
    }
}

impl Drop for Delay {
    fn drop(&mut self) {
        self.ignore()
    }
}

pub enum ClientEvent<Ip: IpAddress> {
    Map(MapEvent<Ip>),
    Service(Error),
}

pub struct MapEvent<Ip: IpAddress> {
    pub id: usize,
    pub kind: MapEventKind<Ip>,
}

impl<Ip: IpAddress> MapEvent<Ip> {
    pub fn new(id: usize, kind: MapEventKind<Ip>) -> Self {
        Self { id, kind }
    }
}

pub enum MapEventKind<Ip: IpAddress> {
    /// The mapping was accepted by the PCP server and is now running
    Accpeted {
        /// The accepted lifetime
        lifetime: u32,
        /// The assigned external IP address
        external_ip: Ip,
        /// The assigned external port
        external_port: u16,
    },
    /// The mapping lifetime has expired, the mapping is no longer running
    Expired,
    /// The mapping received an error of some sort
    Error,
    /// The mapping has been assigned a new identifier
    NewId(usize),
}
