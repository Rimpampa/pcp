use crate::types::ResponsePacket;
use super::handle::{Error, RequestType};
use super::map::{InboundMap, OutboundMap};
use super::state::Alert;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug)]
/// Events that a PCP has to process
pub enum Event {
    /// The server sent a respone packet
    ServerResponse(Instant, ResponsePacket),
    /// The handler requests an inbound mapping; the first Sender tells the map handler the id of
    /// the mapping
    InboundMap(
        InboundMap,
        RequestType,
        mpsc::Sender<Option<usize>>,
        mpsc::Sender<Alert>,
    ),
    /// The handler requests an outbound mapping; the first Sender tells the map handler the id of
    /// the mapping
    OutboundMap(
        OutboundMap,
        RequestType,
        mpsc::Sender<Option<usize>>,
        mpsc::Sender<Alert>,
    ),
    /// The handler of the mapping requests to revoke a mapping
    Revoke(usize),
    /// The handler of the mapping requests to renew a mapping for the specified lifetime
    Renew(usize, u32),
    /// The handler of the mapping has been dropped
    Drop(usize),
    /// A delay has ended
    Delay(usize, Duration),
    /// The handler of the client has dropped or has requested to shutdown the service
    Shutdown,
    /// The listening thread generated an error
    ListenError(Error),
}

impl Event {
    /// Function used for processing a `ResponsePacketSlice`
    pub fn packet_event(response: ResponsePacket) -> Self {
        Self::ServerResponse(Instant::now(), response)
    }
}

/// An handle to a waiting thread: one the thread wait ends an event is sent
pub struct Delay {
    signal: Option<mpsc::Sender<()>>,
}

impl Delay {
    /// Creates a `Delay` event that will be sent through the event `channel` after the secified
    /// amount of `time`
    pub fn by(time: Duration, id: usize, channel: mpsc::Sender<Event>) -> Self {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            thread::sleep(time);
            if rx.try_recv().is_err() {
                channel.send(Event::Delay(id, time)).ok();
            }
        });
        Self { signal: Some(tx) }
    }
    /// Once called, the event won't be sent through the channel (thus ignoring it).
    /// If the event was already sent at the time of calling the method, or any other error
    /// happens, `false` will be returned. Only when the delay gets truly ignored `true` will be
    /// returned
    pub fn ignore(&mut self) -> bool {
        self.signal
            .take()
            .map(|channel| matches!(channel.send(()), Ok(_)))
            .unwrap_or(false)
    }
}
