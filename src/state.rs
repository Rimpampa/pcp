use super::event::Delay;
use super::handle::RequestType;
use crate::types::{RequestPacket, ResultCode, MAX_PACKET_SIZE};
use std::{net::IpAddr, time::Duration};

/// A notitification sent when the state of a mapping changes
/// or when the external address selected by the server is recieved
pub enum Alert {
    StateChange,
    Assigned(IpAddr, u16, u32),
}

/// The state of a mapping
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum State {
    /// The request is sent but the client still hasn't processed it
    Requested,
    /// The message has been retrasmitted for the Nth time, the value is N
    Starting(usize),
    /// The request is being resent for the Nth in order to keep in alive,
    /// the first value is N and the last value is the lifetime
    Updating(usize, u32),
    /// The server sends a `Success` response
    Running,
    /// The server sends an error response
    Error(ResultCode),
    /// The lifetime has ended
    Expired,
    /// The map has been revoked
    Revoked,
    /// The map has been dropped
    Dropped,
}

/// Represents the current state of a mapping and its data
pub struct MappingState {
    /// Channel used to send alerts to the handle
    pub state: State,
    pub delay: Delay,
    /// Request data with the filed parsed
    pub request: RequestPacket,
    /// Request data as raw bytes
    buffer: [u8; MAX_PACKET_SIZE],
    size: usize,
    /// Type of request
    pub kind: RequestType,
    /// Remaining lifetime
    pub rem: Duration,
    pub renew: Duration,
}

impl MappingState {
    pub fn new(request: RequestPacket, delay: Delay, kind: RequestType) -> Self {
        let mut buffer = [0; MAX_PACKET_SIZE];
        request.copy_to(&mut buffer);
        Self {
            state: State::Starting(0),
            size: request.size(),
            delay,
            request,
            buffer,
            kind,
            rem: Duration::ZERO,
            renew: Duration::ZERO,
        }
    }

    pub fn bytes(&mut self) -> &[u8] {
        if self.size == 0 {
            self.update_size();
            self.request.copy_to(&mut self.buffer);
        }
        &self.buffer[..self.size]
    }

    pub fn clear(&mut self) {
        self.size = 0;
    }

    pub fn update_size(&mut self) {
        self.size = self.request.size()
    }
}

// /// An handle to a requested mapping
// pub struct MapHandle<'a> {
//     client: &'a Client,
//     id: usize,
// }

// impl<'a> MapHandle<'a> {
//     // /// Returns the state of the mapping
//     // pub fn state(&self) -> State {
//     //     self.state.get()
//     // }

//     // /// Requests to renew the mapping for the specified lifetime
//     // pub fn renew(&self, lifetime: u32) {
//     //     self.to_client.send(Event::Renew(self.id, lifetime)).ok();
//     // }

//     // /// Requests to revoke the mapping
//     // pub fn revoke(&self) {
//     //     self.to_client.send(Event::Revoke(self.id)).ok();
//     // }

//     // /// Waits for an alert to arrive
//     // pub fn wait_alert(&self) -> Result<Alert, RecvError> {
//     //     self.from_client.recv()
//     // }

//     // /// Returns the first alert received if there is one
//     // pub fn poll_alert(&self) -> Option<Alert> {
//     //     self.from_client.try_recv().ok()
//     // }
// }
