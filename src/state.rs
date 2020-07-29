use super::event::{Delay, Event};
use super::IpAddress;
use crate::types::{RequestPacket, ResultCode};
use std::net::IpAddr;
use std::sync::mpsc::{self, RecvError};
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// A wrapper around the `State` enum that can be shared as modified between threads safely
#[derive(Debug)]
pub struct AtomicState(RwLock<State>);

impl AtomicState {
    /// Creates a new `AtomicState`
    pub fn new(init: State) -> Self {
        Self(RwLock::new(init))
    }
    /// Sets the state value
    pub fn set(&self, value: State) {
        *self.0.write().unwrap() = value;
    }
    /// Returns the state
    pub fn get(&self) -> State {
        *self.0.read().unwrap()
    }
}

pub enum Alert {
    StateChange,
    Assigned(IpAddr, u16),
}

/// The state of a mapping
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum State {
    /// The request is sent but the client still hasn't processed it
    Requested,
    /// The request has been sent to the server for the first time
    Starting,
    /// The message has been retrasmitted for the nth time
    Retrying(usize),
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

// TODO: non usare un Option<Vec<u8>> ma trova un modo di non dover reallocare ogni volta

/// Represents the current state of a mapping and its data
pub struct MappingState {
    /// Channel used to send alerts to the handle
    to_handle: mpsc::Sender<Alert>,
    state: Arc<AtomicState>,
    pub delay: Delay,
    /// Request data with the filed parsed
    pub request: RequestPacket,
    /// Request data as a `Vec<u8>`
    pub buffer: Option<Vec<u8>>,
}

impl MappingState {
    pub fn new(
        to_handle: mpsc::Sender<Alert>,
        state: Arc<AtomicState>,
        request: RequestPacket,
        delay: Delay,
        buffer: Option<Vec<u8>>,
    ) -> Self {
        MappingState {
            to_handle,
            state,
            request,
            delay,
            buffer,
        }
    }
    /// Sets the state of the mapping an alerts the handle of a state change
    pub fn set_state(&self, state: State) {
        self.state.set(state);
        self.to_handle.send(Alert::StateChange).ok();
    }
    /// Returns the state of the mapping
    pub fn get_state(&self) -> State {
        self.state.get()
    }
    /// Sends an alert to the handle
    pub fn alert(&self, alert: Alert) {
        self.to_handle.send(alert).ok();
    }
}

/// An handle to a requested mapping
pub struct MapHandle<Ip: IpAddress> {
    state: Arc<AtomicState>,
    id: usize,
    /// Channel used to send instructions to the PCP client thread
    to_client: mpsc::Sender<Event<Ip>>,
    /// Channel used to receive alerts from the PCP client thread
    from_client: mpsc::Receiver<Alert>,
}

impl<Ip: IpAddress> MapHandle<Ip> {
    pub(crate) fn new(
        id: usize,
        state: Arc<AtomicState>,
        to_client: mpsc::Sender<Event<Ip>>,
        from_client: mpsc::Receiver<Alert>,
    ) -> Self {
        Self {
            id,
            state,
            to_client,
            from_client,
        }
    }
    /// Returns the state of the mapping
    pub fn state(&self) -> State {
        self.state.get()
    }
    /// Requests to renew the mapping for the specified lifetime
    pub fn renew(&self, lifetime: u32) {
        self.to_client.send(Event::Renew(self.id, lifetime)).ok();
    }
    /// Requests to revoke the mapping
    pub fn revoke(&self) {
        self.to_client.send(Event::Revoke(self.id)).ok();
    }
    /// Waits for an alert to arrive
    pub fn wait(&self) -> Result<Alert, RecvError> {
        self.from_client.recv()
    }
}

impl<Ip: IpAddress> Drop for MapHandle<Ip> {
    fn drop(&mut self) {
        self.to_client.send(Event::Drop(self.id)).ok();
    }
}
