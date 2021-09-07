//! This module defines all the structs representing PCP response and request
//! packets and the fields contained in them.
//!
//! # Parsing
//!
//! Every type that may be retrieved from the network (all the response types)
//! have a *-Sliced* counterpart that serves as a zero-copy type that just
//! checks if the provided slice is valid and provides methods to access the
//! fields.
//!
//! All those types implement the `Parsable` trait so that they can be copied
//! into a struct where the fields can be accessed directly.
//!
//! # Sending
//!
//! Every data type that is owned has a `bytes` method that returns a correctly
//! formatted byte array representing that data, that can be directly be sent
//! to the PCP server. For the slice types, only the ones that are composed of a
//! single slice have the `slice` methods that returns the inner slice, which
//! can be directly used to send the data, the others have to be parsed first or
//! the fields have to be accessed one at the time.
//!
//! # Recieving
//!
//! When a slice of data is received for the network it can then be made into a
//! -Slice data type via the `try_from` method, as each of them implements the
//! `TryFrom` trait (from std), that checks if the data is valid for that type
//! and returns a `Result` that can lead to a `ParsingError` if the data is not
//! valid

mod base;
mod op_code;
mod option_code;
mod packet;
mod parsing_error;
mod protocols;
mod result_code;

use std::time::Instant;

pub use base::*;
pub use op_code::OpCode;
pub use option_code::OptionCode;
pub use packet::*;
pub use parsing_error::ParsingError;
pub use protocols::ProtocolNumber;
pub use result_code::ResultCode;

pub const UNICAST_PORT: u16 = 5351;
pub const MULTICAST_PORT: u16 = 5350;

#[derive(Debug, Clone, Copy)]
pub struct Epoch {
    /// The actual value
    value: u32,
    /// [Instant] of when it was received
    last_check: Instant,
}

impl Epoch {
    /// Creates a new [Epoch] that has been received now
    pub fn new(value: u32) -> Self {
        Self {
            value,
            last_check: Instant::now(),
        }
    }
    /// Creates a new [Epoch] that has been received in the instant `when`
    pub fn new_when(value: u32, when: Instant) -> Self {
        Self {
            value,
            last_check: when,
        }
    }

    /// Validate the epoch according to the previous one and time elapsed since then
    pub fn validate_epoch(&self, previous: Option<Epoch>) -> bool {
        // Checks that the epoch is in range
        let check1 = |prev: &Epoch| self.value >= prev.value.saturating_sub(1);
        // Checks that the epoch difference corresponds to the time difference exprienced by the client
        let check2 = |prev: &Epoch| {
            let client = prev.last_check.elapsed().as_secs() as u32;
            let server = self.value.saturating_sub(prev.value);

            client + 2 >= server - server / 16 && server + 2 >= client - client / 16
        };
        // If there was no previus epoch take it as good
        previous.filter(check1).filter(check2).is_none()
    }
}
