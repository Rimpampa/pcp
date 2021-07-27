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

use std::ops::Index;

pub use base::*;
pub use op_code::OpCode;
pub use option_code::OptionCode;
pub use packet::*;
pub use parsing_error::ParsingError;
pub use protocols::ProtocolNumber;
pub use result_code::ResultCode;
