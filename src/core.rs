//! This module defines all the structs representing PCP response and request
//! packets and the fields contained in them.
//!
//! TODO

mod error;
pub use error::Error;

mod op_code;
pub use op_code::OpCode;

mod epoch;
pub use epoch::Epoch;

mod option_code;
pub use option_code::OptionCode;

mod result_code;
pub use result_code::ResultCode;

mod protocols;
pub use protocols::ProtocolNumber;

mod util;

pub mod option;
pub use option::Option;

/// Maximum size a PCP UDP packet can have
pub const MAX_PACKET_SIZE: usize = 1100;

/// IANA assigned UDP port number for PCP servers
///
/// A PCP servers use this UDP port for:
/// - listening for unicast clients requests
/// - sending multicast notifications to clients
pub const SERVER_PORT: u16 = 5351;

/// IANA assigned UDP port number for PCP client
///
/// PCP clients listen on this UDP port for servers
/// multicast notifications
///
/// **Note** that on transmission the clients can
/// use any UDP port
pub const CLIENT_PORT: u16 = 5350;
