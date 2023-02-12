use super::{OpCode, OptionCode};
use core::fmt;

/// Errors returned by the (de)serialization functions
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    /// The operation code found in the packet is not known
    UnknownOpCode(u8),
    /// The option code found in the packet is not known
    UnknownOptionCode(u8),
    /// The result code found in the packet is not known
    UnknownResultCode(u8),
    /// The protocol number found in the packet is not valid
    ///
    /// Valid [`ProtocolNumber`](super::ProtocolNumber)s are
    /// registered by the IANA
    InvalidProtocolNumber(u8),
    /// There isn't enough space to fit the required amount of data
    ///
    /// The [`usize`] value indicates the number of bytes that don't fit
    NotEnoughSpace(usize),
    /// The length field of the option haeader is not valid for its [`OptionCode`]
    InvalidOptionLength(OptionCode, usize),
    /// The mask prefix is not valid
    ///
    /// This may happen because the IP address is an
    /// IPv6 mapped IPv4 address which has a minimum prefix
    /// mask bitsize of `96`
    InvalidPrefix(u8),
    /// The option code is not valid for the opcode
    InvalidOption(OpCode, OptionCode),
    /// The version field found in the packet indicates a version that is not supported
    ///
    /// The only supported version is version 2
    VersionNotSupported(u8),
    /// The packet is not a response
    ///
    /// The `R` flag of the response message header is not set
    NotAResponse,
    /// The packet is not a request
    ///
    /// The `R` flag of the request message header is not clear
    NotARequest,
    /// The constructed packet is too big
    PacketTooBig(usize),
    /// The port number for the [`Peer`](super::request::Peer)
    /// is not valid because it's 0
    ///
    /// The value of 0 is explicitly prohibited by the PCP specification
    ZeroRemotePeerPort,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            UnknownOpCode(c) => write!(f, "The value {c} is not a valid opcode"),
            UnknownOptionCode(c) => write!(f, "The value {c} is not a valid option code"),
            UnknownResultCode(c) => write!(f, "The value {c} is not a valid result code"),
            InvalidProtocolNumber(n) => write!(f, "The value {n} is not a valid protocol number"),
            NotEnoughSpace(l) => write!(f, "The the slice as an invalid length of {l}"),
            InvalidOptionLength(o, l) => write!(f, "{o:?} options cannot be {l} bytes long"),
            VersionNotSupported(v) => write!(f, "Unsupported version {v}"),
            NotAResponse => write!(f, "The request flag is set thus it's not a response"),
            NotARequest => write!(f, "The request flag is not set thus it's not a request"),
            InvalidPrefix(p) => write!(f, "Invalid prefix length of {p}"),
            InvalidOption(o, p) => write!(f, "The option {o:?} is not valid for the opcode {p:?}"),
            PacketTooBig(l) => write!(f, "The generated packet of size {l} is too big"),
            ZeroRemotePeerPort => write!(f, "The remote peer port cannot be 0"),
        }
    }
}
