use super::{OpCode, OptionCode};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    InvalidOpCode(u8),
    InvalidOptionCode(u8),
    InvalidResultCode(u8),
    InvalidProtocolNumber(u8),
    InvalidSliceSize(usize, usize),
    InvalidOptionLength(OptionCode, usize),
    InvalidPrefix(u8),
    InvalidOption(OpCode, OptionCode),
    VersionNotSupported(u8),
    /// The R field of the response message header is not 1
    NotAResponse,
    /// The R field of the request message header is not 0
    NotARequest,
    /// The option code (2nd) is not valid for that opcode (1st)
    /// The constructed packet is too big
    PacketTooBig(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Error::*;
        match self {
            InvalidOpCode(c) => write!(f, "The value {} is not a valid opcode", c),
            InvalidOptionCode(c) => write!(f, "The value {} is not a valid option code", c),
            InvalidResultCode(c) => write!(f, "The value {} is not a valid result code", c),
            InvalidProtocolNumber(n) => write!(f, "The value {} is not a valid protocol number", n),
            InvalidSliceSize(l, _) => write!(f, "The the slice as an invalid length of {}", l),
            InvalidOptionLength(o, l) => {
                write!(f, "A length of {} is invalid for the option {:?}", l, o)
            }
            VersionNotSupported(v) => write!(f, "Unsupported version {}", v),
            NotAResponse => write!(f, "The request flag is set thus it's not a response"),
            NotARequest => write!(f, "The request flag is not set thus it's not a request"),
            InvalidPrefix(p) => write!(f, "Invalid prefix length of {}", p),
            InvalidOption(o, p) => {
                write!(f, "The option {:?} is not valid for the opcode {:?}", o, p)
            }
            PacketTooBig(l) => write!(f, "The generated packet of size {} is too big", l),
        }
    }
}
