use super::{OpCode, OptionCode};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ParsingError {
    /// The parsed value (1st) is not an opcode
    NotAnOpCode(u8),
    /// The parsed value (1st) is not an option code
    NotAnOptionCode(u8),
    /// The parsed value (1st) is not a result code
    NotAResultCode(u8),
    /// The parsed value (1st) is not a protocol number
    NotAProtocolNumber(u8),
    /// The size of the value (1st) is bigger than the size of the slice
    InvalidSliceLength(usize),
    /// The option length field (2nd) is invalid for that option code (1st)
    InvalidOptionLength(OptionCode, usize),
    /// The version (1st) is not supported
    VersionNotSupported(u8),
    /// The R field of the response message header is not 1
    NotAResponse,
    /// The R field of the request message header is not 0
    NotARequest,
    /// The filter option prefix is invalid
    InvalidPrefix(u8),
    /// The option code (2nd) is not valid for that opcode (1st)
    InvalidOption(OpCode, OptionCode),
    /// The constructed packet is too big
    PacketTooBig(usize),
}

impl fmt::Display for ParsingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use ParsingError::*;
        match self {
            NotAnOpCode(c) => write!(f, "The value {} is not a valid opcode", c),
            NotAnOptionCode(c) => write!(f, "The value {} is not a valid option code", c),
            NotAResultCode(c) => write!(f, "The value {} is not a valid result code", c),
            NotAProtocolNumber(n) => write!(f, "The value {} is not a valid protocol number", n),
            InvalidSliceLength(l) => write!(f, "The the slice as an invalid length of {}", l),
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
