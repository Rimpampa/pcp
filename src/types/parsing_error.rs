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
    /// The mask prefix is not valid
    /// 
    /// This may happen because the IP address is an
    /// IPv6 mapped IPv4 address which has a minimum prefix
    /// mask bitsize of `96`
    InvalidPrefix(u8),
    /// The option code is not valid for the opcode
    InvalidOption(OpCode, OptionCode),
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
