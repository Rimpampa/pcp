use super::{OpCode, OptionCode};

#[derive(Debug, Clone, Copy)]
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
    /// The filter option prefix is invalid
    InvalidPrefix(u8),
    /// The option code (2nd) is not valid for that opcode (1st)
    InvalidOption(OpCode, OptionCode),
}
