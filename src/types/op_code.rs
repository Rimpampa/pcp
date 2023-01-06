use super::{OptionCode, ParsingError};
use std::convert::TryFrom;

/// The PCP operation
///
/// This enum represents the possible values of the
/// `Opcode` field in PCP repsonse and request headers.
///
/// In requests this field indicates the operation to perform
/// while in responses it is used to know to which operation
/// it's referring.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpCode {
    Announce = 0,
    Map = 1,
    Peer = 2,
}

impl OpCode {
    /// Return all the valid [`OptionCode`]s for this [`OpCode`]
    ///
    /// Some options can never appear in some specific [`OpCode`]s,
    /// the slice returned by this function can be used to validate
    /// PCP requests and responses.
    pub const fn valid_options(&self) -> &'static [OptionCode] {
        use OptionCode::*;
        match self {
            Self::Announce => &[],
            Self::Map => &[ThirdParty, PreferFailure, Filter],
            Self::Peer => &[ThirdParty],
        }
    }

    /// Checks if the provided [`OptionCode`]s for this [`OpCode`]
    ///
    /// This is an utility function that uses the [`valid_option()`]
    /// to simplify checking the validity of the option opcode pair.
    pub fn is_option_valid(&self, option: OptionCode) -> bool {
        self.valid_options().contains(&option)
    }
}

impl TryFrom<u8> for OpCode {
    type Error = ParsingError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0 => Ok(Self::Announce),
            1 => Ok(Self::Map),
            2 => Ok(Self::Peer),
            n => Err(ParsingError::NotAnOpCode(n)),
        }
    }
}
