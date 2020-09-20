use super::{OptionCode, ParsingError};
use std::convert::TryFrom;

/// The `OpCode` field contained in the PCP response and request headers.
///
/// _On requests_: it indicates the operation that the server has to perform.
///
/// _On responses_: it's the same of the request it's responding to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpCode {
    Announce = 0,
    Map = 1,
    Peer = 2,
}

impl OpCode {
    /// Returns the array containing all the valid option codes for this opcode
    pub const fn valid_options(&self) -> &'static [OptionCode] {
        use OptionCode as oc;
        match self {
            Self::Announce => &[],
            Self::Map => &[oc::ThirdParty, oc::PreferFailure, oc::Filter],
            Self::Peer => &[oc::ThirdParty],
        }
    }
    /// Checks if the provided option code is valid for this opcode
    pub fn valid_option(&self, option: &OptionCode) -> bool {
        self.valid_options().iter().any(|o| o == option)
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
