use super::{util, Error, OptionCode};

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

    /// Checks if the provided [`OptionCode`] is valid for this [`OpCode`]
    ///
    /// This is an utility function that uses the [`valid_option()`]
    /// to simplify checking the validity of the option opcode pair.
    pub fn is_option_valid(&self, option: OptionCode) -> bool {
        self.valid_options().contains(&option)
    }
}

impl TryFrom<u8> for OpCode {
    type Error = Error;

    fn try_from(byte: u8) -> util::Result<Self> {
        match byte {
            0 => Ok(OpCode::Announce),
            1 => Ok(OpCode::Map),
            2 => Ok(OpCode::Peer),
            n => Err(Error::InvalidOpCode(n)),
        }
    }
}
