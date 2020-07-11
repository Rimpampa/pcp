use super::ParsingError;
use std::convert::TryFrom;

/// The `OptionCode` field contained in the PCP option header (see `OptionHeader`)
///
/// Currently only three option codes are defined
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OptionCode {
    /// Indicates the MAP or PEER request is for a host other than the host sending the PCP option
    ThirdParty = 1,
    /// indicates that the PCP server should not create an alternative mapping if the
    /// suggested external port and address cannot be mapped
    PreferFailure = 2,
    /// specifies a filter for incoming packets
    Filter = 3,
}

impl TryFrom<u8> for OptionCode {
    type Error = ParsingError;

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            1 => Ok(Self::ThirdParty),
            2 => Ok(Self::PreferFailure),
            3 => Ok(Self::Filter),
            n => Err(ParsingError::NotAnOptionCode(n)),
        }
    }
}
