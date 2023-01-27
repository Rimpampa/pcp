use super::{Error, util};
use util::Deserialize;

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

impl Deserialize<OptionCode> for &[u8] {
    fn de(&mut self) -> util::Result<OptionCode> {
        match self.de()? {
            1 => Ok(OptionCode::ThirdParty),
            2 => Ok(OptionCode::PreferFailure),
            3 => Ok(OptionCode::Filter),
            n => Err(Error::InvalidOptionCode(n)),
        }
    }
}
