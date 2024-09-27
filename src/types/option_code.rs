use super::{Error, util::{self, Serialize}};
use util::Deserialize;

/// TODO
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OptionCode {
    ThirdParty = 1,
    PreferFailure = 2,
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

impl Serialize<OptionCode> for [u8] {
    fn se(&mut self, value: OptionCode) -> util::Result<&mut Self> {
        self.se(value as u8)
    }
}
