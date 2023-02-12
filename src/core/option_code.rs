use super::{util, Error};
use util::{Deserializer, Serializer};

/// The `OptionCode` field contained in the PCP option header (see `OptionHeader`)
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OptionCode {
    ThirdParty = 1,
    PreferFailure = 2,
    Filter = 3,
}

impl util::Deserialize for OptionCode {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        match data.deserialize()? {
            1 => Ok(Self::ThirdParty),
            2 => Ok(Self::PreferFailure),
            3 => Ok(Self::Filter),
            n => Err(Error::UnknownOptionCode(n)),
        }
    }
}

impl util::Serialize for OptionCode {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer.serialize(self as u8)
    }
}
