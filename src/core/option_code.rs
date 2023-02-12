use super::{util, Error};
use util::{Deserializer, Serializer};

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

impl util::Deserialize for OptionCode {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        match data.deserialize()? {
            1 => Ok(Self::ThirdParty),
            2 => Ok(Self::PreferFailure),
            3 => Ok(Self::Filter),
            n => Err(Error::InvalidOptionCode(n)),
        }
    }
}

impl util::Serialize for OptionCode {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer.serialize(self as u8)
    }
}
