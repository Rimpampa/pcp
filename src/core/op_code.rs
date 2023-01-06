use super::{util, Error, OptionCode};
use util::{Deserializer, Serializer};

/// The PCP operation
///
/// This enum represents the possible values of the
/// `Opcode` field in PCP repsonse and request headers.
///
/// In requests this field indicates the operation to perform
/// while in responses it is used to know to which operation
/// it's referring to.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpCode {
    /// Rapid recovery system which allows PCP clients to
    /// repair failed mappings within seconds, rather than the minutes or
    /// hours it might take if they relied solely on waiting for the next
    /// routine renewal of the mapping
    Announce = 0,
    /// Create an explicit dynamic mapping between an Internal Address + Port
    /// and an External Address + Port.  
    Map = 1,
    /// Create a new dynamic outbound mapping to a remote peer's IP
    /// address and port, or extend the lifetime of an existing
    /// outbound mapping
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

/// [`OpCode`] field + `R` field
///
/// Check [`Response`](super::Response) and [`Request`](super::Request)
/// docs for the actual layout of this field
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum ROpCode {
    /// Reponse `OpCode`, `R` field is 1
    Response(OpCode),
    /// Request `OpCode`, `R` field is 0
    Request(OpCode),
}

impl util::Serialize for ROpCode {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer.serialize(match self {
            Self::Response(o) => 0b10000000 | o as u8,
            Self::Request(o) => o as u8,
        })
    }
}

impl util::Deserialize for ROpCode {
    fn deserialize(data: &mut Deserializer<'_>) -> util::Result<Self> {
        let byte: u8 = data.deserialize()?;
        match byte & 0b10000000 {
            0b00000000 => match byte {
                0 => Ok(Self::Request(OpCode::Announce)),
                1 => Ok(Self::Request(OpCode::Map)),
                2 => Ok(Self::Request(OpCode::Peer)),
                n => Err(Error::UnknownOpCode(n)),
            },
            _ => match byte & 0b01111111 {
                0 => Ok(Self::Response(OpCode::Announce)),
                1 => Ok(Self::Response(OpCode::Map)),
                2 => Ok(Self::Response(OpCode::Peer)),
                n => Err(Error::UnknownOpCode(n)),
            },
        }
    }
}
