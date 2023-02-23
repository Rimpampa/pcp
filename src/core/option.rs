use std::net::Ipv6Addr;

use super::{util, Error, OptionCode};
use util::{Deserializer, Serializer};

/// PCP filter option payload
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Option Code=3 |  Reserved     |   Option Length=20            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |    Reserved   | Prefix Length |      Remote Peer Port         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |               Remote Peer IP address (128 bits)               |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Filter {
    /// Indicates how many bits of the IPv4 or IPv6 address are relevant for this filter
    ///
    /// The value 0 indicates "no filter", and will remove all previous filters
    pub prefix_length: u8,
    /// The port number of the remote peer
    ///
    /// The value 0 indicates "all ports"
    pub remote_peer_port: u16,
    /// The IP address of the remote peer.
    pub remote_peer_addr: Ipv6Addr,
}

impl Filter {
    /// The [`OptionCode`] of the [`Filter`] PCP option
    pub const CODE: OptionCode = OptionCode::Filter;

    /// Value of the *length* field in the header of every [`Filter`] PCP option
    pub const LENGTH: u16 = 20;
}

impl util::Serialize for Filter {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer
            .serialize(0u8)?
            .serialize(self.prefix_length)?
            .serialize(self.remote_peer_port)?
            .serialize(self.remote_peer_addr)
    }
}

impl util::Deserialize for Filter {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        let filter = Filter {
            prefix_length: data.skip(1)?.deserialize()?,
            remote_peer_port: data.deserialize()?,
            remote_peer_addr: data.deserialize()?,
        };
        match filter.remote_peer_addr.segments() {
            [0, 0, 0, 0, 0, 0xffff, _, _] if filter.prefix_length < 96 => {
                Err(Error::InvalidPrefix(filter.prefix_length))
            }
            _ => Ok(filter),
        }
    }
}

/// PCP third party option payload
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Option Code=1 |  Reserved     |   Option Length=16            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                Internal IP Address (128 bits)                 |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct ThirdParty {
    /// Internal IP address for this mapping
    pub internal_addr: Ipv6Addr,
}

impl ThirdParty {
    /// The [`OptionCode`] of the [`ThirdParty`] PCP option
    pub const CODE: OptionCode = OptionCode::ThirdParty;

    /// Value of the *length* field in the header of every [`ThirdParty`] PCP option
    pub const LENGTH: u16 = 16;
}

impl util::Serialize for ThirdParty {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer.serialize(self.internal_addr)
    }
}

impl util::Deserialize for ThirdParty {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        Ok(ThirdParty {
            internal_addr: data.deserialize()?,
        })
    }
}

/// PCP prefer failure option payload
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Option Code=2 |  Reserved     |   Option Length=0             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct PreferFailure;

impl PreferFailure {
    /// The [`OptionCode`] of the [`PreferFailure`] PCP option
    pub const CODE: OptionCode = OptionCode::PreferFailure;

    /// Value of the *length* field in the header of every [`PreferFailure`] PCP option
    pub const LENGTH: u16 = 0;
}

impl util::Serialize for PreferFailure {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        Ok(buffer)
    }
}

impl util::Deserialize for PreferFailure {
    fn deserialize(_data: &mut Deserializer) -> util::Result<Self> {
        Ok(PreferFailure)
    }
}

/// PCP option
///
/// PCP options extend the contents of a PCP packet by
/// specifying special beheviours which is not always needed.
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Option Code  |  Reserved     |       Option Length           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                       (optional) Data                         :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Option {
    Filter(Filter),
    ThirdParty(ThirdParty),
    PreferFailure(PreferFailure),
}

impl Option {
    /// Size of the PCP option header (in bytes)
    pub const HEADER_SIZE: usize = 4;

    /// Returns the [`OptionCode`] of this [`Option`]
    pub const fn option_code(&self) -> OptionCode {
        match self {
            Self::Filter(_) => Filter::CODE,
            Self::ThirdParty(_) => ThirdParty::CODE,
            Self::PreferFailure(_) => PreferFailure::CODE,
        }
    }

    /// Returns the length of the payload of this [`Option`]
    ///
    /// This is equivalent to the `Option Length` field of the
    /// PCP option header.
    ///
    /// This field reflects the semantic length of the option,
    /// not including any padding octets.
    ///
    /// The padding can be computed by rounding this value to the
    /// next multiple of 4:
    /// ```ignore
    /// option.length() + option.length() % 4
    /// ```
    pub const fn length(&self) -> u16 {
        match self {
            Self::Filter(_) => Filter::LENGTH,
            Self::ThirdParty(_) => ThirdParty::LENGTH,
            Self::PreferFailure(_) => PreferFailure::LENGTH,
        }
    }
}

impl util::Serialize for Option {
    fn serialize<const S: usize>(self, mut buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer = buffer
            .serialize(self.option_code() as u8)?
            .serialize(0u8)?
            .serialize(self.length())?;
        match self {
            Option::Filter(p) => buffer.serialize(p),
            Option::ThirdParty(p) => buffer.serialize(p),
            Option::PreferFailure(p) => buffer.serialize(p),
        }
    }
}

impl util::Deserialize for Option {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        let code = data.deserialize()?;
        let length = data.deserialize()?;
        let check = match code {
            OptionCode::Filter => Filter::LENGTH,
            OptionCode::ThirdParty => ThirdParty::LENGTH,
            OptionCode::PreferFailure => PreferFailure::LENGTH,
        };
        if check != length {
            return Err(Error::InvalidOptionLength(code, length as usize));
        }
        Ok(match code {
            OptionCode::ThirdParty => Self::ThirdParty(data.deserialize()?),
            OptionCode::PreferFailure => Self::PreferFailure(data.deserialize()?),
            OptionCode::Filter => Self::Filter(data.deserialize()?),
        })
    }
}

impl From<Filter> for Option {
    fn from(v: Filter) -> Self {
        Self::Filter(v)
    }
}

impl From<ThirdParty> for Option {
    fn from(v: ThirdParty) -> Self {
        Self::ThirdParty(v)
    }
}

impl From<PreferFailure> for Option {
    fn from(v: PreferFailure) -> Self {
        Self::PreferFailure(v)
    }
}

pub struct RawOption<'a> {
    bytes: &'a [u8],
}

impl RawOption<'_> {
    pub fn option_code(&self) -> u8 {
        self.bytes[0]
    }

    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.bytes[2], self.bytes[3]])
    }

    pub fn data(&self) -> &[u8] {
        &self.bytes[4..][..self.length() as usize]
    }
}

impl PartialEq for RawOption<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.option_code() == other.option_code() && self.data() == other.data()
    }
}

// impl<'a> util::Deserialize<'a> for RawOption<'a> {
//     fn deserialize(data: &'a mut Deserializer<'_>) -> util::Result<Self> {
//         let header = data.peek(4)?;
//         let length = u16::from_be_bytes([header[2], header[3]]);
//         let length = length + ((4 - (length % 4)) % 4);
//         Ok(Self {
//             bytes: data.advance(length as usize)?,
//         })
//     }
// }
