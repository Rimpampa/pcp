use std::net::Ipv6Addr;

use super::{util, Error, OptionCode};
use util::{Deserialize, DeserializeSkip, Serialize};

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
#[derive(PartialEq, Debug)]
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

impl Serialize<Filter> for [u8] {
    fn se(&mut self, filter: Filter) -> util::Result<&mut Self> {
        self.se(0u8)?
            .se(filter.prefix_length)?
            .se(filter.remote_peer_port)?
            .se(filter.remote_peer_addr)
    }
}

impl Deserialize<Filter> for &[u8] {
    fn de(&mut self) -> util::Result<Filter> {
        let filter = Filter {
            prefix_length: self.skip(1)?.de()?,
            remote_peer_port: self.de()?,
            remote_peer_addr: self.de()?,
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
#[derive(PartialEq, Debug)]
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

impl Serialize<ThirdParty> for [u8] {
    fn se(&mut self, value: ThirdParty) -> util::Result<&mut Self> {
        self.se(value.internal_addr)
    }
}

impl Deserialize<ThirdParty> for &[u8] {
    fn de(&mut self) -> util::Result<ThirdParty> {
        Ok(ThirdParty {
            internal_addr: self.de()?,
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
#[derive(PartialEq, Debug)]
pub struct PreferFailure;

impl PreferFailure {
    /// The [`OptionCode`] of the [`PreferFailure`] PCP option
    pub const CODE: OptionCode = OptionCode::PreferFailure;

    /// Value of the *length* field in the header of every [`PreferFailure`] PCP option
    pub const LENGTH: u16 = 0;
}

impl Serialize<PreferFailure> for [u8] {
    fn se(&mut self, _: PreferFailure) -> util::Result<&mut Self> {
        Ok(self)
    }
}

impl Deserialize<PreferFailure> for &[u8] {
    fn de(&mut self) -> util::Result<PreferFailure> {
        Ok(PreferFailure)
    }
}

/// PCP option
///
/// PCP options extend the contents of a PCP packet by
/// specifying special beheviours which is not always needed.
///
///
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
#[derive(PartialEq, Debug)]
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

impl Serialize<Option> for [u8] {
    fn se(mut self: &mut Self, value: Option) -> util::Result<&mut Self> {
        self = self.se(value.option_code() as u8)?
            .se(0u8)?
            .se(value.length())?;
        match value {
            Option::Filter(p) => self.se(p),
            Option::ThirdParty(p) => self.se(p),
            Option::PreferFailure(p) => self.se(p),
        }
    }
}

impl Deserialize<Option> for &[u8] {
    fn de(&mut self) -> util::Result<Option> {
        let code = self.de()?;
        let length = self.de()?;
        let check = match code {
            OptionCode::Filter => Filter::LENGTH,
            OptionCode::ThirdParty => ThirdParty::LENGTH,
            OptionCode::PreferFailure => PreferFailure::LENGTH,
        };
        if check != length {
            return Err(Error::InvalidOptionLength(code, length as usize));
        }
        Ok(match code {
            OptionCode::ThirdParty => Option::ThirdParty(self.de()?),
            OptionCode::PreferFailure => Option::PreferFailure(self.de()?),
            OptionCode::Filter => Option::Filter(self.de()?),
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
