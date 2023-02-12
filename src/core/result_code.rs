use std::fmt;

use super::{util, Error};
use util::{Deserializer, Serializer};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ResultCode {
    /// Success
    Success = 0,
    /// The version number at the start of the PCP Request header is, not recognized
    /// by this PCP server
    UnsuppVersion = 1,
    /// The requested operation is disabled for this PCP client, or, the PCP client requested
    /// an operation that cannot be fulfilled by the PCP server's security policy
    NotAuthorized = 2,
    /// The request could not be successfully parsed
    MalformedRequest = 3,
    /// Unsupported Opcode
    UnsuppCode = 4,
    /// Unsupported option
    UnsuppOption = 5,
    /// Malformed option
    MalformedOption = 6,
    /// The PCP server or the device it controls is experiencing a network failure of some sort
    NetworkFailure = 7,
    /// Request is well-formed and valid, but the server has insufficient resources to complete
    /// the requested operation at this time
    NoResources = 8,
    /// Unsupported transport protocol
    UnsuppProtocol = 9,
    /// This attempt to create a new mapping would exceed this subscriber's port quota
    UserExQuota = 10,
    /// The suggested external port and/or external address cannot be provided
    CannotProvideExternal = 11,
    /// The source IP address of the request packet does not match the contents of the PCP
    /// Client's IP Address field, due to an unexpected NAT on the path between the PCP client
    /// and the PCP-controlled NAT or firewall
    AddressMismatch = 12,
    /// The PCP server was not able to create the filters in this request
    ExcessiveRemotePeers = 13,
}

impl ResultCode {
    pub const fn explain(&self) -> &'static str {
        use ResultCode::*;

        match self {
            Success => "Success",

            UnsuppVersion => concat!(
                "The version number at the start of the PCP Request header is",
                " not recognized by this PCP server"
            ),

            NotAuthorized => concat!(
                "The requested operation is disabled for this PCP client, or",
                " the PCP client requested an operation that cannot be fulfilled by the PCP",
                " server's security policy"
            ),

            MalformedRequest => "The request could not be successfully parsed",

            UnsuppCode => "Unsupported Opcode",

            UnsuppOption => "Unsupported option",

            MalformedOption => "Malformed option",

            NetworkFailure => concat!(
                "The PCP server or the device it controls is experiencing a",
                " network failure of some sort"
            ),

            NoResources => concat!(
                "Request is well-formed and valid, but the server has",
                " insufficient resources to complete the requested operation at this time"
            ),

            UnsuppProtocol => "Unsupported transport protocol",

            UserExQuota => concat!(
                "This attempt to create a new mapping would exceed this",
                " subscriber's port quota"
            ),

            CannotProvideExternal => concat!(
                "The suggested external port and/or external address",
                " cannot be provided"
            ),

            AddressMismatch => concat!(
                "The source IP address of the request packet does not",
                " match the contents of the PCP Client's IP Address field, due to an unexpected",
                " NAT on the path between the PCP client and the PCP-controlled NAT or firewall"
            ),

            ExcessiveRemotePeers => concat!(
                "The PCP server was not able to create the filters in",
                " this request"
            ),
        }
    }
}

impl fmt::Display for ResultCode {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{:?}: {}", self, self.explain())
    }
}

impl util::Deserialize for ResultCode {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        match data.deserialize()? {
            0 => Ok(Self::Success),
            1 => Ok(Self::UnsuppVersion),
            2 => Ok(Self::NotAuthorized),
            3 => Ok(Self::MalformedRequest),
            4 => Ok(Self::UnsuppCode),
            5 => Ok(Self::UnsuppOption),
            6 => Ok(Self::MalformedOption),
            7 => Ok(Self::NetworkFailure),
            8 => Ok(Self::NoResources),
            9 => Ok(Self::UnsuppProtocol),
            10 => Ok(Self::UserExQuota),
            11 => Ok(Self::CannotProvideExternal),
            12 => Ok(Self::AddressMismatch),
            13 => Ok(Self::ExcessiveRemotePeers),
            n => Err(Error::InvalidResultCode(n)),
        }
    }
}

impl util::Serialize for ResultCode {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer.serialize(self as u8)
    }
}
