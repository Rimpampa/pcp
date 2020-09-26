use super::IpAddress;
use crate::types::ProtocolNumber;

/// Trait used to generalize any type of mapping
pub trait Map<Ip: IpAddress> {}
impl<Ip: IpAddress> Map<Ip> for InboundMap<Ip> {}
impl<Ip: IpAddress> Map<Ip> for OutboundMap<Ip> {}

#[derive(Clone, Debug)]
pub struct Filter<Ip: IpAddress> {
    pub remote_port: u16,
    pub remote_addr: Ip,
    pub prefix: u8,
}

#[derive(Clone, Debug)]
/// An inbound map, is used to create an explicit dynamic mapping between an Internal Address +
/// Port and an External Address + Port.
pub struct InboundMap<Ip: IpAddress> {
    pub(crate) lifetime: u32,
    pub(crate) internal_port: u16,
    pub(crate) protocol: Option<ProtocolNumber>,
    pub(crate) third_party: Option<Ip>,
    pub(crate) external_port: Option<u16>,
    pub(crate) external_addr: Option<Ip>,
    pub(crate) filters: Vec<Filter<Ip>>,
    pub(crate) prefer_failure: bool,
}

impl<Ip: IpAddress> InboundMap<Ip> {
    /// Creates a new inbound mapping with the specified lifetime and that maps
    /// the specified port
    pub fn new(internal_port: u16, lifetime: u32) -> Self {
        Self {
            lifetime,
            internal_port,
            protocol: None,
            third_party: None,
            external_port: None,
            external_addr: None,
            filters: Vec::new(),
            prefer_failure: false,
        }
    }

    /// Specifies a specific protocol to be used
    pub fn protocol(mut self, number: ProtocolNumber) -> Self {
        match self.protocol {
            Some(_) => panic!("The protocol number was already specified"),
            None => self.protocol = Some(number),
        }
        self
    }

    /// Suggests an external address to be used
    pub fn external_address(mut self, suggest: Ip) -> Self {
        match self.external_addr {
            Some(_) => panic!("The suggested external address was already specified"),
            None => self.external_addr = Some(suggest),
        }
        self
    }

    /// Suggests an external port to be used
    pub fn external_port(mut self, suggest: u16) -> Self {
        match self.external_port {
            Some(_) => panic!("The suggested external port was already specified"),
            None => self.external_port = Some(suggest),
        }
        self
    }

    /// Specifies that the mapping is done on behalf of another host.
    ///
    /// PCP servers may not implement this feature
    pub fn third_party(mut self, addr: Ip) -> Self {
        match self.third_party {
            Some(_) => panic!("The third party host address was already specified"),
            None => self.third_party = Some(addr),
        }
        self
    }

    /// Indicates that the PCP server should not create an alternative mapping if the suggested
    /// external port and address cannot be mapped
    pub fn prefer_failure(mut self, prefer: bool) -> Self {
        self.prefer_failure = prefer;
        self
    }

    /// Specifies a filter for incoming packets
    pub fn filter(mut self, remote_port: u16, remote_addr: Ip, prefix: u8) -> Self {
        if prefix > Ip::LENGTH {
            panic!("The specified prefix is greater than {}", prefix);
        }
        self.filters.push(Filter {
            remote_port,
            remote_addr,
            prefix,
        });
        self
    }
}

/// An outbound map is used to create a new dynamic mapping to a remote peer's IP address and port
#[derive(Clone, Debug)]
pub struct OutboundMap<Ip: IpAddress> {
    pub(crate) lifetime: u32,
    pub(crate) internal_port: u16,
    pub(crate) remote_addr: Ip,
    pub(crate) remote_port: u16,
    pub(crate) protocol: Option<ProtocolNumber>,
    pub(crate) third_party: Option<Ip>,
    pub(crate) external_port: Option<u16>,
    pub(crate) external_addr: Option<Ip>,
}

impl<Ip: IpAddress> OutboundMap<Ip> {
    /// Creates a new `OutboundMap`
    pub fn new(internal_port: u16, remote_addr: Ip, remote_port: u16, lifetime: u32) -> Self {
        Self {
            lifetime,
            internal_port,
            remote_addr,
            remote_port,
            protocol: None,
            third_party: None,
            external_port: None,
            external_addr: None,
        }
    }

    /// Specifies a specific protocol to be used
    pub fn protocol(mut self, number: ProtocolNumber) -> Self {
        match self.protocol {
            Some(_) => panic!("The protocol number was already specified"),
            None => self.protocol = Some(number),
        }
        self
    }

    /// Suggests an external address to be used
    pub fn external_address(mut self, suggest: Ip) -> Self {
        match self.external_addr {
            Some(_) => panic!("The suggested external address was already specified"),
            None => self.external_addr = Some(suggest),
        }
        self
    }

    /// Suggests an external port to be used
    pub fn external_port(mut self, suggest: u16) -> Self {
        match self.external_port {
            Some(_) => panic!("The suggested external port was already specified"),
            None => self.external_port = Some(suggest),
        }
        self
    }

    /// Specifies that the mapping is done on behalf of another host.
    ///
    /// PCP servers may not implement this feature
    pub fn third_party(mut self, addr: Ip) -> Self {
        match self.third_party {
            Some(_) => panic!("The third party host address was already specified"),
            None => self.third_party = Some(addr),
        }
        self
    }
}
