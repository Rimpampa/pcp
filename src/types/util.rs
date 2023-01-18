use super::Error::{self, *};

pub fn sized_ref<const S: usize>(s: &[u8]) -> Result<&[u8; S], Error> {
    let s = s.get(..S).ok_or_else(|| InvalidSliceLength(s.len()))?;
    Ok(s.try_into().unwrap())
}

pub fn sized_mut<const S: usize>(s: &mut [u8]) -> Option<&mut [u8; S]> {
    Some(s.get_mut(..S)?.try_into().unwrap())
}

pub trait Deserialize<Out> {
    fn de(&self) -> Out;
}

impl<const S: usize> Deserialize<[u8; S]> for [u8] {
    fn de(&self) -> [u8; S] {
        self.try_into().unwrap()
    }
}

impl Deserialize<u16> for [u8] {
    fn de(&self) -> u16 {
        u16::from_be_bytes(self.de())
    }
}

impl Deserialize<u32> for [u8] {
    fn de(&self) -> u32 {
        u32::from_be_bytes(self.de())
    }
}

impl Deserialize<std::net::Ipv6Addr> for [u8] {
    fn de(&self) -> std::net::Ipv6Addr {
        Deserialize::<[u8; 16]>::de(self).into()
    }
}

pub trait Serialize {
    fn se(&self, out: &mut [u8]);
}

impl<const S: usize> Serialize for [u8; S] {
    fn se(&self, out: &mut [u8]) {
        out.copy_from_slice(self)
    }
}

impl Serialize for u16 {
    fn se(&self, out: &mut [u8]) {
        self.to_be_bytes().se(out)
    }
}

impl Serialize for u32 {
    fn se(&self, out: &mut [u8]) {
        self.to_be_bytes().se(out)
    }
}

impl Serialize for std::net::Ipv6Addr {
    fn se(&self, out: &mut [u8]) {
        self.octets().se(out)
    }
}

pub trait ConstantSize {
    const SIZE: usize;
}
