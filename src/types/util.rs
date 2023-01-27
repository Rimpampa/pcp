use std::net::Ipv6Addr;

use super::Error::{self, InvalidSliceSize};

pub type Result<T> = core::result::Result<T, Error>;

pub trait DeserializeSkip<Out>: Deserialize<Out> {
    fn skip(&mut self, times: usize) -> Result<&mut Self> {
        match (0..times).flat_map(|_| self.de().err()).next() {
            Some(err) => Err(err),
            None => Ok(self),
        }
    }
}

impl DeserializeSkip<u8> for &[u8] {}

pub trait Deserialize<Out> {
    fn de(&mut self) -> Result<Out>;
}

impl<const S: usize> Deserialize<[u8; S]> for &[u8] {
    fn de(&mut self) -> Result<[u8; S]> {
        let arr = self.get(..S).ok_or(InvalidSliceSize(self.len(), S))?;
        *self = &self[S..];
        Ok(arr.try_into().unwrap())
    }
}

impl Deserialize<u8> for &[u8] {
    fn de(&mut self) -> Result<u8> {
        let [v]: [_; 1] = self.de()?;
        Ok(v)
    }
}

impl Deserialize<u16> for &[u8] {
    fn de(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.de()?))
    }
}

impl Deserialize<u32> for &[u8] {
    fn de(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.de()?))
    }
}

impl Deserialize<Ipv6Addr> for &[u8] {
    fn de(&mut self) -> Result<Ipv6Addr> {
        Ok(From::<[u8; 16]>::from(self.de()?))
    }
}

pub trait Serialize<In> {
    fn se(&mut self, value: In) -> Result<&mut Self>;
}

impl Serialize<&[u8]> for [u8] {
    fn se(&mut self, value: &[u8]) -> Result<&mut Self> {
        if self.len() < value.len() {
            return Err(InvalidSliceSize(self.len(), value.len()));
        }
        self[..value.len()].copy_from_slice(&value);
        Ok(&mut self[value.len()..])
    }
}

impl<const S: usize> Serialize<[u8; S]> for [u8] {
    fn se(&mut self, value: [u8; S]) -> Result<&mut Self> {
        self.se(&value[..])
    }
}

impl Serialize<u8> for [u8] {
    fn se(&mut self, value: u8) -> Result<&mut Self> {
        self.se([value])
    }
}

impl Serialize<u16> for [u8] {
    fn se(&mut self, value: u16) -> Result<&mut Self> {
        self.se(value.to_be_bytes())
    }
}

impl Serialize<u32> for [u8] {
    fn se(&mut self, value: u32) -> Result<&mut Self> {
        self.se(value.to_be_bytes())
    }
}

impl Serialize<Ipv6Addr> for [u8] {
    fn se(&mut self, value: Ipv6Addr) -> Result<&mut Self> {
        self.se(value.octets())
    }
}
