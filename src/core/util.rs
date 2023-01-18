use std::net::Ipv6Addr;

use super::Error::{self, InvalidSliceSize};

pub type Result<T> = core::result::Result<T, Error>;

#[repr(transparent)]
pub struct Deserializer<'a>(&'a [u8]);

impl<'a> Deserializer<'a> {
    pub fn new(s: &'a [u8]) -> Self {
        Self(s)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn skip(&mut self, by: usize) -> Result<&mut Self> {
        self.advance(by)?;
        Ok(self)
    }

    pub fn advance(&mut self, by: usize) -> Result<&[u8]> {
        if self.0.len() > by {
            return Err(InvalidSliceSize(self.0.len(), by));
        }
        let (l, r) = self.0.split_at(by);
        self.0 = r;
        Ok(l)
    }

    pub fn advance_at_most(&mut self, by: usize) -> &[u8] {
        self.advance(by.min(self.0.len())).unwrap()
    }

    pub fn deserialize<T: Deserialize>(&mut self) -> Result<T> {
        T::deserialize(self)
    }
}

pub trait Deserialize: Sized {
    fn deserialize(data: &mut Deserializer<'_>) -> Result<Self>;
}

impl Deserialize for () {
    fn deserialize(_data: &mut Deserializer<'_>) -> Result<Self> {
        Ok(())
    }
}

impl<const S: usize> Deserialize for [u8; S] {
    fn deserialize(data: &mut Deserializer<'_>) -> Result<Self> {
        data.advance(S).map(Self::try_from).map(|r| r.unwrap())
    }
}

impl<const S: usize> Deserialize for heapless::Vec<u8, S> {
    fn deserialize(data: &mut Deserializer<'_>) -> Result<Self> {
        Ok(heapless::Vec::from_slice(data.advance_at_most(S)).unwrap())
    }
}

impl Deserialize for u8 {
    fn deserialize(data: &mut Deserializer<'_>) -> Result<Self> {
        Ok(data.advance(1)?[0])
    }
}

impl Deserialize for u16 {
    fn deserialize(data: &mut Deserializer<'_>) -> Result<Self> {
        data.deserialize().map(u16::from_be_bytes)
    }
}

impl Deserialize for u32 {
    fn deserialize(data: &mut Deserializer<'_>) -> Result<Self> {
        data.deserialize().map(u32::from_be_bytes)
    }
}

impl Deserialize for Ipv6Addr {
    fn deserialize(data: &mut Deserializer<'_>) -> Result<Self> {
        data.deserialize().map(<[u8; 16]>::into)
    }
}

#[repr(transparent)]
pub struct Serializer<'a, const SIZE: usize>(&'a mut heapless::Vec<u8, SIZE>);

impl<'a, const SIZE: usize> Serializer<'a, SIZE> {
    pub fn new(vec: &'a mut heapless::Vec<u8, SIZE>) -> Self {
        Self(vec)
    }

    pub fn push(self, data: &[u8]) -> Result<Self> {
        match self.0.extend_from_slice(data) {
            Ok(_) => Ok(self),
            Err(_) => Err(InvalidSliceSize(SIZE - self.0.len(), data.len())),
        }
    }

    pub fn serialize<T: Serialize>(self, v: T) -> Result<Self> {
        v.serialize(self)
    }
}

pub trait Serialize {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>>;
}

impl<T: Copy + Serialize> Serialize for &T {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>> {
        T::serialize(*self, buffer)
    }
}

impl Serialize for () {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>> {
        Ok(buffer)
    }
}

impl Serialize for &[u8] {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>> {
        buffer.push(self)
    }
}

impl<const SIZE: usize> Serialize for heapless::Vec<u8, SIZE> {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>> {
        buffer.serialize(&self[..])
    }
}

impl<const SIZE: usize> Serialize for [u8; SIZE] {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>> {
        buffer.serialize(&self[..])
    }
}

impl Serialize for u8 {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>> {
        buffer.serialize([self])
    }
}

impl Serialize for u16 {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>> {
        buffer.serialize(self.to_be_bytes())
    }
}

impl Serialize for u32 {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>> {
        buffer.serialize(self.to_be_bytes())
    }
}

impl Serialize for Ipv6Addr {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> Result<Serializer<S>> {
        buffer.serialize(self.octets())
    }
}
