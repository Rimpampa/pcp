use std::{iter, ops::Not};

use super::{util, Option};
use util::{Deserializer, Serializer};

/// Payload + raw options pair
///
/// This struct contains the payload as a parsed value of type `T`
/// and the options as an array of bytes that should be big enough to
/// hold the maximum size of the options given the [`MAX_PACKET_SIZE`]
/// limit.
///
/// The options are not parsed because it cannot be known how many of
/// them there will be and of what type, use the [`options()`] method
/// to get an iterator of parsed options.
#[derive(PartialEq, Debug)]
pub struct Payload<T, const SIZE: usize> {
    /// Parsed payload data
    pub data: T,
    /// Raw options
    pub raw_options: heapless::Vec<u8, SIZE>,
}

impl<T, const SIZE: usize> Payload<T, SIZE> {
    /// Get the options conatined in this packet
    pub fn options(&self) -> impl Iterator<Item = util::Result<Option>> + '_ {
        let mut de = util::Deserializer::new(&self.raw_options);
        iter::from_fn(move || de.is_empty().not().then(|| de.deserialize()))
    }

    /// Add an [`Option`] to the pyload
    pub fn with(&mut self, option: Option) -> util::Result<()> {
        Serializer::new(&mut self.raw_options)
            .serialize(option)
            .and(Ok(()))
    }
}

impl<T, const SIZE: usize> util::Serialize for &Payload<T, SIZE>
where
    for<'a> &'a T: util::Serialize,
{
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer
            .serialize(&self.data)?
            .serialize(self.raw_options.as_slice())
    }
}

impl<T: util::Deserialize, const SIZE: usize> util::Deserialize for Payload<T, SIZE> {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        Ok({
            Self {
                data: data.deserialize()?,
                raw_options: data.deserialize()?,
            }
        })
    }
}