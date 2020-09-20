//! This module contains all the headers described in the RFC

mod option;
mod request;
mod response;

pub use option::{OptionHeader, OptionHeaderSlice};
pub use request::RequestHeader;
pub use response::{ResponseHeader, ResponseHeaderSlice};
