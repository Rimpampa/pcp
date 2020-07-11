pub mod types;
// use types::*;

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use headers::*;
//     use payloads::*;
//     use std::convert::{TryFrom, TryInto};
//     use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

//     #[test]
//     /// Convert an option header to a slice and back
//     fn option() {
//         let option = OptionHeader::new(OptionCode::PreferFailure, 0);
//         let option_array = option.bytes();
//         let option_slice = OptionHeaderSlice::try_from(&option_array[..]).unwrap();
//         let option_parsed = option_slice.parse();
//         assert_eq!(option, option_parsed);
//     }

//     #[test]
//     fn conversions() {
//         assert_eq!(
//             (ResultCode::Success as u8).try_into(),
//             Ok(ResultCode::Success)
//         );
//         assert_eq!((OpCode::Map as u8).try_into(), Ok(OpCode::Map));
//     }

//     #[test]
//     fn response() {
//         #[rustfmt::skip]
//         let response_array: [u8; ResponseHeader::SIZE] = [
//             2,
//             OpCode::Map as u8 | 0b_1000_0000,
//             0,
//             ResultCode::Success as u8,
//             0, 0, 0, 1,
// 			0, 0, 0, 1,
//             0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
//         ];
//         let response = ResponseHeader {
//             version: 2,
//             opcode: OpCode::Map,
//             result: ResultCode::Success,
//             epoch: 1,
//             lifetime: 1,
//         };
//         let response_slice = ResponseHeaderSlice::try_from(&response_array[..]).unwrap();
//         let response_parsed = response_slice.parse();
//         assert_eq!(response, response_parsed);
//     }

//     #[test]
//     fn map() {
//         let request = RequestHeader::new(
//             2,
//             OpCode::Map,
//             60000,
//             Ipv4Addr::new(192, 168, 1, 101).into(),
//         );
//         let nonce = (0..12).fold([0; 12], |mut a, b| {
//             a[b] = b as u8;
//             a
//         });
//         let map_request = MapRequestPayload::new(
//             nonce,
//             Some(ProtocolNumber::Tcp),
//             5000,
//             0,
//             Ipv4Addr::UNSPECIFIED.into(),
//         );

//         const TOT: usize = MapRequestPayload::SIZE + RequestHeader::SIZE;
//         let packet = request
//             .bytes()
//             .iter()
//             .chain(map_request.bytes().iter())
//             .enumerate()
//             .fold([0; TOT], |mut a, (i, &b)| {
//                 a[i] = b;
//                 a
//             });
//         println!("binding socket");
//         let so = UdpSocket::bind(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 101), 8000)).unwrap();
//         println!("socket bound, sending bytes");
//         let bytes_send = so
//             .send_to(
//                 &packet,
//                 SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 5351),
//             )
//             .unwrap();
//         println!("bytes sent, receiving bytes");
//         let mut buffer = [0u8; 1100];
//         let (bytes_recv, ip) = so.recv_from(&mut buffer).unwrap();

//         let response_slice = ResponseHeaderSlice::try_from(&buffer[..bytes_recv]).unwrap();
//         let response = response_slice.parse();

//         let map_response_slice =
//             MapResponsePayloadSlice::try_from(&buffer[ResponseHeader::SIZE..bytes_recv]).unwrap();
//         let map_response = map_response_slice.parse();

//         println!(
//             concat!(
//                 "number of bytes sent: {}\n",
//                 "number of bytes received: {}\n",
//                 "response header: {:#?}\n",
//                 "response payload: {:#?}\nip: {}"
//             ),
//             bytes_send, bytes_recv, response, map_response, ip
//         );
//     }
// }
