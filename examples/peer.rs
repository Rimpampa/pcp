use pcp::{Alert, Client, OutboundMap, ProtocolNumber, Request, RequestType};
use std::net::Ipv4Addr;

fn main() {
    let pcp = Client::<Ipv4Addr>::start(
        [192, 168, 1, 101].into(), // My address
        [192, 168, 1, 1].into(),   // PCP server address
    )
    .unwrap();

    // Define a mapping that maps requests incoming from 151.15.69.139 on TCP port
    // 7000 to my address on TCP port 6000
    let map =
        OutboundMap::new(6000, [151, 15, 69, 139].into(), 7000, 120).protocol(ProtocolNumber::Tcp);

    // Request the mapping
    let handle = pcp.request(map, RequestType::Once).unwrap();

    while let Ok(alert) = handle.wait_alert() {
        match alert {
            Alert::StateChange => println!("State: {:?}", handle.state()),
            Alert::Assigned(ip, port, lifetime) => println!(
                "Assigned ip: {:?}\nAssigned port: {}\nAssigned lifetime: {}",
                ip, port, lifetime,
            ),
        }
    }
}
