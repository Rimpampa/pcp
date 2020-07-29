use pcp::{Client, ClientEvent, MapEventKind, OutboundMap, ProtocolNumber, RequestKind};
use std::net::Ipv4Addr;

fn main() {
    let mut pcp = Client::<Ipv4Addr>::start(
        [192, 168, 1, 101].into(), // My address
        [192, 168, 1, 1].into(),   // PCP server address
    )
    .unwrap();

    // Define a mapping that maps requests incoming from 151.15.69.139 on TCP port
    // 7000 to my address on TCP port 6000
    let map =
        OutboundMap::new(6000, [151, 15, 69, 139].into(), 7000, 120).protocol(ProtocolNumber::Tcp);

    // Request the mapping
    pcp.request(1, map, RequestKind::Repeat(0));

    while let Some(event) = pcp.wait() {
        match event {
            ClientEvent::Map(e) => {
                println!("Map #{} event:", e.id);
                match e.kind {
                    MapEventKind::Accpeted {
                        lifetime,
                        external_ip: ip,
                        external_port: port,
                    } => println!(
                        "- accepted with\n  \
                        * lifetime = {lifetime}\n  \
                        * external socket = {ip}:{port}"
                    ),
                    MapEventKind::Expired => println!("- expired"),
                    MapEventKind::NewId(i) => println!("- new id {i}"),
                    MapEventKind::Error => println!("- error!"),
                }
            }
            ClientEvent::Service(e) => println!("Service error:\n- {e}"),
        }
    }
}
