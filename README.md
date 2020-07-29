# pcp-rs
An implementation of the Porto Control Protocol(PCP) client defined in
[RFC 6887](https://tools.ietf.org/html/rfc6887)

The PCP protocol is used to request the NAT device that is operating on your network to map pairs
of internal address + port to external ones with the option to filter the incoming packets based
on the address of the remote peer and/or the port number used
