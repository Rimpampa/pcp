use std::convert::TryFrom;

/// All the IP protocol numbers defined by the IANA
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum ProtocolNumber {
    /// IPv6 Hop-by-Hop Option, IPv6 extension header, [RFC8200]
    Hopopt = 0,
    /// Internet Control Message, [RFC792]
    Icmp = 1,
    /// Internet Group Management, [RFC1112]
    Igmp = 2,
    /// Gateway-to-Gateway, [RFC823]
    Ggp = 3,
    /// IPv4 encapsulation, [RFC2003]
    Ipv4 = 4,
    /// Stream, [RFC1190][RFC1819]
    St = 5,
    /// Transmission Control, [RFC793]
    Tcp = 6,
    /// CBT, [Tony_Ballardie]
    Cbt = 7,
    /// Exterior Gateway Protocol, [RFC888][David_Mills]
    Egp = 8,
    /// "any private interior gateway (used by Cisco for their IGRP)", [Internet_Assigned_Numbers_Authority]
    Igp = 9,
    /// BBN RCC Monitoring, [Steve_Chipman]
    BbnRccMon = 10,
    /// Network Voice Protocol, [RFC741][Steve_Casner]
    NvpII = 11,
    /// PUP, "[Boggs,  D.,  J. Shoch,  E. Taft,  and R. Metcalfe,  ""PUP: An Internetwork Architecture"",  XEROX Palo Alto Research Center,  CSL-79-10,  July 1979; also in IEEE Transactions on Communication,  Volume COM-28,  Number 4,  April 1980.][[XEROX]]"
    Pup = 12,
    /// ARGUS, [Robert_W_Scheifler]
    Argus = 13,
    /// EMCON, [<mystery contact>]
    Emcon = 14,
    /// Cross Net Debugger, "[Haverty,  J.,  ""XNET Formats for Internet Protocol Version 4"",  IEN 158,  October 1980.][Jack_Haverty]"
    Xnet = 15,
    /// Chaos, [J_Noel_Chiappa]
    Chaos = 16,
    /// User Datagram, [RFC768][Jon_Postel]
    Udp = 17,
    /// Multiplexing, "[Cohen,  D. and J. Postel,  ""Multiplexing Protocol"",  IEN 90,  USC/Information Sciences Institute,  May 1979.][Jon_Postel]"
    Mux = 18,
    /// DCN Measurement Subsystems, [David_Mills]
    DcnMeas = 19,
    /// Host Monitoring, [RFC869][Bob_Hinden]
    Hmp = 20,
    /// Packet Radio Measurement, [Zaw_Sing_Su]
    Prm = 21,
    /// XEROX NS IDP, "[""The Ethernet,  A Local Area Network: Data Link Layer and Physical Layer Specification"",  AA-K759B-TK,  Digital Equipment Corporation,  Maynard,  MA.  Also as: ""The Ethernet - A Local Area Network"",  Version 1.0,  Digital Equipment Corporation,  Intel Corporation,  Xerox Corporation,  September 1980.  And: ""The Ethernet,  A Local Area Network: Data Link Layer and Physical Layer Specifications"",  Digital,  Intel and Xerox,  November 1982. And: XEROX,  ""The Ethernet,  A Local Area Network: Data Link Layer and Physical Layer Specification"",  X3T51/80-50,  Xerox Corporation,  Stamford,  CT.,  October 1980.][[XEROX]]"
    XnsIdp = 22,
    /// Trunk-1, [Barry_Boehm]
    Trunk1 = 23,
    /// Trunk-2, [Barry_Boehm]
    Trunk2 = 24,
    /// Leaf-1, [Barry_Boehm]
    Leaf1 = 25,
    /// Leaf-2, [Barry_Boehm]
    Leaf2 = 26,
    /// Reliable Data Protocol, [RFC908][Bob_Hinden]
    Rdp = 27,
    /// Internet Reliable Transaction, [RFC938][Trudy_Miller]
    Irtp = 28,
    /// ISO Transport Protocol Class 4, [RFC905][<mystery contact>]
    IsoTp4 = 29,
    /// Bulk Data Transfer Protocol, [RFC969][David_Clark]
    Netblt = 30,
    /// MFE Network Services Protocol, "[Shuttleworth,  B.,  ""A Documentary of MFENet,  a National Computer Network"",  UCRL-52317,  Lawrence Livermore Labs,  Livermore,  California,  June 1977.][Barry_Howard]"
    MfeNsp = 31,
    /// MERIT Internodal Protocol, [Hans_Werner_Braun]
    MeritInp = 32,
    /// Datagram Congestion Control Protocol, [RFC4340]
    Dccp = 33,
    /// Third Party Connect Protocol, [Stuart_A_Friedberg]
    ThreePc = 34,
    /// Inter-Domain Policy Routing Protocol, [Martha_Steenstrup]
    Idpr = 35,
    /// XTP, [Greg_Chesson]
    Xtp = 36,
    /// Datagram Delivery Protocol, [Wesley_Craig]
    Ddp = 37,
    /// IDPR Control Message Transport Proto, [Martha_Steenstrup]
    IdprCmtp = 38,
    /// TP++ Transport Protocol, [Dirk_Fromhein]
    TpPlusPlus = 39,
    /// IL Transport Protocol, [Dave_Presotto]
    Il = 40,
    /// IPv6 encapsulation, [RFC2473]
    Ipv6 = 41,
    /// Source Demand Routing Protocol, [Deborah_Estrin]
    Sdrp = 42,
    /// Routing Header for IPv6, IPv6 extension header, [Steve_Deering]
    Ipv6Route = 43,
    /// Fragment Header for IPv6, IPv6 extension header, [Steve_Deering]
    Ipv6Frag = 44,
    /// Inter-Domain Routing Protocol, [Sue_Hares]
    Idrp = 45,
    /// Reservation Protocol, [RFC2205][RFC3209][Bob_Braden]
    Rsvp = 46,
    /// Generic Routing Encapsulation, [RFC2784][Tony_Li]
    Gre = 47,
    /// Dynamic Source Routing Protocol, [RFC4728]
    Dsr = 48,
    /// BNA, [Gary Salamon]
    Bna = 49,
    /// Encap Security Payload, IPv6 extension header, [RFC4303]
    Esp = 50,
    /// Authentication Header, IPv6 extension header, [RFC4302]
    Ah = 51,
    /// Integrated Net Layer Security  TUBA, [K_Robert_Glenn]
    INlsp = 52,
    /// IP with Encryption, [John_Ioannidis]
    Swipe = 53,
    /// NBMA Address Resolution Protocol, [RFC1735]
    Narp = 54,
    /// IP Mobility, [Charlie_Perkins]
    Mobile = 55,
    /// "Transport Layer Security Protocol using Kryptonet key management", [Christer_Oberg]
    Tlsp = 56,
    /// SKIP, [Tom_Markson]
    Skip = 57,
    /// ICMP for IPv6, [RFC8200]
    Ipv6Icmp = 58,
    /// No Next Header for IPv6, [RFC8200]
    Ipv6NoNxt = 59,
    /// Destination Options for IPv6, IPv6 extension header, [RFC8200]
    Ipv6Opts = 60,
    /// any host internal protocol, [Internet_Assigned_Numbers_Authority]
    HostInternal = 61,
    /// CFTP, "[Forsdick,  H.,  ""CFTP"",  Network Message,  Bolt Beranek and Newman,  January 1982.][Harry_Forsdick]"
    Cftp = 62,
    /// any local network, [Internet_Assigned_Numbers_Authority]
    LocalNetwork = 63,
    /// SATNET and Backroom EXPAK, [Steven_Blumenthal]
    SatExpak = 64,
    /// Kryptolan, [Paul Liu]
    Kryptolan = 65,
    /// MIT Remote Virtual Disk Protocol, [Michael_Greenwald]
    Rvd = 66,
    /// Internet Pluribus Packet Core, [Steven_Blumenthal]
    Ippc = 67,
    /// any distributed file system, [Internet_Assigned_Numbers_Authority]
    DistributedFs = 68,
    /// SATNET Monitoring, [Steven_Blumenthal]
    SatMon = 69,
    /// VISA Protocol, [Gene_Tsudik]
    Visa = 70,
    /// Internet Packet Core Utility, [Steven_Blumenthal]
    Ipcv = 71,
    /// Computer Protocol Network Executive, [David Mittnacht]
    Cpnx = 72,
    /// Computer Protocol Heart Beat, [David Mittnacht]
    Cphb = 73,
    /// Wang Span Network, [Victor Dafoulas]
    Wsn = 74,
    /// Packet Video Protocol, [Steve_Casner]
    Pvp = 75,
    /// Backroom SATNET Monitoring, [Steven_Blumenthal]
    BrSatMon = 76,
    /// SUN ND PROTOCOL-Temporary, [William_Melohn]
    SunNd = 77,
    /// WIDEBAND Monitoring, [Steven_Blumenthal]
    WbMon = 78,
    /// WIDEBAND EXPAK, [Steven_Blumenthal]
    WbExpak = 79,
    /// ISO Internet Protocol, [Marshall_T_Rose]
    IsoIp = 80,
    /// VMTP, [Dave_Cheriton]
    Vmtp = 81,
    /// SECURE-VMTP, [Dave_Cheriton]
    SecureVmtp = 82,
    /// VINES, [Brian Horn]
    Vines = 83,
    /// Transaction Transport Protocol or Internet Protocol Traffic Manager, [Jim_Stevens]
    TtpOrIptm = 84,
    /// NSFNET-IGP, [Hans_Werner_Braun]
    NsfnetIgp = 85,
    /// Dissimilar Gateway Protocol, "[M/A-COM Government Systems,  ""Dissimilar Gateway Protocol Specification,  Draft Version"",  Contract no. CS901145,  November 16,  1987.][Mike_Little]"
    Dgp = 86,
    /// TCF, [Guillermo_A_Loyola]
    Tcf = 87,
    /// EIGRP, [RFC7868]
    Eigrp = 88,
    /// OSPFIGP, [RFC1583][RFC2328][RFC5340][John_Moy]
    OspfigP = 89,
    /// Sprite RPC Protocol, "[Welch,  B.,  ""The Sprite Remote Procedure Call System"",  Technical Report,  UCB/Computer Science Dept.,  86/302,  University of California at Berkeley,  June 1986.][Bruce Willins]"
    SpriteRpc = 90,
    /// Locus Address Resolution Protocol, [Brian Horn]
    Larp = 91,
    /// Multicast Transport Protocol, [Susie_Armstrong]
    Mtp = 92,
    /// AX.25 Frames, [Brian_Kantor]
    Ax25 = 93,
    /// IP-within-IP Encapsulation Protocol, [John_Ioannidis]
    IpIp = 94,
    /// Mobile Internetworking Control Pro., [John_Ioannidis]
    Micp = 95,
    /// Semaphore Communications Sec. Pro., [Howard_Hart]
    SccSp = 96,
    /// Ethernet-within-IP Encapsulation, [RFC3378]
    Etherip = 97,
    /// Encapsulation Header, [RFC1241][Robert_Woodburn]
    Encap = 98,
    /// any private encryption scheme, [Internet_Assigned_Numbers_Authority]
    PrivEncryption = 99,
    /// GMTP, [[RXB5]]
    Gmtp = 100,
    /// Ipsilon Flow Management Protocol, "[Bob_Hinden][November 1995,  1997.]"
    Ifmp = 101,
    /// PNNI over IP, [Ross_Callon]
    Pnni = 102,
    /// Protocol Independent Multicast, [RFC7761][Dino_Farinacci]
    Pim = 103,
    /// ARIS, [Nancy_Feldman]
    Aris = 104,
    /// SCPS, [Robert_Durst]
    Scps = 105,
    /// QNX, [Michael_Hunter]
    Qnx = 106,
    /// 107, A/N, Active Networks, [Bob_Braden]
    AN = 107,
    /// IP Payload Compression Protocol, [RFC2393]
    IpComp = 108,
    /// Sitara Networks Protocol, [Manickam_R_Sridhar]
    Snp = 109,
    /// Compaq Peer Protocol, [Victor_Volpe]
    CompaqPeer = 110,
    /// IPX in IP, [CJ_Lee]
    IpxInIp = 111,
    /// Virtual Router Redundancy Protocol, [RFC5798]
    Vrrp = 112,
    /// PGM Reliable Transport Protocol, [Tony_Speakman]
    Pgm = 113,
    /// any 0-hop protocol, [Internet_Assigned_Numbers_Authority]
    ZeroHop = 114,
    /// Layer Two Tunneling Protocol, [RFC3931][Bernard_Aboba]
    L2tp = 115,
    /// D-II Data Exchange (DDX), [John_Worley]
    Ddx = 116,
    /// Interactive Agent Transfer Protocol, [John_Murphy]
    Iatp = 117,
    /// Schedule Transfer Protocol, [Jean_Michel_Pittet]
    Stp = 118,
    /// SpectraLink Radio Protocol, [Mark_Hamilton]
    Srp = 119,
    /// UTI, [Peter_Lothberg]
    Uti = 120,
    /// Simple Message Protocol, [Leif_Ekblad]
    Smp = 121,
    /// Simple Multicast Protocol, [Jon_Crowcroft][draft-perlman-simple-multicast]
    Sm = 122,
    /// Performance Transparency Protocol, [Michael_Welzl]
    Ptp = 123,
    /// [Tony_Przygienda]
    IsisOverIpv4 = 124,
    /// [Criag_Partridge]
    Fire = 125,
    /// Combat Radio Transport Protocol, [Robert_Sautter]
    Crtp = 126,
    /// Combat Radio User Datagram, [Robert_Sautter]
    Crudp = 127,
    /// [Kurt_Waber]
    Sscopmce = 128,
    /// [[Hollbach]]
    Iplt = 129,
    /// Secure Packet Shield, [Bill_McIntosh]
    Sps = 130,
    /// Private IP Encapsulation within IP, [Bernhard_Petri]
    Pipe = 131,
    /// Stream Control Transmission Protocol, [Randall_R_Stewart]
    Sctp = 132,
    /// Fibre Channel, [Murali_Rajagopal][RFC6172]
    Fc = 133,
    /// [RFC3175]
    RsvpE2eIgnore = 134,
    /// IPv6 extension header, [RFC6275]
    MobilityHeader = 135,
    /// [RFC3828]
    UdpLite = 136,
    /// [RFC4023]
    MplsInIp = 137,
    /// MANET Protocols, [RFC5498]
    Manet = 138,
    /// Host Identity Protocol, IPv6 extension header, [RFC7401]
    Hip = 139,
    /// Shim6 Protocol, IPv6 extension header, [RFC5533]
    Shim6 = 140,
    /// Wrapped Encapsulating Security Payload, [RFC5840]
    Wesp = 141,
    /// Robust Header Compression, [RFC5858]
    Rohc = 142,
    /// "Ethernet (TEMPORARY - registered 2020-01-31,  expires 2021-01-31)", [draft-ietf-spring-srv6-network-programming]
    Ethernet = 143,
    /// Use for experimentation and testing, IPv6 extension header, [RFC3692]
    Test1 = 253,
    /// Use for experimentation and testing, IPv6 extension header, [RFC3692]
    Test2 = 254,
}

impl TryFrom<u8> for ProtocolNumber {
    type Error = ();

    fn try_from(val: u8) -> Result<ProtocolNumber, Self::Error> {
        use ProtocolNumber::*;
        match val {
            0 => Ok(Hopopt),
            1 => Ok(Icmp),
            2 => Ok(Igmp),
            3 => Ok(Ggp),
            4 => Ok(Ipv4),
            5 => Ok(St),
            6 => Ok(Tcp),
            7 => Ok(Cbt),
            8 => Ok(Egp),
            9 => Ok(Igp),
            10 => Ok(BbnRccMon),
            11 => Ok(NvpII),
            12 => Ok(Pup),
            13 => Ok(Argus),
            14 => Ok(Emcon),
            15 => Ok(Xnet),
            16 => Ok(Chaos),
            17 => Ok(Udp),
            18 => Ok(Mux),
            19 => Ok(DcnMeas),
            20 => Ok(Hmp),
            21 => Ok(Prm),
            22 => Ok(XnsIdp),
            23 => Ok(Trunk1),
            24 => Ok(Trunk2),
            25 => Ok(Leaf1),
            26 => Ok(Leaf2),
            27 => Ok(Rdp),
            28 => Ok(Irtp),
            29 => Ok(IsoTp4),
            30 => Ok(Netblt),
            31 => Ok(MfeNsp),
            32 => Ok(MeritInp),
            33 => Ok(Dccp),
            34 => Ok(ThreePc),
            35 => Ok(Idpr),
            36 => Ok(Xtp),
            37 => Ok(Ddp),
            38 => Ok(IdprCmtp),
            39 => Ok(TpPlusPlus),
            40 => Ok(Il),
            41 => Ok(Ipv6),
            42 => Ok(Sdrp),
            43 => Ok(Ipv6Route),
            44 => Ok(Ipv6Frag),
            45 => Ok(Idrp),
            46 => Ok(Rsvp),
            47 => Ok(Gre),
            48 => Ok(Dsr),
            49 => Ok(Bna),
            50 => Ok(Esp),
            51 => Ok(Ah),
            52 => Ok(INlsp),
            53 => Ok(Swipe),
            54 => Ok(Narp),
            55 => Ok(Mobile),
            56 => Ok(Tlsp),
            57 => Ok(Skip),
            58 => Ok(Ipv6Icmp),
            59 => Ok(Ipv6NoNxt),
            60 => Ok(Ipv6Opts),
            61 => Ok(HostInternal),
            62 => Ok(Cftp),
            63 => Ok(LocalNetwork),
            64 => Ok(SatExpak),
            65 => Ok(Kryptolan),
            66 => Ok(Rvd),
            67 => Ok(Ippc),
            68 => Ok(DistributedFs),
            69 => Ok(SatMon),
            70 => Ok(Visa),
            71 => Ok(Ipcv),
            72 => Ok(Cpnx),
            73 => Ok(Cphb),
            74 => Ok(Wsn),
            75 => Ok(Pvp),
            76 => Ok(BrSatMon),
            77 => Ok(SunNd),
            78 => Ok(WbMon),
            79 => Ok(WbExpak),
            80 => Ok(IsoIp),
            81 => Ok(Vmtp),
            82 => Ok(SecureVmtp),
            83 => Ok(Vines),
            84 => Ok(TtpOrIptm),
            85 => Ok(NsfnetIgp),
            86 => Ok(Dgp),
            87 => Ok(Tcf),
            88 => Ok(Eigrp),
            89 => Ok(OspfigP),
            90 => Ok(SpriteRpc),
            91 => Ok(Larp),
            92 => Ok(Mtp),
            93 => Ok(Ax25),
            94 => Ok(IpIp),
            95 => Ok(Micp),
            96 => Ok(SccSp),
            97 => Ok(Etherip),
            98 => Ok(Encap),
            99 => Ok(PrivEncryption),
            100 => Ok(Gmtp),
            101 => Ok(Ifmp),
            102 => Ok(Pnni),
            103 => Ok(Pim),
            104 => Ok(Aris),
            105 => Ok(Scps),
            106 => Ok(Qnx),
            107 => Ok(AN),
            108 => Ok(IpComp),
            109 => Ok(Snp),
            110 => Ok(CompaqPeer),
            111 => Ok(IpxInIp),
            112 => Ok(Vrrp),
            113 => Ok(Pgm),
            114 => Ok(ZeroHop),
            115 => Ok(L2tp),
            116 => Ok(Ddx),
            117 => Ok(Iatp),
            118 => Ok(Stp),
            119 => Ok(Srp),
            120 => Ok(Uti),
            121 => Ok(Smp),
            122 => Ok(Sm),
            123 => Ok(Ptp),
            124 => Ok(IsisOverIpv4),
            125 => Ok(Fire),
            126 => Ok(Crtp),
            127 => Ok(Crudp),
            128 => Ok(Sscopmce),
            129 => Ok(Iplt),
            130 => Ok(Sps),
            131 => Ok(Pipe),
            132 => Ok(Sctp),
            133 => Ok(Fc),
            134 => Ok(RsvpE2eIgnore),
            135 => Ok(MobilityHeader),
            136 => Ok(UdpLite),
            137 => Ok(MplsInIp),
            138 => Ok(Manet),
            139 => Ok(Hip),
            140 => Ok(Shim6),
            141 => Ok(Wesp),
            142 => Ok(Rohc),
            143 => Ok(Ethernet),
            253 => Ok(Test1),
            254 => Ok(Test2),
            _ => Err(()),
        }
    }
}
