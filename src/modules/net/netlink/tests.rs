use std::sync::Mutex;

use super::build::{self, done, error, message, with_attributes};
use super::*;

fn v4(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A kernel that answers each dump from a list, in order.
struct Replies(Mutex<Vec<(Dump, Vec<Vec<u8>>)>>);

impl Kernel for Replies {
    fn dump(&self, dump: Dump) -> io::Result<Vec<Vec<u8>>> {
        let mut replies = self.0.lock().unwrap();
        let position = replies
            .iter()
            .position(|(kind, _)| *kind == dump)
            .expect("a reply for every dump");
        Ok(replies.remove(position).1)
    }

    fn watch(&self) -> io::Result<Box<dyn Watch>> {
        Err(io::Error::other("not in this test"))
    }
}

fn joined(messages: &[Vec<u8>]) -> Vec<u8> {
    messages.concat()
}

#[test]
fn builds_dump_requests() {
    let request = request(RTM_GETADDR, IFADDRMSG_LEN);
    assert_eq!(request.len(), 24);
    assert_eq!(u32_at(&request, 0), 24);
    assert_eq!(u16_at(&request, 4), RTM_GETADDR);
    assert_eq!(u16_at(&request, 6), NLM_F_REQUEST | NLM_F_DUMP);
    assert_eq!(&request[16..], [0; 8]);
    assert_eq!(Dump::Links.request(), (RTM_GETLINK, 16));
    assert_eq!(Dump::Routes.request(), (RTM_GETROUTE, 12));
    assert_eq!(Dump::Nexthops.request(), (RTM_GETNEXTHOP, 8));
}

#[test]
fn parses_links() {
    let mut tables = Tables::default();
    let reply = joined(&[
        build::link(
            2,
            "eth0",
            IFF_UP,
            Some([0xc0, 0x74, 0x2b, 0x00, 0x00, 0x01]),
            6,
            true,
        ),
        build::link(3, "wwan0", 0, None, 2, false),
        done(),
    ]);
    parse_dump(Dump::Links, &[reply], &mut tables).unwrap();
    assert_eq!(
        tables.links[0],
        Link {
            index: 2,
            name: "eth0".into(),
            flags: IFF_UP,
            mac: Some(vec![0xc0, 0x74, 0x2b, 0x00, 0x00, 0x01]),
            permanent_mac: None,
            mtu: Some(1500),
            oper_state: 6,
            carrier: Some(true),
        }
    );
    assert_eq!(tables.links[1].mac, None);
    assert_eq!(tables.links[1].carrier, Some(false));
}

#[test]
fn a_link_keeps_its_permanent_address_and_drops_zero_ones() {
    let header = vec![0u8; IFINFOMSG_LEN];
    let body = with_attributes(
        header,
        &[
            (IFLA_IFNAME, b"wlan0\0".to_vec()),
            (IFLA_ADDRESS, vec![0; 6]),
            (IFLA_PERM_ADDRESS, vec![0xcc, 0x21, 0x9d, 0xb0, 0x5b, 0x16]),
            // The nested flag is masked off the type.
            (0x8000 | 99, vec![1, 2, 3, 4]),
        ],
    );
    let parsed = link(&body).unwrap().unwrap();
    assert_eq!(parsed.mac, None);
    assert_eq!(
        parsed.permanent_mac,
        Some(vec![0xcc, 0x21, 0x9d, 0xb0, 0x5b, 0x16])
    );
    // A link without a name isn't one the module can report.
    assert_eq!(link(&[0; IFINFOMSG_LEN]).unwrap(), None);
}

#[test]
fn parses_addresses_with_their_flags() {
    let mut tables = Tables::default();
    let reply = joined(&[
        build::address(2, v4("192.168.5.31"), 24, 0),
        build::address(
            2,
            v4("2001:db8:5:1::1"),
            64,
            IFA_F_TEMPORARY | IFA_F_DEPRECATED,
        ),
        done(),
    ]);
    parse_dump(Dump::Addresses, &[reply], &mut tables).unwrap();
    assert_eq!(tables.addresses[0].address, v4("192.168.5.31"));
    assert_eq!(tables.addresses[0].prefix, 24);
    assert_eq!(
        tables.addresses[1].flags,
        IFA_F_TEMPORARY | IFA_F_DEPRECATED
    );
}

#[test]
fn a_point_to_point_address_is_the_local_end() {
    let mut header = vec![AF_INET, 32, 0x40, 0];
    header.extend_from_slice(&7u32.to_ne_bytes());
    let body = with_attributes(
        header,
        &[
            (IFA_ADDRESS, vec![10, 64, 64, 64]),
            (IFA_LOCAL, vec![10, 0, 0, 2]),
        ],
    );
    let parsed = address(&body).unwrap().unwrap();
    assert_eq!(parsed.address, v4("10.0.0.2"));
    assert_eq!(
        parsed.flags, IFA_F_TENTATIVE,
        "from the header without IFA_FLAGS"
    );
    // No address at all, or one of an unknown family.
    assert_eq!(address(&[AF_INET, 0, 0, 0, 1, 0, 0, 0]).unwrap(), None);
    let odd = with_attributes(vec![7, 0, 0, 0, 1, 0, 0, 0], &[(IFA_ADDRESS, vec![1; 4])]);
    assert_eq!(address(&odd).unwrap(), None);
}

#[test]
fn keeps_only_main_table_default_unicast_routes() {
    let mut tables = Tables::default();
    let gateway = v4("192.168.5.1");
    let mut specific = build::default_route(false, Some(2), Some(gateway), 100, None);
    specific[NLMSG_HDR_LEN + 1] = 24; // a /24, not a default route
    let mut local_table = build::default_route(false, Some(2), Some(gateway), 100, None);
    // RTA_TABLE overrides the header's table: make it the local table.
    let table_at = local_table
        .windows(4)
        .position(|w| w == 254u32.to_ne_bytes())
        .unwrap();
    local_table[table_at..table_at + 4].copy_from_slice(&255u32.to_ne_bytes());
    let mut blackhole = build::default_route(false, Some(2), None, 1, None);
    blackhole[NLMSG_HDR_LEN + 7] = 6;
    let reply = joined(&[
        build::default_route(false, Some(2), Some(gateway), 100, None),
        build::default_route(true, None, None, 100, Some(1_241_586_351)),
        specific,
        local_table,
        blackhole,
        // No way out at all.
        build::default_route(false, None, None, 5, None),
        done(),
    ]);
    parse_dump(Dump::Routes, &[reply], &mut tables).unwrap();
    assert_eq!(
        tables.routes,
        [
            Route {
                ipv6: false,
                metric: 100,
                via: Via::Hops(vec![Hop {
                    index: 2,
                    gateway: Some(gateway)
                }]),
            },
            Route {
                ipv6: true,
                metric: 100,
                via: Via::Nexthop(1_241_586_351),
            },
        ]
    );
}

#[test]
fn parses_multipath_routes_and_foreign_gateways() {
    let mut first = vec![0u8; RTNEXTHOP_LEN];
    let first_attributes = with_attributes(Vec::new(), &[(RTA_GATEWAY, vec![10, 0, 0, 1])]);
    first[0..2].copy_from_slice(&u16::try_from(RTNEXTHOP_LEN + 8).unwrap().to_ne_bytes());
    first[4..8].copy_from_slice(&3u32.to_ne_bytes());
    first.extend_from_slice(&first_attributes);
    let mut second = vec![0u8; RTNEXTHOP_LEN];
    let mut rtvia = u16::from(AF_INET6).to_ne_bytes().to_vec();
    rtvia.extend_from_slice(&v6_octets("fe80::1"));
    let second_attributes = with_attributes(Vec::new(), &[(RTA_VIA, rtvia)]);
    let second_len = RTNEXTHOP_LEN + second_attributes.len();
    second[0..2].copy_from_slice(&u16::try_from(second_len).unwrap().to_ne_bytes());
    second[4..8].copy_from_slice(&4u32.to_ne_bytes());
    second.extend_from_slice(&second_attributes);
    let header = vec![AF_INET, 0, 0, 0, 254, 3, 0, RTN_UNICAST, 0, 0, 0, 0];
    let body = with_attributes(header, &[(RTA_MULTIPATH, [first, second].concat())]);
    let parsed = route(&body).unwrap().unwrap();
    assert_eq!(
        parsed.via,
        Via::Hops(vec![
            Hop {
                index: 3,
                gateway: Some(v4("10.0.0.1"))
            },
            Hop {
                index: 4,
                gateway: Some(v4("fe80::1"))
            },
        ])
    );
    // A hop whose length runs past the attribute.
    let mut broken = vec![0u8; RTNEXTHOP_LEN];
    broken[0] = 200;
    let header = vec![AF_INET, 0, 0, 0, 254, 3, 0, RTN_UNICAST, 0, 0, 0, 0];
    let body = with_attributes(header, &[(RTA_MULTIPATH, broken)]);
    assert_eq!(route(&body).unwrap_err().kind(), io::ErrorKind::InvalidData);
}

fn v6_octets(text: &str) -> [u8; 16] {
    text.parse::<Ipv6Addr>().unwrap().octets()
}

#[test]
fn resolves_routes_through_nexthops_and_groups() {
    let router = v4("fe80::1");
    let mut tables = Tables::default();
    let group = with_attributes(
        vec![AF_INET6, 0, 0, 0, 0, 0, 0, 0],
        &[
            (NHA_ID, 9u32.to_ne_bytes().to_vec()),
            (
                NHA_GROUP,
                [
                    [1u32.to_ne_bytes(), [1, 0, 0, 0]].concat(),
                    [2u32.to_ne_bytes(), [1, 0, 0, 0]].concat(),
                ]
                .concat(),
            ),
        ],
    );
    let reply = joined(&[
        build::nexthop(1, 2, router),
        build::nexthop(2, 3, v4("fe80::2")),
        message(RTM_NEWNEXTHOP, 0x2, &group),
        // No id: not one a route can name.
        message(RTM_NEWNEXTHOP, 0x2, &[0; NHMSG_LEN]),
        done(),
    ]);
    parse_dump(Dump::Nexthops, &[reply], &mut tables).unwrap();
    assert_eq!(tables.nexthops.len(), 3);
    let through = |id| Route {
        ipv6: true,
        metric: 100,
        via: Via::Nexthop(id),
    };
    assert_eq!(
        tables.hops(&through(1)),
        [Hop {
            index: 2,
            gateway: Some(router)
        }]
    );
    assert_eq!(tables.hops(&through(9)).len(), 2);
    assert_eq!(tables.hops(&through(404)), []);
    // A group that names itself stops at the depth limit.
    tables.nexthops.push(Nexthop {
        id: 5,
        hop: None,
        group: vec![5],
    });
    assert_eq!(tables.hops(&through(5)), []);
}

#[test]
fn a_dump_ends_with_done_or_an_error() {
    let mut tables = Tables::default();
    // Done may come in a later datagram.
    parse_dump(
        Dump::Links,
        &[build::link(1, "eth0", 0, None, 6, true), done()],
        &mut tables,
    )
    .unwrap();
    assert_eq!(tables.links.len(), 1);
    // An acknowledgement (errno 0) ends it too.
    parse_dump(Dump::Links, &[error(0)], &mut tables).unwrap();
    let refused = parse_dump(Dump::Links, &[error(libc::EPERM)], &mut tables).unwrap_err();
    assert_eq!(refused.raw_os_error(), Some(libc::EPERM));
    let cases = [
        vec![build::link(1, "eth0", 0, None, 6, true)],
        vec![message(NLMSG_OVERRUN, 0, &[])],
        vec![message(NLMSG_ERROR, 0, &[0, 0])],
        vec![vec![0; 8]],
        vec![{
            let mut bad = done();
            bad[0] = 4;
            bad
        }],
        vec![message(RTM_NEWLINK, 0, &[0; 4])],
        vec![message(RTM_NEWADDR, 0, &[0; 4])],
        vec![message(RTM_NEWROUTE, 0, &[0; 4])],
        vec![message(RTM_NEWNEXTHOP, 0, &[0; 4])],
    ];
    for (n, datagrams) in cases.iter().enumerate() {
        let dump = match n {
            6 => Dump::Addresses,
            7 => Dump::Routes,
            8 => Dump::Nexthops,
            _ => Dump::Links,
        };
        let error = parse_dump(dump, datagrams, &mut Tables::default()).unwrap_err();
        assert_eq!(
            error.kind(),
            io::ErrorKind::InvalidData,
            "case {n}: {error}"
        );
    }
    // Messages of another kind are skipped.
    parse_dump(
        Dump::Addresses,
        &[joined(&[build::link(1, "eth0", 0, None, 6, true), done()])],
        &mut tables,
    )
    .unwrap();
}

#[test]
fn attributes_must_fit() {
    for bytes in [vec![200u8, 0, 1, 0], vec![2, 0, 1, 0]] {
        assert_eq!(
            attributes(&bytes).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    assert_eq!(attributes(&[1, 2]).unwrap(), []);
    assert_eq!(u32_of(&[1, 2]), None);
    assert_eq!(via(&[1]), None);
}

#[test]
fn ends_dump_spots_the_last_datagram() {
    assert!(ends_dump(&done()));
    assert!(ends_dump(&error(libc::EINVAL)));
    assert!(ends_dump(&[0; 3]), "a datagram that doesn't parse ends it");
    assert!(!ends_dump(&build::link(1, "eth0", 0, None, 6, true)));
}

#[test]
fn read_retries_interrupted_dumps_and_tolerates_missing_nexthops() {
    let interrupted = message(RTM_NEWLINK, NLM_F_DUMP_INTR, &[0; IFINFOMSG_LEN]);
    let kernel = Replies(Mutex::new(vec![
        (Dump::Links, vec![interrupted]),
        (
            Dump::Links,
            vec![joined(&[
                build::link(2, "eth0", IFF_UP, None, 6, true),
                done(),
            ])],
        ),
        (
            Dump::Addresses,
            vec![joined(&[build::address(2, v4("10.0.0.2"), 8, 0), done()])],
        ),
        (Dump::Routes, vec![done()]),
        (Dump::Nexthops, vec![error(libc::EOPNOTSUPP)]),
        (Dump::Rules, vec![done()]),
    ]));
    let tables = read(&kernel).unwrap();
    assert_eq!(tables.links.len(), 1);
    assert_eq!(tables.addresses.len(), 1);
    assert!(tables.nexthops.is_empty());

    let interrupted = || message(RTM_NEWLINK, NLM_F_DUMP_INTR, &[0; IFINFOMSG_LEN]);
    let kernel = Replies(Mutex::new(vec![
        (Dump::Links, vec![interrupted()]),
        (Dump::Links, vec![interrupted()]),
        (Dump::Links, vec![interrupted()]),
    ]));
    assert_eq!(
        read(&kernel).unwrap_err().kind(),
        io::ErrorKind::Interrupted
    );

    let kernel = Replies(Mutex::new(vec![
        (Dump::Links, vec![done()]),
        (Dump::Addresses, vec![error(libc::EPERM)]),
    ]));
    assert_eq!(read(&kernel).unwrap_err().raw_os_error(), Some(libc::EPERM));
}

#[test]
fn clear_empties_one_table() {
    let mut tables = Tables {
        links: vec![Link {
            index: 1,
            name: "a".into(),
            flags: 0,
            mac: None,
            permanent_mac: None,
            mtu: None,
            oper_state: 0,
            carrier: None,
        }],
        addresses: vec![Address {
            index: 1,
            address: v4("10.0.0.1"),
            prefix: 8,
            flags: 0,
        }],
        routes: vec![Route {
            ipv6: false,
            metric: 0,
            via: Via::Nexthop(1),
        }],
        nexthops: vec![Nexthop {
            id: 1,
            hop: None,
            group: vec![],
        }],
        source: crate::modules::net::routes::plan::State {
            rules: vec![crate::modules::net::routes::plan::Rule {
                source: std::net::Ipv4Addr::new(10, 0, 0, 1),
                priority: 10_001,
                table: 10_001,
            }],
            routes: vec![crate::modules::net::routes::plan::Route {
                table: 10_001,
                destination: (std::net::Ipv4Addr::UNSPECIFIED, 0),
                gateway: None,
                interface: 1,
                source: std::net::Ipv4Addr::new(10, 0, 0, 1),
            }],
        },
    };
    for dump in Dump::ALL {
        clear(&mut tables, dump);
    }
    assert_eq!(tables, Tables::default());
}

#[test]
fn reads_this_machines_tables() {
    let tables = read(&Rtnetlink).unwrap();
    let lo = tables
        .links
        .iter()
        .find(|link| link.flags & IFF_LOOPBACK != 0)
        .expect("a loopback interface");
    assert_eq!(lo.mac, None, "loopback's address is all zeros");
}

#[test]
fn the_change_socket_waits_and_returns() {
    let mut watch = Rtnetlink.watch().unwrap();
    // Nothing need change in a second; either way it returns.
    let _ = watch.wait().unwrap();
}
