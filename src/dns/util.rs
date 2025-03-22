pub const ROOT_IP_ADDRS: &[&str] = &[
    "198.41.0.4",     // A
    "170.247.170.2",  // B
    "192.33.4.12",    // C
    "199.7.91.13",    // D
    "192.203.230.10", // E
    "192.5.5.241",    // F
    "192.112.36.4",   // G
    "198.97.190.53",  // H
    "192.36.148.17",  // I
    "192.58.128.30",  // J
    "193.0.14.129",   // K
    "199.7.83.42",    // L
    "202.12.27.33",   // M
];

fn parse_dns_name(name_str: &str) -> Vec<u8> {
    if name_str.len() > 255 {
        panic!("too long domain name {}", name_str);
    }

    let long_label = name_str.split('.').find(|label_str| label_str.len() > 63);
    if long_label.is_some() {
        panic!("too long label {}", name_str);
    }

    return name_str
        .split('.')
        .map(|str| str.to_string().into_bytes())
        .map(|label_bytes| [vec![label_bytes.len() as u8], label_bytes].concat())
        .collect::<Vec<Vec<u8>>>()
        .concat();
}
#[cfg(test)]
mod parse_dns_name {
    use crate::dns::util::parse_dns_name;

    #[test]
    fn case1() {
        let bytes = parse_dns_name("example.com.");

        assert_eq!(
            bytes,
            vec![
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0
            ]
        );
    }

    #[test]
    #[should_panic]
    fn case2() {
        parse_dns_name(
            "longnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongnamelongname",
        );
    }

    #[test]
    #[should_panic]
    fn case3() {
        parse_dns_name("longlabellonglabellonglabellonglabellonglabellonglabellonglabell.com");
    }
}

pub fn create_dns_a_question_message(id_num: u16, name_str: &str) -> Vec<u8> {
    let id = id_num.to_be_bytes().to_vec();
    let flags = 0_u16.to_be_bytes().to_vec(); // !qr opecode=Query !aa !tc !rd !ra ZZZ rcode=none
    let qcount = 1_u16.to_be_bytes().to_vec();
    let anount = 0_u16.to_be_bytes().to_vec();
    let nsount = 0_u16.to_be_bytes().to_vec();
    let arount = 0_u16.to_be_bytes().to_vec();

    let qname = parse_dns_name(name_str);
    let qtype = 1_u16.to_be_bytes().to_vec(); // A
    let qclass = 1_u16.to_be_bytes().to_vec(); // IN

    return [
        id, flags, qcount, anount, nsount, arount, qname, qtype, qclass,
    ]
    .concat();
}
