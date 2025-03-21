pub fn parse_macaddr(str: &str) -> Vec<u8> {
    let vec = str
        .split(':')
        .map(|str| u8::from_str_radix(str, 16).unwrap())
        .collect::<Vec<u8>>();

    if vec.len() != 6 {
        panic!("invalid hwaddr format: {}", str);
    }

    return vec;
}

#[cfg(test)]
mod parse_macaddr {
    use crate::util::*;

    #[test]
    fn case1() {
        assert_eq!(
            parse_macaddr("11:22:33:dd:ee:ff"),
            vec![0x11, 0x22, 0x33, 0xdd, 0xee, 0xff]
        );
    }

    #[test]
    #[should_panic]
    fn case2() {
        parse_macaddr("11:22:33:dd:ee");
    }

    #[test]
    #[should_panic]
    fn case3() {
        parse_macaddr("11:22:33:dd:ee:fff");
    }
}

pub fn print_macaddr(addr: &Vec<u8>) -> String {
    if addr.len() != 6 {
        panic!("invalid hwaddr length: {}", addr.len());
    }

    return addr
        .iter()
        .map(|x| format!("{:02x}", x))
        .collect::<Vec<String>>()
        .join(":");
}

#[cfg(test)]
mod print_macaddr {
    use crate::util::*;

    #[test]
    fn case1() {
        assert_eq!(
            print_macaddr(&vec![0x00, 0x01, 0x11, 0xff, 0xff, 0xff]),
            "00:01:11:ff:ff:ff"
        );
    }
}

pub fn parse_ipaddr(str: &str) -> Vec<u8> {
    let vec = str
        .split('.')
        .map(|str| u8::from_str_radix(str, 10).unwrap())
        .collect::<Vec<u8>>();

    if vec.len() != 4 {
        panic!("invalid ipaddr format: {}", str);
    }

    return vec;
}

#[cfg(test)]
mod parse_ipaddr {
    use crate::util::*;

    #[test]
    fn case1() {
        assert_eq!(parse_ipaddr("192.168.0.1"), vec![192, 168, 0, 1]);
    }

    #[test]
    #[should_panic]
    fn case2() {
        parse_macaddr("192.168.0.1.1");
    }

    #[test]
    #[should_panic]
    fn case3() {
        parse_macaddr("192.168.0.256");
    }
}

pub fn print_ipaddr(addr: &Vec<u8>) -> String {
    if addr.len() != 4 {
        panic!("invalid ipaddr length: {}", addr.len());
    }

    return addr
        .iter()
        .map(|x| format!("{}", x))
        .collect::<Vec<String>>()
        .join(".");
}

#[cfg(test)]
mod print_ipaddr {
    use crate::util::*;

    #[test]
    fn case1() {
        assert_eq!(print_ipaddr(&vec![0, 10, 100, 255]), "0.10.100.255");
    }
}

// see: https://docs.google.com/presentation/d/1kjvdsM2Slfug4t4lQ5HRCitoTbH7edl-1OPtEaG53D8/edit#slide=id.gd326ebd0a8_0_798
pub fn checksum16(data: &Vec<u8>, init: u32) -> u16 {
    let mut sum = init;
    let mut index = 0;
    while index + 1 < data.len() {
        sum += u32::from_be_bytes([0, 0, data[index], data[index + 1]]);
        index += 2;
    }

    if index < data.len() {
        sum += u32::from_be_bytes([0, 0, data[index], 0]);
    }

    while sum & 0xffff0000 != 0 {
        sum = (sum & 0x0000ffff) + (sum >> 16);
    }

    return !(sum as u16);
}

#[cfg(test)]
mod checksum16 {
    use crate::util::*;

    #[test]
    fn case1() {
        assert_eq!(
            checksum16(&vec![0x00, 0x05, 0xff, 0xfe, 0x00, 0x00], 0),
            0xfffb
        );
    }

    #[test]
    fn case2() {
        let header = vec![0x12_u8, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let sum = checksum16(&header, 0);

        assert_eq!(checksum16(&header, sum as u32), 0);
    }

    #[test]
    fn case3() {
        let header = vec![0x12_u8, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x01];
        let sum = checksum16(&header, 0);

        assert_eq!(checksum16(&header, sum as u32), 0);
    }
}

#[allow(dead_code)]
pub fn dump_vec(data: &Vec<u8>) {
    println!(
        "{}",
        data.iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join(" ")
    )
}
