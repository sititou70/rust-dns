use crate::util::*;
use num::FromPrimitive;

pub fn create_udp_datagram(
    src_port_num: u16,
    dest_port_num: u16,
    data: &Vec<u8>,
    src_ipaddr_str: &str,
    dest_ipaddr_str: &str,
) -> Vec<u8> {
    let src_port = src_port_num.to_be_bytes().to_vec();
    let dest_port = dest_port_num.to_be_bytes().to_vec();
    let length = (8 // udp header size
         + u16::from_usize(data.len()).unwrap())
    .to_be_bytes()
    .to_vec();

    let src_ipaddr = parse_ipaddr(src_ipaddr_str);
    let dest_ipaddr = parse_ipaddr(dest_ipaddr_str);
    let zero = vec![0_u8];
    let protocol_number = vec![17_u8];
    let udp_length = length.clone();
    let checksum = checksum16(
        &[
            // pseudo header
            src_ipaddr,
            dest_ipaddr,
            zero,
            protocol_number,
            udp_length,
            // datagram
            src_port.clone(),
            dest_port.clone(),
            length.clone(),
            vec![0_u8, 0], // initial checksum
            data.clone(),
        ]
        .concat(),
        0,
    )
    .to_be_bytes()
    .to_vec();

    return [src_port, dest_port, length, checksum, data.clone()].concat();
}

pub fn get_udp_datagram_data(datagram: &Vec<u8>) -> Vec<u8> {
    let length = u16::from_be_bytes([datagram[4], datagram[5]]) as usize;
    return datagram[8..length].to_vec();
}
