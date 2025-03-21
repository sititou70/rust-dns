use crate::util::*;
use num::FromPrimitive;

pub fn create_ip_packet(
    protocol: u8,
    id: u16,
    src_ipaddr_str: &str,
    dest_ipaddr_str: &str,
    data: &Vec<u8>,
) -> Vec<u8> {
    let internet_header_length = 20_u8; // min ip header size
    let version_and_ihl = vec![4 << 4 & 0xf0 | (internet_header_length >> 2) & 0x0f];
    let type_of_service = vec![0_u8];
    let total_length = (internet_header_length as u16 + u16::from_usize(data.len()).unwrap())
        .to_be_bytes()
        .to_vec();
    let identification = id.to_be_bytes().to_vec();
    let flag_and_offset = vec![0_u8, 0];
    let time_to_live = vec![255_u8];
    let protocol = vec![protocol];
    let src_ipaddr = parse_ipaddr(src_ipaddr_str);
    let dest_ipaddr = parse_ipaddr(dest_ipaddr_str);
    let header_checksum = checksum16(
        &[
            version_and_ihl.clone(),
            type_of_service.clone(),
            total_length.clone(),
            identification.clone(),
            flag_and_offset.clone(),
            time_to_live.clone(),
            protocol.clone(),
            src_ipaddr.clone(),
            dest_ipaddr.clone(),
        ]
        .concat(),
        0,
    )
    .to_be_bytes()
    .to_vec();

    return [
        version_and_ihl,
        type_of_service,
        total_length,
        identification,
        flag_and_offset,
        time_to_live,
        protocol,
        header_checksum,
        src_ipaddr,
        dest_ipaddr,
        data.clone(),
    ]
    .concat();
}

pub fn get_ip_packet_data(packet: &Vec<u8>) -> Vec<u8> {
    let internet_header_length = ((packet[0] & 0x0f) << 2) as usize;
    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    return packet[internet_header_length..total_length].to_vec();
}
