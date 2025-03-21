use crate::util::*;

pub fn create_arp_request_message(
    sender_ipaddr_str: &str,
    sender_macaddr_str: &str,
    target_ipaddr_str: &str,
) -> Vec<u8> {
    let hardware_type = 1_u16.to_be_bytes().to_vec();
    let protocol_type = 0x0800_u16.to_be_bytes().to_vec(); // IPv4
    let hardware_size = vec![6_u8];
    let protocol_size = vec![4_u8];
    let opecode = 1_u16.to_be_bytes().to_vec(); // request
    let sender_hwaddr = parse_macaddr(sender_macaddr_str);
    let sender_ipaddr = parse_ipaddr(sender_ipaddr_str);
    let target_hwaddr = parse_macaddr("00:00:00:00:00:00");
    let target_ipaddr = parse_ipaddr(target_ipaddr_str);

    return [
        hardware_type,
        protocol_type,
        hardware_size,
        protocol_size,
        opecode,
        sender_hwaddr,
        sender_ipaddr,
        target_hwaddr,
        target_ipaddr,
    ]
    .concat();
}
