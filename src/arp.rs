use crate::{ether::get_ethernet_frame_data, util::*};

pub fn create_arp_request_message(
    sender_ipaddr_str: &str,
    sender_macaddr_str: &str,
    target_ipaddr_str: &str,
) -> Vec<u8> {
    let hardware_type = 1_u16.to_be_bytes().to_vec(); // ethernet
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

pub fn create_arp_reply_message(
    sender_ipaddr_str: &str,
    sender_macaddr_str: &str,
    target_ipaddr_str: &str,
    target_macaddr_str: &str,
) -> Vec<u8> {
    let hardware_type = 1_u16.to_be_bytes().to_vec(); // ethernet
    let protocol_type = 0x0800_u16.to_be_bytes().to_vec(); // IPv4
    let hardware_size = vec![6_u8];
    let protocol_size = vec![4_u8];
    let opecode = 2_u16.to_be_bytes().to_vec(); // reply
    let sender_hwaddr = parse_macaddr(sender_macaddr_str);
    let sender_protoaddr = parse_ipaddr(sender_ipaddr_str);
    let target_hwaddr = parse_macaddr(target_macaddr_str);
    let target_protoaddr = parse_ipaddr(target_ipaddr_str);

    return [
        hardware_type,
        protocol_type,
        hardware_size,
        protocol_size,
        opecode,
        sender_hwaddr,
        sender_protoaddr,
        target_hwaddr,
        target_protoaddr,
    ]
    .concat();
}

pub fn is_arp_request(frame: &Vec<u8>, my_ipaddr: &str, my_macaddr: &str) -> bool {
    // destination is broadcast or my mac address
    if !(frame[0..6] == parse_macaddr("ff:ff:ff:ff:ff:ff")
        || frame[0..6] == parse_macaddr(my_macaddr))
    {
        return false;
    }
    // type is arp
    if frame[12..12 + 2] != [0x08_u8, 0x06_u8] {
        return false;
    }

    let message = get_ethernet_frame_data(&frame);
    // opecode is request
    if message[6..6 + 2] != vec![0x00, 0x01] {
        return false;
    };

    // target protocol address is my ip address
    if message[24..24 + 4] != parse_ipaddr(&my_ipaddr) {
        return false;
    }

    return true;
}

pub fn is_arp_reply(frame: &Vec<u8>, my_ipaddr: &str, my_macaddr: &str) -> bool {
    // destination is my mac address
    if frame[0..6] != parse_macaddr(my_macaddr) {
        return false;
    }
    // type is arp
    if frame[12..12 + 2] != [0x08_u8, 0x06_u8] {
        return false;
    }

    let message = get_ethernet_frame_data(&frame);
    // opecode is reply
    if message[6..6 + 2] != vec![0x00, 0x02] {
        return false;
    }

    // target protocol address is my ip address
    if message[24..24 + 4] != parse_ipaddr(my_ipaddr) {
        return false;
    }

    return true;
}
