mod arp;
mod ether;
mod ip;
mod udp;
mod util;

use arp::create_arp_request_message;
use ether::*;
use ip::*;
use tun_tap::*;
use udp::*;
use util::{dump_vec, parse_macaddr, print_macaddr};

fn main() {
    let iface = Iface::new("tap0", Mode::Tap).expect("Failed to create a TAP device");

    // settings
    let gateway_ipaddr = "192.168.70.1";
    let my_ipaddr = "192.168.70.2";
    let my_macaddr = "00:00:5e:00:53:01";
    let my_udp_port = 12345;

    // arp
    let arp_message = create_arp_request_message(my_ipaddr, my_macaddr, gateway_ipaddr);
    let arp_frame = create_ethernet_frame(0x0806, "ff:ff:ff:ff:ff:ff", my_macaddr, &arp_message);
    iface
        .send(
            &[
                vec![0_u8, 0, 0, 0], // for IFF_NO_PI
                arp_frame,
            ]
            .concat()
            .to_vec(),
        )
        .unwrap();

    let gateway_macaddr;
    loop {
        let mut frame = vec![0; 1500];
        iface.recv(&mut frame).unwrap();
        frame.drain(0..4); // for IFF_NO_PI

        // check
        //// destination is my macaddre
        if frame[0..6] != parse_macaddr(my_macaddr) {
            continue;
        }
        //// type is arp
        if frame[12..12 + 2] != [0x08_u8, 0x06_u8] {
            continue;
        }

        let message = get_ethernet_frame_data(&frame);
        //// opecode is reply
        if message[6..6 + 2] != vec![0x00, 0x02] {
            continue;
        }

        gateway_macaddr = print_macaddr(&message[8..8 + 6].to_vec());

        println!("arp reply received, gateway_macaddr: {}", gateway_macaddr);
        break;
    }

    // udp
    let udp_datagram = create_udp_datagram(
        my_udp_port,
        8080,
        &"hogehoge".as_bytes().to_vec(),
        my_ipaddr,
        "192.168.0.4",
    );
    let udp_packet = create_ip_packet(
        17, //udp
        123,
        my_ipaddr,
        "192.168.0.4",
        &udp_datagram,
    );
    let udp_frame = create_ethernet_frame(0x0800, &gateway_macaddr, my_macaddr, &udp_packet);
    iface
        .send(
            &[
                vec![0_u8, 0, 0, 0], // for IFF_NO_PI
                udp_frame,
            ]
            .concat()
            .to_vec(),
        )
        .unwrap();

    loop {
        let mut frame = vec![0; 1500];
        iface.recv(&mut frame).unwrap();
        frame.drain(0..4); // for IFF_NO_PI

        // check
        //// destination is my macaddre
        if frame[0..6] != parse_macaddr(my_macaddr) {
            continue;
        }
        //// type is ip
        if frame[12..12 + 2] != [0x08_u8, 0x00_u8] {
            continue;
        }

        let ethernet_frame_data = get_ethernet_frame_data(&frame);
        let ip_packet_data = get_ip_packet_data(&ethernet_frame_data);
        let udp_datagram_data = get_udp_datagram_data(&ip_packet_data);

        dump_vec(&udp_datagram_data);
        break;
    }
}
