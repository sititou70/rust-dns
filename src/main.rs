mod arp;
mod dns;
mod ether;
mod ip;
mod udp;
mod util;

use std::{thread, time::Duration};

use arp::create_arp_request_message;
use dns::*;
use ether::*;
use ip::*;
use rand::random_range;
use tun_tap::*;
use udp::*;
use util::{parse_macaddr, print_macaddr};

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

    // dns
    let root_ip_addr = ROOT_IP_ADDRS[random_range(0..ROOT_IP_ADDRS.len())];
    let dns_message = create_dns_a_question_message(12345, "example.com.");
    let dns_udp_datagram =
        create_udp_datagram(my_udp_port, 53, &dns_message, my_ipaddr, root_ip_addr);
    let dns_ip_packet = create_ip_packet(
        17, // udp
        123,
        my_ipaddr,
        root_ip_addr,
        &dns_udp_datagram,
    );
    let dns_ethernet_frame = create_ethernet_frame(
        0x0800, // ipv4
        &gateway_macaddr,
        my_macaddr,
        &dns_ip_packet,
    );

    thread::sleep(Duration::from_millis(1000));

    iface
        .send(
            &[
                vec![0_u8, 0, 0, 0], // for IFF_NO_PI
                dns_ethernet_frame,
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

        let ip_packet = get_ethernet_frame_data(&frame);
        let udp_datagram = get_ip_packet_data(&ip_packet);
        let dns_message = get_udp_datagram_data(&udp_datagram);
        let message = match parse_dns_message(&dns_message) {
            Ok(message) => message,
            Err(_) => continue,
        };

        if message.header.id != 12345 {
            continue;
        }

        println!("{}", message);
        break;
    }
}
