mod arp;
mod dns;
mod ether;
mod ip;
mod udp;
mod util;

use std::{env, thread, time::Duration};

use arp::{create_arp_reply_message, create_arp_request_message, is_arp_reply, is_arp_request};
use dns::*;
use ether::*;
use ip::*;
use rand::random_range;
use tun_tap::*;
use udp::*;
use util::{parse_macaddr, print_macaddr};

fn main() {
    let args: Vec<String> = env::args().collect();
    let domain_name = args[1].clone();

    let iface =
        Iface::without_packet_info("tap0", Mode::Tap).expect("Failed to create a TAP device");
    iface
        .set_non_blocking()
        .expect("failed to set non blocking");

    // settings
    let gateway_ipaddr = "192.168.70.1";
    let my_ipaddr = "192.168.70.2";
    let my_macaddr = "00:00:5e:00:53:01";
    let my_udp_port = 12345;

    // arp
    let gateway_macaddr = resolve_macaddr(gateway_ipaddr, my_ipaddr, my_macaddr, &iface).unwrap();
    println!("gateway_macaddr resolved: {}", gateway_macaddr);

    // dns
    let resolved_ip_addr = resolve_domain_name(
        &domain_name,
        None,
        123,
        my_udp_port,
        my_ipaddr,
        my_macaddr,
        gateway_ipaddr,
        &gateway_macaddr,
        &iface,
    )
    .unwrap();
    println!("resolved: {}", resolved_ip_addr);
}

fn resolve_macaddr(
    ipaddr_str: &str,
    my_ipaddr: &str,
    my_macaddr: &str,
    iface: &Iface,
) -> Result<String, String> {
    loop {
        let arp_message = create_arp_request_message(my_ipaddr, my_macaddr, ipaddr_str);
        let arp_frame = create_ethernet_frame(
            0x0806, // arp
            "ff:ff:ff:ff:ff:ff",
            my_macaddr,
            &arp_message,
        );

        println!("send arp request...");
        iface.send(&arp_frame).unwrap();
        thread::sleep(Duration::from_millis(3000));

        loop {
            let mut frame = vec![0; 1500];
            let recv_result = iface.recv(&mut frame);
            if recv_result.is_err() {
                break;
            }

            if is_arp_reply(&frame, my_macaddr) {
                let message = get_ethernet_frame_data(&frame);
                return Ok(print_macaddr(&message[8..8 + 6].to_vec()));
            }
        }
    }
}

fn resolve_domain_name(
    name: &str,
    server_ipaddr_str: Option<&str>,
    id: u16,
    my_udp_port: u16,
    my_ipaddr: &str,
    my_macaddr: &str,
    gateway_ipaddr: &str,
    gateway_macaddr: &str,
    iface: &Iface,
) -> Result<String, String> {
    let root_ip_addr = ROOT_IP_ADDRS[random_range(0..ROOT_IP_ADDRS.len())];
    let dest_ipaddr = server_ipaddr_str.unwrap_or(root_ip_addr);
    let log_label = format!("[{} -> {}]", name, dest_ipaddr);

    loop {
        let dns_message = create_dns_a_question_message(id, &name);
        let dns_udp_datagram =
            create_udp_datagram(my_udp_port, 53, &dns_message, my_ipaddr, dest_ipaddr);
        let dns_ip_packet = create_ip_packet(
            17, // udp
            id,
            my_ipaddr,
            dest_ipaddr,
            &dns_udp_datagram,
        );
        let dns_ethernet_frame = create_ethernet_frame(
            0x0800, // ipv4
            &gateway_macaddr,
            my_macaddr,
            &dns_ip_packet,
        );

        println!("{} send dns request to {}...", log_label, dest_ipaddr);
        iface.send(&dns_ethernet_frame).unwrap();
        thread::sleep(Duration::from_millis(3000));

        loop {
            let mut frame = vec![0; 1500];
            let recv_result = iface.recv(&mut frame);
            if recv_result.is_err() {
                break;
            }

            // check arp
            if is_arp_request(&frame, my_ipaddr, my_macaddr) {
                let arp_message = create_arp_reply_message(
                    my_ipaddr,
                    my_macaddr,
                    gateway_ipaddr,
                    gateway_macaddr,
                );
                let arp_frame = create_ethernet_frame(
                    0x0806, // arp
                    gateway_macaddr,
                    my_macaddr,
                    &arp_message,
                );
                iface.send(&arp_frame).unwrap();
                continue;
            }

            // check dns
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

            if message.header.id != id {
                continue;
            }

            println!("{} dns response message received:", log_label);
            println!("{}", message);

            let answer_rr = message.answers.iter().find(|rr| {
                rr.rr_class == DnsClass::IN && rr.rr_type == DnsType::A && rr.name == name
            });
            if answer_rr.is_some() {
                let address = answer_rr.unwrap().rdata.clone();
                println!(
                    "{} answer resource record found. address={}",
                    log_label, address
                );
                return Ok(address);
            }

            let cname_rr = message.answers.iter().find(|rr| {
                rr.rr_class == DnsClass::IN && rr.rr_type == DnsType::CNAME && rr.name == name
            });
            if cname_rr.is_some() {
                let cname = cname_rr.unwrap().rdata.clone();
                println!(
                    "{} canonical name found, resolving... name={}",
                    log_label, cname
                );

                let cname_address = resolve_domain_name(
                    &cname,
                    None,
                    id + 1,
                    my_udp_port,
                    my_ipaddr,
                    my_macaddr,
                    gateway_ipaddr,
                    gateway_macaddr,
                    iface,
                )
                .unwrap();

                println!(
                    "{} canonical name resolved. name={} cname_address={}",
                    log_label, cname, cname_address
                );

                return Ok(cname_address);
            }

            let name_server_rrs: Vec<&DnsResourceRecord> = message
                .authorities
                .iter()
                .filter(|rr| rr.rr_class == DnsClass::IN && rr.rr_type == DnsType::NS)
                .collect();
            if name_server_rrs.len() != 0 {
                let name_server_rr = name_server_rrs[random_range(0..name_server_rrs.len())];
                println!(
                    "{} name server resource record found. server_name={}",
                    log_label, name_server_rr.rdata
                );

                let additional_rr_for_name_server = message.additionals.iter().find(|rr| {
                    rr.rr_class == DnsClass::IN
                        && rr.rr_type == DnsType::A
                        && rr.name == name_server_rr.rdata
                });

                let name_server_address = if additional_rr_for_name_server.is_some() {
                    let name_server_address = additional_rr_for_name_server.unwrap().rdata.clone();

                    println!(
                        "{} additional A resource record for name server found. name_server_address={}",
                        log_label, name_server_address
                    );

                    name_server_address
                } else {
                    println!(
                        "{} additional A resource record for name server not found, resolving name server address...",
                        log_label
                    );

                    let name_server_address = resolve_domain_name(
                        &name_server_rr.rdata,
                        None,
                        id + 1,
                        my_udp_port,
                        my_ipaddr,
                        my_macaddr,
                        gateway_ipaddr,
                        gateway_macaddr,
                        iface,
                    )
                    .unwrap();

                    println!(
                        "{} name server address resolved. name_server_address={}",
                        log_label, name_server_address,
                    );

                    name_server_address
                };

                println!(
                    "{} resolving another name server... name_server_address={}",
                    log_label, name_server_address,
                );

                let resolved_address = resolve_domain_name(
                    &name,
                    Some(&name_server_address),
                    id + 1,
                    my_udp_port,
                    my_ipaddr,
                    my_macaddr,
                    gateway_ipaddr,
                    gateway_macaddr,
                    iface,
                )
                .unwrap();

                println!(
                    "{} resolving another name server... done. resolved_address={}",
                    log_label, resolved_address,
                );

                return Ok(resolved_address);
            }
        }
    }
}
