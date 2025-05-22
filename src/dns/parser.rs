use crate::util::print_ipaddr;

use super::model::{
    DnsClass, DnsHeaderOpecode, DnsHeaderRcode, DnsHeaderSection, DnsMessage,
    DnsQuestionSectionEntry, DnsResourceRecord, DnsType,
};
use num::FromPrimitive;

fn print_dns_domain_name(message: &Vec<u8>, offset: usize) -> (String, usize) {
    let label_length = message[offset] as usize;
    if label_length == 0 {
        return ("".to_string(), 1);
    }

    if message[offset] & 0b11000000 != 0 {
        let new_offset =
            u16::from_be_bytes([message[offset] & 0b00111111, message[offset + 1]]) as usize;
        let (name, _) = print_dns_domain_name(message, new_offset);

        return (name, 2);
    };

    let label = std::str::from_utf8(&message[offset + 1..=offset + label_length])
        .unwrap()
        .to_string();
    let (rest_name, rest_length) = print_dns_domain_name(message, offset + label_length + 1);

    return (label + "." + &rest_name, 1 + label_length + rest_length);
}
#[cfg(test)]
mod print_dns_domain_name {
    use crate::dns::parser::print_dns_domain_name;

    // from rfc1035 4.1.4. see: https://jprs.jp/tech/material/rfc/RFC1035-ja.txt
    const TEST_MESSAGE: [u8; 93] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 20 zeros
        1, b'F', 3, b'I', b'S', b'I', 4, b'A', b'R', b'P', b'A', 0, // 1 F 3 ISI 4 ARPA 0
        0, 0, 0, 0, 0, 0, 0, 0, // 8 zeros
        3, b'F', b'O', b'O', 0b11000000, 20, // 3 FOO 0b11 20
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 18 zeros
        0b11000000, 26, // 0b11 26
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, // 26 zeros
        0, // 0
    ];

    #[test]
    fn case1() {
        let (name, size) = print_dns_domain_name(&TEST_MESSAGE.to_vec(), 20);
        assert_eq!(name, "F.ISI.ARPA.");
        assert_eq!(size, 12);
    }

    #[test]
    fn case2() {
        let (name, size) = print_dns_domain_name(&TEST_MESSAGE.to_vec(), 40);
        assert_eq!(name, "FOO.F.ISI.ARPA.");
        assert_eq!(size, 6);
    }

    #[test]
    fn case3() {
        let (name, size) = print_dns_domain_name(&TEST_MESSAGE.to_vec(), 64);
        assert_eq!(name, "ARPA.");
        assert_eq!(size, 2);
    }

    #[test]
    fn case4() {
        let (name, size) = print_dns_domain_name(&TEST_MESSAGE.to_vec(), 92);
        assert_eq!(name, "");
        assert_eq!(size, 1);
    }
}

fn parse_dns_header_section(message: &Vec<u8>) -> Result<DnsHeaderSection, String> {
    let id = u16::from_be_bytes([message[0], message[1]]);
    let qr = message[2] & 0b10000000 != 0;
    let opcode = DnsHeaderOpecode::from_u8((message[2] & 0b01111000) >> 3)
        .ok_or("unknown opecode".to_string())?;
    let aa = message[2] & 0b00000100 != 0;
    let tc = message[2] & 0b00000010 != 0;
    let rd = message[2] & 0b00000001 != 0;
    let ra = message[3] & 0b10000000 != 0;
    let rcode = DnsHeaderRcode::from_u8(message[3] & 0b00001111).ok_or("unknown rcode")?;
    let qdcount = u16::from_be_bytes([message[4], message[5]]);
    let ancount = u16::from_be_bytes([message[6], message[7]]);
    let nscount = u16::from_be_bytes([message[8], message[9]]);
    let arcount = u16::from_be_bytes([message[10], message[11]]);

    return Ok(DnsHeaderSection {
        id,
        qr,
        opcode,
        aa,
        tc,
        rd,
        ra,
        rcode,
        qdcount,
        ancount,
        nscount,
        arcount,
    });
}
#[cfg(test)]
mod parse_dns_header_section {
    use crate::dns::{
        model::{DnsHeaderOpecode, DnsHeaderRcode},
        parser::parse_dns_header_section,
    };

    #[test]
    fn case1() {
        let header = parse_dns_header_section(&vec![
            0x00, 0x01,       // id
            0b10000100, // qr opecode=Query aa !tc !rd
            0b00000000, // !ra ZZZ rcode=NoError
            0x00, 0x02, // qdcount
            0x00, 0x03, // ancount
            0x00, 0x04, // nscount
            0x00, 0x05, // arcount
        ])
        .unwrap();

        assert_eq!(header.id, 1);
        assert_eq!(header.qr, true);
        assert_eq!(header.opcode, DnsHeaderOpecode::Query); // noop
        assert_eq!(header.aa, true);
        assert_eq!(header.tc, false);
        assert_eq!(header.rd, false);
        assert_eq!(header.ra, false);
        assert_eq!(header.rcode, DnsHeaderRcode::NoError);
        assert_eq!(header.qdcount, 2);
        assert_eq!(header.ancount, 3);
        assert_eq!(header.nscount, 4);
        assert_eq!(header.arcount, 5);
    }

    #[test]
    #[should_panic]
    fn case2() {
        parse_dns_header_section(&vec![
            0x00, 0x01,       // id
            0b11110100, // qr opecode=unknown! aa !tc !rd
            0b00000000, // !ra ZZZ rcode=NoError
            0x00, 0x02, // qdcount
            0x00, 0x03, // ancount
            0x00, 0x04, // nscount
            0x00, 0x05, // arcount
        ])
        .unwrap();
    }
}

fn parse_dns_question_section_entry(
    message: &Vec<u8>,
    offset: usize,
) -> Result<(DnsQuestionSectionEntry, usize), (String, usize)> {
    let (q_name, q_name_length) = print_dns_domain_name(message, offset);
    let q_type = DnsType::from_u16(u16::from_be_bytes([
        message[offset + q_name_length],
        message[offset + q_name_length + 1],
    ]))
    .ok_or(("unknown q_type".to_string(), q_name_length + 4))?;
    let q_class = DnsClass::from_u16(u16::from_be_bytes([
        message[offset + q_name_length + 2],
        message[offset + q_name_length + 3],
    ]))
    .ok_or(("unknown q_class".to_string(), q_name_length + 4))?;

    return Ok((
        DnsQuestionSectionEntry {
            q_name,
            q_type,
            q_class,
        },
        q_name_length + 4,
    ));
}
#[cfg(test)]
mod parse_dns_question_section_entry {
    use crate::dns::model::{DnsClass, DnsType};

    use super::parse_dns_question_section_entry;

    #[test]
    fn case1() {
        let (entry, size) = parse_dns_question_section_entry(
            &vec![
                0, 0, 0, 0, // offset
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // qname
                0x00, 0x01, // qtype
                0x00, 0x01, // qclass
            ],
            4,
        )
        .unwrap();

        assert_eq!(entry.q_name, "example.com.");
        assert_eq!(entry.q_type, DnsType::A);
        assert_eq!(entry.q_class, DnsClass::IN);
        assert_eq!(size, 17);
    }

    #[test]
    fn case2() {
        let (name, size) = parse_dns_question_section_entry(
            &vec![
                0, 0, 0, 0, // offset
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // qname
                0x00, 0xff, // unknown qtype!
                0x00, 0x01, // qclass
            ],
            4,
        )
        .unwrap_err();

        assert_eq!(name, "unknown q_type".to_string());
        assert_eq!(size, 17);
    }
}

fn parse_dns_resource_record(
    message: &Vec<u8>,
    offset: usize,
) -> Result<(DnsResourceRecord, usize), (String, usize)> {
    let (name, name_length) = print_dns_domain_name(message, offset);

    let rd_length = u16::from_be_bytes([
        message[offset + name_length + 8],
        message[offset + name_length + 9],
    ]) as usize;

    let rr_type = DnsType::from_u16(u16::from_be_bytes([
        message[offset + name_length],
        message[offset + name_length + 1],
    ]))
    .ok_or(("unknown rr_type".to_string(), name_length + 10 + rd_length))?;
    let rr_class = DnsClass::from_u16(u16::from_be_bytes([
        message[offset + name_length + 2],
        message[offset + name_length + 3],
    ]))
    .ok_or(("unknown rr_class".to_string(), name_length + 10 + rd_length))?;
    let ttl = u32::from_be_bytes([
        message[offset + name_length + 4],
        message[offset + name_length + 5],
        message[offset + name_length + 6],
        message[offset + name_length + 7],
    ]);

    let rdata = match rr_type {
        DnsType::A => print_ipaddr(&vec![
            message[offset + name_length + 10],
            message[offset + name_length + 11],
            message[offset + name_length + 12],
            message[offset + name_length + 13],
        ]),
        DnsType::NS => print_dns_domain_name(message, offset + name_length + 10).0,
        DnsType::CNAME => print_dns_domain_name(message, offset + name_length + 10).0,
    };

    return Ok((
        DnsResourceRecord {
            name,
            rr_type,
            rr_class,
            ttl,
            rdata,
        },
        name_length + 10 + rd_length,
    ));
}
#[cfg(test)]
mod parse_dns_resource_record {
    use crate::dns::{
        model::{DnsClass, DnsType},
        parser::parse_dns_resource_record,
    };

    #[test]
    fn case1() {
        let (rr, size) = parse_dns_resource_record(
            &vec![
                0, 0, 0, 0, // offset
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // name
                0x00, 1, // rr type
                0x00, 0x01, // rr class
                0x00, 0x00, 0x00, 123, // ttl
                0x00, 4, // rd_length
                0x08, 0x08, 0x08, 0x08, // rdata
            ],
            4,
        )
        .unwrap();

        assert_eq!(rr.name, "example.com.");
        assert_eq!(rr.rr_type, DnsType::A);
        assert_eq!(rr.rr_class, DnsClass::IN);
        assert_eq!(rr.ttl, 123);
        assert_eq!(rr.rdata, "8.8.8.8");
        assert_eq!(size, 27);
    }

    #[test]
    fn case2() {
        let (rr, size) = parse_dns_resource_record(
            &vec![
                0, 0, 0, 0, // offset
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // name
                0x00, 2, // rr type
                0x00, 0x01, // rr class
                0x00, 0x00, 0x00, 123, // ttl
                0x00, 13, // rd_length
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // rdata
            ],
            4,
        )
        .unwrap();

        assert_eq!(rr.name, "example.com.");
        assert_eq!(rr.rr_type, DnsType::NS);
        assert_eq!(rr.rr_class, DnsClass::IN);
        assert_eq!(rr.ttl, 123);
        assert_eq!(rr.rdata, "example.com.");
        assert_eq!(size, 36);
    }

    #[test]
    fn case3() {
        let (rr, size) = parse_dns_resource_record(
            &vec![
                0, 0, 0, 0, // offset
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // name
                0x00, 5, // rr type
                0x00, 0x01, // rr class
                0x00, 0x00, 0x00, 123, // ttl
                0x00, 13, // rd_length
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // rdata
            ],
            4,
        )
        .unwrap();

        assert_eq!(rr.name, "example.com.");
        assert_eq!(rr.rr_type, DnsType::CNAME);
        assert_eq!(rr.rr_class, DnsClass::IN);
        assert_eq!(rr.ttl, 123);
        assert_eq!(rr.rdata, "example.com.");
        assert_eq!(size, 36);
    }

    #[test]
    fn case4() {
        let (name, size) = parse_dns_resource_record(
            &vec![
                0, 0, 0, 0, // offset
                7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, // name
                0x00, 0x01, // rr type
                0x00, 0xff, // unknown rr class!
                0x00, 0x00, 0x00, 123, // ttl
                0x00, 0x04, // rd_length
                0x08, 0x08, 0x08, 0x08, // rdata
            ],
            4,
        )
        .unwrap_err();

        assert_eq!(name, "unknown rr_class".to_string());
        assert_eq!(size, 27);
    }
}

pub fn parse_dns_message(message: &Vec<u8>) -> Result<DnsMessage, String> {
    let header = parse_dns_header_section(message)?;

    let mut offset = 12; // header length

    let mut questions = Vec::new();
    for _ in 0..header.qdcount {
        let result = parse_dns_question_section_entry(message, offset);
        match result {
            Ok((question, size)) => {
                questions.push(question);
                offset += size;
            }
            Err((_, size)) => {
                offset += size;
            }
        }
    }

    let mut answers = Vec::new();
    for _ in 0..header.ancount {
        let result = parse_dns_resource_record(message, offset);
        match result {
            Ok((rr, size)) => {
                answers.push(rr);
                offset += size;
            }
            Err((_, size)) => {
                offset += size;
            }
        }
    }

    let mut authorities = Vec::new();
    for _ in 0..header.nscount {
        let result = parse_dns_resource_record(message, offset);
        match result {
            Ok((rr, size)) => {
                authorities.push(rr);
                offset += size;
            }
            Err((_, size)) => {
                offset += size;
            }
        }
    }

    let mut additionals = Vec::new();
    for _ in 0..header.arcount {
        let result = parse_dns_resource_record(message, offset);
        match result {
            Ok((rr, size)) => {
                additionals.push(rr);
                offset += size;
            }
            Err((_, size)) => {
                offset += size;
            }
        }
    }

    return Ok(DnsMessage {
        header,
        questions,
        answers,
        authorities,
        additionals,
    });
}
#[cfg(test)]
mod parse_dns_message {
    use crate::dns::{
        model::{DnsClass, DnsHeaderOpecode, DnsHeaderRcode, DnsType},
        parser::parse_dns_message,
    };

    #[test]
    fn case1() {
        let message = parse_dns_message(&vec![
            0xd1, 0xb4, // id
            0x80, // qr opecode=Query !aa !tc !rd
            0x00, // !ra ZZZ rcode=NoError
            0x00, 0x01, // qdcount=1
            0x00, 0x00, // ancount=0
            0x00, 0x08, // nscount=8
            0x00, 0x0a, // arcount=10
            // questions
            0x05, 0x61, 0x31, 0x34, 0x32, 0x32, 0x04, 0x64, 0x73, 0x63, 0x72, 0x06, 0x61, 0x6b,
            0x61, 0x6d, 0x61, 0x69, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00,
            0x01, // a1422.dscr.akamai.net. IN A
            // answers
            // authorities
            0xc0, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x09, 0x06, 0x6e,
            0x37, 0x64, 0x73, 0x63, 0x72, 0xc0,
            0x17, // dscr.akamai.net. 4000 IN NS n7dscr.akamai.net.
            0xc0, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x09, 0x06, 0x6e,
            0x35, 0x64, 0x73, 0x63, 0x72, 0xc0,
            0x17, // dscr.akamai.net. 4000 IN NS n5dscr.akamai.net.
            0xc0, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x09, 0x06, 0x6e,
            0x32, 0x64, 0x73, 0x63, 0x72, 0xc0,
            0x17, // dscr.akamai.net. 4000 IN NS n2dscr.akamai.net.
            0xc0, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x09, 0x06, 0x6e,
            0x30, 0x64, 0x73, 0x63, 0x72, 0xc0,
            0x17, // dscr.akamai.net. 4000 IN NS n0dscr.akamai.net.
            0xc0, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x09, 0x06, 0x6e,
            0x34, 0x64, 0x73, 0x63, 0x72, 0xc0,
            0x17, // dscr.akamai.net. 4000 IN NS n4dscr.akamai.net.
            0xc0, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x09, 0x06, 0x6e,
            0x33, 0x64, 0x73, 0x63, 0x72, 0xc0,
            0x17, // dscr.akamai.net. 4000 IN NS n3dscr.akamai.net.
            0xc0, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x09, 0x06, 0x6e,
            0x36, 0x64, 0x73, 0x63, 0x72, 0xc0,
            0x17, // dscr.akamai.net. 4000 IN NS n6dscr.akamai.net.
            0xc0, 0x12, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x09, 0x06, 0x6e,
            0x31, 0x64, 0x73, 0x63, 0x72, 0xc0,
            0x17, // dscr.akamai.net. 4000 IN NS n1dscr.akamai.net.
            // additionals
            0xc0, 0x87, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x04, 0x17, 0xcc,
            0x78, 0x5c, // n4dscr.akamai.net. 4000 IN A 23.204.120.92
            0xc0, 0x72, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x10, 0x26, 0x00,
            0x14, 0x80, 0xe8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xc0, // n0dscr.akamai.net. 4000 IN AAAA 2600:1480:e800::c0
            0xc0, 0x48, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x04, 0x17, 0xcc,
            0x78, 0x4e, // n5dscr.akamai.net. 4000 IN A 23.204.120.78
            0xc0, 0x9c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x04, 0x17, 0xd1,
            0x2d, 0x35, // n3dscr.akamai.net. 4000 IN A 23.209.45.53
            0xc0, 0xb1, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x04, 0x17, 0xcc,
            0x78, 0x5d, // n6dscr.akamai.net. 4000 IN A 23.204.120.93
            0xc0, 0xc6, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x04, 0x17, 0xd0,
            0x55, 0x97, // n1dscr.akamai.net. 4000 IN A 23.208.85.151
            0xc0, 0x72, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x04, 0x58, 0xdd,
            0x51, 0xc0, // n0dscr.akamai.net. 4000 IN A 88.221.81.192
            0xc0, 0x5d, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x04, 0x17, 0xcc,
            0x78, 0x57, // n2dscr.akamai.net. 4000 IN A 23.204.120.87
            0xc0, 0x33, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0f, 0xa0, 0x00, 0x04, 0x17, 0x20,
            0xf8, 0x1c, // n7dscr.akamai.net. 4000 IN A 23.32.248.28
            0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ROOT OPT
        ])
        .unwrap();

        assert_eq!(message.header.id, u16::from_be_bytes([0xd1, 0xb4]));
        assert_eq!(message.header.qr, true);
        assert_eq!(message.header.opcode, DnsHeaderOpecode::Query);
        assert_eq!(message.header.aa, false);
        assert_eq!(message.header.tc, false);
        assert_eq!(message.header.rd, false);
        assert_eq!(message.header.ra, false);
        assert_eq!(message.header.rcode, DnsHeaderRcode::NoError);
        assert_eq!(message.header.qdcount, 1);
        assert_eq!(message.header.ancount, 0);
        assert_eq!(message.header.nscount, 8);
        assert_eq!(message.header.arcount, 10);

        assert_eq!(message.questions.len(), 1);
        assert_eq!(message.questions[0].q_name, "a1422.dscr.akamai.net.");
        assert_eq!(message.questions[0].q_type, DnsType::A);
        assert_eq!(message.questions[0].q_class, DnsClass::IN);

        assert_eq!(message.answers.len(), 0);

        assert_eq!(message.authorities.len(), 8);
        assert_eq!(message.authorities[0].name, "dscr.akamai.net.");
        assert_eq!(message.authorities[0].rr_type, DnsType::NS);
        assert_eq!(message.authorities[0].rr_class, DnsClass::IN);
        assert_eq!(message.authorities[0].ttl, 4000);
        assert_eq!(message.authorities[0].rdata, "n7dscr.akamai.net.");

        assert_eq!(message.additionals.len(), 8);
        assert_eq!(message.additionals[0].name, "n4dscr.akamai.net.");
        assert_eq!(message.additionals[0].rr_type, DnsType::A);
        assert_eq!(message.additionals[0].rr_class, DnsClass::IN);
        assert_eq!(message.additionals[0].ttl, 4000);
        assert_eq!(message.additionals[0].rdata, "23.204.120.92");
    }
}
