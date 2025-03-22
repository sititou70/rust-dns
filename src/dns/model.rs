use core::fmt;

use num_derive::FromPrimitive;

#[derive(PartialEq, FromPrimitive, Debug)]
pub enum DnsType {
    A = 1,
    NS = 2,
    CNAME = 5,
}
impl fmt::Display for DnsType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DnsType::A => write!(f, "A"),
            DnsType::NS => write!(f, "NS"),
            DnsType::CNAME => write!(f, "CNAME"),
        }
    }
}

#[derive(PartialEq, FromPrimitive, Debug)]
pub enum DnsClass {
    IN = 1,
}
impl fmt::Display for DnsClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DnsClass::IN => write!(f, "IN"),
        }
    }
}

#[derive(PartialEq, FromPrimitive, Debug)]
pub enum DnsHeaderOpecode {
    Query = 0,
    IQuery = 1,
    Status = 2,
}
impl fmt::Display for DnsHeaderOpecode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DnsHeaderOpecode::Query => write!(f, "Query"),
            DnsHeaderOpecode::IQuery => write!(f, "IQuery"),
            DnsHeaderOpecode::Status => write!(f, "Status"),
        }
    }
}

#[derive(PartialEq, FromPrimitive, Debug)]
pub enum DnsHeaderRcode {
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NoNameError = 3,
    NotImplemented = 4,
    Refused = 5,
}
impl fmt::Display for DnsHeaderRcode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DnsHeaderRcode::NoError => write!(f, "NoError"),
            DnsHeaderRcode::FormatError => write!(f, "FormatError"),
            DnsHeaderRcode::ServerFailure => write!(f, "ServerFailure"),
            DnsHeaderRcode::NoNameError => write!(f, "NoNameError"),
            DnsHeaderRcode::NotImplemented => write!(f, "NotImplemented"),
            DnsHeaderRcode::Refused => write!(f, "Refused"),
        }
    }
}

#[derive(Debug)]
pub struct DnsHeaderSection {
    pub id: u16,
    pub qr: bool,
    pub opcode: DnsHeaderOpecode,
    pub aa: bool,
    pub tc: bool,
    pub rd: bool,
    pub ra: bool,
    pub rcode: DnsHeaderRcode,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}
fn print_bool(b: bool, label: &str) -> String {
    if b {
        label.to_string()
    } else {
        "!".to_string() + label
    }
}
impl fmt::Display for DnsHeaderSection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "id={}", self.id)?;
        write!(f, " {}", print_bool(self.qr, "qr"))?;
        write!(f, " opecode={}", self.opcode)?;
        write!(f, " {}", print_bool(self.aa, "aa"))?;
        write!(f, " {}", print_bool(self.tc, "tc"))?;
        write!(f, " {}", print_bool(self.rd, "rd"))?;
        write!(f, " {}", print_bool(self.ra, "ra"))?;
        write!(f, " rcode={}", self.rcode)?;
        write!(f, " qdcount={}", self.qdcount)?;
        write!(f, " ancount={}", self.ancount)?;
        write!(f, " nscount={}", self.nscount)?;
        write!(f, " arcount={}", self.arcount)
    }
}

#[derive(Debug)]
pub struct DnsQuestionSectionEntry {
    pub q_name: String,
    pub q_type: DnsType,
    pub q_class: DnsClass,
}
impl fmt::Display for DnsQuestionSectionEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.q_name)?;
        write!(f, "\t{}", self.q_class)?;
        write!(f, "\t{}", self.q_type)
    }
}

#[derive(Debug)]
pub struct DnsResourceRecord {
    pub name: String,
    pub rr_type: DnsType,
    pub rr_class: DnsClass,
    pub ttl: u32,
    pub rdata: String,
}
impl fmt::Display for DnsResourceRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)?;
        write!(f, "\t{}", self.ttl)?;
        write!(f, "\t{}", self.rr_class)?;
        write!(f, "\t{}", self.rr_type)?;
        write!(f, "\t{}", self.rdata)
    }
}

#[derive(Debug)]
pub struct DnsMessage {
    pub header: DnsHeaderSection,
    pub questions: Vec<DnsQuestionSectionEntry>,
    pub answers: Vec<DnsResourceRecord>,
    pub authorities: Vec<DnsResourceRecord>,
    pub additionals: Vec<DnsResourceRecord>,
}
impl fmt::Display for DnsMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "header:\n\t{}\n", self.header)?;

        write!(f, "Question Section:\n")?;
        for q in &self.questions {
            write!(f, "\t{}\n", q)?;
        }

        write!(f, "Answer Section:\n")?;
        for a in &self.answers {
            write!(f, "\t{}\n", a)?;
        }

        write!(f, "Authority Section:\n")?;
        for a in &self.authorities {
            write!(f, "\t{}\n", a)?;
        }

        write!(f, "Additional Section:\n")?;
        for a in &self.additionals {
            write!(f, "\t{}\n", a)?;
        }

        write!(f, "")
    }
}
