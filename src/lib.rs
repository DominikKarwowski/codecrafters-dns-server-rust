pub mod dns_message;

use crate::dns_message::*;

use std::error::Error;
use std::io;
use std::net::{SocketAddr, UdpSocket};

pub struct DnsServerConfig {
    bind_addr: String,
    mode: DnsServerMode,
}

enum DnsServerMode {
    ResolvingServer,
    ForwardingServer(String),
}

impl DnsServerConfig {
    pub fn new(mut args: impl Iterator<Item = String>) -> Self {
        args.next();

        let bind_addr = "127.0.0.1:2053".to_owned();

        let mode = match args.next() {
            Some(arg) if arg == "--resolver" => {
                if let Some(argv) = args.next() {
                    DnsServerMode::ForwardingServer(argv)
                } else {
                    DnsServerMode::ResolvingServer
                }
            }
            _ => DnsServerMode::ResolvingServer,
        };

        DnsServerConfig { bind_addr, mode }
    }
}

pub fn run_dns_server(config: &DnsServerConfig) -> Result<(), Box<dyn Error>> {
    let udp_socket = UdpSocket::bind(&config.bind_addr)?;
    let mut buf = [0; 512];

    loop {
        let (size, source) = udp_socket.recv_from(&mut buf)?;

        println!("Received {} bytes from {}", size, source);

        match &config.mode {
            DnsServerMode::ForwardingServer(resolver_addr) => {
                let _ = handle_query_fwd(&buf, &udp_socket, source, &resolver_addr)?;
            }
            DnsServerMode::ResolvingServer => {
                let _ = resolve_query(&buf, &udp_socket, source)?;
            }
        }
    }
}

fn resolve_query(
    buf: &[u8; 512],
    udp_socket: &UdpSocket,
    source: SocketAddr,
) -> Result<usize, io::Error> {
    let query = DnsMessage::deserialize(&buf);
    let response = create_response(&query);

    udp_socket.send_to(&response, source)
}

fn handle_query_fwd(
    buf: &[u8; 512],
    udp_socket: &UdpSocket,
    source: SocketAddr,
    resolver_addr: &str,
) -> Result<usize, io::Error> {
    let response = handle_question_fwd(&buf, &udp_socket, &resolver_addr);
    
    udp_socket.send_to(&response, source)
}

fn handle_question_fwd(buf: &[u8; 512], udp_socket: &UdpSocket, resolver_addr: &str) -> [u8; 512] {
    let query = DnsMessage::deserialize(&buf);

    let mut fwd_responses = Vec::new();

    // TODO: make async
    for q in query.questions {
        let mut fwd_buf: [u8; 512] = [0; 512];

        let msg = DnsMessage {
            header: Header {
                qd_count: 1,
                ..query.header.clone()
            },
            questions: vec![q],
            answers: Vec::new(),
        }
        .serialize();

        udp_socket
            .send_to(buf, resolver_addr)
            .expect("Failed to forward query");

        udp_socket.recv_from(&mut fwd_buf).unwrap();

        // TODO: ensure thread safe push when async
        fwd_responses.push(DnsMessage::deserialize(&fwd_buf));
    }

    let fwd_responses = fwd_responses;

    let header = Header {
        packet_id: query.header.packet_id,
        qr_ind: QueryResponseIndicator::Response,
        op_code: query.header.op_code.clone(),
        is_auth_ans: false,
        is_trunc: false,
        is_rec_desired: query.header.is_rec_desired,
        is_rec_available: false,
        r_code: match query.header.op_code {
            OperationCode::Query => ResponseCode::NoError,
            _ => ResponseCode::NotImplemented,
        },
        qd_count: query.header.qd_count,
        an_count: query.header.qd_count,
        ns_count: 0,
        ar_count: 0,
    };

    fwd_responses
        .into_iter()
        .fold(
            DnsMessage {
                header,
                questions: Vec::new(),
                answers: Vec::new(),
            },
            |mut acc, mut elem| {
                acc.questions.append(&mut elem.questions);
                acc.answers.append(&mut elem.answers);
                acc
            },
        )
        .serialize()
}

fn create_response(query: &DnsMessage) -> [u8; 512] {
    let r_code = match query.header.op_code {
        OperationCode::Query => ResponseCode::NoError,
        _ => ResponseCode::NotImplemented,
    };

    let mut questions = Vec::new();
    let mut answers = Vec::new();

    for q in &query.questions {
        questions.push(Question {
            name: q.name.clone(),
            record_type: q.record_type,
            class: q.class,
        });

        answers.push(Answer {
            name: q.name.clone(),
            record_type: 1,
            class: 1,
            time_to_live: 60,
            length: 4,
            data: vec![8, 8, 8, 8],
        });
    }

    let header = Header {
        packet_id: query.header.packet_id,
        qr_ind: QueryResponseIndicator::Response,
        op_code: query.header.op_code.clone(),
        is_auth_ans: false,
        is_trunc: false,
        is_rec_desired: query.header.is_rec_desired,
        is_rec_available: false,
        r_code,
        qd_count: query.header.qd_count,
        an_count: answers.len().try_into().unwrap(),
        ns_count: 0,
        ar_count: 0,
    };

    let dns_message = DnsMessage {
        header,
        questions,
        answers,
    };

    dns_message.serialize()
}
