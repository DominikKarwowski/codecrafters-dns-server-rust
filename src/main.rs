mod dns_message;

use crate::dns_message::*;
use std::env;
use std::env::Args;
#[allow(unused_imports)]
use std::net::UdpSocket;

fn main() {
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    let resolver_addr = try_read_args(env::args());
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);

                match &resolver_addr {
                    Some(resolver_addr) => {
                        let response = handle_question_fwd(&buf, &udp_socket, &resolver_addr);
                        udp_socket
                            .send_to(&response, source)
                            .expect("Failed to send response");
                    }
                    None => {
                        let query = DnsMessage::deserialize(&buf);
                        let response = create_response(&query);
                        udp_socket
                            .send_to(&response, source)
                            .expect("Failed to send response");
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

fn try_read_args(args: Args) -> Option<String> {
    let args: Vec<String> = args.collect();

    let resolver_addr = if args.get(1)? == "--resolver" {
        args.get(2)?.to_string()
    } else {
        return None;
    };

    Some(resolver_addr)
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

    fwd_responses.into_iter().fold(
        DnsMessage {
            header,
            questions: Vec::new(),
            answers: Vec::new(),
        },
        |mut acc, mut elem| {
            acc.questions.append(&mut elem.questions);
            acc.answers.append(&mut elem.answers);
            acc
        }

    ).serialize()
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
