mod dns_message;

use crate::dns_message::*;
#[allow(unused_imports)]
use std::net::UdpSocket;

fn main() {
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let response = create_response(&buf);
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}

fn create_response(buf: &[u8; 512]) -> [u8; 512] {
    let query = DnsMessage::deserialize(buf);

    let r_code = match query.header.op_code {
        OperationCode::Query => ResponseCode::NoError,
        _ => ResponseCode::NotImplemented,
    };

    let header = Header {
        packet_id: query.header.packet_id,
        qr_ind: QueryResponseIndicator::Response,
        op_code: query.header.op_code,
        is_auth_ans: false,
        is_trunc: false,
        is_rec_desired: query.header.is_rec_desired,
        is_rec_available: false,
        r_code,
        qd_count: 1,
        an_count: 1,
        ns_count: 0,
        ar_count: 0,
    };

    let question = Question {
        name: query.question.name.clone(),
        record_type: 1,
        class: 1,
    };

    let answer = Answer {
        name: query.question.name,
        record_type: 1,
        class: 1,
        time_to_live: 60,
        length: 4,
        data: vec![8, 8, 8, 8],
    };

    let dns_message = DnsMessage { header, question, answer };

    dns_message.serialize()
}
