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
    let header = Header {
        packet_id: 1234,
        qr_ind: QueryResponseIndicator::Response,
        op_code: OperationCode::Query,
        is_auth_ans: false,
        is_trunc: false,
        is_rec_desired: false,
        is_rec_available: false,
        r_code: ResponseCode::NoError,
        qd_count: 0,
        an_count: 0,
        ns_count: 0,
        ar_count: 0,
    };

    let dns_message = DnsMessage { header };

    dns_message.serialize()
}
