pub struct DnsMessage {
    pub header: Header,
    pub question: Question,
    pub answer: Answer,
}

pub struct Header {
    pub packet_id: u16,
    pub qr_ind: QueryResponseIndicator,
    pub op_code: OperationCode,
    pub is_auth_ans: bool,
    pub is_trunc: bool,
    pub is_rec_desired: bool,
    pub is_rec_available: bool,
    pub r_code: ResponseCode,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

pub enum QueryResponseIndicator {
    Query,
    Response,
}

pub enum OperationCode {
    Query,
    IQuery,
    Status,
}

pub enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
}

pub struct Question {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
}

pub struct Answer {
    pub name: String,
    pub record_type: u16,
    pub class: u16,
    pub time_to_live: u32,
    pub length: u16,
    pub data: Vec<u8>,
}

impl DnsMessage {
    pub fn deserialize(buf: &[u8; 512]) -> DnsMessage {
        let header = Header::deserialize(buf);
        let question = Question::deserialize(buf);
        let answer = Answer::deserialize(buf);

        DnsMessage { header, question, answer }
    }

    pub fn serialize(&self) -> [u8; 512] {
        let mut msg: [u8; 512] = [0; 512];

        msg[..12].copy_from_slice(&self.header.serialize());

        let question = &self.question.serialize();
        let curr_len = 12 + question.len();
        msg[12..curr_len].copy_from_slice(question);

        let answer = &self.answer.serialize();
        let prev_len = curr_len;
        let curr_len = prev_len + answer.len();
        msg[prev_len..curr_len].copy_from_slice(answer);

        msg
    }
}

impl Header {
    fn deserialize(buf: &[u8; 512]) -> Header {
        Header {
            packet_id: u16::from_be_bytes(
                buf[..2].try_into().expect("Failed to create packet_id."),
            ),
            qr_ind: Self::deserialize_qr_ind(buf),
            op_code: Self::deserialize_op_code(buf),
            is_auth_ans: get_bit_flag_for_byte(buf, 2, 2),
            is_trunc: get_bit_flag_for_byte(buf, 2, 1),
            is_rec_desired: get_bit_flag_for_byte(buf, 2, 0),
            is_rec_available: get_bit_flag_for_byte(buf, 3, 7),
            r_code: Self::deserialize_r_code(buf),
            qd_count: u16::from_be_bytes(buf[4..6].try_into().expect("Failed to create qd_count")),
            an_count: u16::from_be_bytes(buf[6..8].try_into().expect("Failed to create an_count")),
            ns_count: u16::from_be_bytes(buf[8..10].try_into().expect("Failed to create ns_count")),
            ar_count: u16::from_be_bytes(
                buf[10..12].try_into().expect("Failed to create ar_count"),
            ),
        }
    }

    fn serialize(&self) -> [u8; 12] {
        let mut header: [u8; 12] = [0; 12];

        header[..2].copy_from_slice(&self.packet_id.to_be_bytes());

        let qr_ind = Self::serialize_qr_ind(&self.qr_ind);
        let op_code = Self::serialize_op_code(&self.op_code);
        let is_auth_ans = self.is_auth_ans.as_bit_flag(2);
        let is_trunc = self.is_trunc.as_bit_flag(1);
        let is_rec_desired = self.is_rec_desired.as_bit_flag(0);
        header[2] = qr_ind | op_code | is_auth_ans | is_trunc | is_rec_desired;

        let is_rec_available = self.is_rec_available.as_bit_flag(7);
        let r_code = Self::serialize_r_code(&self.r_code);
        header[3] = is_rec_available | r_code;

        header[4..6].copy_from_slice(&self.qd_count.to_be_bytes());
        header[6..8].copy_from_slice(&self.an_count.to_be_bytes());
        header[8..10].copy_from_slice(&self.ns_count.to_be_bytes());
        header[10..12].copy_from_slice(&self.ar_count.to_be_bytes());

        header
    }

    fn deserialize_qr_ind(buf: &[u8; 512]) -> QueryResponseIndicator {
        match (buf[2] >> 7) & 1 == 1 {
            false => QueryResponseIndicator::Query,
            true => QueryResponseIndicator::Response,
        }
    }

    fn serialize_qr_ind(qr_ind: &QueryResponseIndicator) -> u8 {
        (match qr_ind {
            QueryResponseIndicator::Query => 0,
            QueryResponseIndicator::Response => 1,
        }) << 7
    }

    fn deserialize_op_code(buf: &[u8; 512]) -> OperationCode {
        match buf[2] >> 3 {
            0 => OperationCode::Query,
            1 => OperationCode::IQuery,
            2 => OperationCode::Status,
            _ => panic!("Unexpected OPCODE value"),
        }
    }

    fn serialize_op_code(op_code: &OperationCode) -> u8 {
        (match op_code {
            OperationCode::Query => 0,
            OperationCode::IQuery => 1,
            OperationCode::Status => 2,
        }) << 3
    }

    fn deserialize_r_code(buf: &[u8; 512]) -> ResponseCode {
        match buf[3] {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            _ => panic!("Unexpected RCODE value"),
        }
    }

    fn serialize_r_code(r_code: &ResponseCode) -> u8 {
        match r_code {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
        }
    }
}

impl Question {
    fn deserialize(raw: &[u8]) -> Question {
        // dummy impl
        Question {
            name: "".to_string(),
            record_type: 0,
            class: 0,
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut serialized: Vec<u8> = name_to_labels(&self.name);

        serialized.extend_from_slice(&self.record_type.to_be_bytes());
        serialized.extend_from_slice(&self.class.to_be_bytes());

        serialized
    }
}

impl Answer {
    fn deserialize(raw: &[u8]) -> Answer {
        // dummy impl
        Answer {
            name: "".to_string(),
            record_type: 0,
            class: 0,
            time_to_live: 0,
            length: 0,
            data: Vec::new(),
        }

    }

    fn serialize(&self) -> Vec<u8> {
        let mut serialized: Vec<u8> = name_to_labels(&self.name);

        serialized.extend_from_slice(&self.record_type.to_be_bytes());
        serialized.extend_from_slice(&self.class.to_be_bytes());
        serialized.extend_from_slice(&self.time_to_live.to_be_bytes());
        serialized.extend_from_slice(&self.length.to_be_bytes());
        serialized.extend_from_slice(&self.data);

        serialized
    }
}

fn name_to_labels(input: &str) -> Vec<u8> {
    let mut labels: Vec<u8> = Vec::new();

    let name = input.split('.');

    for n in name {
        labels.push(
            n.len()
                .try_into()
                .expect("domain name part length exceeded"),
        );

        for c in n.chars() {
            let mut c_buf = vec![0; c.len_utf8()];

            c.encode_utf8(&mut c_buf);

            for b in c_buf {
                labels.push(b);
            }
        }
    }

    labels.push(0);

    labels
}

fn get_bit_flag_for_byte(buf: &[u8; 512], byte_idx: usize, bit_idx: u8) -> bool {
    buf[byte_idx].get_bit_flag(bit_idx)
}

trait GetBitFlag {
    fn get_bit_flag(&self, bit_idx: u8) -> bool;
}

impl GetBitFlag for u8 {
    fn get_bit_flag(&self, bit_idx: u8) -> bool {
        if bit_idx > 7 {
            panic!("Bit index must be between 0 and 7")
        };

        (self >> bit_idx) & 1 == 1
    }
}

trait AsBitFlag {
    fn as_bit_flag(&self, bit_idx: u8) -> u8;
}

impl AsBitFlag for bool {
    fn as_bit_flag(&self, bit_idx: u8) -> u8 {
        if bit_idx > 7 {
            panic!("Bit index must be between 0 and 7")
        };

        let bit: u8 = if *self { 1 } else { 0 };
        bit << bit_idx
    }
}
