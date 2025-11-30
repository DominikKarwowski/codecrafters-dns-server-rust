use std::str::from_utf8;

pub struct DnsMessage {
    pub header: Header,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer>,
}

#[derive(Clone)]
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

#[derive(Clone)]
pub enum QueryResponseIndicator {
    Query,
    Response,
}

#[derive(Clone)]
pub enum OperationCode {
    Query,
    IQuery,
    Status,
    Other(u8),
}

#[derive(Clone)]
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

trait Serializable {
    fn serialize(&self) -> Vec<u8>;
}

impl DnsMessage {
    pub fn deserialize(buf: &[u8; 512]) -> DnsMessage {
        let header = Header::deserialize(buf);
        let (questions, curr_pos) = Question::deserialize_questions(buf, &header.qd_count);
        let answers = Answer::deserialize_answers(buf, &header.an_count, curr_pos);

        DnsMessage {
            header,
            questions,
            answers,
        }
    }

    pub fn serialize(&self) -> [u8; 512] {
        let mut msg: [u8; 512] = [0; 512];

        let pos = 12;
        msg[..pos].copy_from_slice(&self.header.serialize());

        let questions_iter = self.questions.iter().map(|item| item as &dyn Serializable);
        let (pos, msg) = Self::copy_from_iter(questions_iter, pos, msg);

        let answers_iter = self.answers.iter().map(|item| item as &dyn Serializable);
        let (_, msg) = Self::copy_from_iter(answers_iter, pos, msg);

        msg
    }

    fn copy_from_iter<'a>(
        iter: impl Iterator<Item = &'a dyn Serializable>,
        start_pos: usize,
        msg: [u8; 512],
    ) -> (usize, [u8; 512]) {
        iter.fold((start_pos, msg), |mut acc, elem| {
            let serialized = elem.serialize();
            let begin = acc.0;
            let end = begin + serialized.len();
            acc.1[begin..end].copy_from_slice(&serialized);
            (end, acc.1)
        })
    }
}

impl Header {
    fn deserialize(buf: &[u8; 512]) -> Header {
        Header {
            packet_id: u16::from_be_bytes(
                buf[..2]
                    .try_into()
                    .expect("Failed to deserialize packet_id."),
            ),
            qr_ind: Self::deserialize_qr_ind(buf),
            op_code: Self::deserialize_op_code(buf),
            is_auth_ans: get_bit_flag_for_byte(buf, 2, 2),
            is_trunc: get_bit_flag_for_byte(buf, 2, 1),
            is_rec_desired: get_bit_flag_for_byte(buf, 2, 0),
            is_rec_available: get_bit_flag_for_byte(buf, 3, 7),
            r_code: Self::deserialize_r_code(buf),
            qd_count: u16::from_be_bytes(buf[4..6].try_into().unwrap()),
            an_count: u16::from_be_bytes(buf[6..8].try_into().unwrap()),
            ns_count: u16::from_be_bytes(buf[8..10].try_into().unwrap()),
            ar_count: u16::from_be_bytes(buf[10..12].try_into().unwrap()),
        }
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
        match (buf[2] >> 3) & 0xF {
            0 => OperationCode::Query,
            1 => OperationCode::IQuery,
            2 => OperationCode::Status,
            v => OperationCode::Other(v),
        }
    }

    fn serialize_op_code(op_code: &OperationCode) -> u8 {
        (match op_code {
            OperationCode::Query => 0,
            OperationCode::IQuery => 1,
            OperationCode::Status => 2,
            OperationCode::Other(v) => *v,
        }) << 3
    }

    fn deserialize_r_code(buf: &[u8; 512]) -> ResponseCode {
        match buf[3] & 0xF {
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

impl Serializable for Header {
    fn serialize(&self) -> Vec<u8> {
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

        header.to_vec()
    }
}

impl Question {
    fn deserialize(raw: &[u8], pos: usize) -> (Question, usize) {
        let (name, mut pos) = deserialize_name(raw, pos);

        let record_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        pos += 2;

        let class = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        pos += 2;

        (
            Question {
                name,
                record_type,
                class,
            },
            pos,
        )
    }

    fn deserialize_questions(raw: &[u8], qd_count: &u16) -> (Vec<Question>, usize) {
        let mut questions = Vec::new();

        let mut curr_q_start = 12;

        for _ in 0..*qd_count {
            let (q, next_q_start) = Self::deserialize(raw, curr_q_start);
            questions.push(q);
            curr_q_start = next_q_start;
        }

        (questions, curr_q_start)
    }
}

impl Serializable for Question {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized: Vec<u8> = serialize_name(&self.name);

        serialized.extend_from_slice(&self.record_type.to_be_bytes());
        serialized.extend_from_slice(&self.class.to_be_bytes());

        serialized
    }
}

impl Answer {
    fn deserialize_answers(raw: &[u8], an_count: &u16, pos: usize) -> Vec<Answer> {
        let mut answers = Vec::new();

        let mut curr_pos = pos;

        for _ in 0..*an_count {
            let (a, next_pos) = Self::deserialize(raw, curr_pos);
            answers.push(a);
            curr_pos = next_pos;
        }

        answers
    }

    fn deserialize(raw: &[u8], pos: usize) -> (Answer, usize) {
        let (name, mut pos) = deserialize_name(raw, pos);

        let record_type = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        pos += 2;

        let class = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        pos += 2;

        let time_to_live = u32::from_be_bytes(raw[pos..pos + 4].try_into().unwrap());
        pos += 4;

        let length = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        pos += 2;

        let mut data = Vec::new();
        if record_type == 1 && class == 1 {
            for _ in 0..4 {
                data.push(raw[pos]);
                pos += 1;
            }
        } else {
            panic!("RR TYPE different than 'A' and CLASS different than 'IN' are not supported.")
        }

        (
            Answer {
                name,
                record_type,
                class,
                time_to_live,
                length,
                data,
            },
            pos,
        )
    }
}

impl Serializable for Answer {
    fn serialize(&self) -> Vec<u8> {
        let mut serialized: Vec<u8> = serialize_name(&self.name);

        serialized.extend_from_slice(&self.record_type.to_be_bytes());
        serialized.extend_from_slice(&self.class.to_be_bytes());
        serialized.extend_from_slice(&self.time_to_live.to_be_bytes());
        serialized.extend_from_slice(&self.length.to_be_bytes());
        serialized.extend_from_slice(&self.data);

        serialized
    }
}

fn serialize_name(input: &str) -> Vec<u8> {
    input
        .split('.')
        .map(|label| {
            let label_len: u8 = label
                .len()
                .try_into()
                .expect("domain name part length exceeded");

            let chars_encoded = label
                .chars()
                .map(|c| {
                    let mut c_buf = vec![0; c.len_utf8()];
                    c.encode_utf8(&mut c_buf);
                    c_buf
                })
                .flatten();

            [label_len].into_iter().chain(chars_encoded)
        })
        .flatten()
        .chain(vec![0u8; 1].into_iter())
        .collect()
}

fn deserialize_name(raw: &[u8], pos: usize) -> (String, usize) {
    let init_state = NameDeserializeState::new(pos);

    let state = deserialize_name_rec(raw, init_state);

    (state.labels.join("."), state.end_pos)
}

struct NameDeserializeState<'a> {
    pos: usize,
    end_pos: usize,
    skipped_to_offset: bool,
    labels: Vec<&'a str>,
}

impl<'a> NameDeserializeState<'a> {
    fn new(pos: usize) -> Self {
        NameDeserializeState {
            pos,
            end_pos: pos,
            skipped_to_offset: false,
            labels: Vec::new(),
        }
    }
}

fn deserialize_name_rec<'a>(raw: &'a [u8], state: NameDeserializeState<'a>) -> NameDeserializeState<'a> {
    if state.pos >= raw.len() {
        panic!("Name deserialization error");
    }

    let is_offset_ptr = |val| val & 0xC0 == 0xC0;

    match raw[state.pos] {
        0 => NameDeserializeState {
            end_pos: match state.skipped_to_offset {
                true => state.end_pos,
                false => state.pos + 1,
            },
            ..state
        },
        v if is_offset_ptr(&v) => {
            let i = state.pos;
            let state = NameDeserializeState {
                pos: (u16::from_be_bytes(raw[i..i+2].try_into().unwrap()) & 0x3FFF) as usize,
                end_pos: match state.skipped_to_offset {
                    true => state.end_pos,
                    false => state.pos + 2,
                },
                skipped_to_offset: true,
                ..state
            };

            deserialize_name_rec(raw, state)
        }
        v => {
            let len = v as usize;
            let begin = state.pos + 1;
            let end = begin + len;

            let label =
                from_utf8(&raw[begin..end]).expect("Sequence of bytes is not a valid UTF-8 string");

            let state = NameDeserializeState {
                pos: end,
                end_pos: end,
                labels: [state.labels, vec![label]].concat(),
                ..state
            };

            deserialize_name_rec(raw, state)
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_to_labels_parses_string() {
        let result = serialize_name("github.com");

        assert_eq!(
            result,
            [0x6, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x3, 0x63, 0x6f, 0x6d, 0x0]
        );
    }
}
