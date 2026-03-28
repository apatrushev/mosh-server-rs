use std::io::{self, Read, Write};

use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use prost::Message as ProstMessage;

use crate::{
    network::{self, Connection},
    proto::{
        client_buffers::UserMessage,
        host_buffers::{
            EchoAck,
            HostBytes,
            HostMessage,
            Instruction as HostInstruction,
            ResizeMessage as HostResizeMessage,
        },
        transport_buffers::Instruction,
    },
};

const MOSH_PROTOCOL_VERSION: u32 = 2;
const FRAG_HEADER_LEN: usize = 8 + 2;

const SEND_INTERVAL_MIN: u64 = 20;
const SEND_INTERVAL_MAX: u64 = 250;
const ACK_INTERVAL: u64 = 3000;
const ACK_DELAY: u64 = 100;

struct Fragment {
    id: u64,
    fragment_num: u16,
    is_final: bool,
    contents: Vec<u8>,
}

impl Fragment {
    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < FRAG_HEADER_LEN {
            return None;
        }
        let id = u64::from_be_bytes(data[0..8].try_into().ok()?);
        let combined = u16::from_be_bytes(data[8..10].try_into().ok()?);
        let is_final = (combined & 0x8000) != 0;
        let fragment_num = combined & 0x7FFF;
        let contents = data[FRAG_HEADER_LEN..].to_vec();
        Some(Fragment {
            id,
            fragment_num,
            is_final,
            contents,
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(FRAG_HEADER_LEN + self.contents.len());
        out.extend_from_slice(&self.id.to_be_bytes());
        let combined: u16 = if self.is_final {
            0x8000 | self.fragment_num
        } else {
            self.fragment_num
        };
        out.extend_from_slice(&combined.to_be_bytes());
        out.extend_from_slice(&self.contents);
        out
    }
}

struct FragmentAssembly {
    fragments: Vec<Option<Vec<u8>>>,
    current_id: u64,
    fragments_arrived: usize,
    fragments_total: Option<usize>,
}

impl FragmentAssembly {
    fn new() -> Self {
        FragmentAssembly {
            fragments: Vec::new(),
            current_id: u64::MAX,
            fragments_arrived: 0,
            fragments_total: None,
        }
    }

    fn add_fragment(&mut self, frag: &Fragment) -> bool {
        let idx = frag.fragment_num as usize;
        if frag.id != self.current_id {
            self.fragments.clear();
            self.fragments.resize(idx + 1, None);
            self.fragments[idx] = Some(frag.contents.clone());
            self.fragments_arrived = 1;
            self.fragments_total = None;
            self.current_id = frag.id;
        } else {
            if idx >= self.fragments.len() {
                self.fragments.resize(idx + 1, None);
            }
            if self.fragments[idx].is_none() {
                self.fragments[idx] = Some(frag.contents.clone());
                self.fragments_arrived += 1;
            }
        }

        if frag.is_final {
            self.fragments_total = Some(idx + 1);
            self.fragments.resize(idx + 1, None);
        }

        if let Some(total) = self.fragments_total {
            self.fragments_arrived == total
        } else {
            false
        }
    }

    fn get_assembly(&mut self) -> Option<Instruction> {
        let mut encoded = Vec::new();
        for f in &self.fragments {
            encoded.extend_from_slice(f.as_ref()?);
        }
        self.fragments.clear();
        self.fragments_arrived = 0;
        self.fragments_total = None;

        let decompressed = zlib_decompress(&encoded).ok()?;
        Instruction::decode(decompressed.as_slice()).ok()
    }
}

struct Fragmenter {
    next_id: u64,
    last_old_num: u64,
    last_new_num: u64,
}

impl Fragmenter {
    fn new() -> Self {
        Fragmenter {
            next_id: 0,
            last_old_num: u64::MAX,
            last_new_num: u64::MAX,
        }
    }

    fn make_fragments(&mut self, inst: &Instruction, mtu: usize) -> Vec<Fragment> {
        let payload_mtu = mtu - FRAG_HEADER_LEN;

        if inst.old_num() != self.last_old_num || inst.new_num() != self.last_new_num {
            self.next_id += 1;
        }
        self.last_old_num = inst.old_num();
        self.last_new_num = inst.new_num();

        let serialized = inst.encode_to_vec();
        let compressed = zlib_compress(&serialized);

        let mut frags = Vec::new();
        let mut offset = 0;
        let mut frag_num: u16 = 0;
        loop {
            let end = (offset + payload_mtu).min(compressed.len());
            let is_final = end == compressed.len();
            frags.push(Fragment {
                id: self.next_id,
                fragment_num: frag_num,
                is_final,
                contents: compressed[offset..end].to_vec(),
            });
            offset = end;
            frag_num += 1;
            if is_final {
                break;
            }
        }
        frags
    }
}

pub enum UserAction {
    Keystroke(Vec<u8>),
    Resize(i32, i32),
}

pub fn parse_user_actions(diff: &[u8]) -> Vec<UserAction> {
    let msg = match UserMessage::decode(diff) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };
    let mut actions = Vec::new();
    for inst in &msg.instruction {
        if let Some(ref ks) = inst.keystroke
            && let Some(ref keys) = ks.keys
        {
            actions.push(UserAction::Keystroke(keys.clone()));
        }
        if let Some(ref rs) = inst.resize {
            actions.push(UserAction::Resize(rs.width(), rs.height()));
        }
    }
    actions
}

pub fn make_host_diff(
    data: &[u8],
    echo_ack: Option<u64>,
    resize: Option<(i32, i32)>,
) -> Vec<u8> {
    let mut msg = HostMessage {
        instruction: Vec::new(),
    };

    if let Some(ack_num) = echo_ack {
        msg.instruction.push(HostInstruction {
            hostbytes: None,
            resize: None,
            echoack: Some(EchoAck {
                echo_ack_num: Some(ack_num),
            }),
        });
    }

    if let Some((w, h)) = resize {
        msg.instruction.push(HostInstruction {
            hostbytes: None,
            resize: Some(HostResizeMessage {
                width: Some(w),
                height: Some(h),
            }),
            echoack: None,
        });
    }

    if !data.is_empty() {
        msg.instruction.push(HostInstruction {
            hostbytes: Some(HostBytes {
                hoststring: Some(data.to_vec()),
            }),
            resize: None,
            echoack: None,
        });
    }

    msg.encode_to_vec()
}

pub struct ServerTransport {
    connection: Connection,
    last_sent_num: u64,
    ack_num: u64,
    assumed_receiver_num: u64,
    fragmenter: Fragmenter,
    next_ack_time: u64,
    next_send_time: u64,
    pending_output: Vec<u8>,
    pending_echo_ack: Option<u64>,
    pending_resize: Option<(i32, i32)>,
    shutdown_in_progress: bool,
    shutdown_tries: i32,
    received_state_num: u64,
    assembly: FragmentAssembly,
    input_history: Vec<(u64, u64)>,
    echo_ack: u64,
    last_ack_sent_to_client: u64,
}

impl ServerTransport {
    pub fn new(connection: Connection) -> Self {
        let now = network::timestamp();
        ServerTransport {
            connection,
            last_sent_num: 0,
            ack_num: 0,
            assumed_receiver_num: 0,
            fragmenter: Fragmenter::new(),
            next_ack_time: now + ACK_INTERVAL,
            next_send_time: u64::MAX,
            pending_output: Vec::new(),
            pending_echo_ack: None,
            pending_resize: None,
            shutdown_in_progress: false,
            shutdown_tries: 0,
            received_state_num: 0,
            assembly: FragmentAssembly::new(),
            input_history: Vec::new(),
            echo_ack: 0,
            last_ack_sent_to_client: 0,
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn get_remote_state_num(&self) -> u64 {
        self.received_state_num
    }

    pub fn shutdown_in_progress(&self) -> bool {
        self.shutdown_in_progress
    }

    pub fn start_shutdown(&mut self) {
        self.shutdown_in_progress = true;
    }

    pub fn shutdown_acknowledged(&self) -> bool {
        self.shutdown_in_progress && self.ack_num == u64::MAX
    }

    pub fn counterparty_shutdown_ack_sent(&self) -> bool {
        self.received_state_num == u64::MAX && self.last_ack_sent_to_client == u64::MAX
    }

    pub fn shutdown_ack_timed_out(&self) -> bool {
        self.shutdown_tries >= 16
    }

    pub fn register_input_frame(&mut self, frame_num: u64, now: u64) {
        self.input_history.push((frame_num, now));
    }

    pub fn update_echo_ack(&mut self, now: u64) -> bool {
        const ECHO_TIMEOUT: u64 = 50;
        let mut newest = 0u64;
        for &(num, ts) in &self.input_history {
            if ts <= now.saturating_sub(ECHO_TIMEOUT) {
                newest = newest.max(num);
            }
        }
        self.input_history.retain(|&(num, _)| num >= newest);
        if self.echo_ack != newest {
            self.echo_ack = newest;
            true
        } else {
            false
        }
    }

    pub fn echo_ack(&self) -> u64 {
        self.echo_ack
    }

    pub fn push_output(&mut self, data: &[u8]) {
        self.pending_output.extend_from_slice(data);
        self.next_send_time = network::timestamp() + SEND_INTERVAL_MIN;
    }

    pub fn set_pending_echo_ack(&mut self, ack: u64) {
        self.pending_echo_ack = Some(ack);
        self.next_send_time = network::timestamp() + SEND_INTERVAL_MIN;
    }

    pub fn set_pending_resize(&mut self, w: i32, h: i32) {
        self.pending_resize = Some((w, h));
        self.next_send_time = network::timestamp() + SEND_INTERVAL_MIN;
    }

    fn has_pending_data(&self) -> bool {
        !self.pending_output.is_empty()
            || self.pending_echo_ack.is_some()
            || self.pending_resize.is_some()
    }

    fn take_pending_diff(&mut self) -> Vec<u8> {
        let diff = make_host_diff(
            &self.pending_output,
            self.pending_echo_ack.take(),
            self.pending_resize.take(),
        );
        self.pending_output.clear();
        diff
    }

    pub fn recv(&mut self) -> Result<Option<Vec<u8>>, io::Error> {
        let payload = match self.connection.recv()? {
            Some(p) => p,
            None => return Ok(None),
        };

        let frag = match Fragment::from_bytes(&payload) {
            Some(f) => f,
            None => return Ok(None),
        };

        if !self.assembly.add_fragment(&frag) {
            return Ok(None);
        }

        let inst = match self.assembly.get_assembly() {
            Some(i) => i,
            None => return Ok(None),
        };

        if inst.protocol_version() != MOSH_PROTOCOL_VERSION {
            log::warn!("Protocol version mismatch: {}", inst.protocol_version());
            return Ok(None);
        }

        let client_ack = inst.ack_num();
        if client_ack > self.ack_num {
            self.ack_num = client_ack;
        }

        if inst.new_num() == u64::MAX {
            self.received_state_num = u64::MAX;
            let now = network::timestamp();
            self.next_ack_time = now;
            return Ok(None);
        }

        let now = network::timestamp();
        if self.next_ack_time > now + ACK_DELAY {
            self.next_ack_time = now + ACK_DELAY;
        }

        if inst.new_num() <= self.received_state_num && inst.new_num() != u64::MAX {
            return Ok(None);
        }

        if inst.old_num() != self.received_state_num && inst.old_num() != 0 {
            return Ok(None);
        }

        self.received_state_num = inst.new_num();

        let diff = inst.diff.unwrap_or_default();
        if diff.is_empty() {
            return Ok(None);
        }

        Ok(Some(diff))
    }

    pub fn tick(&mut self) -> Result<(), io::Error> {
        if !self.connection.has_remote_addr() {
            return Ok(());
        }

        let now = network::timestamp();

        if now < self.next_ack_time && now < self.next_send_time {
            return Ok(());
        }

        if self.has_pending_data()
            && (now >= self.next_send_time || now >= self.next_ack_time)
        {
            let diff = self.take_pending_diff();
            let new_num = self.last_sent_num + 1;
            self.last_sent_num = new_num;
            self.send_instruction(&diff, new_num)?;
            self.next_ack_time = now + ACK_INTERVAL;
            self.next_send_time = u64::MAX;
        } else if now >= self.next_ack_time {
            let new_num = if self.shutdown_in_progress {
                self.shutdown_tries += 1;
                u64::MAX
            } else {
                self.last_sent_num + 1
            };
            if new_num != u64::MAX {
                self.last_sent_num = new_num;
            }
            self.send_instruction(&[], new_num)?;
            self.next_ack_time = now + ACK_INTERVAL;
        }

        if self.shutdown_in_progress {
            let send_interval = self.send_interval();
            self.next_ack_time = self.next_ack_time.min(now + send_interval);
        }

        Ok(())
    }

    pub fn wait_time(&self) -> u64 {
        if !self.connection.has_remote_addr() {
            return u64::MAX;
        }
        let now = network::timestamp();
        let next = self.next_ack_time.min(self.next_send_time);
        next.saturating_sub(now)
    }

    fn send_interval(&self) -> u64 {
        let rto = self.connection.timeout();
        rto.clamp(SEND_INTERVAL_MIN, SEND_INTERVAL_MAX)
    }

    fn send_instruction(&mut self, diff: &[u8], new_num: u64) -> Result<(), io::Error> {
        let chaff_len = (rand::random::<u8>() % 17) as usize;
        let chaff: Vec<u8> = (0..chaff_len).map(|_| rand::random()).collect();
        let inst = Instruction {
            protocol_version: Some(MOSH_PROTOCOL_VERSION),
            old_num: Some(self.assumed_receiver_num),
            new_num: Some(new_num),
            ack_num: Some(self.received_state_num),
            throwaway_num: Some(0),
            diff: if diff.is_empty() {
                None
            } else {
                Some(diff.to_vec())
            },
            chaff: Some(chaff),
        };

        self.last_ack_sent_to_client = self.received_state_num;

        let payload_mtu = self.connection.get_mtu()
            - network::ADDED_BYTES
            - network::CRYPTO_ADDED_BYTES;
        let fragments = self.fragmenter.make_fragments(&inst, payload_mtu);

        for frag in &fragments {
            self.connection.send(&frag.to_bytes())?;
        }

        self.assumed_receiver_num = new_num;
        Ok(())
    }
}

fn zlib_compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("zlib compress write");
    encoder.finish().expect("zlib compress finish")
}

fn zlib_decompress(data: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}
