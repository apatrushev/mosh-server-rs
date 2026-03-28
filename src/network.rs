use std::{
    io,
    net::{SocketAddr, UdpSocket},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::crypto::{self, Base64Key, CryptoError, Message, MoshNonce, Session};

const PORT_RANGE_LOW: u16 = 60001;
const PORT_RANGE_HIGH: u16 = 60999;

const IPV4_HEADER_LEN: usize = 20 + 8;
const DEFAULT_IPV4_MTU: usize = 1280;

pub const ADDED_BYTES: usize = 8 + 4;
pub const CRYPTO_ADDED_BYTES: usize = 16;

const SERVER_ASSOCIATION_TIMEOUT: u64 = 40000;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    ToServer = 0,
    ToClient = 1,
}

pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn timestamp16() -> u16 {
    let ts = (timestamp() % 65536) as u16;
    if ts == 0xFFFF { 0 } else { ts }
}

pub fn timestamp_diff(tsnew: u16, tsold: u16) -> u16 {
    let diff = tsnew as i32 - tsold as i32;
    if diff < 0 {
        (diff + 65536) as u16
    } else {
        diff as u16
    }
}

pub struct Packet {
    pub seq: u64,
    pub direction: Direction,
    pub timestamp: u16,
    pub timestamp_reply: u16,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn from_message(msg: &Message) -> Result<Self, CryptoError> {
        if msg.text.len() < 4 {
            return Err(CryptoError {
                message: "Packet too short for timestamps.".into(),
            });
        }
        let nonce_val = msg.nonce.val();
        let seq = crypto::nonce_seq(nonce_val);
        let direction = if crypto::nonce_is_to_client(nonce_val) {
            Direction::ToClient
        } else {
            Direction::ToServer
        };
        let ts = u16::from_be_bytes([msg.text[0], msg.text[1]]);
        let ts_reply = u16::from_be_bytes([msg.text[2], msg.text[3]]);
        let payload = msg.text[4..].to_vec();

        Ok(Packet {
            seq,
            direction,
            timestamp: ts,
            timestamp_reply: ts_reply,
            payload,
        })
    }

    pub fn to_message(&self) -> Message {
        let nonce_val =
            crypto::make_nonce_val(self.direction == Direction::ToClient, self.seq);
        let mut text = Vec::with_capacity(4 + self.payload.len());
        text.extend_from_slice(&self.timestamp.to_be_bytes());
        text.extend_from_slice(&self.timestamp_reply.to_be_bytes());
        text.extend_from_slice(&self.payload);

        Message {
            nonce: MoshNonce::from_val(nonce_val),
            text,
        }
    }
}

pub struct Connection {
    socket: UdpSocket,
    remote_addr: Option<SocketAddr>,
    key: Base64Key,
    session: Session,
    direction: Direction,
    mtu: usize,
    saved_timestamp: u16,
    saved_timestamp_received_at: u64,
    expected_receiver_seq: u64,
    last_heard: u64,
    seq_counter: u64,
    rtt_hit: bool,
    srtt: f64,
    rttvar: f64,
}

impl Connection {
    pub fn new_server(
        desired_ip: Option<&str>,
        desired_port: Option<&str>,
    ) -> Result<Self, io::Error> {
        let key = Base64Key::new();
        let session = Session::new(&key).map_err(|e| io::Error::other(e.message))?;

        let (port_low, port_high) = if let Some(port_str) = desired_port {
            parse_port_range(port_str)?
        } else {
            (PORT_RANGE_LOW, PORT_RANGE_HIGH)
        };

        let bind_ip = desired_ip.unwrap_or("0.0.0.0");

        let mut socket = None;
        for port in port_low..=port_high {
            let addr = format!("{}:{}", bind_ip, port);
            match UdpSocket::bind(&addr) {
                Ok(s) => {
                    s.set_nonblocking(true)?;
                    socket = Some(s);
                    break;
                }
                Err(_) => continue,
            }
        }

        let socket =
            socket.ok_or_else(|| io::Error::other("Could not bind to any port"))?;

        Ok(Connection {
            socket,
            remote_addr: None,
            key,
            session,
            direction: Direction::ToClient,
            mtu: DEFAULT_IPV4_MTU - IPV4_HEADER_LEN,
            saved_timestamp: 0xFFFF,
            saved_timestamp_received_at: 0,
            expected_receiver_seq: 0,
            last_heard: 0,
            seq_counter: 0,
            rtt_hit: false,
            srtt: 1000.0,
            rttvar: 500.0,
        })
    }

    pub fn port(&self) -> Result<u16, io::Error> {
        Ok(self.socket.local_addr()?.port())
    }

    pub fn get_key(&self) -> String {
        self.key.printable_key()
    }

    pub fn get_mtu(&self) -> usize {
        self.mtu
    }

    pub fn has_remote_addr(&self) -> bool {
        self.remote_addr.is_some()
    }

    pub fn timeout(&self) -> u64 {
        let rto = (self.srtt + 4.0 * self.rttvar).ceil() as u64;
        rto.clamp(50, 1000)
    }

    pub fn socket_fd(&self) -> &UdpSocket {
        &self.socket
    }

    pub fn send(&mut self, payload: &[u8]) -> Result<(), io::Error> {
        let remote = match self.remote_addr {
            Some(addr) => addr,
            None => return Ok(()),
        };

        let now = timestamp();

        if now.wrapping_sub(self.last_heard) > SERVER_ASSOCIATION_TIMEOUT
            && self.last_heard != 0
        {
            self.remote_addr = None;
            eprintln!("Server now detached from client.");
            return Ok(());
        }

        let mut ts_reply: u16 = 0xFFFF;
        if now - self.saved_timestamp_received_at < 1000
            && self.saved_timestamp != 0xFFFF
        {
            ts_reply = self
                .saved_timestamp
                .wrapping_add((now - self.saved_timestamp_received_at) as u16);
            self.saved_timestamp = 0xFFFF;
            self.saved_timestamp_received_at = 0;
        }

        self.seq_counter += 1;
        let packet = Packet {
            seq: self.seq_counter,
            direction: self.direction,
            timestamp: timestamp16(),
            timestamp_reply: ts_reply,
            payload: payload.to_vec(),
        };

        let msg = packet.to_message();
        let encrypted = self
            .session
            .encrypt(&msg)
            .map_err(|e| io::Error::other(e.message))?;

        let _ = self.socket.send_to(&encrypted, remote);
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Option<Vec<u8>>, io::Error> {
        let mut buf = [0u8; 2048];
        let (n, src) = match self.socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(e) => return Err(e),
        };

        let msg = match self.session.decrypt(&buf[..n]) {
            Ok(m) => m,
            Err(e) => {
                log::debug!("Crypto error on recv: {}", e.message);
                return Ok(None);
            }
        };

        let packet = match Packet::from_message(&msg) {
            Ok(p) => p,
            Err(e) => {
                log::debug!("Packet parse error: {}", e.message);
                return Ok(None);
            }
        };

        if packet.direction != Direction::ToServer {
            log::debug!("Received packet with wrong direction");
            return Ok(None);
        }

        let out_of_order = packet.seq < self.expected_receiver_seq;
        if !out_of_order {
            self.expected_receiver_seq = packet.seq + 1;

            if packet.timestamp != 0xFFFF {
                self.saved_timestamp = packet.timestamp;
                self.saved_timestamp_received_at = timestamp();
            }

            if packet.timestamp_reply != 0xFFFF {
                let now = timestamp16();
                let r = timestamp_diff(now, packet.timestamp_reply) as f64;
                if r < 5000.0 {
                    if !self.rtt_hit {
                        self.srtt = r;
                        self.rttvar = r / 2.0;
                        self.rtt_hit = true;
                    } else {
                        let alpha = 1.0 / 8.0;
                        let beta = 1.0 / 4.0;
                        self.rttvar =
                            (1.0 - beta) * self.rttvar + beta * (self.srtt - r).abs();
                        self.srtt = (1.0 - alpha) * self.srtt + alpha * r;
                    }
                }
            }

            let changed = self.remote_addr != Some(src);
            self.remote_addr = Some(src);
            self.last_heard = timestamp();
            if changed {
                eprintln!("Server now attached to client at {}", src);
            }
        }

        Ok(Some(packet.payload))
    }
}

fn parse_port_range(s: &str) -> Result<(u16, u16), io::Error> {
    if let Some((low, high)) = s.split_once(':') {
        let low: u16 = low.parse().map_err(|_| io::Error::other("Invalid port"))?;
        let high: u16 = high.parse().map_err(|_| io::Error::other("Invalid port"))?;
        Ok((low, high))
    } else {
        let port: u16 = s.parse().map_err(|_| io::Error::other("Invalid port"))?;
        Ok((port, port))
    }
}
