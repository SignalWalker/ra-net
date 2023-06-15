use std::{net::SocketAddr, sync::Arc, time::Duration};

use arraydeque::ArrayDeque;
use crossbeam::{
    atomic::AtomicCell,
    channel::{self, Receiver, Sender},
};
use dashmap::DashMap;
use parking_lot::RwLock;
use socket2::SockAddr;

use crate::{
    Ack, AckBitfield, PacketHeader, RdpError, RdpPacket, RdpSocketInternal, RdpStream, SendState,
    SendStatus, SeqNum,
};

type SeqBuf = ArrayDeque<SeqNum, { std::mem::size_of::<AckBitfield>() * 8 }, arraydeque::Wrapping>;

#[derive(Debug)]
pub(crate) struct RdpStreamInternal {
    remote_addr: SockAddr,
    local_seq: AtomicCell<SeqNum>,
    remote_seq: AtomicCell<SeqNum>,
    seq_ring: RwLock<SeqBuf>,
    // internal
    sock: Arc<RdpSocketInternal>,
    recv_queue: Receiver<Box<RdpPacket>>,
    ack_map: DashMap<SeqNum, SendStatus>,
}

impl RdpStreamInternal {
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.sock.addr.as_socket().unwrap()
    }

    #[inline]
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr.as_socket().unwrap()
    }

    pub(crate) fn with_channel(
        remote_addr: SockAddr,
        sock: Arc<RdpSocketInternal>,
        recv_queue: Receiver<Box<RdpPacket>>,
    ) -> Result<Arc<Self>, RdpError> {
        Ok(Arc::new(Self {
            remote_addr,
            local_seq: AtomicCell::default(),
            remote_seq: AtomicCell::default(),
            seq_ring: RwLock::default(),
            sock,
            recv_queue,
            ack_map: DashMap::default(),
        }))
    }

    pub(crate) fn new(
        remote_addr: SockAddr,
        sock: Arc<RdpSocketInternal>,
    ) -> Result<(Sender<Box<RdpPacket>>, Arc<Self>), RdpError> {
        let (sender, recv_queue) = channel::unbounded();
        Self::with_channel(remote_addr, sock, recv_queue).map(|s| (sender, s))
    }

    pub(crate) fn to_external(self: Arc<Self>) -> RdpStream {
        RdpStream { internal: self }
    }

    #[inline]
    pub fn remote_seq(&self) -> SeqNum {
        self.remote_seq.load()
    }

    #[inline]
    fn ack(&self, seq: SeqNum) {
        if let Some((_, status)) = self.ack_map.remove(&seq) {
            status.trip(SendState::Acknowledged);
        }
    }

    #[inline]
    fn recv_inner(&self, packet: Box<RdpPacket>) -> Result<Box<RdpPacket>, RdpError> {
        let header = packet.header();
        let header_seq = header.seq;
        if header_seq > self.remote_seq() {
            let old = self.remote_seq.swap(header.seq);
            self.seq_ring.write().push_back(old);
        }
        let header_ack = header.ack;
        self.ack(header_ack.curr);
        for seq in header_ack {
            self.ack(seq);
        }
        Ok(packet)
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Box<RdpPacket>, RdpError> {
        self.recv_inner(self.recv_queue.recv_timeout(timeout)?)
    }

    pub fn recv(&self, blocking: bool) -> Result<Box<RdpPacket>, RdpError> {
        if !blocking && self.recv_queue.is_empty() {
            return Err(RdpError::WouldBlock);
        }
        self.recv_inner(self.recv_queue.recv()?)
    }

    pub fn send(&self, data: &[u8]) -> Result<SendStatus, RdpError> {
        let seq = self.local_seq.fetch_update(|seq| Some(seq + 1)).unwrap();

        let remote_seq = self.remote_seq.load();
        let seq_ring = self.seq_ring.read();

        self.sock.send_packet_to(
            &RdpPacket::new(
                PacketHeader {
                    seq,
                    ack: Ack {
                        curr: remote_seq,
                        prev: construct_bitfield(remote_seq, &seq_ring),
                    },
                    ..Default::default()
                },
                data,
            ),
            &self.remote_addr,
        )?;
        let status = SendStatus::new();
        if let Some(lost) = self.ack_map.insert(seq, status.clone()) {
            lost.trip(SendState::Lost);
        }
        Ok(status)
    }
}

#[inline]
const fn bits_in<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

fn construct_bitfield(current: SeqNum, seq: &SeqBuf) -> AckBitfield {
    let mut res = AckBitfield::default();
    for seq in seq {
        let diff = (current - *seq).0 as usize;
        if diff > bits_in::<AckBitfield>() {
            continue;
        }
        res |= 1 << diff - 1;
    }
    res
}
