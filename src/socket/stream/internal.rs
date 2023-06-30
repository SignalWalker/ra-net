use crate::{
    Ack, AckBitfield, PacketHeader, RdpError, RdpPacket, RdpSocketInternal, RdpStream, SendState,
    SendStatus, SeqNum,
};
use arraydeque::ArrayDeque;
use crossbeam::{
    atomic::AtomicCell,
    channel::{self, Receiver, Sender},
};
use dashmap::DashMap;
use futures::future::RemoteHandle;
use parking_lot::RwLock;
use socket2::SockAddr;
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

type SeqBuf = ArrayDeque<SeqNum, { std::mem::size_of::<AckBitfield>() * 8 }, arraydeque::Wrapping>;

#[derive(Debug)]
pub(crate) struct RdpStreamInternal {
    remote_addr: SockAddr,
    local_seq: AtomicCell<SeqNum>,
    remote_seq: Arc<AtomicCell<SeqNum>>,
    seq_ring: Arc<RwLock<SeqBuf>>,
    // internal
    sock: Arc<RdpSocketInternal>,
    recv_queue: Receiver<Box<RdpPacket>>,
    ack_map: Arc<DashMap<SeqNum, SendStatus>>,
    stop_flag: Arc<AtomicBool>,
    recv_thread: Option<RemoteHandle<Result<(), RdpError>>>,
}

impl Drop for RdpStreamInternal {
    fn drop(&mut self) {
        let _ = futures::executor::block_on(self.stop());
    }
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
        pool: impl futures::task::SpawnExt,
        remote_addr: SockAddr,
        sock: Arc<RdpSocketInternal>,
        recv_queue: Receiver<Box<RdpPacket>>,
    ) -> Result<Arc<Self>, RdpError> {
        let (send_internal, recv_internal) = channel::unbounded();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let ack_map = Arc::new(DashMap::default());
        let remote_seq = Arc::new(AtomicCell::default());
        let seq_ring = Arc::new(RwLock::default());
        Ok(Arc::new(Self {
            remote_addr,
            local_seq: AtomicCell::default(),
            sock,
            recv_queue: recv_internal,
            recv_thread: Some(
                pool.spawn_with_handle(Self::recv_thread(
                    stop_flag.clone(),
                    recv_queue,
                    send_internal,
                    ack_map.clone(),
                    remote_seq.clone(),
                    seq_ring.clone(),
                ))
                .unwrap(),
            ),
            ack_map,
            seq_ring,
            stop_flag,
            remote_seq,
        }))
    }

    pub(crate) fn new(
        pool: impl futures::task::SpawnExt,
        remote_addr: SockAddr,
        sock: Arc<RdpSocketInternal>,
    ) -> Result<(Sender<Box<RdpPacket>>, Arc<Self>), RdpError> {
        let (sender, recv_queue) = channel::unbounded();
        Self::with_channel(pool, remote_addr, sock, recv_queue).map(|s| (sender, s))
    }

    pub(crate) fn to_external(self: Arc<Self>) -> RdpStream {
        RdpStream { internal: self }
    }

    #[inline]
    pub fn remote_seq(&self) -> SeqNum {
        self.remote_seq.load()
    }

    pub fn recv_timeout(&self, timeout: Duration) -> Result<Box<RdpPacket>, RdpError> {
        self.recv_queue
            .recv_timeout(timeout)
            .map_err(RdpError::from)
    }

    pub fn recv(&self, blocking: bool) -> Result<Box<RdpPacket>, RdpError> {
        if !blocking && self.recv_queue.is_empty() {
            return Err(RdpError::WouldBlock);
        }
        self.recv_queue.recv().map_err(RdpError::from)
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

    /// Task function for checking acks.
    async fn recv_thread(
        stop_flag: Arc<AtomicBool>,
        recv_queue: Receiver<Box<RdpPacket>>,
        internal_queue: Sender<Box<RdpPacket>>,
        ack_map: Arc<DashMap<SeqNum, SendStatus>>,
        remote_seq: Arc<AtomicCell<SeqNum>>,
        seq_ring: Arc<RwLock<SeqBuf>>,
    ) -> Result<(), RdpError> {
        #[inline]
        fn ack(ack_map: &DashMap<SeqNum, SendStatus>, seq: SeqNum) {
            if let Some((_, status)) = ack_map.remove(&seq) {
                status.trip(SendState::Acknowledged);
            }
        }

        const TIMEOUT: Duration = Duration::from_millis(200);

        let ack_map = &*ack_map;
        while !stop_flag.load(Ordering::Relaxed) {
            let msg = match recv_queue.recv_timeout(TIMEOUT) {
                Ok(m) => m,
                Err(channel::RecvTimeoutError::Timeout) => continue,
                _ => break,
            };

            // process acks
            let header = msg.header();
            let header_seq = header.seq;
            if header_seq > remote_seq.load() {
                let old = remote_seq.swap(header.seq);
                seq_ring.write().push_back(old);
            }
            let header_ack = header.ack;
            // notify waiting SendStatii
            ack(ack_map, header_ack.curr);
            for seq in header_ack {
                ack(ack_map, seq);
            }

            if let Err(error) = internal_queue.send(msg) {
                tracing::error!(?error, "failed to process RdpStream message");
                break;
            }
        }
        Ok(())
    }

    #[must_use]
    fn stop(&mut self) -> impl std::future::Future<Output = Result<(), RdpError>> {
        self.stop_flag.store(true, Ordering::Relaxed);
        self.recv_thread.take().unwrap()
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
