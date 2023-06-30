use std::{
    io::Result as IoResult,
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    sync::{atomic::AtomicBool, Arc, Weak},
    time::Duration,
};

use crossbeam::channel::{self, Receiver, Sender};
use dashmap::{DashMap, DashSet};
use futures::future::RemoteHandle;
use parking_lot::{Condvar, Mutex};
use socket2::{Domain, Protocol, SockAddr, Socket};

use crate::{
    MulticastAddr, MulticastAddrV4, MulticastAddrV6, PacketFlags, PacketHeader, RdpError, RdpEvent,
    RdpPacket, RdpStream, RdpStreamInternal, MAX_DGRAM_BYTES,
};

lazy_static::lazy_static! {
    pub(super) static ref SOCK_MAP: DashMap<SocketAddr, Weak<RdpSocketInternal>> = DashMap::default();
}

#[derive(Debug)]
pub(crate) struct RdpSocketInternal {
    pub(crate) udp: Socket,
    pub(crate) addr: SockAddr,
    pub(crate) mcasts: DashSet<MulticastAddr>,
    // internal
    packet_queue: Receiver<(SocketAddr, Box<RdpPacket>)>,
    connection_queue: Receiver<(SocketAddr, RdpStream)>,
    streams: Arc<DashMap<SocketAddr, (Sender<Box<RdpPacket>>, Weak<RdpStreamInternal>)>>,
    event_flag: Arc<(Mutex<RdpEvent>, Condvar)>,
    stop_flag: Arc<AtomicBool>,
    recv_thread: Option<RemoteHandle<Result<(), RdpError>>>,
}

impl Drop for RdpSocketInternal {
    fn drop(&mut self) {
        let _ = futures::executor::block_on(self.stop());
    }
}

impl RdpSocketInternal {
    pub fn find_or_bind(
        pool: impl futures::task::SpawnExt + Copy + Send + 'static,
        addrs: impl ToSocketAddrs,
    ) -> Result<(SocketAddr, Arc<Self>), RdpError> {
        let addrs = addrs.to_socket_addrs()?;
        let mut res = None;

        {
            for addr in addrs {
                if let Some(internal) = SOCK_MAP.get(&addr).and_then(|sock| sock.upgrade()) {
                    return Ok((internal.addr.as_socket().unwrap(), internal));
                }

                let addr = SockAddr::from(addr);
                let sock = match Socket::new(
                    match addr.is_ipv4() {
                        true => Domain::IPV4,
                        false => Domain::IPV6,
                    },
                    socket2::Type::DGRAM,
                    Some(Protocol::UDP),
                ) {
                    Ok(sock) => sock,
                    Err(e) => {
                        res = Some(Err(e));
                        continue;
                    }
                };

                match sock.bind(&addr).and_then(|_| {
                    Self::new(pool, sock.local_addr()?, sock, Duration::from_millis(200))
                }) {
                    Ok(sock) => {
                        res = Some(Ok((sock.addr.clone(), sock)));
                        break;
                    }
                    Err(e) => {
                        res = Some(Err(e));
                        continue;
                    }
                }
            }
        }

        match res {
            None => Err(RdpError::InvalidAddressInput),
            Some(Err(e)) => Err(e.into()),
            Some(Ok((addr, sock))) => {
                let addr = addr.as_socket().unwrap();
                SOCK_MAP.insert(addr, Arc::downgrade(&sock));
                Ok((addr, sock))
            }
        }
    }

    /// Bind the socket to an address and begin listening for packets.
    fn new(
        pool: impl futures::task::SpawnExt + Copy + Send + 'static,
        addr: SockAddr,
        udp: Socket,
        timeout: Duration,
    ) -> IoResult<Arc<Self>> {
        udp.set_nonblocking(false)?;
        udp.set_write_timeout(Some(timeout))?;
        udp.set_read_timeout(Some(timeout))?;
        let recv_sock = udp.try_clone()?;

        let (connection_sender, connection_queue) = channel::unbounded();
        let (packet_sender, packet_queue) = channel::unbounded();

        let stop_flag = Arc::new(AtomicBool::from(false));
        let recv_stop_flag = stop_flag.clone();

        // let stream_map = Arc::new(DashMap::new());
        // let recv_stream_map = stream_map.clone();

        let event_flag = Arc::new((Mutex::new(RdpEvent::default()), Condvar::new()));
        let recv_evt_flag = event_flag.clone();

        let streams = Arc::new(DashMap::<
            SocketAddr,
            (Sender<Box<RdpPacket>>, Weak<RdpStreamInternal>),
        >::new());
        let recv_streams = streams.clone();

        let (weak_send, weak_recv) = channel::bounded(1);

        let res = Arc::new(Self {
            udp,
            addr,
            mcasts: DashSet::new(),
            // internal
            packet_queue,
            connection_queue,
            event_flag,
            stop_flag,
            streams,
            recv_thread: Some(
                pool.spawn_with_handle(Self::recv_thread(
                    pool,
                    weak_recv,
                    recv_sock,
                    recv_stop_flag,
                    recv_evt_flag,
                    connection_sender,
                    packet_sender,
                    recv_streams,
                ))
                .unwrap(),
            ),
        });

        weak_send
            .send(Arc::downgrade(&res))
            .expect("failed to send weak pointer to recv thread");

        Ok(res)
    }

    pub fn accept_connection(&self, blocking: bool) -> Result<(SocketAddr, RdpStream), RdpError> {
        if !blocking && self.connection_queue.is_empty() {
            return Err(RdpError::WouldBlock);
        }
        self.connection_queue.recv().map_err(RdpError::from)
    }

    pub fn accept_connection_timeout(
        &self,
        duration: Duration,
    ) -> Result<(SocketAddr, RdpStream), RdpError> {
        self.connection_queue
            .recv_timeout(duration)
            .map_err(RdpError::from)
    }

    pub fn recv_from(&self, blocking: bool) -> Result<(SocketAddr, Box<RdpPacket>), RdpError> {
        if !blocking && self.packet_queue.is_empty() {
            return Err(RdpError::WouldBlock);
        }
        self.packet_queue.recv().map_err(RdpError::from)
    }

    pub fn recv_from_timeout(
        &self,
        duration: Duration,
    ) -> Result<(SocketAddr, Box<RdpPacket>), RdpError> {
        self.packet_queue
            .recv_timeout(duration)
            .map_err(RdpError::from)
    }

    /// Wait for either a connection attempt or a disconnected packet.
    pub fn wait(&self) -> RdpEvent {
        let &(ref lock, ref cvar) = &*self.event_flag;
        let mut evt = lock.lock();
        cvar.wait(&mut evt);
        *evt
    }

    /// Wait for either a connection attempt or a disconnected packet, with a timeout.
    pub fn wait_timeout(&self, timeout: Duration) -> (RdpEvent, parking_lot::WaitTimeoutResult) {
        let &(ref lock, ref cvar) = &*self.event_flag;
        let mut evt = lock.lock();
        let timeout_res = cvar.wait_for(&mut evt, timeout);
        (*evt, timeout_res)
    }

    pub fn send_packet_to(
        &self,
        pkt: &RdpPacket<PacketHeader>,
        addr: &SockAddr,
    ) -> Result<(), RdpError> {
        let buf = pkt.as_bytes();
        if buf.len() > MAX_DGRAM_BYTES {
            return Err(RdpError::PacketTooLarge);
        }
        self.udp.send_to(buf, addr)?;
        Ok(())
    }

    pub fn send_to(&self, buf: &[u8], addr: &SockAddr) -> Result<(), RdpError> {
        self.send_packet_to(
            &RdpPacket::new(
                PacketHeader {
                    flags: PacketFlags::DISCONNECTED,
                    ..Default::default()
                },
                buf,
            ),
            addr,
        )
    }

    pub fn connect_to(
        self: &Arc<Self>,
        pool: impl futures::task::SpawnExt,
        addr: SocketAddr,
    ) -> Result<RdpStream, RdpError> {
        match self.streams.get_mut(&addr) {
            Some(mut e) => {
                let (sender, weak) = e.value_mut();
                let internal = match weak.upgrade() {
                    Some(i) => i,
                    None => {
                        let internal;
                        (*sender, internal) =
                            RdpStreamInternal::new(pool, addr.into(), self.clone())?;
                        *weak = Arc::downgrade(&internal);
                        internal
                    }
                };
                Ok(internal.to_external())
            }
            None => {
                let (sender, internal) = RdpStreamInternal::new(pool, addr.into(), self.clone())?;
                let weak = Arc::downgrade(&internal);

                self.streams.insert(addr, (sender, weak));

                Ok(internal.to_external())
            }
        }
    }

    #[must_use]
    fn stop(&mut self) -> impl std::future::Future<Output = Result<(), RdpError>> {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.recv_thread.take().unwrap()
    }

    // pub fn try_into_udp(mut self) -> Result<UdpSocket, RdpError> {
    //     self.stop().unwrap()?;
    //     Ok(self.udp.try_clone()?)
    // }

    #[inline]
    pub const fn is_ipv4(&self) -> bool {
        self.addr.is_ipv4()
    }

    #[inline]
    pub const fn is_ipv6(&self) -> bool {
        self.addr.is_ipv6()
    }

    pub fn join_multicast_v4(&self, addr: MulticastAddrV4) -> Result<bool, RdpError> {
        if !self.is_ipv4() {
            return Err(RdpError::IpVersionMismatch);
        }
        let m_addr = MulticastAddr::V4(addr);
        if self.mcasts.contains(&m_addr) {
            return Ok(false);
        }
        tracing::debug!(local = ?self.addr, group = ?addr, "joining multicast group");
        self.udp.join_multicast_v4(&addr.0, &addr.1)?;
        self.mcasts.insert(m_addr);
        Ok(true)
    }

    pub fn join_multicast_v6(&self, addr: MulticastAddrV6) -> Result<bool, RdpError> {
        if !self.is_ipv6() {
            return Err(RdpError::IpVersionMismatch);
        }
        let m_addr = MulticastAddr::V6(addr);
        if self.mcasts.contains(&m_addr) {
            return Ok(false);
        }
        tracing::debug!(local = ?self.addr, group = ?addr, "joining multicast group");
        self.udp.join_multicast_v6(&addr.0, addr.1)?;
        self.mcasts.insert(m_addr);
        Ok(true)
    }

    pub fn join_multicast(&self, addr: MulticastAddr) -> Result<bool, RdpError> {
        match addr {
            MulticastAddr::V4(v4) => self.join_multicast_v4(v4),
            MulticastAddr::V6(v6) => self.join_multicast_v6(v6),
        }
    }

    pub fn in_multicast_group(&self, addr: &MulticastAddr) -> bool {
        self.mcasts.contains(addr)
    }

    async fn recv_thread(
        pool: impl futures::task::SpawnExt + Copy,
        weak_recv: Receiver<Weak<RdpSocketInternal>>,
        sock: Socket,
        stop_flag: Arc<AtomicBool>,
        event_flag: Arc<(Mutex<RdpEvent>, Condvar)>,
        connection_queue: Sender<(SocketAddr, RdpStream)>,
        packet_queue: Sender<(SocketAddr, Box<RdpPacket>)>,
        streams: Arc<DashMap<SocketAddr, (Sender<Box<RdpPacket>>, Weak<RdpStreamInternal>)>>,
    ) -> Result<(), RdpError> {
        let local_addr = sock.local_addr()?.as_socket().unwrap();
        tracing::debug!(addr = %local_addr, "initializing RdpSocketInternal");

        let rdp_ref = weak_recv.recv()?;

        let mut buf = [MaybeUninit::new(0u8); MAX_DGRAM_BYTES];

        while !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
            let (read_amt, addr) = match sock.recv_from(&mut buf) {
                Ok(res) => res,
                Err(e) => match e.kind() {
                    std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock => continue,
                    _ => return Err(e.into()),
                },
            };
            let addr = addr.as_socket().unwrap();

            tracing::trace!(local = %local_addr, remote = %addr, len = read_amt, "received data; constructing RdpPacket...");

            let packet: &RdpPacket = match RdpPacket::from_slice(unsafe {
                MaybeUninit::slice_assume_init_ref(&buf[0..read_amt])
            }) {
                Ok(p) => p,
                // bad data; skip it
                Err(_) => continue,
            };

            let header = packet.header();

            let mut event = RdpEvent::None;
            if header.flags.contains(PacketFlags::DISCONNECTED) {
                tracing::debug!(local = %local_addr, remote = ?addr, len = read_amt, connected = false, "received packet");

                packet_queue
                    .send((addr, packet.to_owned()))
                    .map_err(|_| RdpError::ChannelDisconnected)?;

                event = RdpEvent::Packet;
            } else {
                tracing::debug!(local = %local_addr, remote = ?addr, len = read_amt, connected = true, "received packet");

                let stream = streams.entry(addr.clone()).or_insert_with(|| {
                    tracing::debug!(local = %local_addr, remote = ?addr, "initializing new RdpStream");

                    let (sender, internal) = RdpStreamInternal::new(
                        pool,
                        addr.into(),
                        rdp_ref
                            .upgrade()
                            .expect("socket dropped without terminating recv_thread"),
                    ).unwrap();
                    let weak = Arc::downgrade(&internal);
                    let ext = internal.to_external();

                    connection_queue
                        .send((addr.clone(), ext))
                        .map_err(|_| RdpError::ChannelDisconnected).unwrap();

                    event = RdpEvent::Connection;

                    (sender, weak)
                });
                match stream.0.send(packet.to_owned()) {
                    Ok(_) => {}
                    Err(_) => {
                        tracing::debug!(local = %local_addr, remote = ?addr, "forgetting dropped RdpStream");
                        // stream object dropped; consider it disconnected
                        streams.remove(&addr);
                    }
                }
            }
            if event != RdpEvent::None {
                let &(ref lock, ref cvar) = &*event_flag;
                *lock.lock() = event;
                cvar.notify_all();
            }
        }

        tracing::trace!(local = %local_addr, "exiting recv_thread");

        Ok(())
    }
}
