use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};

use crossbeam::channel;
use socket2::SockAddr;

use crate::{PacketHeader, RdpPacket, MAX_DGRAM_BYTES};

mod internal;
pub(crate) use internal::*;

mod stream;
pub use stream::*;

mod multicast;
pub use multicast::*;

#[cfg(feature = "ggrs")]
mod ggrs;
#[cfg(feature = "ggrs")]
pub use self::ggrs::*;

#[derive(Debug, thiserror::Error)]
pub enum RdpError {
    #[error(transparent)]
    ChannelRecv(#[from] channel::RecvError),
    #[error("cannot send packets larger than {} bytes", MAX_DGRAM_BYTES)]
    PacketTooLarge,
    #[error("channel disconnected")]
    ChannelDisconnected,
    #[error("socket does not hold unique reference to internal data")]
    SocketNotUnique,
    #[error("operation would block the thread")]
    WouldBlock,
    #[error("operation timed out")]
    Timeout,
    #[error("attempted version-specific IP operation with mismatched version")]
    IpVersionMismatch,
    #[error("attempted to join multicast group with nonexistant interface")]
    NoSuchInterface,
    #[error("could not bind to requested address")]
    AddrUnavailable,
    #[error("could not convert input to SocketAddr")]
    InvalidAddressInput,
    #[error("attempted to perform socket operation with mismatched address family (IPv4/IPv6)")]
    AddrFamilyUnsupported,
}

impl From<std::io::Error> for RdpError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match Self::try_from(err.kind()) {
            Ok(r) => r,
            Err(kind) => match kind {
                ErrorKind::Uncategorized => match err.raw_os_error() {
                    Some(19) => Self::NoSuchInterface,
                    Some(97) => Self::AddrFamilyUnsupported,
                    _ => todo!("{err:?}"),
                },
                _ => todo!("{err:?}"),
            },
        }
    }
}

impl TryFrom<std::io::ErrorKind> for RdpError {
    type Error = std::io::ErrorKind;
    fn try_from(value: std::io::ErrorKind) -> Result<Self, Self::Error> {
        use std::io::ErrorKind;
        match value {
            ErrorKind::WouldBlock => Ok(Self::WouldBlock),
            ErrorKind::TimedOut => Ok(Self::Timeout),
            ErrorKind::AddrNotAvailable => Ok(Self::AddrUnavailable),
            _ => Err(value),
        }
    }
}

impl From<channel::RecvTimeoutError> for RdpError {
    fn from(value: channel::RecvTimeoutError) -> Self {
        match value {
            channel::RecvTimeoutError::Timeout => Self::Timeout,
            channel::RecvTimeoutError::Disconnected => Self::ChannelDisconnected,
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RdpEvent {
    #[default]
    None,
    Packet,
    Connection,
}

#[derive(Debug, Clone)]
pub struct RdpSocket {
    internal: Arc<RdpSocketInternal>,
}

impl PartialEq for RdpSocket {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.internal, &other.internal)
    }
}

impl Eq for RdpSocket {}

impl RdpSocket {
    #[inline]
    pub fn bind(addrs: impl ToSocketAddrs) -> Result<(SocketAddr, Self), RdpError> {
        RdpSocketInternal::find_or_bind(addrs).map(|(addr, internal)| (addr, Self { internal }))
    }

    #[inline]
    pub fn addr(&self) -> SocketAddr {
        self.internal.addr.as_socket().unwrap()
    }

    #[inline]
    pub fn accept_connection(&self, blocking: bool) -> Result<(SocketAddr, RdpStream), RdpError> {
        self.internal.accept_connection(blocking)
    }

    #[inline]
    pub fn accept_connection_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(SocketAddr, RdpStream), RdpError> {
        self.internal.accept_connection_timeout(timeout)
    }

    #[inline]
    pub fn recv_from(&self, blocking: bool) -> Result<(SocketAddr, Box<RdpPacket>), RdpError> {
        self.internal.recv_from(blocking)
    }

    #[inline]
    pub fn recv_from_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(SocketAddr, Box<RdpPacket>), RdpError> {
        self.internal.recv_from_timeout(timeout)
    }

    #[inline]
    pub fn send_packet_to(
        &self,
        pkt: &RdpPacket<PacketHeader>,
        addr: impl Into<SockAddr>,
    ) -> Result<(), RdpError> {
        self.internal.send_packet_to(pkt, &addr.into())
    }

    #[inline]
    pub fn send_to(&self, buf: &[u8], addr: impl Into<SockAddr>) -> Result<(), RdpError> {
        self.internal.send_to(buf, &addr.into())
    }

    #[inline]
    pub fn connect_to(&self, addr: SocketAddr) -> Result<RdpStream, RdpError> {
        self.internal.connect_to(addr)
    }

    #[inline]
    pub fn wait(&self) -> RdpEvent {
        self.internal.wait()
    }

    #[inline]
    pub fn wait_timeout(&self, timeout: Duration) -> (RdpEvent, parking_lot::WaitTimeoutResult) {
        self.internal.wait_timeout(timeout)
    }

    // /// # Safety
    // ///
    // /// Attempting to receive packets on the returned socket will interfere with existing RdpSockets
    // /// bound to the same address.
    // pub unsafe fn try_clone_udp_socket(&self) -> IoResult<std::net::UdpSocket> {
    //     self.internal.udp.try_clone()
    // }

    #[inline]
    pub fn join_multicast(&self, addr: MulticastAddr) -> Result<bool, RdpError> {
        self.internal.join_multicast(addr)
    }

    #[inline]
    pub fn join_multicast_v4(&self, addr: Ipv4Addr, interface: Ipv4Addr) -> Result<bool, RdpError> {
        self.internal
            .join_multicast_v4(MulticastAddrV4(addr, interface))
    }

    #[inline]
    pub fn join_multicast_v6(&self, addr: Ipv6Addr, interface: u32) -> Result<bool, RdpError> {
        self.internal
            .join_multicast_v6(MulticastAddrV6(addr, interface))
    }

    #[inline]
    pub fn join_multicast_simple(&self, addr: IpAddr) -> Result<bool, RdpError> {
        self.internal.join_multicast(addr.into())
    }

    #[inline]
    pub fn in_multicast_group(&self, addr: &MulticastAddr) -> bool {
        self.internal.in_multicast_group(addr)
    }

    #[inline]
    pub fn is_ipv4(&self) -> bool {
        self.internal.is_ipv4()
    }

    #[inline]
    pub fn is_ipv6(&self) -> bool {
        self.internal.is_ipv6()
    }
}

// impl TryFrom<RdpSocket> for std::net::UdpSocket {
//     type Error = RdpError;
//
//     fn try_from(mut value: RdpSocket) -> Result<Self, Self::Error> {
//         let internal = match Arc::try_unwrap(value.internal) {
//             Ok(internal) => internal,
//             Err(internal) => {
//                 value.internal = internal;
//                 return Err(RdpError::SocketNotUnique);
//             }
//         };
//         internal.try_into_udp()
//     }
// }
