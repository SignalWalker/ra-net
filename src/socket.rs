use std::{
    io,
    net::{SocketAddr, ToSocketAddrs},
    sync::{Arc, Weak},
    time::Duration,
};

use dashmap::DashMap;
use futures::future::RemoteHandle;
use smol::Async;
use socket2::{Domain, Protocol, SockAddr, Socket};

use crate::packet::RtpPacket;

pub struct RtpSocketBuilder {
    executor: Box<dyn futures::task::Spawn>,
}

impl Default for RtpSocketBuilder {
    fn default() -> Self {
        Self { executor: todo!() }
    }
}

impl RtpSocketBuilder {
    pub fn bind(&self, addrs: impl ToSocketAddrs) -> Result<RtpSocket, SocketError> {
        let (_, internal) = RtpSocketInternal::find_or_bind(&self.executor, addrs)?;
        Ok(RtpSocket { internal })
    }
}

lazy_static::lazy_static! {
    static ref SOCK_MAP: DashMap<SocketAddr, Weak<RtpSocketInternal>> = DashMap::default();
}

#[derive(Debug, thiserror::Error)]
pub enum SocketError {
    #[error("could not resolve any socket address from input values")]
    InvalidAddressInput,
    #[error("async task executor was shut down")]
    ExecutorShutdown,
}

impl From<std::io::Error> for SocketError {
    fn from(err: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match err.kind() {
            ErrorKind::InvalidInput => Self::InvalidAddressInput,
            ErrorKind::Uncategorized => match err.raw_os_error() {
                _ => todo!("{err:?}"),
            },
            _ => todo!("{err:?}"),
        }
    }
}

impl From<futures::task::SpawnError> for SocketError {
    fn from(err: futures::task::SpawnError) -> Self {
        match err.is_shutdown() {
            true => Self::ExecutorShutdown,
            false => todo!("{err:?}"),
        }
    }
}

// impl TryFrom<std::io::ErrorKind> for SocketError {
//     type Error = std::io::ErrorKind;
//     fn try_from(kind: std::io::ErrorKind) -> Result<Self, Self::Error> {
//         use std::io::ErrorKind;
//         match kind {
//             _ => Err(kind),
//         }
//     }
// }

struct SocketData {
    addr: SockAddr,
    sock: smol::net::UdpSocket,
}

pub(crate) struct RtpSocketInternal {
    data: Arc<SocketData>,
    recv_task: RemoteHandle<Result<(), SocketError>>,
}

/// For [`SocketAddr`] in `addr`, run a function, folding `Err` and returning early on `Ok`.
///
/// This is pretty much just [`each_addr`](https://github.com/rust-lang/rust/blob/3ae0ef79fe4485ad5f0bfc4cd1f27a1b3fd94f60/library/std/src/net/mod.rs#L71)
/// from the standard library -- reimplemented because the std implementation isn't exported.
fn each_addr<A: ToSocketAddrs, F, T>(addr: A, mut f: F) -> Result<T, SocketError>
where
    F: FnMut(&SocketAddr) -> Result<T, SocketError>,
{
    let addrs = match addr.to_socket_addrs() {
        Ok(addrs) => addrs,
        Err(e) => return Err(SocketError::from(e)),
    };
    let mut last_err = None;
    for addr in addrs {
        match f(&addr) {
            Ok(l) => return Ok(l),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or(SocketError::InvalidAddressInput))
}

impl RtpSocketInternal {
    /// Either find an existing [`RtpSocketInternal`] bound to a given address, or bind a new one.
    pub(crate) fn find_or_bind(
        executor: &impl futures::task::SpawnExt,
        addrs: impl ToSocketAddrs,
    ) -> Result<(SocketAddr, Arc<Self>), SocketError> {
        each_addr(addrs, |addr| {
            if let Some(internal) = SOCK_MAP.get(&addr).and_then(|sock| sock.upgrade()) {
                return Ok((internal.data.addr.as_socket().unwrap(), internal));
            }
            match Self::bind(executor, SockAddr::from(*addr)) {
                Ok(sock) => {
                    let addr = sock.data.addr.as_socket().unwrap();
                    SOCK_MAP.insert(addr, Arc::downgrade(&sock));
                    Ok((addr, sock))
                }
                Err(e) => Err(SocketError::from(e)),
            }
        })
    }

    fn bind(
        executor: &impl futures::task::SpawnExt,
        addr: SockAddr,
    ) -> Result<Arc<Self>, SocketError> {
        let sock = Socket::new(
            match addr.is_ipv4() {
                true => Domain::IPV4,
                false => Domain::IPV6,
            },
            socket2::Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        sock.bind(&addr)?;
        sock.set_reuse_address(false)?;

        let data = Arc::new(SocketData {
            addr,
            sock: smol::net::UdpSocket::from(Async::new(std::net::UdpSocket::from(sock))?),
        });

        let recv_task = executor.spawn_with_handle(Self::recv_loop(data.clone()))?;

        Ok(Self { data, recv_task }.into())
    }

    async fn recv_loop(data: Arc<SocketData>) -> Result<(), SocketError> {
        let local_addr = data.addr.as_socket().unwrap();
        let sock = &data.sock;
        scopeguard::defer! { tracing::trace!(local = %local_addr, "exiting recv_loop"); }

        let mut buf = vec![0; 1024];
        loop {
            let (read_amt, src_addr) = match data.sock.recv_from(&mut buf).await {
                Ok(r) => r,
                Err(e) => match e.kind() {
                    std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::WouldBlock => continue,
                    _ => return Err(e.into()),
                },
            };

            let pkt: &RtpPacket = match RtpPacket::try_from_slice(&buf[0..read_amt]) {
                Ok(p) => p,
                // bad packet; skip it
                Err(_) => continue,
            };
        }
    }
}

pub struct RtpSocket {
    internal: Arc<RtpSocketInternal>,
}

impl RtpSocket {
    pub fn builder() -> RtpSocketBuilder {
        RtpSocketBuilder::default()
    }

    pub fn bind(addrs: impl ToSocketAddrs) -> Result<Self, SocketError> {
        RtpSocketBuilder::default().bind(addrs)
    }
}
