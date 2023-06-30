use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::{RdpError, RdpPacket, SeqNum};

mod status;
pub use status::*;

mod internal;
pub(crate) use internal::*;

#[derive(Debug, Clone)]
pub struct RdpStream {
    internal: Arc<RdpStreamInternal>,
}

impl RdpStream {
    #[inline]
    pub fn local_addr(&self) -> SocketAddr {
        self.internal.local_addr()
    }

    #[inline]
    pub fn remote_addr(&self) -> SocketAddr {
        self.internal.remote_addr()
    }

    #[inline]
    pub fn remote_seq(&self) -> SeqNum {
        self.internal.remote_seq()
    }

    #[inline]
    pub fn recv(&self, blocking: bool) -> Result<Box<RdpPacket>, RdpError> {
        self.internal.recv(blocking)
    }

    #[inline]
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Box<RdpPacket>, RdpError> {
        self.internal.recv_timeout(timeout)
    }

    #[inline]
    pub fn send(&self, data: &[u8]) -> Result<SendStatus, RdpError> {
        self.internal.send(data)
    }

    pub async fn send_reliable(self, data: &[u8]) -> Result<(), RdpError> {
        loop {
            match self.send(data)?.await {
                SendState::Lost => continue,
                SendState::Acknowledged => return Ok(()),
                SendState::Pending => unreachable!(),
            }
        }
    }
}
