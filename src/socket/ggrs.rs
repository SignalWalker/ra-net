use ggrs::NonBlockingSocket;

use crate::RdpSocket;

impl NonBlockingSocket<std::net::SocketAddr> for RdpSocket {
    fn send_to(&mut self, msg: &ggrs::Message, addr: &std::net::SocketAddr) {
        RdpSocket::send_to(self, &bincode::serialize(&msg).unwrap(), *addr).unwrap()
    }

    fn receive_all_messages(&mut self) -> Vec<(std::net::SocketAddr, ggrs::Message)> {
        let mut res: Vec<(std::net::SocketAddr, ggrs::Message)> = Vec::new();
        loop {
            match self.recv_from(false) {
                Ok((addr, m)) => res.push((addr, bincode::deserialize(m.data()).unwrap())),
                Err(crate::RdpError::WouldBlock) => return res,
                Err(e) => panic!("{e:?}"),
            }
        }
    }
}
