use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastAddrV4(pub Ipv4Addr, pub Ipv4Addr);

impl MulticastAddrV4 {
    #[inline]
    pub fn ip(self) -> Ipv4Addr {
        self.0
    }
}

impl Display for MulticastAddrV4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.0, self.1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MulticastAddrV6(pub Ipv6Addr, pub u32);

impl MulticastAddrV6 {
    #[inline]
    pub fn ip(self) -> Ipv6Addr {
        self.0
    }
}

impl Display for MulticastAddrV6 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.0, self.1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MulticastAddr {
    V4(MulticastAddrV4),
    V6(MulticastAddrV6),
}

impl MulticastAddr {
    #[inline]
    pub fn ip(self) -> IpAddr {
        match self {
            Self::V4(MulticastAddrV4(addr, _)) => IpAddr::V4(addr),
            Self::V6(MulticastAddrV6(addr, _)) => IpAddr::V6(addr),
        }
    }
}

impl Display for MulticastAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MulticastAddr::V4(v4) => v4.fmt(f),
            MulticastAddr::V6(v6) => v6.fmt(f),
        }
    }
}

impl From<MulticastAddrV4> for MulticastAddr {
    fn from(addr: MulticastAddrV4) -> Self {
        Self::V4(addr)
    }
}

impl From<MulticastAddrV6> for MulticastAddr {
    fn from(addr: MulticastAddrV6) -> Self {
        Self::V6(addr)
    }
}

impl From<Ipv4Addr> for MulticastAddrV4 {
    fn from(addr: Ipv4Addr) -> Self {
        Self(addr, Ipv4Addr::UNSPECIFIED)
    }
}

impl From<Ipv6Addr> for MulticastAddrV6 {
    fn from(addr: Ipv6Addr) -> Self {
        Self(addr, 0)
    }
}

impl From<Ipv4Addr> for MulticastAddr {
    fn from(addr: Ipv4Addr) -> Self {
        Self::V4(addr.into())
    }
}

impl From<Ipv6Addr> for MulticastAddr {
    fn from(addr: Ipv6Addr) -> Self {
        Self::V6(addr.into())
    }
}

impl From<IpAddr> for MulticastAddr {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => addr.into(),
            IpAddr::V6(addr) => addr.into(),
        }
    }
}
