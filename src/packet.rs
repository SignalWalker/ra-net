mod sequence;
use std::{alloc::Layout, mem};

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::VerifyingKey;

// pub use sequence::*;

pub mod handshake;

#[derive(Debug, thiserror::Error)]
pub enum RtpPacketError {
    #[error(transparent)]
    PodCast(#[from] bytemuck::PodCastError),
    #[error("received packet too small to contain rtp header")]
    PacketTooSmall,
    #[error("received packet does not begin with rtp protocol id")]
    ProtocolIdMismatch,
    #[error("attempted to construct packet with data larger than {}B", u16::MAX)]
    DataOverflow,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::TransparentWrapper, bytemuck::NoUninit,
)]
#[repr(transparent)]
pub struct PeerId([u8; 32]);

unsafe impl bytemuck::checked::CheckedBitPattern for PeerId {
    type Bits = [u8; 32];

    fn is_valid_bit_pattern(bits: &Self::Bits) -> bool {
        CompressedEdwardsY::from_slice(bits)
            .ok()
            .and_then(|c| c.decompress())
            .is_some()
    }
}

impl From<PeerId> for CompressedEdwardsY {
    fn from(id: PeerId) -> Self {
        CompressedEdwardsY(id.0)
    }
}

impl From<PeerId> for VerifyingKey {
    fn from(id: PeerId) -> Self {
        // this should always succeed, because PeerIds can only be constructed from
        // verified-valid `CompressedEdwardsY` bit patterns
        Self::from_bytes(&id.0).unwrap()
    }
}

// bitflags::bitflags! {
//     #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::TransparentWrapper, bytemuck::Pod, bytemuck::Zeroable)]
//     #[repr(transparent)]
//     pub struct PacketFlags: u8 {
//         const UNUSED_0      = 0b00000001;
//         const UNUSED_1      = 0b00000010;
//         const UNUSED_2      = 0b00000100;
//         const UNUSED_3      = 0b00001000;
//         const UNUSED_4      = 0b00010000;
//         const UNUSED_5      = 0b00100000;
//         const UNUSED_6      = 0b01000000;
//         const UNUSED_7      = 0b10000000;
//     }
// }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::NoUninit)]
#[repr(u8)]
pub enum RtpPacketType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    HandshakeCookie = 3,
    Transport = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, bytemuck::NoUninit)]
#[repr(C)]
pub struct RtpPacketHeader {
    /// Source peer
    pub src: PeerId,
    /// Destination peer
    pub dst: PeerId,
    /// Length of message data
    pub msg_len: u16,
}

impl RtpPacketHeader {
    #[inline]
    pub fn msg_len(&self) -> u16 {
        unsafe { std::ptr::read_unaligned(std::ptr::addr_of!(self.msg_len)) }
    }
}

#[repr(C)]
pub struct RtpPacket {
    pub header: RtpPacketHeader,
    /// Extension data followed by message data
    data: [u8],
}

impl std::fmt::Debug for RtpPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RdpPacket")
            .field("src", &self.header.src)
            .field("dst", &self.header.dst)
            .field("message", &format!("({}B)", self.header.msg_len()))
            .finish()
    }
}

impl RtpPacket {
    /// Return the length of the payload data carried by this packet, in bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        std::mem::size_of_val(self)
    }

    #[inline]
    pub const fn data(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len()) }
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.data.as_mut_ptr(), self.len()) }
    }

    #[inline]
    pub(crate) fn layout(len: usize) -> Layout {
        Layout::new::<RtpPacketHeader>()
            .extend_packed(Layout::new::<u8>().repeat(len).unwrap().0)
            .unwrap()
    }

    /// Return a byte slice over this entire packet.
    pub const fn as_bytes<'s>(&'s self) -> &'s [u8] {
        unsafe {
            std::slice::from_raw_parts::<'s, u8>(std::ptr::addr_of!(*self) as *const u8, self.len())
        }
    }

    /// Return a mutable byte slice over this entire packet.
    pub const fn as_bytes_mut<'s>(&'s mut self) -> &'s mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut::<'s, u8>(
                std::ptr::addr_of_mut!(*self) as *mut u8,
                self.len(),
            )
        }
    }
}

impl RtpPacket {
    pub fn try_from_slice<'data>(bytes: &'data [u8]) -> Result<&'data Self, RtpPacketError> {
        if bytes.len() < mem::size_of::<RtpPacketHeader>() {
            return Err(RtpPacketError::PacketTooSmall);
        }

        Ok(unsafe { &*((bytes as *const [u8]) as *const Self) })
    }

    pub fn try_from_slice_mut<'data>(
        bytes: &'data mut [u8],
    ) -> Result<&'data mut Self, RtpPacketError> {
        if bytes.len() < mem::size_of::<RtpPacketHeader>() {
            return Err(RtpPacketError::PacketTooSmall);
        }

        Ok(unsafe { &mut *((bytes as *mut [u8]) as *mut Self) })
    }
}

impl ToOwned for RtpPacket {
    type Owned = Box<Self>;

    #[inline]
    fn to_owned(&self) -> Self::Owned {
        Self::new(self.header, self.data())
    }
}

impl RtpPacket {
    fn new(header: RtpPacketHeader, data: &[u8]) -> Box<Self> {
        use std::{alloc, ptr};
        let layout = Self::layout(data.len());
        let res_ptr = unsafe { alloc::alloc(layout) };
        if res_ptr.is_null() {
            alloc::handle_alloc_error(layout);
        }
        let res_ptr = ptr::from_raw_parts_mut::<Self>(res_ptr as *mut (), data.len());
        unsafe {
            let header_ptr = ptr::addr_of_mut!((*res_ptr).header);
            header_ptr.write(header);

            let data_ptr = ptr::addr_of_mut!((*res_ptr).data);
            ptr::copy_nonoverlapping::<u8>(data.as_ptr(), data_ptr as *mut u8, data.len());

            Box::from_raw(res_ptr)
        }
    }

    pub fn with_msg(
        src: PeerId,
        dst: PeerId,
        msg: &impl bytemuck::NoUninit,
    ) -> Result<Box<Self>, RtpPacketError> {
        let msg = bytemuck::bytes_of(msg);
        if msg.len() > (u16::MAX as usize) {
            return Err(RtpPacketError::DataOverflow);
        }
        Ok(Self::new(
            RtpPacketHeader {
                src,
                dst,
                msg_len: msg.len() as u16,
            },
            msg,
        ))
    }
}

#[derive(Debug)]
pub struct RtpPacketBuilder {
    pub src: PeerId,
    pub dst: PeerId,
}

impl RtpPacketBuilder {
    pub fn build(&self, msg: &impl bytemuck::NoUninit) -> Result<Box<RtpPacket>, RtpPacketError> {
        RtpPacket::with_msg(self.src, self.dst, msg)
    }
}

impl RtpPacket {
    pub const fn builder(src: PeerId, dst: PeerId) -> RtpPacketBuilder {
        RtpPacketBuilder { src, dst }
    }
}
