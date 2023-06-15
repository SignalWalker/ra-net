mod sequence;
use std::alloc::Layout;

pub use sequence::*;

use crate::{MAX_DGRAM_BYTES, PROTOCOL_ID};

pub type AckBitfield = u32;

pub struct AckBitfieldIter {
    base: SeqNum,
    ack: AckBitfield,
    i: usize,
}

impl AckBitfieldIter {
    fn new(base: SeqNum, ack: AckBitfield) -> Self {
        Self { base, ack, i: 0 }
    }
}

impl Iterator for AckBitfieldIter {
    type Item = SeqNum;

    fn next(&mut self) -> Option<Self::Item> {
        const BITS: usize = std::mem::size_of::<AckBitfield>() * 8;

        let res = loop {
            if self.i >= BITS {
                return None;
            }
            if (self.ack & (1 << self.i)) == 1 {
                self.i += 1;
                break self.base - (self.i as u16 + 1);
            } else {
                self.i += 1;
            }
        };

        Some(res)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let res = std::mem::size_of::<AckBitfield>() * 8 - self.i;
        (res, Some(res))
    }
}

bitflags::bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
    #[repr(transparent)]
    pub struct PacketFlags: u8 {
        const DISCONNECTED = 0b00000001;
        const UNUSED_1 =     0b00000010;
        const UNUSED_2 =     0b00000100;
        const UNUSED_3 =     0b00001000;
        const UNUSED_4 =     0b00010000;
        const UNUSED_5 =     0b00100000;
        const UNUSED_6 =     0b01000000;
        const UNUSED_7 =     0b10000000;
    }
}

unsafe impl bytemuck::Zeroable for PacketFlags {}
unsafe impl bytemuck::Pod for PacketFlags {}

#[derive(Debug, Default, bytemuck::Pod, bytemuck::Zeroable, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct Ack {
    pub curr: SeqNum,
    pub prev: AckBitfield,
}

impl IntoIterator for Ack {
    type Item = SeqNum;

    type IntoIter = AckBitfieldIter;

    fn into_iter(self) -> Self::IntoIter {
        AckBitfieldIter::new(self.curr, self.prev)
    }
}

#[derive(Debug, bytemuck::Pod, bytemuck::Zeroable, Clone, Copy, PartialEq, Eq)]
#[repr(C, packed)]
pub struct PacketHeader {
    pub flags: PacketFlags,
    pub seq: SeqNum,
    pub ack: Ack,
}

impl Default for PacketHeader {
    fn default() -> Self {
        Self {
            flags: PacketFlags::default(),
            seq: SeqNum::default(),
            ack: Ack::default(),
        }
    }
}

impl PacketHeader {
    #[inline]
    pub fn new(flags: PacketFlags, seq: SeqNum, ack: Ack) -> Self {
        Self { flags, seq, ack }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RdpPacketError {
    #[error(transparent)]
    PodCast(#[from] bytemuck::PodCastError),
    #[error("received packet too small to contain rdp header")]
    PacketTooSmall,
    #[error("received packet does not begin with rdp protocol id")]
    ProtocolIdMismatch,
}

#[repr(C, packed)]
pub struct RdpPacket<Header = PacketHeader> {
    protocol_id: u32,
    header: Header,
    data: [u8],
}

impl<Header: std::fmt::Debug + Copy> std::fmt::Debug for RdpPacket<Header> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let header = self.header;
        f.debug_struct("RdpPacket")
            .field("protocol_id", &self.protocol_id())
            .field("header", &header)
            .finish_non_exhaustive()
    }
}

impl<Header> RdpPacket<Header> {
    #[inline]
    pub fn len(&self) -> usize {
        std::mem::size_of_val(self)
    }

    #[inline]
    pub fn protocol_id(&self) -> u32 {
        self.protocol_id
    }

    #[inline]
    pub fn header_ptr(&self) -> *const Header {
        std::ptr::addr_of!(self.header)
    }

    #[inline]
    pub fn header_ptr_mut(&mut self) -> *mut Header {
        std::ptr::addr_of_mut!(self.header)
    }

    #[inline]
    pub fn data(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len()) }
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.data.as_mut_ptr(), self.len()) }
    }

    pub const fn max_data_bytes() -> usize {
        MAX_DGRAM_BYTES - std::mem::size_of::<u32>() - std::mem::size_of::<Header>()
    }

    #[inline]
    pub fn header_layout() -> Layout {
        Layout::new::<u32>()
            .extend_packed(Layout::new::<Header>())
            .unwrap()
    }

    #[inline]
    pub fn layout(len: usize) -> Layout {
        Self::header_layout()
            .extend_packed(Layout::new::<u8>().repeat(len).unwrap().0)
            .unwrap()
    }

    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts::<u8>(
                std::ptr::addr_of!(*self) as *const u8,
                Self::layout(self.len()).size(),
            )
        }
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        unsafe {
            std::slice::from_raw_parts_mut::<u8>(
                std::ptr::addr_of_mut!(*self) as *mut u8,
                Self::layout(self.len()).size(),
            )
        }
    }
}

impl<Header: Copy> RdpPacket<Header> {
    #[inline]
    pub fn header(&self) -> Header {
        unsafe { std::ptr::read_unaligned(self.header_ptr()) }
    }

    #[inline]
    pub fn set_header(&mut self, val: Header) {
        unsafe { std::ptr::write_unaligned(self.header_ptr_mut(), val) }
    }
}

impl<Header: bytemuck::AnyBitPattern> AsRef<[u8]> for RdpPacket<Header> {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<Header: bytemuck::AnyBitPattern> RdpPacket<Header> {
    pub fn from_slice<'data>(bytes: &'data [u8]) -> Result<&'data Self, RdpPacketError> {
        if bytes.len() < Self::header_layout().size() {
            return Err(RdpPacketError::PacketTooSmall);
        }

        if *bytemuck::try_from_bytes::<u32>(&bytes[..std::mem::size_of_val(&PROTOCOL_ID)])?
            != PROTOCOL_ID
        {
            return Err(RdpPacketError::ProtocolIdMismatch);
        }

        Ok(unsafe { &*((bytes as *const [u8]) as *const Self) })
    }

    pub fn from_slice_mut<'data>(
        bytes: &'data mut [u8],
    ) -> Result<&'data mut Self, RdpPacketError> {
        if bytes.len() < Self::header_layout().size() {
            return Err(RdpPacketError::PacketTooSmall);
        }

        if *bytemuck::try_from_bytes::<u32>(&bytes[..std::mem::size_of::<u32>()])? != PROTOCOL_ID {
            return Err(RdpPacketError::ProtocolIdMismatch);
        }

        Ok(unsafe { &mut *((bytes as *mut [u8]) as *mut Self) })
    }
}

impl<Header: Copy> ToOwned for RdpPacket<Header> {
    type Owned = Box<Self>;

    #[inline]
    fn to_owned(&self) -> Self::Owned {
        Self::new(self.header, self.data())
    }
}

impl<Header: Copy> RdpPacket<Header> {
    pub fn new(header: Header, data: &[u8]) -> Box<Self> {
        use std::ptr;
        let layout = Self::layout(data.len());
        let res_ptr = unsafe { std::alloc::alloc(layout) };
        if res_ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }
        let res_ptr = ptr::from_raw_parts_mut::<Self>(res_ptr as *mut (), data.len());
        unsafe {
            let protocol_ptr = ptr::addr_of_mut!((*res_ptr).protocol_id);
            protocol_ptr.write(PROTOCOL_ID);

            let header_ptr = ptr::addr_of_mut!((*res_ptr).header);
            header_ptr.write(header);

            let data_ptr = ptr::addr_of_mut!((*res_ptr).data);
            ptr::copy_nonoverlapping::<u8>(data.as_ptr(), data_ptr as *mut u8, data.len());

            Box::from_raw(res_ptr)
        }
    }
}
