use bitflags::bitflags;

/**
 * CSP 2.x
 *
 * +--------+-----------------------------------+-----------------------------------------+---------------------+-------------------+----------------------+
 * |        |                                   |                                         |                     |                   |                      |
 * | 2 PRIO |      14 DESTINATION               |       14 SOURCE                         | 6 DESTINATION PORT  | 6 SOURCE PORT     | 6 FLAGS              |
 * |        |                                   |                                         |                     |                   |                      |
 * +--------+-----------------------------------+-----------------------------------------+---------------------+-------------------+----------------------+
 *
 */

const CSP_ID2_HOST_SIZE: usize = 14;
const CSP_ID2_PORT_SIZE: usize = 6;

const CSP_ID2_PRIO_MASK: u64 = 0x3;
const CSP_ID2_PRIO_OFFSET: usize = 46;
const CSP_ID2_DST_MASK: u64 = 0x3FFF;
const CSP_ID2_DST_OFFSET: usize = 32;
const CSP_ID2_SRC_MASK: u64 = 0x3FFF;
const CSP_ID2_SRC_OFFSET: usize = 18;
const CSP_ID2_DPORT_MASK: u64 = 0x3F;
const CSP_ID2_DPORT_OFFSET: usize = 12;
const CSP_ID2_SPORT_MASK: u64 = 0x3F;
const CSP_ID2_SPORT_OFFSET: usize = 6;
const CSP_ID2_FLAGS_MASK: u64 = 0x3F;
const CSP_ID2_FLAGS_OFFSET: usize = 0;

const CSP_ID2_HEADER_SIZE: usize = 6;

/// Message priority
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Priority {
    Critical = 0,
    High = 1,
    /// Normal (default)
    Normal = 2,
    Low = 3,
}

impl Priority {
    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Critical,
            1 => Self::High,
            2 => Self::Normal,
            3 => Self::Low,
            _ => unreachable!(),
        }
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Flags: u8{
        /// Reserved for future use
        const CSP_FRES1 = 0x80;
        /// Reserved for future use
        const CSP_FRES2 = 0x40;
        /// Reserved for future use
        const CSP_FRES3 = 0x20;
        /// Use fragmentation
        const CSP_FFRAG = 0x10;
        /// Use HMAC verification
        const CSP_FHMAC = 0x08;
        /// Use RDP protocol
        const CSP_FRDP = 0x02;
        /// Use CRC32 checksum
        const CSP_FCRC32 = 0x01;
    }
}

/// CSP identifier/header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(packed)]
pub(crate) struct CspId {
    pub prio: Priority,
    pub flags: Flags,
    pub src: u16,
    pub dst: u16,
    pub dport: u8,
    pub sport: u8,
}

impl CspId {
    pub(crate) fn to_header(&self) -> [u8; CSP_ID2_HEADER_SIZE] {
        // Pack into 64-bit using host endian
        let mut id2: u64 = ((self.prio as u64) << CSP_ID2_PRIO_OFFSET)
            | ((self.dst as u64) << CSP_ID2_DST_OFFSET)
            | ((self.src as u64) << CSP_ID2_SRC_OFFSET)
            | ((self.dport as u64) << CSP_ID2_DPORT_OFFSET)
            | ((self.sport as u64) << CSP_ID2_SPORT_OFFSET)
            | ((self.flags.bits() as u64) << CSP_ID2_FLAGS_OFFSET);

        // We first shift up the 48 bit header to most significant end of the 64-bit
        id2 = id2 << 16;

        //Convert to big / network endian
        let data = id2.to_be_bytes();

        return [data[0], data[1], data[2], data[3], data[4], data[5]];
    }

    pub(crate) fn from_header(header: &[u8]) -> Self {
        let id2 = u64::from_be_bytes([
            header[0], header[1], header[2], header[3], header[4], header[5], 0, 0,
        ]);

        CspId {
            prio: Priority::from_u8(((id2 >> CSP_ID2_PRIO_OFFSET) & CSP_ID2_PRIO_MASK) as u8),
            dst: ((id2 >> CSP_ID2_DST_OFFSET) & CSP_ID2_DST_MASK) as u16,
            src: ((id2 >> CSP_ID2_SRC_OFFSET) & CSP_ID2_SRC_MASK) as u16,
            dport: ((id2 >> CSP_ID2_DPORT_OFFSET) & CSP_ID2_DPORT_MASK) as u8,
            sport: ((id2 >> CSP_ID2_SPORT_OFFSET) & CSP_ID2_SPORT_MASK) as u8,
            flags: Flags::from_bits_retain(
                ((id2 >> CSP_ID2_FLAGS_OFFSET) & CSP_ID2_FLAGS_MASK) as u8,
            ),
        }
    }

    pub(crate) fn clear(&mut self) {
        self.prio = Priority::Critical;
        self.flags = Flags::empty();
        self.src = 0;
        self.dst = 0;
        self.sport = 0;
        self.dport = 0;
    }
}

pub const fn get_host_bits() -> usize {
    CSP_ID2_HOST_SIZE
}

pub const fn get_max_nodeid() -> u16 {
    (1 << CSP_ID2_HOST_SIZE) - 1
}

pub const fn get_max_port() -> usize {
    (1 << CSP_ID2_PORT_SIZE) - 1
}

pub const fn get_header_size() -> usize {
    CSP_ID2_HEADER_SIZE
}

pub fn is_broadcast(addr: u16, iface_addr: u16, iface_netmask: u16) -> bool {
    let hostmask: u16 = (1 << get_host_bits() as u16 - iface_netmask) - 1;
    let netmask: u16 = (1 << get_host_bits()) - 1 - hostmask;

    if (addr & hostmask) == hostmask && (addr & netmask) == (iface_addr & netmask) {
        return true;
    }

    if addr == get_max_nodeid() as u16 {
        return true;
    }

    return false;
}
