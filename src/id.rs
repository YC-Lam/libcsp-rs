//! CSP 2.x uses a 48-bit network-order header: priority (2 bits), destination
//! and source node IDs (14 bits each), destination and source ports (6 bits
//! each), then 6 flag bits.

use bitflags::bitflags;

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
        const RES1 = 0x80;
        /// Reserved for future use
        const RES2 = 0x40;
        /// Reserved for future use
        const RES3 = 0x20;
        /// Use fragmentation
        const FRAG = 0x10;
        /// Use HMAC verification
        const HMAC = 0x08;
        /// Use RDP protocol
        const RDP = 0x02;
        /// Use CRC32 checksum
        const CRC32 = 0x01;
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
    /// Encode the identifier as the six-byte CSP 2.x network header.
    pub(crate) fn to_header(&self) -> [u8; CSP_ID2_HEADER_SIZE] {
        // Pack the fields into the low 48 bits before serializing in network order.
        let mut id2: u64 = ((self.prio as u64) << CSP_ID2_PRIO_OFFSET)
            | ((self.dst as u64) << CSP_ID2_DST_OFFSET)
            | ((self.src as u64) << CSP_ID2_SRC_OFFSET)
            | ((self.dport as u64) << CSP_ID2_DPORT_OFFSET)
            | ((self.sport as u64) << CSP_ID2_SPORT_OFFSET)
            | ((self.flags.bits() as u64) << CSP_ID2_FLAGS_OFFSET);

        // Shift the 48-bit header into the most significant end of the word.
        id2 = id2 << 16;

        // Convert to big / network endian.
        let data = id2.to_be_bytes();

        return [data[0], data[1], data[2], data[3], data[4], data[5]];
    }

    /// Decode a six-byte CSP 2.x network header.
    ///
    /// Callers must validate the input length before calling this method.
    pub(crate) fn from_header(header: &[u8]) -> Self {
        let id2 = u64::from_be_bytes([
            header[0], header[1], header[2], header[3], header[4], header[5], 0, 0,
        ]) >> 16;

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

/// Return the 14-bit network mask for a prefix length, clamped to CSP's
/// address width.
pub(crate) const fn address_mask(prefix_len: usize) -> u16 {
    let prefix_len = if prefix_len > CSP_ID2_HOST_SIZE {
        CSP_ID2_HOST_SIZE
    } else {
        prefix_len
    };
    if prefix_len == 0 {
        0
    } else {
        (((1u32 << prefix_len) - 1) << (CSP_ID2_HOST_SIZE - prefix_len)) as u16
    }
}

/// Check whether `addr` is the all-ones host address for an interface subnet,
/// or CSP's global all-ones node address.
///
/// The prefix length is limited to the 14-bit node address width. A full-width
/// prefix has no host bits, so only the global broadcast address applies.
pub fn is_broadcast(addr: u16, iface_addr: u16, iface_netmask: u16) -> bool {
    let prefix_len = (iface_netmask as usize).min(CSP_ID2_HOST_SIZE);
    if prefix_len == CSP_ID2_HOST_SIZE {
        return addr == get_max_nodeid();
    }

    let network_mask = address_mask(prefix_len);
    let hostmask = get_max_nodeid() ^ network_mask;
    ((addr & hostmask) == hostmask && (addr & network_mask) == (iface_addr & network_mask))
        || addr == get_max_nodeid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_width_subnet_does_not_broadcast_its_interface_address() {
        assert!(!is_broadcast(0x1234, 0x1234, 14));
        assert!(is_broadcast(get_max_nodeid(), 0x1234, 14));
        assert!(!is_broadcast(0x1234, 0x1234, u16::MAX));
    }

    #[test]
    fn subnet_broadcast_matches_only_its_network() {
        assert!(!is_broadcast(0x2000, 0x2000, 13));
        assert!(is_broadcast(0x2001, 0x2000, 13));
        assert!(!is_broadcast(0x2001, 0x2002, 13));
        assert!(is_broadcast(get_max_nodeid(), 0x2000, 13));
    }
}
