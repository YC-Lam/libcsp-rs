#![no_std]

pub mod arch;
pub mod interfaces;

mod bridge;
mod buffer;
mod conn;
mod crc32;
mod dedup;
mod id;
mod rdp;

use bitflags::bitflags;

pub use buffer::Packet;
pub use interfaces::Interface;

const CSP_QFIFO_LEN: usize = 15;
const CSP_PORT_MAX_BIND: u8 = 16;
const CSP_CONN_RXQUEUE_LEN: usize = 16;
const CSP_CONN_MAX: usize = 8;
const CSP_BUFFER_SIZE: usize = 256;
const CSP_BUFFER_COUNT: usize = 15;
const CSP_RDP_MAX_WINDOW: usize = 5;
const CSP_RTABLE_SIZE: usize = 10;

pub const CSP_NO_VIA_ADDRESS: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceID(usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeStamp {
    pub tv_sec: u32,
    pub tv_nsec: u32,
}

/// Reserved port for CSP services.
/// CSP management, e.g. memory, routes, stats
pub const CSP_CMP: u8 = 0;
/// Reserved port for CSP services.
/// Ping - return ping
pub const CSP_PING: u8 = 0;
/// Reserved port for CSP services.
/// Current process list
pub const CSP_PS: u8 = 0;
/// Reserved port for CSP services.
/// Free memory
pub const CSP_MEMFREE: u8 = 0;
/// Reserved port for CSP services.
/// Reboot, see #CSP_REBOOT_MAGIC and #CSP_REBOOT_SHUTDOWN_MAGIC
pub const CSP_REBOOT: u8 = 0;
/// Reserved port for CSP services.
/// Free CSP buffer
pub const CSP_BUF_FREE: u8 = 0;
/// Reserved port for CSP services.
/// Uptime
pub const CSP_UPTIME: u8 = 0;
/// Listen on all ports, primarily used with csp_bind(
pub const CSP_ANY: u8 = 255;

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

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SocketOptions: u32{
        /// No socket options
        const CSP_SO_NONE = 0x0000;
        /// Require RDP
        const CSP_SO_RDPREQ = 0x0001;
        /// Prohibit RDP
        const CSP_SO_RDPPROHIB = 0x0002;
        /// Require HMAC
        const CSP_SO_HMACREQ = 0x0004;
        /// Prohibit HMAC
        const CSP_SO_HMACPROHIB = 0x0008;
        /// Require CRC32
        const CSP_SO_CRC32REQ = 0x0040;
        /// Prohibit CRC32
        const CSP_SO_CRC32PROHIB = 0x0080;
        /// Enable Connection Less mode
        const CSP_SO_CONN_LESS = 0x0100;
        /// Copy opts from incoming packet only applies to csp_sendto_reply()
        const CSP_SO_SAME = 0x8000;
    }
}

bitflags! {
    /// CSP Connect options
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct ConnOptions: u32{
        /// No connection options
        const CSP_O_NONE = 0x0000;
        /// Enable RDP
        const CSP_O_RDP = 0x0001;
        /// Disable RDP
        const CSP_O_NORDP = 0x0002;
        /// Enable HMAC
        const CSP_O_HMAC = 0x0004;
        /// Disable HMAC
        const CSP_O_NOHMAC = 0x0008;
        /// Enable CRC32
        const CSP_O_CRC32 = 0x0040;
        /// Disable CRC32
        const CSP_O_NOCRC32 = 0x0080;
        const CSP_O_SAME = 0x8000;
    }
}

const CSP_PACKET_PADDING_BYTES: usize = 8;
const CSP_RDP_HEADER_SIZE: usize = 5;

pub struct Socket {
    pub(crate) rx_queue: arch::Queue<&'static mut Packet, CSP_CONN_RXQUEUE_LEN>,
    pub(crate) opts: SocketOptions,
}

/// Max length of host name - including zero termination
const CSP_HOSTNAME_LEN: usize = 20;
/// Max length of model name - including zero termination
const CSP_MODEL_LEN: usize = 30;

/// Magic number for reboot request, for service-code #CSP_REBOOT
const CSP_REBOOT_MAGIC: u32 = 0x80078007;
/** Magic number for shutdown request, for service-code #CSP_REBOOT */
const CSP_REBOOT_SHUTDOWN_MAGIC: u32 = 0xD1E5529A;
