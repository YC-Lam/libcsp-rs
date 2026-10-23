#![no_std]

#[cfg(test)]
extern crate std;

pub mod arch;
pub mod interfaces;

mod bridge;

// mod cmp;
mod buffer;
mod conn;
mod crc32;
mod dedup;
mod id;
mod io;
mod rdp;

pub use buffer::Packet;

pub use id::{Flags, Priority};

pub use interfaces::{
    Interface, InterfaceID, add_interface, get_interface_by_addr, get_interface_by_broadcast,
    get_interface_by_isdfl, get_interface_by_name, get_interface_by_subnet, print_interface_list,
    remove_interface,
};

pub fn init() {
    buffer::buffer_init();
    conn::init();

    todo!(); // qfifo_init()
    todo!(); // rdp_queue_init()

    /* Loopback */
    // csp_if_lo.netmask = csp_id_get_host_bits();
    // csp_iflist_add(&csp_if_lo);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Timeout,
    CRC32,
    FeatureDisabled,
    ConnectionClosed,
    BufferOverflow,
    InvalidOperation
}

const CSP_QFIFO_LEN: usize = 15;
const CSP_RTABLE_SIZE: usize = 10;

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

/// Max length of host name - including zero termination
const CSP_HOSTNAME_LEN: usize = 20;
/// Max length of model name - including zero termination
const CSP_MODEL_LEN: usize = 30;

/// Magic number for reboot request, for service-code #CSP_REBOOT
const CSP_REBOOT_MAGIC: u32 = 0x80078007;
/** Magic number for shutdown request, for service-code #CSP_REBOOT */
const CSP_REBOOT_SHUTDOWN_MAGIC: u32 = 0xD1E5529A;

pub struct CspStream{

}

impl CspStream{

}

pub struct CspListener{

}

impl CspListener{
    
}