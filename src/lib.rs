#![no_std]

#[cfg(test)]
extern crate std;

mod arch;
pub mod interfaces;

// mod cmp;
mod bridge;
mod buffer;
mod conn;
mod crc32;
mod dedup;
pub mod drivers;
mod id;
mod io;
mod port;
mod promisc;
mod qfifo;
#[cfg(feature = "rdp")]
mod rdp;
#[cfg(feature = "rdp")]
mod rdp_queue;
mod route;

pub use bridge::{bridge_set_interfaces, bridge_work};

pub use buffer::Packet;

pub use crate::conn::ConnOptions;

pub use id::{Flags, Priority};

pub use interfaces::{
    Interface, InterfaceID, add_interface, print_interface_list, remove_interface,
};

pub use route::route_work;

pub async fn init() {
    qfifo::init();
    #[cfg(feature = "rdp")]
    rdp_queue::init();

    /* Loopback */
    todo!(); // csp_if_lo.netmask = csp_id_get_host_bits();
    // csp_iflist_add(&csp_if_lo);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Timeout,
    CRC32,
    HMAC,
    FeatureDisabled,
    ConnectionClosed,
    BufferOverflow,
    InvalidOperation,
    PortBusy,
    AllocError,
    CanBusError,
}

const CSP_RTABLE_SIZE: usize = 10;

/// Reserved port for CSP services.
/// CSP management, e.g. memory, routes, stats
pub const CSP_CMP: u8 = 0;
/// Reserved port for CSP services.
/// Ping - return ping
pub const CSP_PING: u8 = 1;
/// Reserved port for CSP services.
/// Current process list
pub const CSP_PS: u8 = 2;
/// Reserved port for CSP services.
/// Free memory
pub const CSP_MEMFREE: u8 = 3;
/// Reserved port for CSP services.
/// Reboot, see #CSP_REBOOT_MAGIC and #CSP_REBOOT_SHUTDOWN_MAGIC
pub const CSP_REBOOT: u8 = 4;
/// Reserved port for CSP services.
/// Free CSP buffer
pub const CSP_BUF_FREE: u8 = 5;
/// Reserved port for CSP services.
/// Uptime
pub const CSP_UPTIME: u8 = 6;

/// Listen on all ports, primarily used with csp_bind(
pub const CSP_ANY: u8 = 255;

/// Magic number for reboot request, for service-code #CSP_REBOOT
const CSP_REBOOT_MAGIC: u32 = 0x80078007;
/** Magic number for shutdown request, for service-code #CSP_REBOOT */
const CSP_REBOOT_SHUTDOWN_MAGIC: u32 = 0xD1E5529A;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketPort {
    Any,
    Port(u8),
}

impl From<u8> for SocketPort {
    fn from(value: u8) -> Self {
        if value == CSP_ANY {
            return SocketPort::Any;
        }

        SocketPort::Port(value)
    }
}

pub struct CspStream {
    peer_addr: u16,
    peer_port: u8,
    local_addr: u16,
    local_port: u8,
    conn: Option<conn::Connection>,
}

impl Drop for CspStream {
    fn drop(&mut self) {
        if let Some(conn) = &self.conn {
            conn.close_nonblocking();
        }
    }
}

impl CspStream {
    pub async fn connect(
        prio: Priority,
        addr: u16,
        port: u8,
        opts: ConnOptions,
    ) -> Result<Self, Error> {
        let conn = conn::Connection::connect(prio, addr, port, u32::MAX, opts).await?;

        return Ok(Self {
            peer_addr: conn.src(),
            peer_port: conn.sport(),
            local_addr: conn.dst(),
            local_port: conn.dport(),
            conn: Some(conn),
        });
    }

    pub fn peer_addr(&self) -> u16 {
        self.peer_addr
    }

    pub fn peer_port(&self) -> u8 {
        self.peer_port
    }

    pub fn local_addr(&self) -> u16 {
        self.local_addr
    }

    pub fn local_port(&self) -> u8 {
        self.local_port
    }

    /// Send packet on a connection.
    /// This will fail if total data is larger then 256 bytes.
    /// CRC32 costs 4 bytes and RDP header costs 5 bytes if enabled.
    pub async fn send(&mut self, data: &[u8]) -> Result<usize, Error> {
        if let Some(conn) = self.conn.as_mut() {
            let mut packet = Packet::get().ok_or(Error::AllocError)?;
            packet.append_data(data)?;

            io::send(conn, packet).await?;

            return Ok(data.len());
        } else {
            return Err(Error::ConnectionClosed);
        }
    }

    pub async fn read(&mut self, data: &mut [u8], timeout: u32) -> Result<usize, Error> {
        if let Some(conn) = self.conn.as_mut() {
            let packet = conn.read(timeout).await?;

            if packet.data_length() > data.len() {
                return Err(Error::BufferOverflow);
            }
            // get packet size
            let len = packet.data_length();
            // copy data
            data[..len].copy_from_slice(packet.data());
            return Ok(len);
        } else {
            return Err(Error::ConnectionClosed);
        }
    }

    pub fn is_active(&self) -> bool {
        if let Some(conn) = self.conn.as_ref() {
            conn.is_active()
        } else {
            false
        }
    }

    /// This must be called before CspStream is dropped
    pub async fn close(&mut self) {
        if let Some(mut conn) = self.conn.take() {
            conn.close().await
        }
    }
}

pub struct CspListener {
    sock: port::Socket,
    port: SocketPort,
}

impl CspListener {
    pub async fn bind<P: Into<SocketPort>>(port: P) -> Result<Self, Error> {
        let port = port.into();

        let mut socket = port::Socket::new();

        socket.bind(match port {
            SocketPort::Any => CSP_ANY,
            SocketPort::Port(p) => p,
        })?;

        socket.listen(10)?;

        return Ok(Self { sock: socket, port });
    }

    pub fn local_port(&self) -> SocketPort {
        return self.port;
    }

    pub async fn accept(&self, timeout: u32) -> Result<CspStream, Error> {
        let conn = self.sock.accept(timeout).await?;

        return Ok(CspStream {
            peer_addr: conn.src(),
            peer_port: conn.sport(),
            local_addr: conn.dst(),
            local_port: conn.dport(),
            conn: Some(conn),
        });
    }

    pub async fn close(&mut self) {
        self.sock.close().await
    }
}
