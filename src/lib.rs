#![no_std]

#[cfg(any(test, feature = "std"))]
extern crate std;

#[cfg(feature = "hmac")]
pub mod crypto;
pub mod drivers;
pub mod interfaces;
pub mod promisc;
#[cfg(feature = "rtable")]
pub mod rtable;
pub mod sfp;

mod arch;
// mod cmp;
mod bridge;
mod buffer;
mod conn;
mod crc32;
mod dedup;
mod id;
mod io;
mod port;
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

/// Initialize CSP core state. Loopback registration is automatic and does not depend on this call.
pub async fn init() {
    let _ = interfaces::INTERFACES.get_or_init();
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
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
    Sfp,
    Mtu,
}

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

/// Remote endpoint for a received connectionless CSP packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpPeer {
    pub addr: u16,
    pub port: u8,
}

/// Connectionless CSP socket for sending and receiving datagrams.
pub struct UdpSocket {
    sock: port::Socket,
    local_port: u8,
}

impl UdpSocket {
    /// Bind a connectionless socket to a local CSP port.
    pub async fn bind<P: Into<SocketPort>>(port: P) -> Result<Self, Error> {
        let port = match port.into() {
            SocketPort::Any => return Err(Error::InvalidOperation),
            SocketPort::Port(port) => port,
        };
        let mut sock = port::Socket::new_connectionless();
        sock.bind(port)?;
        Ok(Self {
            sock,
            local_port: port,
        })
    }

    /// Get the local CSP port.
    pub fn local_port(&self) -> u8 {
        self.local_port
    }

    /// Send a datagram to a CSP address and port.
    pub async fn send_to(
        &self,
        prio: Priority,
        addr: u16,
        dst_port: u8,
        opts: ConnOptions,
        data: &[u8],
    ) -> Result<usize, Error> {
        let mut packet = Packet::get().ok_or(Error::AllocError)?;
        packet.append_data(data)?;
        io::send_to(prio, addr, dst_port, self.local_port, opts, packet).await?;
        Ok(data.len())
    }

    /// Receive a datagram, copying its payload into `data` and returning its sender.
    pub async fn recv_from(
        &self,
        data: &mut [u8],
        timeout: u32,
    ) -> Result<(usize, UdpPeer), Error> {
        let packet = self.sock.recv_packet(timeout).await?;
        let len = packet.data_length();
        if len > data.len() {
            return Err(Error::BufferOverflow);
        }
        data[..len].copy_from_slice(packet.data());
        let peer = UdpPeer {
            addr: packet.id.src,
            port: packet.id.sport,
        };
        Ok((len, peer))
    }

    /// Close the socket and release its bound CSP port.
    pub async fn close(&mut self) {
        self.sock.close().await
    }
}

/// A CSP connection that sends and receives data using SFP fragmentation.
pub struct SfpStream {
    stream: CspStream,
}

impl SfpStream {
    /// Connect to a peer and create an SFP stream.
    pub async fn connect(
        prio: Priority,
        addr: u16,
        port: u8,
        opts: ConnOptions,
    ) -> Result<Self, Error> {
        Ok(Self {
            stream: CspStream::connect(prio, addr, port, opts).await?,
        })
    }

    /// Get the largest data fragment that fits in one packet for this connection.
    pub fn max_mtu(&self) -> Result<u32, Error> {
        let conn = self.stream.conn.as_ref().ok_or(Error::ConnectionClosed)?;
        Ok(sfp::opts_max_mtu(conn.options()))
    }

    pub fn peer_addr(&self) -> u16 {
        self.stream.peer_addr()
    }

    pub fn peer_port(&self) -> u8 {
        self.stream.peer_port()
    }

    pub fn local_addr(&self) -> u16 {
        self.stream.local_addr()
    }

    pub fn local_port(&self) -> u8 {
        self.stream.local_port()
    }

    /// Send `totalsize` bytes in fragments of at most `mtu` bytes.
    ///
    /// The callback fills each requested fragment and receives its source offset.
    pub async fn send<F>(&mut self, totalsize: u32, mtu: u32, mut read: F) -> Result<(), Error>
    where
        F: FnMut(&mut [u8], u32) -> Result<(), Error>,
    {
        let conn = self.stream.conn.as_mut().ok_or(Error::ConnectionClosed)?;
        sfp::send(conn, totalsize, mtu, &mut read).await
    }

    /// Receive one transfer, passing each fragment, its offset, and total size to `write`.
    pub async fn receive<F>(&mut self, timeout: u32, mut write: F) -> Result<(), Error>
    where
        F: FnMut(&[u8], u32, u32) -> Result<(), Error>,
    {
        let conn = self.stream.conn.as_mut().ok_or(Error::ConnectionClosed)?;
        sfp::receive(conn, timeout, &mut write).await
    }

    pub fn is_active(&self) -> bool {
        self.stream.is_active()
    }

    pub async fn close(&mut self) {
        self.stream.close().await
    }
}

/// A listener that accepts connections as SFP streams.
pub struct SfpListener {
    listener: CspListener,
}

impl SfpListener {
    /// Bind an SFP listener to a local CSP port.
    pub async fn bind<P: Into<SocketPort>>(port: P) -> Result<Self, Error> {
        Ok(Self {
            listener: CspListener::bind(port).await?,
        })
    }

    pub fn local_port(&self) -> SocketPort {
        self.listener.local_port()
    }

    /// Accept an incoming connection, waiting up to `timeout` milliseconds.
    pub async fn accept(&self, timeout: u32) -> Result<SfpStream, Error> {
        Ok(SfpStream {
            stream: self.listener.accept(timeout).await?,
        })
    }

    pub async fn close(&mut self) {
        self.listener.close().await
    }
}
