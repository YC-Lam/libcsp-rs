use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bitflags::bitflags;

use crate::arch::Queue;
use crate::conn::{CSP_CONN_RXQUEUE_LEN, Connection};
use crate::id::get_max_port;
use crate::{CSP_ANY, Error, Packet};

const CSP_PORT_MAX_BIND: usize = get_max_port();

/* We rely on the .bss section to clear this, so there is no csp_port_init() function */
static mut PORTS: [Port; CSP_PORT_MAX_BIND + 2] = unsafe { core::mem::zeroed() };
// Port entries point here so registrations remain valid when public handles move.
static mut SOCKETS: [SocketState; CSP_PORT_MAX_BIND + 2] =
    [const { SocketState::new() }; CSP_PORT_MAX_BIND + 2];

fn socket_state(index: usize) -> &'static SocketState {
    unsafe {
        &*core::ptr::addr_of!(SOCKETS)
            .cast::<SocketState>()
            .add(index)
    }
}

/// get callback handler for an incoming port
pub(crate) fn get_callback(port: u8) -> Option<fn(Packet)> {
    // check if valid port
    if port as usize > CSP_PORT_MAX_BIND {
        return None;
    }

    match unsafe { &PORTS[port as usize] } {
        // Check if port is open callback
        Port::OpenCallback(f) => Some(*f),
        // If it's open socket, then return no callback
        Port::Open(_) => None,
        // Otherwise check if we have a match all callback
        Port::Closed => match unsafe { &PORTS[CSP_PORT_MAX_BIND + 1] } {
            Port::OpenCallback(f) => Some(*f),
            _ => None,
        },
    }
}

/// get socket for an incoming port
pub(crate) fn get_socket(port: u8) -> Option<&'static SocketState> {
    // check if valid port
    if port as usize > CSP_PORT_MAX_BIND {
        return None;
    }

    match unsafe { &PORTS[port as usize] } {
        Port::Open(index) => Some(socket_state(*index)),
        // Check if port is open callback
        Port::OpenCallback(_) => None,
        // Otherwise check if we have a match all callback
        Port::Closed => match unsafe { &PORTS[CSP_PORT_MAX_BIND + 1] } {
            Port::Open(index) => Some(socket_state(*index)),
            _ => None,
        },
    }
}

#[repr(u8)]
#[allow(unused)]
pub(crate) enum Port {
    Closed = 0,
    Open(usize),
    OpenCallback(fn(Packet)),
}

impl Port {
    pub fn is_open(&self) -> bool {
        match self {
            Self::Closed => false,
            _ => true,
        }
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

pub(crate) enum ConnOrPacket {
    Connection(Connection),
    Packet(Packet),
}

pub(crate) struct SocketState {
    pub(crate) rx_queue: Queue<ConnOrPacket, CSP_CONN_RXQUEUE_LEN>,
    pub(crate) ready: AtomicBool,
    opts: AtomicU32,
}

impl SocketState {
    pub const fn new() -> Self {
        Self {
            rx_queue: Queue::new(),
            ready: AtomicBool::new(false),
            opts: AtomicU32::new(0),
        }
    }

    pub(crate) fn options(&self) -> SocketOptions {
        SocketOptions::from_bits_retain(self.opts.load(Ordering::Acquire))
    }

    pub(crate) fn is_conn_less(&self) -> bool {
        self.options().contains(SocketOptions::CSP_SO_CONN_LESS)
    }

    pub(crate) fn is_ready_to_recieve(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
}

pub(crate) struct Socket {
    opts: SocketOptions,
    slot: Option<usize>,
}

impl Socket {
    pub const fn new() -> Self {
        Self {
            opts: SocketOptions::empty(),
            slot: None,
        }
    }

    pub const fn new_connectionless() -> Self {
        Self {
            opts: SocketOptions::CSP_SO_CONN_LESS,
            slot: None,
        }
    }

    fn state(&self) -> Result<&'static SocketState, Error> {
        self.slot.map(socket_state).ok_or(Error::ConnectionClosed)
    }

    pub async fn accept(&self, timeout: u32) -> Result<Connection, Error> {
        match self.state()?.rx_queue.pop_with_timeout(timeout).await {
            Ok(ConnOrPacket::Connection(conn)) => Ok(conn),
            Ok(ConnOrPacket::Packet(p)) => {
                drop(p);
                Err(Error::InvalidOperation)
            }
            Err(_) => Err(Error::Timeout),
        }
    }

    ///  Read data from a connection-less server socket.
    pub async fn recv_packet(&self, timeout: u32) -> Result<Packet, Error> {
        //
        let state = self.state()?;
        if !state.is_conn_less() {
            return Err(Error::InvalidOperation);
        }

        let next = match state.rx_queue.pop_with_timeout(timeout).await {
            Ok(p) => p,
            Err(_) => return Err(Error::Timeout),
        };

        match next {
            ConnOrPacket::Connection(mut c) => {
                c.close().await;
                return Err(Error::InvalidOperation);
            }
            ConnOrPacket::Packet(p) => Ok(p),
        }
    }

    pub fn is_conn_less(&self) -> bool {
        self.opts.contains(SocketOptions::CSP_SO_CONN_LESS)
    }

    pub fn listen(&self, _backlog: usize) -> Result<(), Error> {
        self.state()?.ready.store(true, Ordering::Release);
        return Ok(());
    }

    pub fn bind(&mut self, port: u8) -> Result<(), Error> {
        let mut port = port as usize;

        if port == CSP_ANY as usize {
            port = CSP_PORT_MAX_BIND + 1;
        } else if port > CSP_PORT_MAX_BIND {
            return Err(Error::InvalidOperation);
        }

        if unsafe { PORTS[port].is_open() } {
            return Err(Error::PortBusy);
        }

        let state = socket_state(port);
        state.opts.store(self.opts.bits(), Ordering::Release);
        state.ready.store(self.is_conn_less(), Ordering::Release);
        unsafe {
            PORTS[port] = Port::Open(port);
        }
        self.slot = Some(port);

        return Ok(());
    }

    pub async fn close(&mut self) {
        let Some(slot) = self.slot.take() else {
            return;
        };
        unsafe {
            if matches!(PORTS[slot], Port::Open(index) if index == slot) {
                PORTS[slot] = Port::Closed;
            }
        }

        let state = socket_state(slot);
        state.ready.store(false, Ordering::Release);
        state.opts.store(0, Ordering::Release);
        while let Some(next) = state.rx_queue.try_pop() {
            match next {
                ConnOrPacket::Connection(mut c) => c.close().await,
                ConnOrPacket::Packet(p) => drop(p),
            }
        }
    }

}

#[cfg(test)]
mod tests {
    use super::{CSP_PORT_MAX_BIND, Port, Socket, SocketOptions, get_socket};
    use crate::{CSP_ANY, Error};
    use serial_test::serial;
    use std::vec;

    #[tokio::test]
    #[serial]
    async fn bind_listen_close_and_rebind_socket() {
        let port = CSP_PORT_MAX_BIND as u8;
        let mut socket = Socket::new_connectionless();
        assert!(socket.is_conn_less());
        socket.bind(port).unwrap();

        let state = get_socket(port).unwrap();
        assert!(state.is_conn_less());
        assert!(state.is_ready_to_recieve());
        assert!(state.options().contains(SocketOptions::CSP_SO_CONN_LESS));

        let mut duplicate = Socket::new();
        assert_eq!(duplicate.bind(port), Err(Error::PortBusy));

        socket.close().await;
        assert!(get_socket(port).is_none());
        duplicate.bind(port).unwrap();
        duplicate.close().await;
    }

    #[tokio::test]
    #[serial]
    async fn connection_oriented_socket_requires_listen() {
        let port = (CSP_PORT_MAX_BIND - 1) as u8;
        let mut socket = Socket::new();
        socket.bind(port).unwrap();

        let state = get_socket(port).unwrap();
        assert!(!state.is_conn_less());
        assert!(!state.is_ready_to_recieve());
        socket.listen(1).unwrap();
        assert!(state.is_ready_to_recieve());

        socket.close().await;
    }

    #[test]
    fn wildcard_port_is_not_a_valid_receive_port() {
        assert!(get_socket(CSP_ANY).is_none());
    }

    #[test]
    fn closed_port_variant_is_not_open() {
        assert!(!Port::Closed.is_open());
    }
}
