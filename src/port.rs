
use bitflags::bitflags;

use crate::{CSP_ANY, Error, Packet};
use crate::arch::Queue;
use crate::conn::{
    CSP_CONN_RXQUEUE_LEN,
    Connection,
};
use crate::id::get_max_port;

const CSP_PORT_MAX_BIND: usize = get_max_port();

/* We rely on the .bss section to clear this, so there is no csp_port_init() function */
static mut PORTS:[Port; CSP_PORT_MAX_BIND + 2] = unsafe{core::mem::zeroed()};

#[repr(u8)]
pub(crate) enum Port{
	Closed = 0,
    Open(*mut Socket),
    OpenCallback(fn(&Packet))
}

impl Port{
    pub fn get_callback(port: u8) -> Option<fn(&Packet)>{
        if port as usize > CSP_PORT_MAX_BIND{
            return None
        }

        match unsafe{&PORTS[port as usize]}{
            // Check if port is open callback
            Port::OpenCallback(f) => Some(*f),
            // If it's open socket, then return no callback
            Port::Open(_) => None,
            // Otherwise check if we have a match all callback
            Port::Closed => match unsafe{&PORTS[CSP_PORT_MAX_BIND + 1]}{
                Port::OpenCallback(f) => Some(*f),
                _ => None
            }
        }
    }

    pub fn get_socket(port: u8) -> Option<*mut Socket>{
        if port as usize > CSP_PORT_MAX_BIND{
            return None
        }

        match unsafe{&PORTS[port as usize]}{
            Port::Open(s) => Some(*s),
            // Check if port is open callback
            Port::OpenCallback(_) => None,
            // Otherwise check if we have a match all callback
            Port::Closed => match unsafe{&PORTS[CSP_PORT_MAX_BIND + 1]}{
                Port::Open(s) => Some(*s),
                _ => None
            }
        }
    }

    pub fn is_open(&self) -> bool{
        match self{
            Self::Closed => false,
            _ => true
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

enum ConnOrPacket{
    Connection(&'static mut Connection),
    Packet(&'static mut Packet)
}

pub(crate) struct Socket {
    rx_queue: Queue<ConnOrPacket, CSP_CONN_RXQUEUE_LEN>,
    pub(crate) opts: SocketOptions,
}

impl Socket {
    pub const fn new() -> Self {
        Self {
            rx_queue: Queue::new(),
            opts: SocketOptions::empty(),
        }
    }

    pub async fn accept(&self, timeout: u32) -> Result<&'static mut Connection, Error> {
        match self.rx_queue.pop_with_timeout(timeout).await {
            Some(ConnOrPacket::Connection(conn)) => Ok(conn),
            Some(ConnOrPacket::Packet(p)) => {
                p.free();
                Err(Error::InvalidOperation)
            }
            None => Err(Error::Timeout),
        }
    }

    ///  Read data from a connection-less server socket.
    pub async fn recv_packet(&self, timeout: u32) -> Result<&'static Packet, Error> {
        //
        if !self.opts.contains(SocketOptions::CSP_SO_CONN_LESS) {
            return Err(Error::InvalidOperation);
        }

        let next = match self.rx_queue.pop_with_timeout(timeout).await {
            Some(ptr) => ptr,
            None => return Err(Error::Timeout),
        };
        
        match next{
            ConnOrPacket::Connection(c) => {
                c.close();
                return Err(Error::InvalidOperation)
            },
            ConnOrPacket::Packet(p) => Ok(p)
        }
    }

    fn is_conn_less(&self) -> bool{
        self.opts.contains(SocketOptions::CSP_SO_CONN_LESS)
    }

    pub fn listen(&self, _backlog: usize) -> Result<(), Error>{
        return Ok(())
    }

    pub fn bind(&mut self, port: u8) -> Result<(), Error>{
        let mut port = port as usize;

        if port == CSP_ANY as usize{
            port = CSP_PORT_MAX_BIND + 1;
        } else if port > CSP_PORT_MAX_BIND{
            return Err(Error::InvalidOperation)
        }

        if unsafe{PORTS[port].is_open()}{
            return Err(Error::PortBusy)
        }

        if self.is_conn_less(){
            // nothing to do
        }

        unsafe{
            PORTS[port] = Port::Open(self as *mut Socket);
        }

        return Ok(())
    }
}

impl Drop for Socket{
    #[allow(static_mut_refs)]
    fn drop(&mut self) {
        for port in unsafe{&mut PORTS}{
            match port{
                Port::Open(s) => {
                    if core::ptr::eq(*s, self){
                        *port = Port::Closed
                    }
                },
                _ => {}
            }
        }

        while let Some(next) = self.rx_queue.try_pop(){
            match next{
                ConnOrPacket::Connection(c) => c.close(),
                ConnOrPacket::Packet(p) => p.free(),
            }
        }
    }
}