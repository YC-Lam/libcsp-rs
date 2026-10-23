use bitflags::bitflags;

use crate::arch::Queue;
use crate::id::CspId;
use crate::io::Socket;
use crate::rdp::*;
use crate::*;

pub(crate) const CSP_CONN_RXQUEUE_LEN: usize = 16;
const CSP_PORT_MAX_BIND: u8 = 16;
const CSP_CONN_MAX: usize = 8;

// Connection queue
static CONN_QUEUE: Queue<usize, CSP_CONN_MAX> = Queue::new();
/// Connection pool
static mut CONN_POOL: [Connection; CSP_CONN_MAX] = unsafe { core::mem::zeroed() };
/// Used by csp_conn_allocate
static mut CONN_LAST_GIVEN: u8 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnState {
    Closed,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConnType {
    Client,
    Server,
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

const CSP_RDP_CLOSED_BY_USERSPACE: u8 = 0x01;
const CSP_RDP_CLOSED_BY_PROTOCOL: u8 = 0x02;
const CSP_RDP_CLOSED_BY_TIMEOUT: u8 = 0x04;
const CSP_RDP_CLOSED_BY_ALL: u8 =
    CSP_RDP_CLOSED_BY_USERSPACE | CSP_RDP_CLOSED_BY_PROTOCOL | CSP_RDP_CLOSED_BY_TIMEOUT;

pub(crate) struct Connection {
    /// Connection type (CONN_CLIENT or CONN_SERVER)
    conn_type: ConnType,
    /// Connection state (CONN_OPEN or CONN_CLOSED)
    conn_state: ConnState,
    /// Identifier received
    idin: CspId,
    /// Identifier transmitted
    idout: CspId,
    /// When used for outgoing, use this sport
    sport_outgoing: u8,

    /// packet queue, guarantee Some after Connection::init
    rx_queue: Option<Queue<&'static mut Packet, CSP_CONN_RXQUEUE_LEN>>,

    /// incoming connections destination socket
    dest_socket: Option<&'static Socket>,
    /// Time the connection was opened
    timestamp: u32,
    /// Connection or socket options
    opts: ConnOptions,
    /// RDP state
    #[cfg(feature = "rdp")]
    rdp: RdpConnection,
}

pub(crate) fn check_timeouts() {
    #[cfg(feature = "rdp")]
    for i in 0..CSP_CONN_MAX {
        let conn = unsafe { &mut CONN_POOL[i] };
        if conn.conn_state == ConnState::Open {
            todo!() // csp_rdp_check_timeouts(conn);
        }
    }
}

pub(crate) fn init() {
    for i in 0..CSP_CONN_MAX {
        let conn = unsafe { &mut CONN_POOL[i] };

        conn.sport_outgoing = CSP_PORT_MAX_BIND + 1 + i as u8;
        conn.conn_state = ConnState::Closed;
        conn.idin.flags = Flags::empty();
        conn.rx_queue = Some(Queue::new());

        CONN_QUEUE.push_blocking(i);
    }
}

impl Connection {
    pub(crate) fn find_dport(dport: u8) -> Option<&'static mut Connection> {
        // loop over connections
        for i in 0..CSP_CONN_MAX {
            let conn = unsafe { &mut CONN_POOL[i] };

            if conn.idin.dport != dport {
                continue;
            }

            if conn.conn_state != ConnState::Open {
                continue;
            }

            if conn.conn_type != ConnType::Client {
                continue;
            }

            return Some(conn);
        }

        return None;
    }

    pub(crate) fn find_existing(id: &CspId) -> Option<&'static mut Connection> {
        // loop over connections
        for i in 0..CSP_CONN_MAX {
            let conn = unsafe { &mut CONN_POOL[i] };

            if conn.conn_state != ConnState::Open {
                continue;
            }

            // This search looks verbose, Instead of a big if statement, it is written out as
            // conditions. This has been done for clarity. The least likely check is put first
            // for runtime speed improvement.
            // Also this is written using explicit fields, not bitmasks, in order to improve
            // portability and dual use between different header formats.

            // Outgoing connections are uniquely defined by the source port,
            // So only the incoming destination port must match. This means
            // that responses to broadcast addresses, are accepted as long
            // as the incoming port matches the unique source port of the
            // connection
            if conn.conn_type == ConnType::Client {
                // Connection must match dport
                if conn.idin.dport != id.dport {
                    continue;
                }

            // Incoming connections are uniquely defined by the source and
            // destination port, as well as the source node. Incoming
            // connections can never come from a broadcast address
            } else {
                // Connection must match dport
                if conn.idin.dport != id.dport {
                    continue;
                }

                // Connection must match sport
                if conn.idin.sport != id.sport {
                    continue;
                }

                // Connection must match source
                if conn.idin.src != id.src {
                    continue;
                }
            }
        }

        return None;
    }

    pub(crate) async fn allocate(conn_type: ConnType) -> &'static mut Connection {
        // wait for next free connection
        let offset = CONN_QUEUE.pop().await;
        // get connection
        let conn = unsafe { &mut CONN_POOL[offset] };

        conn.timestamp = 0;
        conn.conn_type = conn_type;
        conn.idin.flags = Flags::empty();
        conn.idout.flags = Flags::empty();

        return conn;
    }

    pub(crate) async fn new(
        idin: CspId,
        idout: CspId,
        conn_type: ConnType,
    ) -> &'static mut Connection {
        // allocate connection
        let conn = Self::allocate(conn_type).await;

        // copy id
        conn.idin = idin;
        conn.idout = idout;

        // get timestamp
        conn.timestamp = arch::get_ms();
        // ensure connection queue is empty
        conn.flush_rx_queue();

        return conn;
    }

    #[allow(unused_variables)]
    pub(crate) async fn connect(
        prio: Priority,
        dest: u16,
        dport: u8,
        timeout: u32,
        mut opts: ConnOptions,
    ) -> Result<&'static mut Connection, Error> {
        // opts |= csp_conf.conn_dfl_so;

        // Use 0 as incoming id (this disables the input filter on destination node)
        // This means that for this outgoing connection, we accept the answer coming to whatever address
        // the outgoing interface has. CSP does not support "source address" on outgoing connections
        // so the outgoing source address will be automatically applied after outgoing routing
        // selects which interface the packet will leave from

        let mut incoming_id = CspId {
            prio,
            flags: Flags::empty(),
            src: dest,
            dst: 0,
            dport: 0,
            sport: dport,
        };

        let mut outgoing_id = CspId {
            prio,
            flags: Flags::empty(),
            src: 0,
            dst: dest,
            dport: dport,
            sport: 0,
        };

        if opts.contains(ConnOptions::CSP_O_NOCRC32) {
            opts.remove(ConnOptions::CSP_O_CRC32);
        }

        #[cfg(feature = "rdp")]
        if opts.contains(ConnOptions::CSP_O_RDP) {
            incoming_id.flags |= Flags::CSP_FRDP;
            outgoing_id.flags |= Flags::CSP_FRDP;
        }

        #[cfg(feature = "hmac")]
        if opts.contains(ConnOptions::CSP_O_HMAC) {
            incoming_id.flags |= Flags::CSP_FHMAC;
            outgoing_id.flags |= Flags::CSP_FHMAC;
        }

        if opts.contains(ConnOptions::CSP_O_CRC32) {
            incoming_id.flags |= Flags::CSP_FCRC32;
            outgoing_id.flags |= Flags::CSP_FCRC32;
        }

        let conn = Self::new(incoming_id, outgoing_id, ConnType::Client).await;

        // Outgoing connections always use pre-defined source port
        conn.idout.sport = conn.sport_outgoing;
        conn.idin.dport = conn.sport_outgoing;
        conn.dest_socket = None;

        // set connection options
        conn.opts = opts;

        // Call Transport Layer connect
        #[cfg(feature = "rdp")]
        if outgoing_id.flags.contains(Flags::CSP_FRDP) {
            // If the transport layer has failed to connect
            // deallocate connection structure again and return NULL
            todo!()

            // if csp_rdp_connect(conn){ conn.close() }
        }

        return Ok(conn);
    }

    pub(crate) async fn enqueue_package(&self, packet: &'static mut Packet) {
        self.rx_queue.as_ref().unwrap().push(packet).await;
    }

    pub(crate) fn flush_rx_queue(&self) {
        // flush packet queue
        while let Some(package) = self.rx_queue.as_ref().unwrap().try_pop() {
            // free packet
            package.free();
        }
    }

    pub(crate) fn close(&mut self) {
        self.conn_close(CSP_RDP_CLOSED_BY_USERSPACE);
    }

    #[allow(unused_variables)]
    pub(crate) fn conn_close(&mut self, closed_by: u8) {
        if self.conn_state == ConnState::Closed {
            return;
        }

        #[cfg(feature = "rdp")]
        if self.idin.flags.contains(Flags::CSP_FRDP) || self.idout.flags.contains(Flags::CSP_FRDP) {
            todo!(); // csp_rdp_close(conn, closed_by)
        }

        self.flush_rx_queue();

        #[cfg(feature = "rdp")]
        if self.idin.flags.contains(Flags::CSP_FRDP) {
            todo!(); // csp_rdp_queue_flush(conn)
        }

        self.conn_state = ConnState::Closed;
    }

    pub(crate) fn set_idout_prio(&mut self, prio: Priority){
        self.idout.prio = prio
    }

    pub(crate) fn state(&self) -> ConnState {
        self.conn_state
    }

    pub(crate) fn idout(&self) -> &CspId {
        &self.idout
    }

    pub(crate) fn dport(&self) -> u8 {
        return self.idin.dport;
    }

    pub(crate) fn sport(&self) -> u8 {
        return self.idin.sport;
    }

    pub(crate) fn dst(&self) -> u16 {
        return self.idin.dst;
    }

    pub(crate) fn src(&self) -> u16 {
        return self.idin.src;
    }

    pub(crate) fn flags(&self) -> Flags {
        return self.idin.flags;
    }

    pub(crate) fn is_active(&self) -> bool {
        // This is for sure an RDP connection
        #[cfg(feature = "rdp")]
        if self.idin.flags.contains(Flags::CSP_FRDP) || self.idout.flags.contains(Flags::CSP_FRDP) {
            todo!() // csp_rdp_conn_is_active(conn)
        }

        return true;
    }

    pub async fn read(&self, timeout: u32) -> Result<&'static mut Packet, Error> {
        let mut timeout = timeout;

        #[cfg(feature = "rdp")]
        if self.idin.flags.contains(Flags::CSP_FRDP) {
            timeout = timeout.min(self.rdp.conn_timeout);
        }

        if timeout == 0 {
            match self.rx_queue.as_ref().unwrap().try_pop() {
                Some(p) => return Ok(p),
                None => return Err(Error::Timeout),
            }
        }

        let packet = match self
            .rx_queue
            .as_ref()
            .unwrap()
            .pop_with_timeout(timeout)
            .await
        {
            Some(v) => v,
            None => return Err(Error::Timeout),
        };

        // Packet read could trigger ACK transmission
        #[cfg(feature = "rdp")]
        if self.idin.flags.contains(Flags::CSP_FRDP) && self.rdp.delayed_acks > 0 {
            todo!() // rdp_check_ack(conn)
        }

        return Ok(packet);
    }
}
