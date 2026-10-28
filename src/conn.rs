use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use bitflags::bitflags;

use crate::arch::{LazyLock, Queue};
use crate::id::CspId;
#[cfg(feature = "rdp")]
use crate::rdp::{CSP_RDP_CLOSED_BY_USERSPACE, RdpConnection};
#[cfg(not(feature = "rdp"))]
const CSP_RDP_CLOSED_BY_USERSPACE: u8 = 0;
use crate::*;

pub(crate) const CSP_CONN_RXQUEUE_LEN: usize = 16;
const CSP_PORT_MAX_BIND: u8 = 16;
const CSP_CONN_MAX: usize = 8;

/// Connection pool
static mut CONN_POOL: LazyLock<[ConnectionBuf; CSP_CONN_MAX]> =
    LazyLock::new(|| core::array::from_fn(ConnectionBuf::const_new));

/// index of the last given connection
static CONN_LAST_GIVEN: AtomicUsize = AtomicUsize::new(0);

/// checks RDP connection timeouts
pub(crate) async fn check_timeouts() {
    // only check when rdp is enabled
    #[cfg(feature = "rdp")]
    for i in 0..CSP_CONN_MAX {
        // unsafe required to access connection pool
        let buf = unsafe { &mut CONN_POOL[i] };
        // check if open
        if buf.conn_state.is_open() {
            // create wrapper
            let mut conn = Connection { inner: buf };
            // check timeout
            crate::rdp::check_timeouts(&mut conn).await;
            // prevent drop
            core::mem::forget(conn);
        }
    }
}

#[derive(Debug)]
pub(crate) struct ConnState(AtomicU8);

impl ConnState {
    const CLOSED: u8 = 0;
    const OPEN: u8 = 1;
    const NEED_DROP: u8 = 2;
    const DROPPING: u8 = 3;

    const fn closed() -> Self {
        Self(AtomicU8::new(Self::CLOSED))
    }
    fn try_open(&self) -> bool {
        // only exchange when state is "closed" and not "need drop" or "open"
        self.0
            .compare_exchange(
                Self::CLOSED,
                Self::OPEN,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }
    fn set_closed(&self) {
        self.0.store(Self::CLOSED, Ordering::Release);
    }
    fn is_open(&self) -> bool {
        self.0.load(Ordering::Acquire) == Self::OPEN
    }
    fn is_closed(&self) -> bool {
        self.0.load(Ordering::Acquire) != Self::OPEN
    }
    /// user has dropped the connection, but it has not been closed
    fn set_need_drop(&self) {
        self.0.store(Self::NEED_DROP, Ordering::Release);
    }
    fn is_dropping(&self) -> bool {
        self.0.load(Ordering::Acquire) == Self::DROPPING
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConnectionID(usize);

impl ConnectionID {
    #[cfg(test)]
    pub(crate) const fn from_index(index: usize) -> Self {
        Self(index)
    }
}

pub(crate) struct ConnectionBuf {
    /// used for alloc/dealloc
    id: ConnectionID,
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
    rx_queue: Queue<Option<Packet>, CSP_CONN_RXQUEUE_LEN>,

    /// incoming connections destination socket delivered
    socket_delivered: AtomicBool,

    /// Time the connection was opened
    timestamp: u32,
    /// Connection or socket options
    opts: ConnOptions,
    /// RDP state
    #[cfg(feature = "rdp")]
    rdp: RdpConnection,
}

impl ConnectionBuf {
    const fn const_new(index: usize) -> Self {
        Self {
            id: ConnectionID(index),
            conn_type: ConnType::Client,
            conn_state: ConnState::closed(),
            idin: CspId {
                prio: Priority::Critical,
                flags: Flags::empty(),
                src: 0,
                dst: 0,
                dport: 0,
                sport: 0,
            },
            idout: CspId {
                prio: Priority::Critical,
                flags: Flags::empty(),
                src: 0,
                dst: 0,
                dport: 0,
                sport: 0,
            },
            sport_outgoing: CSP_PORT_MAX_BIND + 1 + index as u8,
            rx_queue: Queue::new(),
            socket_delivered: AtomicBool::new(false),
            timestamp: 0,
            opts: ConnOptions::empty(),
            #[cfg(feature = "rdp")]
            rdp: RdpConnection::const_new(),
        }
    }

    pub(crate) async fn allocate(conn_type: ConnType) -> Option<&'static mut ConnectionBuf> {
        let mut i = CONN_LAST_GIVEN.load(Ordering::Relaxed);

        // loop over connections
        for _ in 0..CSP_CONN_MAX {
            i = (i + 1) % CSP_CONN_MAX;
            // get connection buffer
            let mut conn = unsafe { &mut CONN_POOL[i] };

            // connection is closed but not cleaned up
            if conn
                .conn_state
                .0
                .compare_exchange(
                    ConnState::NEED_DROP,
                    ConnState::DROPPING,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_ok()
            {
                let mut c = Connection { inner: conn };
                c.close().await;

                conn = c.inner;
            }

            // try opening connection
            if conn.conn_state.try_open() {
                conn.timestamp = 0;
                conn.conn_type = conn_type;
                conn.idin.flags = Flags::empty();
                conn.idout.flags = Flags::empty();

                CONN_LAST_GIVEN.store(i, Ordering::Relaxed);

                return Some(conn);
            }
        }

        return None;
    }
}

pub(crate) struct Connection {
    inner: &'static mut ConnectionBuf,
}

impl Connection {
    pub(crate) fn find_existing(id: &CspId) -> Option<Connection> {
        // loop over connections
        for i in 0..CSP_CONN_MAX {
            let conn = unsafe { &mut CONN_POOL[i] };

            if conn.conn_state.is_closed() {
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

            return Some(Connection { inner: conn });
        }

        return None;
    }

    pub(crate) async fn new(idin: CspId, idout: CspId, conn_type: ConnType) -> Option<Connection> {
        // allocate connection
        if let Some(inner) = ConnectionBuf::allocate(conn_type).await {
            // wrap connection
            let conn = Self { inner };

            // copy id
            conn.inner.idin = idin;
            conn.inner.idout = idout;

            // get timestamp
            conn.inner.timestamp = arch::get_ms();
            // ensure connection queue is empty
            conn.flush_rx_queue().await;

            // not linked to socket by default
            conn.set_socket_deliverd(true);

            // reset queue
            conn.inner.rx_queue = Queue::new();

            return Some(conn);
        }

        return None;
    }

    #[allow(unused_variables)]
    pub(crate) async fn connect(
        prio: Priority,
        dest: u16,
        dport: u8,
        timeout: u32,
        mut opts: ConnOptions,
    ) -> Result<Connection, Error> {
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
            sport: dport,
            dst: 0,
            dport: 0,
        };

        let mut outgoing_id = CspId {
            prio,
            flags: Flags::empty(),
            src: 0,
            sport: 0,
            dst: dest,
            dport: dport,
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

        let mut conn = match Self::new(incoming_id, outgoing_id, ConnType::Client).await {
            Some(c) => c,
            None => return Err(Error::AllocError),
        };

        // Outgoing connections always use pre-defined source port
        conn.inner.idout.sport = conn.inner.sport_outgoing;
        conn.inner.idin.dport = conn.inner.sport_outgoing;
        // does not have to be delivered to socket since client
        conn.inner.socket_delivered.store(true, Ordering::Release);

        // set connection options
        conn.inner.opts = opts;

        // Call Transport Layer connect
        #[cfg(feature = "rdp")]
        if outgoing_id.flags.contains(Flags::CSP_FRDP) {
            // If the transport layer has failed to connect
            // deallocate connection structure again and return NULL
            if let Err(e) = crate::rdp::connect(&mut conn).await {
                conn.close().await;

                return Err(e);
            }
        }

        return Ok(conn);
    }

    pub(crate) async fn enqueue_package(&self, packet: Option<Packet>) {
        let _ = self.inner.rx_queue.push(packet).await;
    }

    pub(crate) async fn flush_rx_queue(&self) {
        // flush packet queue
        while let Some(Some(package)) = self.inner.rx_queue.try_pop() {
            // free packet
            drop(package);
        }
    }

    /// this is a work around for public API non-async Drop
    pub(crate) fn close_nonblocking(&self) {
        // avoid double close
        if self.inner.conn_state.is_closed() {
            return;
        }
        // close the queue for sending
        self.inner.rx_queue.close();

        self.inner.conn_state.set_need_drop();
    }

    pub(crate) async fn close(&mut self) {
        self.conn_close(CSP_RDP_CLOSED_BY_USERSPACE).await;
    }

    #[allow(unused_variables)]
    pub(crate) async fn conn_close(&mut self, closed_by: u8) {
        // avoid double close
        if self.inner.conn_state.is_closed() && !self.inner.conn_state.is_dropping() {
            return;
        }
        // close the queue for sending
        self.inner.rx_queue.close();

        #[cfg(feature = "rdp")]
        if self.inner.idin.flags.contains(Flags::CSP_FRDP)
            || self.inner.idout.flags.contains(Flags::CSP_FRDP)
        {
            let _ = crate::rdp::close(self, closed_by).await;
        }

        self.flush_rx_queue().await;

        #[cfg(feature = "rdp")]
        if self.inner.idin.flags.contains(Flags::CSP_FRDP) {
            crate::rdp_queue::flush(Some(self.connection_id())).await;
        }

        self.inner.conn_state.set_closed();
    }

    pub(crate) fn rx_free_capacity(&self) -> usize {
        self.inner.rx_queue.free_capacity()
    }

    pub(crate) fn connection_id(&self) -> ConnectionID {
        return self.inner.id;
    }

    #[cfg(feature = "rdp")]
    pub(crate) fn rdp_connection(&self) -> &RdpConnection {
        &self.inner.rdp
    }

    #[cfg(feature = "rdp")]
    pub(crate) fn rdp_connection_mut(&mut self) -> &mut RdpConnection {
        &mut self.inner.rdp
    }

    pub(crate) fn set_idout_prio(&mut self, prio: Priority) {
        self.inner.idout.prio = prio
    }

    pub(crate) fn set_fragmented(&mut self) {
        self.inner.idout.flags |= Flags::CSP_FFRAG;
    }

    pub(crate) fn idout(&self) -> &CspId {
        &self.inner.idout
    }

    pub(crate) fn dport(&self) -> u8 {
        return self.inner.idin.dport;
    }

    pub(crate) fn sport(&self) -> u8 {
        return self.inner.idin.sport;
    }

    pub(crate) fn dst(&self) -> u16 {
        return self.inner.idin.dst;
    }

    pub(crate) fn src(&self) -> u16 {
        return self.inner.idin.src;
    }

    pub(crate) fn options(&self) -> ConnOptions {
        self.inner.opts
    }

    pub(crate) fn set_options(&mut self, opt: ConnOptions) {
        self.inner.opts = opt;
    }

    pub(crate) fn timestamp(&self) -> u32 {
        self.inner.timestamp
    }

    pub(crate) fn set_timestamp(&mut self, t: u32) {
        self.inner.timestamp = t;
    }

    pub(crate) fn socket_delivered(&self) -> bool {
        return self.inner.socket_delivered.load(Ordering::Acquire);
    }

    pub(crate) fn set_socket_deliverd(&self, v: bool) {
        self.inner.socket_delivered.store(v, Ordering::Release);
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.inner.conn_state.is_closed()
    }

    pub(crate) fn is_active(&self) -> bool {
        // This is for sure an RDP connection
        #[cfg(feature = "rdp")]
        if self.inner.idin.flags.contains(Flags::CSP_FRDP)
            || self.inner.idout.flags.contains(Flags::CSP_FRDP)
        {
            return crate::rdp::conn_is_active(self);
        }

        return true;
    }

    pub async fn read(&mut self, timeout: u32) -> Result<Packet, Error> {
        let mut timeout = timeout;

        #[cfg(feature = "rdp")]
        if self.inner.idin.flags.contains(Flags::CSP_FRDP) {
            timeout = timeout.min(self.inner.rdp.conn_timeout);
        }

        if timeout == 0 {
            match self.inner.rx_queue.try_pop() {
                Some(Some(p)) => return Ok(p),
                Some(None) => return Err(Error::ConnectionClosed),
                None => return Err(Error::Timeout),
            }
        }

        let packet = match self.inner.rx_queue.pop_with_timeout(timeout).await {
            Ok(Some(v)) => v,
            Ok(None) => return Err(Error::ConnectionClosed),
            Err(Error::Timeout) => return Err(Error::Timeout),
            Err(_) => return Err(Error::ConnectionClosed),
        };

        // Packet read could trigger ACK transmission
        #[cfg(feature = "rdp")]
        if self.inner.idin.flags.contains(Flags::CSP_FRDP) && self.inner.rdp.delayed_acks > 0 {
            crate::rdp::check_ack(self).await?;
        }

        return Ok(packet);
    }
}
