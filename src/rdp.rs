//! This is a implementation of the seq/ack handling taken from the Reliable Datagram Protocol (RDP)
//! For more information read RFC 908/1151. The implementation has been extended to include support for
//! delayed acknowledgments, to improve performance over half-duplex links.
use core::sync::atomic::{AtomicU8, Ordering};

use bitflags::bitflags;

use crate::arch::Semaphore;
use crate::conn::{Connection, ConnectionID};
use crate::port::{ConnOrPacket, Socket};
use crate::rdp_queue;
use crate::{Error, Packet, Priority};

const CSP_RDP_HEADER_SIZE: usize = 5;
const CSP_USE_RDP_FAST_CLOSE: bool = true;

pub(crate) const CSP_RDP_CLOSED_BY_USERSPACE: u8 = 0x01;
const CSP_RDP_CLOSED_BY_PROTOCOL: u8 = 0x02;
const CSP_RDP_CLOSED_BY_TIMEOUT: u8 = 0x04;
const CSP_RDP_CLOSED_BY_ALL: u8 =
    CSP_RDP_CLOSED_BY_USERSPACE | CSP_RDP_CLOSED_BY_PROTOCOL | CSP_RDP_CLOSED_BY_TIMEOUT;

static CSP_RDP_WINDOW_SIZE: u32 = 4;
static CSP_RDP_CONN_TIMEOUT: u32 = 10000;
static CSP_RDP_PACKET_TIMEOUT: u32 = 1000;
static CSP_RDP_DELAYED_ACKS: u32 = 1;
static CSP_RDP_ACK_TIMEOUT: u32 = 1000 / 4;
static CSP_RDP_ACK_DELAY_COUNT: u32 = 4 / 2;
static CSP_RDP_INCR: AtomicU8 = AtomicU8::new(0);

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct RdpFlags: u8{
        const RDP_SYN = 0x08;
        const RDP_ACK = 0x04;
        const RDP_EAK = 0x02;
        const RDP_RST = 0x01;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RdpState {
    Closed,
    SynSent,
    SynRecv,
    Open,
    CloseWait,
}

#[repr(packed)]
struct RdpHeader {
    flags: RdpFlags,
    seq_nr: u16,
    ack_nr: u16,
}

const _: () = {
    assert!(size_of::<RdpHeader>() == CSP_RDP_HEADER_SIZE);
};

#[repr(C)]
pub(crate) struct RdpConnection {
    /// Connection state
    state: RdpState,
    /// Tracks 'who' have closed the RDP connection
    closed_by: u8,
    /// The sequence number of the next segment that is to be sent
    snd_nxt: u16,
    /// The sequence number of the oldest unacknowledged segment
    snd_una: u16,
    /// The initial send sequence number
    snd_iss: u16,
    /// The sequence number of the last segment received correctly and in sequence
    rcv_cur: u16,
    /// The initial receive sequence number
    rcv_irs: u16,
    /// The last sequence number acknowledged by the receiver
    rcv_lsa: u16,
    window_size: u32,
    pub conn_timeout: u32,
    packet_timeout: u32,
    pub delayed_acks: u32,
    ack_timeout: u32,
    ack_delay_count: u32,
    ack_timestamp: u32,
    tx_wait: Semaphore<4>,
}

impl RdpConnection {
    pub const fn const_new() -> RdpConnection {
        RdpConnection {
            state: RdpState::Closed,
            closed_by: 0,
            snd_nxt: 0,
            snd_una: 0,
            snd_iss: 0,
            rcv_cur: 0,
            rcv_irs: 0,
            rcv_lsa: 0,
            window_size: 0,
            conn_timeout: CSP_RDP_CONN_TIMEOUT,
            packet_timeout: CSP_RDP_PACKET_TIMEOUT,
            delayed_acks: 0,
            ack_timeout: 0,
            ack_delay_count: 0,
            ack_timestamp: 0,
            tx_wait: Semaphore::new(),
        }
    }
}
/**
 * RDP Headers:
 * The following functions are helper functions that handles the extra RDP
 * information that needs to be appended to all data packets.
 */
impl RdpHeader {
    #[inline]
    fn add(packet: &mut Packet) -> Result<&mut RdpHeader, Error> {
        // add empty header
        // error if buffer size does not fit
        packet.append_data(&[0; size_of::<RdpHeader>()])?;

        // return reference
        return Ok(Self::from_packet(packet));
    }

    #[inline]
    fn remove(packet: &mut Packet) {
        packet.remove_data(size_of::<RdpHeader>());
    }

    #[inline]
    fn from_packet(packet: &Packet) -> &mut RdpHeader {
        unsafe {
            let ptr = packet
                .data()
                .as_ptr()
                .add(packet.data_length() - size_of::<RdpHeader>());
            return (ptr as *mut RdpHeader).as_mut_unchecked();
        }
    }
}

/* Functions for comparing wrapping sequence numbers and timestamps */

/// Return 1 if seq is between start and end (both inclusive)
#[inline]
fn seq_between(seq: u16, start: u16, end: u16) -> bool {
    end.wrapping_sub(start) >= seq.wrapping_sub(start)
}
/// Return 1 if seq is before cmp
#[inline]
fn seq_before(seq: u16, cmp: u16) -> bool {
    (seq.wrapping_sub(cmp) as i16) < 0
}
/// Return 1 if seq is after cmp
#[inline]
fn seq_after(seq: u16, cmp: u16) -> bool {
    seq_before(cmp, seq)
}
/// Return 1 if time is before cmp
#[inline]
fn time_before(time: u32, cmp: u32) -> bool {
    (time.wrapping_sub(cmp) as i32) < 0
}
/// Return 1 if time is after cmp
#[inline]
fn time_after(time: u32, cmp: u32) -> bool {
    time_before(cmp, time)
}

/**
 * CONTROL MESSAGES
 * The following function is used to send empty messages,
 * with ACK, SYN or RST flag.
 */
async fn send_cmp(
    conn: &mut Connection,
    packet: Option<Packet>,
    flags: RdpFlags,
    seq_nr: u16,
    ack_nr: u16,
) -> Result<(), Error> {
    // get or allocate packet
    let mut packet = match packet {
        Some(p) => p,
        None => Packet::get().ok_or(Error::AllocError)?,
    };

    if flags.contains(RdpFlags::RDP_ACK) {
        conn.rdp_connection_mut().rcv_lsa = ack_nr;
    }

    /* Every outgoing message contains the last valid ACK number. So we always set last ack timestamp
     * We do this early to minimize race condition between read() call and router task csp_rdp_new_packet() */
    conn.rdp_connection_mut().ack_timestamp = crate::arch::get_ms();

    /* Add RDP header */
    let header = match RdpHeader::add(&mut packet) {
        Err(e) => {
            return Err(e);
        }
        Ok(h) => h,
    };

    header.seq_nr = seq_nr.to_be();
    header.ack_nr = ack_nr.to_be();

    /* Add a bit of ephemeral data to avoid CMP's to be deduplicated */
    //header.flags = flags;
    header.flags |= RdpFlags::from_bits_retain(CSP_RDP_INCR.fetch_add(1, Ordering::Acquire) << 4);
    header.flags |= flags;

    /* Send copy to tx_queue, before sending packet to IF */
    if flags.contains(RdpFlags::RDP_SYN) {
        let Some(mut rdp_packet) = packet.buffer_clone() else {
            return Err(Error::AllocError);
        };
        rdp_packet.timestamp_tx = crate::arch::get_ms();
        rdp_queue::tx_add(conn.connection_id(), rdp_packet).await;
    }

    /* Send control messages with high priority */
    let idout = *conn.idout();

    conn.set_idout_prio(match idout.prio {
        Priority::Critical => Priority::Critical,
        _ => Priority::High,
    });

    /*csp_rdp_protocol("RDP %p: Send CMP S %u: syn %u, ack %u, eack %u, rst %u, seq_nr %5u, ack_nr %5u, packet_len %u (%u)\n",
                     (void *)conn, conn.rdp_connection().state,
                     ((header.flags & RDP_SYN) != 0), ((header.flags & RDP_ACK) != 0),
                     ((header.flags & RDP_EAK) != 0), ((header.flags & RDP_RST) != 0),
                     be16toh(header.seq_nr), be16toh(header.ack_nr),
                     packet.length, (unsigned int)(packet.length - sizeof(rdp_header_t)));
    */

    /* Send packet to IF */
    return crate::io::send_direct(&idout, packet, None).await;
}

/**
 * SYN Packet
 * The following function sends a SYN packet
 */
async fn send_syn(conn: &mut Connection) -> Result<(), Error> {
    /* Allocate message */
    let mut packet = Packet::get().ok_or(Error::AllocError)?;

    /* Generate contents */
    packet.append_data(&CSP_RDP_WINDOW_SIZE.to_be_bytes())?;
    packet.append_data(&CSP_RDP_CONN_TIMEOUT.to_be_bytes())?;
    packet.append_data(&CSP_RDP_PACKET_TIMEOUT.to_be_bytes())?;
    packet.append_data(&CSP_RDP_DELAYED_ACKS.to_be_bytes())?;
    packet.append_data(&CSP_RDP_ACK_TIMEOUT.to_be_bytes())?;
    packet.append_data(&CSP_RDP_ACK_DELAY_COUNT.to_be_bytes())?;

    let seq_nr = conn.rdp_connection().snd_iss;

    return send_cmp(conn, Some(packet), RdpFlags::RDP_SYN, seq_nr, 0).await;
}

#[inline]
async fn receive_data(conn: &mut Connection, mut packet: Packet) {
    /* Remove RDP header before passing to userspace */
    RdpHeader::remove(&mut packet);

    /* Enqueue data */
    conn.enqueue_package(Some(packet)).await;
}

#[inline]
async fn rx_queue_flush(conn: &mut Connection) {
    // Loop through RX queue
    'front: loop {
        let next_seq_nr = conn.rdp_connection().rcv_cur + 1;

        let filter = |packet: &Packet| {
            // reference header
            let header = RdpHeader::from_packet(&packet);
            // If the matching packet was found:
            header.seq_nr == next_seq_nr as u16
        };

        if let Some(packet) = rdp_queue::rx_try_get_filtered(conn.connection_id(), filter).await {
            // csp_rdp_protocol("RDP %p: Deliver seq %u\n", (void *)conn, header.seq_nr);
            receive_data(conn, packet).await;
            conn.rdp_connection_mut().rcv_cur += 1;

            // Loop from first element again
            continue 'front;
        }

        break;
    }
}

#[inline]
async fn seq_in_rx_queue(conn_id: ConnectionID, seq_nr: u16) -> bool {
    let filter = |packet: &Packet| {
        // reference header
        let header = RdpHeader::from_packet(&packet);
        // check sequence number
        header.seq_nr == seq_nr
    };

    // Loop through RX queue
    if let Some(packet) = rdp_queue::rx_try_get_filtered(conn_id, filter).await {
        // add back to queue
        rdp_queue::rx_add(conn_id, packet).await;

        return true;
    }

    return false;
}

async fn rx_queue_add(conn_id: ConnectionID, packet: Packet, seq_nr: u16) -> Result<(), Error> {
    if seq_in_rx_queue(conn_id, seq_nr).await {
        // csp_rdp_protocol("RDP %p: Already exists in RX queue %u\n", (void *)conn, seq_nr);
        return Err(Error::InvalidOperation);
    }
    // csp_rdp_protocol("RDP %p: Add to RX queue %u\n", (void *) conn, seq_nr);
    rdp_queue::rx_add(conn_id, packet).await;
    return Ok(());
}

#[inline]
fn should_ack(conn: &mut Connection) -> bool {
    // If delayed ACKs are not used, always ACK
    if conn.rdp_connection().delayed_acks == 0 {
        return true;
    }

    // ACK if time since last ACK is greater than ACK timeout
    let time_now = crate::arch::get_ms();
    if time_after(
        time_now,
        conn.rdp_connection().ack_timestamp + conn.rdp_connection().ack_timeout,
    ) {
        return true;
    }

    // ACK if number of unacknowledged packets is greater than delay count
    if seq_after(
        conn.rdp_connection().rcv_cur,
        conn.rdp_connection().rcv_lsa + conn.rdp_connection().ack_delay_count as u16,
    ) {
        return true;
    }

    return false;
}

pub(crate) async fn check_ack(conn: &mut Connection) -> Result<(), Error> {
    /* Check RX queue for spare capacity */
    if conn.rx_free_capacity() <= conn.rdp_connection().window_size as usize {
        return Ok(());
    }

    /* If more space available, only send after ack timeout or immediately if delay_acks is zero */
    if should_ack(conn) {
        let seq_nr = conn.rdp_connection().snd_nxt;
        let ack_nr = conn.rdp_connection().rcv_cur;

        send_cmp(conn, None, RdpFlags::RDP_ACK, seq_nr, ack_nr).await?;
    }

    return Ok(());
}

#[inline]
fn is_conn_ready_for_tx(conn: &mut Connection) -> bool {
    // Check Tx window (messages waiting for acks)
    if seq_after(
        conn.rdp_connection().snd_nxt,
        conn.rdp_connection().snd_una + conn.rdp_connection().window_size as u16 - 1,
    ) {
        return false;
    }
    return true;
}

/**
 * This function must be called with regular intervals for the
 * RDP protocol to work as expected. This takes care of closing
 * stale connections and retransmitting traffic. A good place to
 * call this function is from the CSP router task.
 */
pub(crate) async fn check_timeouts(conn: &mut Connection) {
    let time_now = crate::arch::get_ms();

    /*
     * CONNECTION TIMEOUT:
     * Check that connection has not timed out inside the network stack
     */
    if !conn.socket_delivered() {
        // get deadline
        let deadline = conn.timestamp() + conn.rdp_connection().conn_timeout;

        if time_after(time_now, deadline) {
            //csp_rdp_error("RDP %p: Found a lost connection (now: %" PRIu32 ", ts: %" PRIu32 ", to: %" PRIu32 "), closing\n",
            //			  (void *)conn, time_now, conn.timestamp, conn.rdp_connection().conn_timeout);
            conn.conn_close(
                CSP_RDP_CLOSED_BY_USERSPACE
                    | CSP_RDP_CLOSED_BY_PROTOCOL
                    | CSP_RDP_CLOSED_BY_TIMEOUT,
            )
            .await;
            return;
        }
    }

    /*
     * CLOSE-WAIT TIMEOUT:
     * After waiting a while in CLOSE-WAIT, the connection should be closed.
     */
    if conn.rdp_connection().state == RdpState::CloseWait {
        // get deadline
        let deadline = conn.timestamp() + conn.rdp_connection().conn_timeout;
        if time_after(time_now, deadline) {
            conn.conn_close(CSP_RDP_CLOSED_BY_PROTOCOL | CSP_RDP_CLOSED_BY_TIMEOUT)
                .await;
            return;
        }
    }

    /*
     * MESSAGE TIMEOUT:
     * Check each outgoing message for TX timeout
     */
    let packet_seq = conn.rdp_connection().snd_una;
    let packet_timeout = conn.rdp_connection().packet_timeout;

    let filter = |packet: &Packet| {
        let header = RdpHeader::from_packet(&packet);
        seq_before(u16::from_be(header.seq_nr), packet_seq)
            || time_after(time_now, packet.timestamp_tx + packet_timeout)
    };

    while let Some(mut packet) = rdp_queue::tx_try_get_filtered(conn.connection_id(), filter).await
    {
        /* Get header */
        let header = RdpHeader::from_packet(&packet);

        /* If acked, do not retransmit */
        if seq_before(u16::from_be(header.seq_nr), conn.rdp_connection().snd_una) {
            //csp_rdp_protocol("RDP %p: TX Element Free, time %" PRIu32 ", seq %u, una %u\n",
            //				 (void *)conn, packet.timestamp_tx, be16toh(header.seq_nr), conn.rdp_connection().snd_una);
            drop(packet);
            continue;
        }

        /* Check timestamp and retransmit if needed */
        if time_after(
            time_now,
            packet.timestamp_tx + conn.rdp_connection().packet_timeout,
        ) {
            let Some(new_packet) = packet.buffer_clone() else {
                rdp_queue::tx_add(conn.connection_id(), packet).await;
                continue;
            };
            //csp_rdp_protocol("RDP %p: TX Element timed out, retransmitting seq %u\n",
            //                    (void *)conn, be16toh(header.seq_nr));

            /* Update to latest outgoing ACK */
            header.ack_nr = conn.rdp_connection().rcv_cur.to_be();

            /* Every outgoing message contains the last valid ACK number. So we always set last ack timestamp */
            conn.rdp_connection_mut().ack_timestamp = crate::arch::get_ms();
            /* Send copy to tx_queue */
            packet.timestamp_tx = crate::arch::get_ms();
            let _ = crate::io::send_direct(conn.idout(), new_packet, None).await;
        }

        /* Requeue the TX element */
        rdp_queue::tx_add(conn.connection_id(), packet).await;
    }

    if conn.rdp_connection().state == RdpState::Open {
        // get deadline
        let deadline = conn.timestamp() + conn.rdp_connection().conn_timeout;
        // close connection if timed out
        if time_after(time_now, deadline) {
            conn.conn_close(CSP_RDP_CLOSED_BY_PROTOCOL | CSP_RDP_CLOSED_BY_TIMEOUT)
                .await;
            conn.rdp_connection().tx_wait.post();
            return;
        }

        /* Check if we have unacknowledged segments */
        if conn.rdp_connection().delayed_acks > 0 {
            let _ = check_ack(conn).await;
        }

        /* Wake user task if additional Tx can be done */
        if is_conn_ready_for_tx(conn) {
            //csp_rdp_protocol("RDP %p: Wake Tx task (check timeouts)\n", (void *)conn);
            conn.rdp_connection().tx_wait.post();
        }
    }

    rx_queue_flush(conn).await;
}

fn rand_r(seed: &mut u32) -> u32 {
    *seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    (*seed / 65_536) % 32_768
}

pub(crate) async fn new_packet(
    conn: &mut Connection,
    dest_sock: Option<&Socket>,
    packet: Packet,
) -> bool {
    let mut close_connection = false;

    /* Get RX header and convert to host byte-order */
    let rx_header = RdpHeader::from_packet(&packet);
    rx_header.ack_nr = u16::from_be(rx_header.ack_nr);
    rx_header.seq_nr = u16::from_be(rx_header.seq_nr);

    let mut closed_by = CSP_RDP_CLOSED_BY_PROTOCOL;

    //csp_rdp_protocol(
    //	"RDP %p: Received in S %u: syn %u, ack %u, eack %u, "
    //	"rst %u, seq_nr %5u, ack_nr %5u, packet_len %u (%u)\n",
    //	(void *)conn, conn.rdp_connection().state,
    //	((rx_header.flags & RDP_SYN) != 0), ((rx_header.flags & RDP_ACK) != 0),
    //	((rx_header.flags & RDP_EAK) != 0), ((rx_header.flags & RDP_RST) != 0),
    //	rx_header.seq_nr, rx_header.ack_nr,
    //	packet.length, (unsigned int)(packet.length - sizeof(rdp_header_t)));

    let discard_close = async move |conn: &mut Connection,
                                    closed_by: u8,
                                    _packet: Packet,
                                    close_connection: bool| {
        //
        if conn.socket_delivered() {
            conn.conn_close(closed_by).await;
            conn.enqueue_package(None).await;
        } else {
            conn.conn_close(closed_by | CSP_RDP_CLOSED_BY_USERSPACE)
                .await;
        }

        return close_connection;
    };

    let discard_open = async |packet: Packet, close_connection: bool| {
        drop(packet);
        return close_connection;
    };

    /* If a RESET was received. */
    if rx_header.flags.contains(RdpFlags::RDP_RST) {
        if rx_header.flags.contains(RdpFlags::RDP_ACK) {
            /* Store current ack'ed sequence number */
            conn.rdp_connection_mut().snd_una = rx_header.ack_nr + 1;
        }

        if conn.rdp_connection().state == RdpState::Closed {
            // csp_rdp_protocol("RDP %p: RST received in CLOSED - ignored\n", (void *)conn);
            close_connection = !conn.socket_delivered();

            return discard_open(packet, close_connection).await;
        }

        if conn.rdp_connection().state == RdpState::CloseWait {
            //csp_rdp_protocol("RDP %p: RST received in CLOSE_WAIT, ack: %d - closing\n",
            //				 (void *)conn, (rx_header.flags & RDP_ACK));
            if rx_header.flags.contains(RdpFlags::RDP_ACK) && CSP_USE_RDP_FAST_CLOSE {
                // skip timeout - the other end has acknowledged the RST
                closed_by |= CSP_RDP_CLOSED_BY_TIMEOUT;
            }
            return discard_close(conn, closed_by, packet, close_connection).await;
        }

        if rx_header.seq_nr == conn.rdp_connection().rcv_cur + 1 {
            // csp_rdp_protocol("RDP %p: Received RST in sequence, no more data incoming, reply with RST\n", (void *)conn);
            conn.rdp_connection_mut().state = RdpState::CloseWait;
            conn.set_timestamp(crate::arch::get_ms());

            let seq_nr = conn.rdp_connection().snd_nxt;
            let ack_nr = conn.rdp_connection().rcv_cur;

            let _ = send_cmp(
                conn,
                None,
                RdpFlags::RDP_ACK | RdpFlags::RDP_RST,
                seq_nr,
                ack_nr,
            )
            .await;

            if CSP_USE_RDP_FAST_CLOSE {
                closed_by |= CSP_RDP_CLOSED_BY_TIMEOUT;
            }

            return discard_close(conn, closed_by, packet, close_connection).await;
        }

        // csp_rdp_protocol("RDP %p: RST out of sequence, keep connection open\n", (void *)conn);
        return discard_open(packet, close_connection).await;
    }

    /* The BIG FAT switch (state-machine) */
    match conn.rdp_connection().state {
        /*
         * STATE == CLOSED
         */
        RdpState::Closed => {
            /* Clear ephemeral data added by send_cmp().
            RDP flags are located in the lower 4 bits. */
            let rx_header_flags = rx_header.flags & RdpFlags::all();

            /* No SYN flag set while in closed. Inform by sending back RST */
            if rx_header_flags != RdpFlags::RDP_SYN {
                // csp_rdp_protocol("RDP %p: Not SYN received in CLOSED state. Discarding packet\n", (void *)conn);
                let seq_nr = conn.rdp_connection().snd_nxt;
                let ack_nr = conn.rdp_connection().rcv_cur;
                let _ = send_cmp(conn, None, RdpFlags::RDP_RST, seq_nr, ack_nr).await;

                return discard_close(conn, closed_by, packet, close_connection).await;
            }

            // csp_rdp_protocol("RDP %p: SYN-Received\n", (void *)conn);

            /* Setup TX seq. */
            let mut seed = crate::arch::get_ms();
            conn.rdp_connection_mut().snd_iss = rand_r(&mut seed) as u16;
            conn.rdp_connection_mut().snd_nxt = conn.rdp_connection().snd_iss + 1;
            conn.rdp_connection_mut().snd_una = conn.rdp_connection().snd_iss;

            /* Store RX seq. */
            conn.rdp_connection_mut().rcv_cur = rx_header.seq_nr;
            conn.rdp_connection_mut().rcv_irs = rx_header.seq_nr;
            conn.rdp_connection_mut().rcv_lsa = rx_header.seq_nr;

            /* Store RDP options */
            conn.rdp_connection_mut().window_size = u32::from_be_bytes([
                packet.data()[0],
                packet.data()[1],
                packet.data()[2],
                packet.data()[3],
            ]);
            conn.rdp_connection_mut().conn_timeout = u32::from_be_bytes([
                packet.data()[4],
                packet.data()[5],
                packet.data()[6],
                packet.data()[7],
            ]);
            conn.rdp_connection_mut().packet_timeout = u32::from_be_bytes([
                packet.data()[8],
                packet.data()[9],
                packet.data()[10],
                packet.data()[11],
            ]);
            conn.rdp_connection_mut().delayed_acks = u32::from_be_bytes([
                packet.data()[12],
                packet.data()[13],
                packet.data()[14],
                packet.data()[15],
            ]);
            conn.rdp_connection_mut().ack_timeout = u32::from_be_bytes([
                packet.data()[16],
                packet.data()[17],
                packet.data()[18],
                packet.data()[19],
            ]);
            conn.rdp_connection_mut().ack_delay_count = u32::from_be_bytes([
                packet.data()[20],
                packet.data()[21],
                packet.data()[22],
                packet.data()[23],
            ]);

            //csp_rdp_protocol("RDP %p: window size %" PRIu32 ", conn timeout %" PRIu32 ", packet timeout %" PRIu32 ", delayed acks: %" PRIu32 ", ack timeout %" PRIu32 ", ack each %" PRIu32 " packet\n",
            //				 (void *)conn, conn.rdp_connection().window_size, conn.rdp_connection().conn_timeout, conn.rdp_connection().packet_timeout,
            //				 conn.rdp_connection().delayed_acks, conn.rdp_connection().ack_timeout, conn.rdp_connection().ack_delay_count);

            /* Connection accepted */
            conn.rdp_connection_mut().state = RdpState::SynRecv;

            let seq_nr = conn.rdp_connection().snd_iss;
            let ack_nr = conn.rdp_connection().rcv_irs;

            /* Send SYN/ACK */
            let _ = send_cmp(
                conn,
                None,
                RdpFlags::RDP_ACK | RdpFlags::RDP_SYN,
                seq_nr,
                ack_nr,
            )
            .await;

            return discard_open(packet, close_connection).await;
        }

        /*
         * STATE == SYN-SENT
         */
        RdpState::SynSent => {
            /* First check SYN/ACK */
            if rx_header.flags.contains(RdpFlags::RDP_SYN)
                && rx_header.flags.contains(RdpFlags::RDP_ACK)
            {
                conn.rdp_connection_mut().rcv_cur = rx_header.seq_nr;
                conn.rdp_connection_mut().rcv_irs = rx_header.seq_nr;
                conn.rdp_connection_mut().rcv_lsa = rx_header.seq_nr - 1;
                conn.rdp_connection_mut().snd_una = rx_header.ack_nr + 1;
                conn.rdp_connection_mut().ack_timestamp = crate::arch::get_ms();
                conn.rdp_connection_mut().state = RdpState::Open;

                // csp_rdp_protocol("RDP %p: NP: Connection OPEN\n", (void *)conn);

                let seq_nr = conn.rdp_connection().snd_nxt;
                let ack_nr = conn.rdp_connection().rcv_cur;

                /* Send ACK */
                let _ = send_cmp(conn, None, RdpFlags::RDP_ACK, seq_nr, ack_nr).await;

                /* Wake TX task */
                //csp_rdp_protocol("RDP %p: Wake Tx task (ack)\n", (void *)conn);
                conn.rdp_connection().tx_wait.post();

                return discard_open(packet, close_connection).await;
            }

            /* If there was no SYN in the reply, our SYN message hit an already open connection
             * This is handled by sending a RST.
             * Normally this would be followed up by a new connection attempt, however
             * we don't have a method for signaling this to the user space.
             */
            if rx_header.flags.contains(RdpFlags::RDP_ACK) {
                // csp_rdp_error("RDP %p: Half-open connection found, send RST and wake Tx task\n", conn);

                let seq_nr = conn.rdp_connection().snd_nxt;
                let ack_nr = conn.rdp_connection().rcv_cur;

                let _ = send_cmp(conn, None, RdpFlags::RDP_RST, seq_nr, ack_nr).await;

                conn.rdp_connection().tx_wait.post();

                return discard_open(packet, close_connection).await;
            }

            /* Otherwise we have an invalid command, such as a SYN reply to a SYN command,
             * indicating simultaneous connections, which is not possible in the way CSP
             * reserves some ports for server and some for clients.
             */
            //csp_rdp_error("RDP %p: Invalid reply to SYN request\n", conn);

            return discard_close(conn, closed_by, packet, close_connection).await;
        }

        /*
         * STATE == OPEN
         */
        RdpState::SynRecv | RdpState::Open => {
            /* SYN or !ACK is invalid */
            if rx_header.flags.contains(RdpFlags::RDP_SYN)
                || !rx_header.flags.contains(RdpFlags::RDP_ACK)
            {
                if rx_header.seq_nr != conn.rdp_connection().rcv_irs {
                    //csp_rdp_error("RDP %p: Invalid SYN or no ACK, resetting!\n", (void *)conn);

                    return discard_close(conn, closed_by, packet, close_connection).await;
                } else {
                    // csp_rdp_protocol("RDP %p: Ignoring duplicate SYN packet!\n", (void *)conn);
                    return discard_open(packet, close_connection).await;
                }
            }

            /* Check sequence number */
            if !seq_between(
                rx_header.seq_nr,
                conn.rdp_connection().rcv_cur + 1,
                conn.rdp_connection().rcv_cur + (conn.rdp_connection().window_size * 2) as u16,
            ) {
                //csp_rdp_protocol("RDP %p: Invalid sequence number! %u not between %u and %" PRIu32"\n",
                //				 (void *)conn, rx_header.seq_nr, conn.rdp_connection().rcv_cur + 1U, conn.rdp_connection().rcv_cur + (conn.rdp_connection().window_size * 2U));

                let seq_nr = conn.rdp_connection().snd_iss;
                let ack_nr = conn.rdp_connection().rcv_irs;

                /* If duplicate SYN received, send another SYN/ACK */
                if conn.rdp_connection().state == RdpState::SynRecv {
                    let _ = send_cmp(
                        conn,
                        None,
                        RdpFlags::RDP_ACK | RdpFlags::RDP_SYN,
                        seq_nr,
                        ack_nr,
                    )
                    .await;
                }

                return discard_open(packet, close_connection).await;
            }

            /* Check ACK number */
            if !seq_between(
                rx_header.ack_nr,
                conn.rdp_connection().snd_una - 1 - (conn.rdp_connection().window_size * 2) as u16,
                conn.rdp_connection().snd_nxt - 1,
            ) {
                //csp_rdp_error("RDP %p: Invalid ACK number! %u not between %" PRIu32 " and %u\n",
                //			  (void *)conn, rx_header.ack_nr, conn.rdp_connection().snd_una - 1 - (conn.rdp_connection().window_size * 2), conn.rdp_connection().snd_nxt - 1);

                return discard_open(packet, close_connection).await;
            }

            /* Check SYN_RCVD ACK */
            if conn.rdp_connection().state == RdpState::SynRecv {
                if rx_header.ack_nr != conn.rdp_connection().snd_iss {
                    //csp_rdp_error("RDP %p: SYN-RCVD: Wrong ACK number\n", (void *)conn);

                    return discard_close(conn, closed_by, packet, close_connection).await;
                }
                //csp_rdp_protocol("RDP %p: NC: Connection OPEN\n", (void *)conn);
                conn.rdp_connection_mut().state = RdpState::Open;

                /* If a socket is set, this message is the first in a new connection
                 * so the connection must be queued to the socket. */
                if !conn.socket_delivered() {
                    if let Some(sock) = dest_sock {
                        /* Try queueing */
                        sock.rx_queue
                            .push(ConnOrPacket::Connection(unsafe { core::ptr::read(conn) }))
                            .await
                            .unwrap();
                    }

                    /* Ensure that this connection will not be posted to this socket again
                     * and remember that the connection handle has been passed to userspace
                     * by setting the socket = NULL */
                    conn.set_socket_deliverd(true);
                }
            }

            if conn.socket_delivered() {
                /* User space has taken control of the connection, so RDP needs to "monitor"
                 * the connection by timestamping each time a packet is received in OPEN state */
                conn.set_timestamp(crate::arch::get_ms());
            }

            /* Store current ack'ed sequence number */
            conn.rdp_connection_mut().snd_una = rx_header.ack_nr + 1;

            /* We have an EACK */
            if rx_header.flags.contains(RdpFlags::RDP_EAK) {
                // csp_rdp_protocol("RDP %p: Got EACK\n", (void *)conn);
                return discard_open(packet, close_connection).await;
            }

            /* If no data, return here */
            if packet.data_length() <= size_of::<RdpHeader>() {
                return discard_open(packet, close_connection).await;
            }

            /* If message is not in sequence, store packet for next flush */
            if rx_header.seq_nr != (conn.rdp_connection().rcv_cur + 1) {
                let seq_nr = rx_header.seq_nr;
                if rx_queue_add(conn.connection_id(), packet, seq_nr)
                    .await
                    .is_err()
                {
                    let _ = check_ack(conn).await;
                }
                return close_connection;
            }

            /* Store sequence number before stripping RDP header */
            let seq_nr = rx_header.seq_nr;

            /* Receive data */
            receive_data(conn, packet).await;

            /* Update last received packet */
            conn.rdp_connection_mut().rcv_cur = seq_nr;

            /* Only ACK the message if there is room for a full window in the RX buffer.
             * Unacknowledged segments are ACKed by csp_rdp_check_timeouts when the buffer is
             * no longer full. */
            let _ = check_ack(conn).await;

            /* Flush RX queue */
            rx_queue_flush(conn).await;

            return close_connection;
        }

        RdpState::CloseWait => {
            /* Ignore SYN or !ACK */
            if rx_header.flags.contains(RdpFlags::RDP_SYN)
                || !rx_header.flags.contains(RdpFlags::RDP_ACK)
            {
                //csp_rdp_protocol("RDP %p: Invalid SYN or no ACK in CLOSE-WAIT\n", (void *)conn);
                return discard_open(packet, close_connection).await;
            }

            /* Check ACK number */
            if !seq_between(
                rx_header.ack_nr,
                conn.rdp_connection().snd_una - 1 - (conn.rdp_connection().window_size * 2) as u16,
                conn.rdp_connection().snd_nxt - 1,
            ) {
                //csp_rdp_error("RDP %p: Invalid ACK number! %u not between %" PRIu32 " and %u\n",
                //			  (void *)conn, rx_header.ack_nr, conn.rdp_connection().snd_una - 1 - (conn.rdp_connection().window_size * 2), conn.rdp_connection().snd_nxt - 1);
                return discard_open(packet, close_connection).await;
            }

            /* Store current ack'ed sequence number */
            conn.rdp_connection_mut().snd_una = rx_header.ack_nr + 1;

            let seq_nr = conn.rdp_connection().snd_nxt;
            let ack_nr = conn.rdp_connection().rcv_cur;

            /* Send back a reset */
            let _ = send_cmp(
                conn,
                None,
                RdpFlags::RDP_ACK | RdpFlags::RDP_RST,
                seq_nr,
                ack_nr,
            )
            .await;

            return discard_open(packet, close_connection).await;
        }
    }
}

pub(crate) async fn connect(conn: &mut Connection) -> Result<(), Error> {
    let mut retry = 1;

    conn.rdp_connection_mut().window_size = CSP_RDP_WINDOW_SIZE;
    conn.rdp_connection_mut().conn_timeout = CSP_RDP_CONN_TIMEOUT;
    conn.rdp_connection_mut().packet_timeout = CSP_RDP_PACKET_TIMEOUT;
    conn.rdp_connection_mut().delayed_acks = CSP_RDP_DELAYED_ACKS;
    conn.rdp_connection_mut().ack_timeout = CSP_RDP_ACK_TIMEOUT;
    conn.rdp_connection_mut().ack_delay_count = CSP_RDP_ACK_DELAY_COUNT;
    conn.rdp_connection_mut().ack_timestamp = crate::arch::get_ms();

    loop {
        // csp_rdp_protocol("RDP %p: Active connect, conn state %u\n", (void *)conn, conn.rdp_connection().state);

        if conn.rdp_connection().state == RdpState::Open {
            // csp_rdp_error("RDP %p: Connection already open\n", (void *)conn);
            return Err(Error::InvalidOperation);
        }

        /* Randomize ISS */
        let mut seed = crate::arch::get_ms();
        conn.rdp_connection_mut().snd_iss = rand_r(&mut seed) as u16;
        conn.rdp_connection_mut().snd_nxt = conn.rdp_connection().snd_iss + 1;
        conn.rdp_connection_mut().snd_una = conn.rdp_connection().snd_iss;

        // csp_rdp_protocol("RDP %p: AC: Sending SYN\n", (void *)conn);

        /* Ensure semaphore is busy, so router task can release it */
        let _ = conn.rdp_connection().tx_wait.wait(0).await;

        /* Send SYN message */
        conn.rdp_connection_mut().state = RdpState::SynSent;

        if let Err(_) = send_syn(conn).await {
            break;
        }

        /* Wait for router task to release semaphore */
        // csp_rdp_protocol("RDP %p: AC: Waiting for SYN/ACK reply...\n", (void *)conn);

        let timeout = conn.rdp_connection().conn_timeout;
        let result = conn.rdp_connection().tx_wait.wait(timeout).await;

        if result.is_ok() {
            if conn.rdp_connection().state == RdpState::Open {
                // csp_rdp_protocol("RDP %p: AC: Connection OPEN\n", (void *)conn);
                return Ok(());
            }
            if conn.rdp_connection().state == RdpState::SynSent {
                if retry > 0 {
                    // csp_rdp_error("RDP %p: Half-open connection detected, RST sent, now retrying\n", (void *)conn);
                    rdp_queue::flush(Some(conn.connection_id())).await;

                    retry = 0;
                    continue;
                }
                // csp_rdp_error("RDP %p: Connection stayed half-open, even after RST and retry!\n", (void *)conn);
                break;
            }
        }
    }

    // csp_rdp_protocol("RDP %p: AC: Connection Failed\n", (void *)conn);
    return close_internal(conn, CSP_RDP_CLOSED_BY_PROTOCOL, false).await;
}

pub(crate) async fn send(conn: &mut Connection, packet: &mut Packet) -> Result<(), Error> {
    if conn.rdp_connection().state != RdpState::Open {
        // csp_rdp_error("RDP %p: ERROR cannot send, connection not open (%d)\n", (void *)conn, conn.rdp_connection().state);
        return Err(Error::ConnectionClosed);
    }

    /* Wait here for RDP to become ready or the connection to be closed */
    loop {
        if conn.rdp_connection().state == RdpState::CloseWait
            || conn.rdp_connection().state == RdpState::Closed
        {
            // csp_rdp_error("RDP %p: ERROR cannot send, connection closed by peer or timeout\n", (void *)conn);
            return Err(Error::ConnectionClosed);
        }
        if is_conn_ready_for_tx(conn) {
            break;
        }

        // csp_rdp_protocol("RDP %p: Waiting for window update before sending seq %u\n", (void *)conn, conn.rdp_connection().snd_nxt);

        let timeout = conn.rdp_connection().conn_timeout;
        let _ = conn.rdp_connection().tx_wait.wait(timeout).await;
    }

    /* Add RDP header */
    let tx_header = match RdpHeader::add(packet) {
        Ok(h) => h,
        Err(e) => {
            // csp_rdp_error("RDP %p: No space for RDP header (send)\n", (void *)conn);
            return Err(e);
        }
    };

    tx_header.ack_nr = conn.rdp_connection().rcv_cur.to_be();
    tx_header.seq_nr = conn.rdp_connection().snd_nxt.to_be();
    tx_header.flags |= RdpFlags::RDP_ACK;

    /* Send copy to tx_queue */
    let mut rdp_packet = packet.buffer_clone().ok_or(Error::AllocError)?;

    rdp_packet.timestamp_tx = crate::arch::get_ms();
    rdp_queue::tx_add(conn.connection_id(), rdp_packet).await;

    // csp_rdp_protocol(
    //	"RDP %p: Sending  in S %u: syn %u, ack %u, eack %u, "
    //	"rst %u, seq_nr %5u, ack_nr %5u, packet_len %u (%u)\n",
    //	(void *)conn, conn.rdp_connection().state,
    //	(tx_header.flags & RDP_SYN), (tx_header.flags & RDP_ACK),
    //	(tx_header.flags & RDP_EAK), (tx_header.flags & RDP_RST),
    //	be16toh(tx_header.seq_nr), be16toh(tx_header.ack_nr),
    //	packet.length, (unsigned int)(packet.length - sizeof(rdp_header_t)));

    conn.rdp_connection_mut().snd_nxt += 1;
    conn.rdp_connection_mut().ack_timestamp = crate::arch::get_ms();
    return Ok(());
}

/**
 * @note This function may only be called from csp_close, and is therefore
 * without any checks for null pointers.
 */
pub(crate) async fn close(conn: &mut Connection, closed_by: u8) -> Result<(), Error> {
    return close_internal(conn, closed_by, true).await;
}

async fn close_internal(conn: &mut Connection, closed_by: u8, send_rst: bool) -> Result<(), Error> {
    if conn.rdp_connection_mut().state == RdpState::Closed {
        return Ok(());
    }

    conn.rdp_connection_mut().closed_by |= closed_by;

    /* If connection is open, send reset */
    if conn.rdp_connection().state != RdpState::CloseWait {
        // set close wait
        conn.rdp_connection_mut().state = RdpState::CloseWait;
        conn.set_timestamp(crate::arch::get_ms());

        if send_rst {
            let seq_nr = conn.rdp_connection().snd_nxt;
            let ack_nr = conn.rdp_connection().rcv_cur;

            let _ = send_cmp(
                conn,
                None,
                RdpFlags::RDP_ACK | RdpFlags::RDP_RST,
                seq_nr,
                ack_nr,
            )
            .await;
        }
        // csp_rdp_protocol("RDP %p: csp_rdp_close(0x%x)%s -> CLOSE_WAIT\n", (void *)conn, closed_by, send_rst ? ", sent RST" : "");
        conn.rdp_connection().tx_wait.post(); // wake up any pendng Tx
    }

    if conn.rdp_connection().closed_by != CSP_RDP_CLOSED_BY_ALL {
        //csp_rdp_protocol("RDP %p: csp_rdp_close(0x%x) != %x, waiting for:%s%s%s\n",
        //				 (void *)conn, closed_by, conn.rdp_connection().closed_by,
        //				 (conn.rdp_connection().closed_by & CSP_RDP_CLOSED_BY_USERSPACE) ? "" : " userspace",
        //				 (conn.rdp_connection().closed_by & CSP_RDP_CLOSED_BY_PROTOCOL) ? "" : " protocol",
        //				 (conn.rdp_connection().closed_by & CSP_RDP_CLOSED_BY_TIMEOUT) ? "" : " timeout");
        return Err(Error::InvalidOperation);
    }

    // csp_rdp_protocol("RDP %p: csp_rdp_close(0x%x) -> CLOSED\n", (void *)conn, closed_by);
    conn.rdp_connection_mut().state = RdpState::Closed;
    conn.rdp_connection_mut().closed_by = 0;
    return Ok(());
}

/**
 * RDP Set socket options
 * Controls important parameters of the RDP protocol.
 * These settings will be applied to all new outgoing connections.
 * The settings are global, so be sure no other task are conflicting with your settings.
 */
/*
fn csp_rdp_set_opt(window_size: u32, conn_timeout_ms: u32,
                     packet_timeout_ms: u32, delayed_acks: u32,
                     ack_timeout: u32, ack_delay_count: u32) {
    CSP_RDP_WINDOW_SIZE = window_size;
    CSP_RDP_CONN_TIMEOUT = conn_timeout_ms;
    CSP_RDP_PACKET_TIMEOUT = packet_timeout_ms;
    CSP_RDP_DELAYED_ACKS = delayed_acks;
    CSP_RDP_ACK_TIMEOUT = ack_timeout;
    CSP_RDP_ACK_DELAY_COUNT = ack_delay_count;
}*/

/*
void csp_rdp_get_opt(* window_size, * conn_timeout_ms,
                     * packet_timeout_ms, * delayed_acks,
                     * ack_timeout, * ack_delay_count) {

    if (window_size)
        *window_size = CSP_RDP_WINDOW_SIZE;
    if (conn_timeout_ms)
        *conn_timeout_ms = CSP_RDP_CONN_TIMEOUT;
    if (packet_timeout_ms)
        *packet_timeout_ms = CSP_RDP_PACKET_TIMEOUT;
    if (delayed_acks)
        *delayed_acks = CSP_RDP_DELAYED_ACKS;
    if (ack_timeout)
        *ack_timeout = CSP_RDP_ACK_TIMEOUT;
    if (ack_delay_count)
        *ack_delay_count = CSP_RDP_ACK_DELAY_COUNT;
}*/

pub(crate) fn conn_is_active(conn: &Connection) -> bool {
    let time_now = crate::arch::get_ms();
    let mut active = true;

    let deadline = conn.timestamp() + conn.rdp_connection().conn_timeout;
    if time_after(time_now, deadline) {
        /* The RDP connection has timed out */
        // csp_rdp_error("RDP %p: Timeout no packets received last %u ms\n", (void *)conn, conn.rdp_connection().conn_timeout);
        active = false;
    }

    if conn.rdp_connection().state == RdpState::CloseWait
        || conn.rdp_connection().state == RdpState::Closed
    {
        active = false;
    }

    return active;
}
