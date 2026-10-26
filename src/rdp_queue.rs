use crate::Packet;
use crate::arch::Queue;
use crate::conn::{Connection, ConnectionID};

const CSP_RDP_MAX_WINDOW: usize = 5;

static TX_QUEUE: Queue<&'static mut Packet, CSP_RDP_MAX_WINDOW> = Queue::new();
static RX_QUEUE: Queue<&'static mut Packet, CSP_RDP_MAX_WINDOW> = Queue::new();

pub(crate) fn init() {
    // nothing to do
}

#[inline]
pub(crate) async fn flush(conn: Option<ConnectionID>) {
    if let Some(conn) = conn {
        flush_inner(&TX_QUEUE, conn).await;
        flush_inner(&RX_QUEUE, conn).await;
    } else {
        while let Some(_) = TX_QUEUE.try_pop().await {}
        while let Some(_) = RX_QUEUE.try_pop().await {}
    }
}

#[inline]
async fn flush_inner(
    queue: &Queue<&'static mut Packet, CSP_RDP_MAX_WINDOW>,
    conn: ConnectionID,
) {
    // try consuming packets without blocking
    while let Some(packet) = queue.try_pop().await {
        if packet
            .connection()
            .is_some_and(|c| c == conn)
        {
            packet.free().await;
        } else {
            // put it back
            queue.push(packet).await;
        }
    }
}

#[inline]
async fn get<F>(
    queue: &Queue<&'static mut Packet, CSP_RDP_MAX_WINDOW>,
    conn: ConnectionID,
    filter: F,
) -> Option<&'static mut Packet>
where
    F: Fn(&Packet) -> bool,
{
    // loop through packets
    while let Some(packet) = queue.try_pop().await {
        if packet
            .connection()
            .is_some_and(|c| c == conn)
        {
            // check filter
            if filter(packet) {
                // Found it
                return Some(packet);
            }
        }

        // Put it back and check next
        queue.push(packet).await;
    }

    return None;
}

#[inline]
pub(crate) async fn tx_add(conn: ConnectionID, packet: *const Packet) {
    unsafe {
        let packet = (packet as *mut Packet).as_mut_unchecked();
        // set connection
        packet.set_connection(Some(conn));

        TX_QUEUE.push(packet).await;
    }
}

#[inline]
pub(crate) async fn tx_try_get_filtered<F>(
    conn: ConnectionID,
    filter: F,
) -> Option<&'static mut Packet>
where
    F: Fn(&Packet) -> bool,
{
    return get(&TX_QUEUE, conn, filter).await;
}

#[inline]
pub(crate) async fn rx_add(conn: ConnectionID, packet: *const Packet) {
    unsafe {
        let packet = (packet as *mut Packet).as_mut_unchecked();
        packet.set_connection(Some(conn));
        
        RX_QUEUE.push(packet).await;
    }
}

#[inline]
pub(crate) async fn rx_try_get_filtered<F>(
    conn: ConnectionID,
    filter: F,
) -> Option<&'static mut Packet>
where
    F: Fn(&Packet) -> bool,
{
    return get(&RX_QUEUE, conn, filter).await;
}
