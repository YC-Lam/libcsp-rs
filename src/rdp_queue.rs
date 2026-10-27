use crate::Packet;
use crate::arch::Queue;
use crate::conn::ConnectionID;

const CSP_RDP_MAX_WINDOW: usize = 5;
const CSP_RDP_MAX_WINDOW_QUEUE: usize = CSP_RDP_MAX_WINDOW * 2;

static TX_QUEUE: Queue<Packet, CSP_RDP_MAX_WINDOW_QUEUE> = Queue::new();
static RX_QUEUE: Queue<Packet, CSP_RDP_MAX_WINDOW_QUEUE> = Queue::new();

pub(crate) fn init() {
    // nothing to do
}

#[inline]
pub(crate) async fn flush(conn: Option<ConnectionID>) {
    if let Some(conn) = conn {
        flush_inner(&TX_QUEUE, conn).await;
        flush_inner(&RX_QUEUE, conn).await;
    } else {
        while TX_QUEUE.try_pop().is_some() {}
        while RX_QUEUE.try_pop().is_some() {}
    }
}

#[inline]
async fn flush_inner(queue: &Queue<Packet, CSP_RDP_MAX_WINDOW_QUEUE>, conn: ConnectionID) {
    // try consuming packets without blocking
    while let Some(packet) = queue.try_pop() {
        if packet.connection().is_some_and(|c| c == conn) {
            drop(packet);
        } else {
            // put it back
            let _ = queue.push(packet).await;
        }
    }
}

#[inline]
async fn get<F>(
    queue: &Queue<Packet, CSP_RDP_MAX_WINDOW_QUEUE>,
    conn: ConnectionID,
    filter: F,
) -> Option<Packet>
where
    F: Fn(&Packet) -> bool,
{
    // loop through packets
    while let Some(packet) = queue.try_pop() {
        if packet.connection().is_some_and(|c| c == conn) {
            // check filter
            if filter(&packet) {
                // Found it
                return Some(packet);
            }
        }

        // Put it back and check next
        let _ = queue.push(packet).await;
    }

    return None;
}

#[inline]
pub(crate) async fn tx_add(conn: ConnectionID, mut packet: Packet) {
    packet.set_connection(Some(conn));
    let _ = TX_QUEUE.push(packet).await;
}

#[inline]
pub(crate) async fn tx_try_get_filtered<F>(conn: ConnectionID, filter: F) -> Option<Packet>
where
    F: Fn(&Packet) -> bool,
{
    return get(&TX_QUEUE, conn, filter).await;
}

#[inline]
pub(crate) async fn rx_add(conn: ConnectionID, mut packet: Packet) {
    packet.set_connection(Some(conn));
    let _ = RX_QUEUE.push(packet).await;
}

#[inline]
pub(crate) async fn rx_try_get_filtered<F>(conn: ConnectionID, filter: F) -> Option<Packet>
where
    F: Fn(&Packet) -> bool,
{
    return get(&RX_QUEUE, conn, filter).await;
}
