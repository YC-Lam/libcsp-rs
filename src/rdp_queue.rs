use crate::Packet;
use crate::arch::Queue;
use crate::conn::ConnectionID;

const CSP_RDP_MAX_WINDOW: usize = 5;
const CSP_RDP_MAX_WINDOW_QUEUE: usize = CSP_RDP_MAX_WINDOW * 2;

static TX_QUEUE: Queue<Packet, CSP_RDP_MAX_WINDOW_QUEUE> = Queue::new();
static RX_QUEUE: Queue<Packet, CSP_RDP_MAX_WINDOW_QUEUE> = Queue::new();

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
    // Visit each queued packet at most once; unrelated packets are requeued.
    for _ in 0..CSP_RDP_MAX_WINDOW_QUEUE {
        let Some(packet) = queue.try_pop() else {
            break;
        };

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
    // Scan only the packets that could have been present at the start; requeued
    // non-matches must not make a filtered lookup loop forever.
    for _ in 0..CSP_RDP_MAX_WINDOW_QUEUE {
        let Some(packet) = queue.try_pop() else {
            break;
        };

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

#[cfg(test)]
mod tests {
    use super::*;
    use core::time::Duration;

    #[tokio::test]
    async fn filtered_lookup_preserves_unacknowledged_packet_for_retransmission() {
        let queue = Queue::<Packet, CSP_RDP_MAX_WINDOW_QUEUE>::new();
        let connection = ConnectionID::from_index(usize::MAX);
        let mut packet = Packet::get().unwrap();
        packet.set_connection(Some(connection));
        packet.timestamp_tx = 0;
        packet.append_data(b"unacknowledged").unwrap();
        queue.push(packet).await.unwrap();

        // A dropped packet remains queued until its retransmission deadline expires.
        let before_deadline = tokio::time::timeout(
            Duration::from_millis(100),
            get(&queue, connection, |packet| {
                let deadline = packet.timestamp_tx.wrapping_add(1_000);
                (999u32.wrapping_sub(deadline) as i32) > 0
            }),
        )
        .await
        .unwrap();
        assert!(before_deadline.is_none());

        let packet = get(&queue, connection, |packet| {
            let deadline = packet.timestamp_tx.wrapping_add(1_000);
            (1_001u32.wrapping_sub(deadline) as i32) > 0
        })
        .await
        .unwrap();
        assert_eq!(packet.data(), b"unacknowledged");
    }

    #[tokio::test]
    async fn filtered_lookup_does_not_consume_packets_for_other_connections() {
        let queue = Queue::<Packet, CSP_RDP_MAX_WINDOW_QUEUE>::new();
        let connection = ConnectionID::from_index(1);
        let other_connection = ConnectionID::from_index(2);
        let mut packet = Packet::get().unwrap();
        packet.set_connection(Some(other_connection));
        queue.push(packet).await.unwrap();

        assert!(get(&queue, connection, |_| true).await.is_none());
        assert!(get(&queue, other_connection, |_| true).await.is_some());
    }

    #[tokio::test]
    async fn flushing_one_connection_preserves_packets_for_another() {
        let queue = Queue::<Packet, CSP_RDP_MAX_WINDOW_QUEUE>::new();
        let connection = ConnectionID::from_index(3);
        let other_connection = ConnectionID::from_index(4);
        let mut packet = Packet::get().unwrap();
        packet.set_connection(Some(other_connection));
        packet.append_data(b"other connection").unwrap();
        queue.push(packet).await.unwrap();

        tokio::time::timeout(Duration::from_millis(100), flush_inner(&queue, connection))
            .await
            .expect("flushing unrelated RDP packets must terminate");

        let packet = get(&queue, other_connection, |_| true).await.unwrap();
        assert_eq!(packet.data(), b"other connection");
    }
}
