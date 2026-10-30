use crate::arch::Queue;
use crate::{InterfaceID, Packet};

/// If RDP is enabled, the router needs to awake some times to check timeouts
#[cfg(feature = "rdp")]
const FIFO_TIMEOUT: u32 = 100;

/// If no RDP, the router can sleep until data arrives
#[cfg(not(feature = "rdp"))]
const FIFO_TIMEOUT: u32 = u32::MAX;

const CSP_QFIFO_LEN: usize = 15;

static QFIFO_QUEUE: Queue<Qfifo, CSP_QFIFO_LEN> = Queue::new();

pub(crate) struct Qfifo {
    pub(crate) iface: InterfaceID,
    pub(crate) packet: Packet,
}

pub(crate) async fn read() -> Option<Qfifo> {
    QFIFO_QUEUE.pop_with_timeout(FIFO_TIMEOUT).await.ok()
}

pub(crate) async fn write(packet: Packet, iface: InterfaceID) {
    let qfifo = Qfifo { iface, packet };

    QFIFO_QUEUE.push(qfifo).await.unwrap();
}

#[cfg(test)]
mod tests {
    use super::{read, write};
    use crate::{Packet, interfaces::INTERFACES};

    #[tokio::test]
    async fn queue_preserves_packet_and_interface() {
        let iface = INTERFACES.get_or_init().into_iter().next().unwrap().id();
        let mut packet = Packet::get().unwrap();
        packet.append_data(b"queued").unwrap();

        write(packet, iface).await;

        let queued = read().await.unwrap();
        assert_eq!(queued.iface, iface);
        assert_eq!(queued.packet.data(), b"queued");
    }
}
