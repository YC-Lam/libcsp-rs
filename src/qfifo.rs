use crate::Packet;
use crate::arch::Queue;
use crate::interfaces::InterfacePrivate;

/// If RDP is enabled, the router needs to awake some times to check timeouts
#[cfg(feature = "rdp")]
const FIFO_TIMEOUT: u32 = 100;

/// If no RDP, the router can sleep until data arrives
#[cfg(not(feature = "rdp"))]
const FIFO_TIMEOUT: u32 = u32::MAX;

const CSP_QFIFO_LEN: usize = 15;

static QFIFO_QUEUE: Queue<Qfifo, CSP_QFIFO_LEN> = Queue::new();

pub(crate) struct Qfifo {
    iface: &'static mut InterfacePrivate,
    packet: &'static mut Packet,
}
pub(crate) fn init() {
    // nothing to do
}

pub(crate) async fn read() -> Option<Qfifo> {
    QFIFO_QUEUE.pop_with_timeout(FIFO_TIMEOUT).await
}

pub(crate) async fn write(packet: &'static mut Packet, iface: &'static mut InterfacePrivate) {
    let qfifo = Qfifo { iface, packet };

    QFIFO_QUEUE.push(qfifo).await;
}
