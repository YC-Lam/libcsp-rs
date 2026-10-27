use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::Queue;
use crate::conn::CSP_CONN_RXQUEUE_LEN;
use crate::{Error, Packet};

static PROMISC_QUEUE: Queue<Packet, CSP_CONN_RXQUEUE_LEN> = Queue::new();
static PROMISC_ENABLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn enable() {
    PROMISC_ENABLED.store(true, Ordering::Release);
}

pub(crate) fn disable() {
    PROMISC_ENABLED.store(false, Ordering::Release);
}

pub(crate) async fn read(timeout: u32) -> Result<Packet, Error> {
    match PROMISC_QUEUE.pop_with_timeout(timeout).await {
        Ok(p) => Ok(p),
        Err(_) => Err(Error::Timeout),
    }
}

pub(crate) async fn add(packet: &Packet) {
    if !PROMISC_ENABLED.load(Ordering::Acquire) {
        return;
    }

    /* Make a copy of the message and queue it to the promiscuous task */
    if let Some(packet_copy) = packet.buffer_clone() {
        let _ = PROMISC_QUEUE.push(packet_copy).await;
    }
}
