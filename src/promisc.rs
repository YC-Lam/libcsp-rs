use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::Queue;
use crate::conn::CSP_CONN_RXQUEUE_LEN;
use crate::{Error, Packet};

static PROMISC_QUEUE: Queue<Packet, CSP_CONN_RXQUEUE_LEN> = Queue::new();
static PROMISC_ENABLED: AtomicBool = AtomicBool::new(false);

pub fn enable() {
    PROMISC_ENABLED.store(true, Ordering::Release);
}

pub fn disable() {
    PROMISC_ENABLED.store(false, Ordering::Release);
}

pub async fn read(timeout: u32) -> Result<Packet, Error> {
    match PROMISC_QUEUE.pop_with_timeout(timeout).await {
        Ok(p) => Ok(p),
        Err(_) => Err(Error::Timeout),
    }
}

#[allow(unused)]
pub(crate) async fn add(packet: &Packet) {
    if !PROMISC_ENABLED.load(Ordering::Acquire) {
        return;
    }

    /* Make a copy of the message and queue it to the promiscuous task */
    if let Some(packet_copy) = packet.buffer_clone() {
        let _ = PROMISC_QUEUE.push(packet_copy).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{PROMISC_ENABLED, add, disable, enable, read};
    use crate::{Error, Packet};
    use serial_test::serial;
    use std::vec;

    #[tokio::test]
    #[serial]
    async fn disabled_mode_does_not_enqueue_packets() {
        disable();
        while read(0).await.is_ok() {}

        let mut packet = Packet::get().unwrap();
        packet.append_data(b"not captured").unwrap();
        add(&packet).await;

        assert_eq!(read(0).await.err(), Some(Error::Timeout));
        assert!(!PROMISC_ENABLED.load(core::sync::atomic::Ordering::Acquire));
    }

    #[tokio::test]
    #[serial]
    async fn enabled_mode_queues_a_copy_of_the_packet() {
        while read(0).await.is_ok() {}
        enable();

        let mut packet = Packet::get().unwrap();
        packet.append_data(b"captured").unwrap();
        add(&packet).await;

        let captured = read(0).await.unwrap();
        assert_eq!(captured.data(), b"captured");
        assert_eq!(packet.data(), b"captured");
        drop(captured);
        disable();
    }
}
