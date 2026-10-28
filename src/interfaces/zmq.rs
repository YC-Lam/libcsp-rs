use core::task::{Context, Poll};

use crate::Error;
use crate::buffer::{CSP_BUFFER_SIZE, Packet};
use crate::id::CspId;

use super::{Interface, InterfaceID, InterfacePrivate, TxState};

const CSP_ID_HEADER_SIZE: usize = 6;

/// Maximum CSP frame payload accepted by the ZeroMQ interface.
pub const ZMQ_MTU: usize = CSP_BUFFER_SIZE;
/// Default ZeroMQ hub subscriber port used for CSP transmission.
pub const ZMQPROXY_SUBSCRIBE_PORT: u16 = 6000;
/// Default ZeroMQ hub publisher port used for CSP reception.
pub const ZMQPROXY_PUBLISH_PORT: u16 = 7000;
/// Default interface name.
pub const ZMQHUB_IF_NAME: &str = "ZMQHUB";

/// Driver contract for a ZeroMQ-backed CSP interface.
pub trait ZmqInterfaceDriver: Send + Sync + 'static {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), Error>;
    fn spawn_rx_task(&mut self, iface: InterfaceID);
}

/// CSP interface backed by a ZeroMQ PUB/SUB hub.
///
/// The driver publishes a packed CSP 2.x header followed by the packet data in
/// one single-part message. Register the interface with [`crate::add_interface`]
/// to start its receive thread.
pub struct ZmqInterface<D: ZmqInterfaceDriver> {
    addr: u16,
    netmask: u16,
    is_default: bool,
    private: InterfacePrivate,
    driver: D,
}

impl<D: ZmqInterfaceDriver> ZmqInterface<D> {
    /// Create an interface for a ZeroMQ hub connection.
    pub const fn new(addr: u16, netmask: u16, is_default: bool, driver: D) -> Self {
        Self {
            addr,
            netmask,
            is_default,
            private: InterfacePrivate::new(),
            driver,
        }
    }

    fn poll_tx(&mut self, packet: &Packet, _state: &mut TxState) -> Poll<Result<(), Error>> {
        let header = packet.id.to_header();
        let data = packet.data();
        let mut frame = [0; CSP_ID_HEADER_SIZE + CSP_BUFFER_SIZE];
        frame[..CSP_ID_HEADER_SIZE].copy_from_slice(&header);
        frame[CSP_ID_HEADER_SIZE..CSP_ID_HEADER_SIZE + data.len()].copy_from_slice(data);

        Poll::Ready(
            self.driver
                .send_frame(&frame[..CSP_ID_HEADER_SIZE + data.len()]),
        )
    }
}

impl<D: ZmqInterfaceDriver> Interface for ZmqInterface<D> {
    fn start(&mut self, id: InterfaceID) {
        self.driver.spawn_rx_task(id);
    }

    fn addr(&self) -> u16 {
        self.addr
    }

    fn netmask(&self) -> u16 {
        self.netmask
    }

    fn name(&self) -> &str {
        ZMQHUB_IF_NAME
    }

    fn next_hop(
        &mut self,
        _via: Option<u16>,
        _packet: &Packet,
        _from_me: bool,
    ) -> Result<(), Error> {
        Err(Error::InvalidOperation)
    }

    fn poll_next_hop(
        &mut self,
        _cx: &mut Context<'_>,
        _via: Option<u16>,
        packet: &Packet,
        _from_me: bool,
        state: &mut TxState,
    ) -> Poll<Result<(), Error>> {
        self.poll_tx(packet, state)
    }

    fn alias_add(&mut self, _addr: u16) -> Result<(), Error> {
        Err(Error::InvalidOperation)
    }

    fn is_default(&self) -> bool {
        self.is_default
    }

    fn private(&mut self) -> &mut InterfacePrivate {
        &mut self.private
    }
}

/// Submit a received raw CSP frame from the ZeroMQ driver to the router.
pub(crate) fn receive_frame(iface_id: InterfaceID, frame: &[u8]) -> Result<(), Error> {
    let iface = super::get_interface_by_id(iface_id).ok_or(Error::InvalidOperation)?;

    if frame.len() < CSP_ID_HEADER_SIZE {
        iface.private().frame += 1;
        return Err(Error::InvalidOperation);
    }
    if frame.len() > CSP_ID_HEADER_SIZE + ZMQ_MTU {
        iface.private().rx_error += 1;
        return Err(Error::BufferOverflow);
    }

    let mut packet = match Packet::get() {
        Some(packet) => packet,
        None => {
            iface.private().drop += 1;
            return Err(Error::AllocError);
        }
    };
    packet.setup_rx();
    packet.id = CspId::from_header(frame);
    packet.timestamp_rx = crate::arch::get_ms();
    packet.append_data(&frame[CSP_ID_HEADER_SIZE..])?;

    smol::block_on(crate::qfifo::write(packet, iface_id));
    Ok(())
}

pub(crate) fn reject_multipart(iface_id: InterfaceID) {
    if let Some(iface) = super::get_interface_by_id(iface_id) {
        iface.private().frame += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Flags, Priority};
    use crate::interfaces::INTERFACES;
    use serial_test::serial;
    use std::sync::{Arc, Mutex};
    use std::vec;
    use std::vec::Vec;

    struct TestZmqDriver(Option<Arc<Mutex<Vec<u8>>>>);

    impl ZmqInterfaceDriver for TestZmqDriver {
        fn send_frame(&mut self, frame: &[u8]) -> Result<(), Error> {
            if let Some(sent) = &self.0 {
                sent.lock().unwrap().extend_from_slice(frame);
            }
            Ok(())
        }

        fn spawn_rx_task(&mut self, _iface: InterfaceID) {}
    }

    #[test]
    fn transmit_packs_header_and_payload_into_one_frame() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut iface = ZmqInterface::new(1, 14, false, TestZmqDriver(Some(sent.clone())));
        let mut packet = Packet::get().unwrap();
        packet.id = CspId {
            prio: Priority::High,
            flags: Flags::CSP_FCRC32,
            src: 2,
            dst: 1,
            dport: 10,
            sport: 11,
        };
        packet.append_data(b"zmq").unwrap();

        assert_eq!(
            iface.poll_tx(&packet, &mut TxState::default()),
            Poll::Ready(Ok(()))
        );

        let mut expected = packet.id.to_header().to_vec();
        expected.extend_from_slice(b"zmq");
        assert_eq!(*sent.lock().unwrap(), expected);
    }

    #[tokio::test]
    #[serial]
    #[allow(static_mut_refs)]
    async fn receive_frame_decodes_header_and_enqueues_packet() {
        INTERFACES.get_or_init().clear();
        static mut IFACE: ZmqInterface<TestZmqDriver> =
            ZmqInterface::new(1, 14, false, TestZmqDriver(None));

        let id = unsafe { crate::add_interface(&mut IFACE) };
        let mut packet = Packet::get().unwrap();
        packet.id = CspId {
            prio: Priority::High,
            flags: Flags::CSP_FCRC32,
            src: 2,
            dst: 1,
            dport: 10,
            sport: 11,
        };
        packet.append_data(b"zmq").unwrap();
        let mut frame = packet.id.to_header().to_vec();
        frame.extend_from_slice(packet.data());

        receive_frame(id, &frame).unwrap();
        let received = crate::qfifo::read().await.unwrap();

        assert_eq!(received.iface, id);
        assert_eq!(received.packet.id, packet.id);
        assert_eq!(received.packet.data(), b"zmq");
    }
}
