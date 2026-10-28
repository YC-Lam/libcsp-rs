use core::task::{Context, Poll};

use crate::Error;
use crate::buffer::{CSP_BUFFER_SIZE, Packet};
use crate::id::CspId;

use super::{Interface, InterfaceID, InterfacePrivate, TxState};

const CSP_ID_HEADER_SIZE: usize = 6;

/// Maximum CSP frame length transmitted over I2C.
pub const I2C_MAX_FRAME_SIZE: usize = CSP_ID_HEADER_SIZE + CSP_BUFFER_SIZE;
/// Default I2C interface name.
pub const I2C_DEFAULT_NAME: &str = "I2C";

/// Driver contract for an I2C-backed CSP interface.
pub trait I2cInterfaceDriver: Send + Sync + 'static {
    /// Poll transmission of one complete CSP frame to a seven-bit I2C address.
    fn poll_tx_frame(
        &mut self,
        cx: &mut Context<'_>,
        address: u8,
        frame: &[u8],
        state: &mut TxState,
    ) -> Poll<Result<(), Error>>;

    /// Start reception for the registered interface.
    fn spawn_rx_task(&mut self, iface: InterfaceID);
}

/// CSP interface using I2C physical addresses for next-hop delivery.
pub struct I2cInterface<D: I2cInterfaceDriver> {
    addr: u16,
    netmask: u16,
    name: &'static str,
    is_default: bool,
    private: InterfacePrivate,
    driver: D,
}

impl<D: I2cInterfaceDriver> I2cInterface<D> {
    /// Create an I2C CSP interface.
    pub const fn new(
        addr: u16,
        netmask: u16,
        name: &'static str,
        is_default: bool,
        driver: D,
    ) -> Self {
        Self {
            addr,
            netmask,
            name,
            is_default,
            private: InterfacePrivate::new(),
            driver,
        }
    }

    fn poll_tx(
        &mut self,
        cx: &mut Context<'_>,
        via: Option<u16>,
        packet: &Packet,
        state: &mut TxState,
    ) -> Poll<Result<(), Error>> {
        let address = via.unwrap_or(packet.id.dst) as u8 & 0x7f;
        let header = packet.id.to_header();
        let data = packet.data();
        let mut frame = [0; I2C_MAX_FRAME_SIZE];
        frame[..CSP_ID_HEADER_SIZE].copy_from_slice(&header);
        frame[CSP_ID_HEADER_SIZE..CSP_ID_HEADER_SIZE + data.len()].copy_from_slice(data);
        self.driver.poll_tx_frame(
            cx,
            address,
            &frame[..CSP_ID_HEADER_SIZE + data.len()],
            state,
        )
    }
}

impl<D: I2cInterfaceDriver> Interface for I2cInterface<D> {
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
        self.name
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
        cx: &mut Context<'_>,
        via: Option<u16>,
        packet: &Packet,
        _from_me: bool,
        state: &mut TxState,
    ) -> Poll<Result<(), Error>> {
        self.poll_tx(cx, via, packet, state)
    }

    fn is_loopback_destination(&self, packet: &Packet) -> bool {
        packet.id.dst == self.addr
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

/// Submit a received CSP 2.x frame from an I2C driver to the router.
pub async fn receive_frame(iface_id: InterfaceID, frame: &[u8]) -> Result<(), Error> {
    if frame.len() < CSP_ID_HEADER_SIZE {
        if let Some(iface) = super::get_interface_by_id(iface_id) {
            iface.private().frame += 1;
        }
        return Err(Error::InvalidOperation);
    }
    if frame.len() > I2C_MAX_FRAME_SIZE {
        if let Some(iface) = super::get_interface_by_id(iface_id) {
            iface.private().rx_error += 1;
        }
        return Err(Error::BufferOverflow);
    }

    let mut packet = match Packet::get() {
        Some(packet) => packet,
        None => {
            if let Some(iface) = super::get_interface_by_id(iface_id) {
                iface.private().drop += 1;
            }
            return Err(Error::AllocError);
        }
    };
    packet.setup_rx();
    packet.id = CspId::from_header(frame);
    packet.timestamp_rx = crate::arch::get_ms();
    packet.append_data(&frame[CSP_ID_HEADER_SIZE..])?;

    crate::qfifo::write(packet, iface_id).await;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Flags, Priority};
    use crate::interfaces::INTERFACES;
    use core::task::Waker;
    use serial_test::serial;
    use std::sync::{Arc, Mutex};
    use std::vec;
    use std::vec::Vec;

    struct TestDriver(Option<Arc<Mutex<Vec<(u8, Vec<u8>)>>>>);

    impl I2cInterfaceDriver for TestDriver {
        fn poll_tx_frame(
            &mut self,
            _cx: &mut Context<'_>,
            address: u8,
            frame: &[u8],
            _state: &mut TxState,
        ) -> Poll<Result<(), Error>> {
            if let Some(sent) = &self.0 {
                sent.lock().unwrap().push((address, frame.to_vec()));
            }
            Poll::Ready(Ok(()))
        }

        fn spawn_rx_task(&mut self, _iface: InterfaceID) {}
    }

    fn test_packet() -> Packet {
        let mut packet = Packet::get().unwrap();
        packet.id = CspId {
            prio: Priority::High,
            flags: Flags::CSP_FCRC32,
            src: 2,
            dst: 0x123,
            dport: 10,
            sport: 11,
        };
        packet.append_data(b"i2c").unwrap();
        packet
    }

    #[test]
    fn transmit_encodes_csp_header_and_physical_next_hop() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut iface = I2cInterface::new(1, 14, "I2C", false, TestDriver(Some(sent.clone())));
        let packet = test_packet();
        let mut state = TxState::default();
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);

        assert_eq!(
            iface.poll_tx(&mut cx, None, &packet, &mut state),
            Poll::Ready(Ok(()))
        );
        let frames = sent.lock().unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, 0x23);

        let mut expected = packet.id.to_header().to_vec();
        expected.extend_from_slice(b"i2c");
        assert_eq!(frames[0].1, expected);
    }

    #[tokio::test]
    #[serial]
    #[allow(static_mut_refs)]
    async fn receive_frame_decodes_header_and_enqueues_packet() {
        INTERFACES.get_or_init().clear();
        static mut IFACE: I2cInterface<TestDriver> =
            I2cInterface::new(1, 14, "I2C", false, TestDriver(None));
        let iface_id = unsafe { crate::add_interface(&mut IFACE) };
        let packet = test_packet();
        let mut frame = packet.id.to_header().to_vec();
        frame.extend_from_slice(packet.data());

        assert_eq!(
            receive_frame(iface_id, &[1, 2]).await,
            Err(Error::InvalidOperation)
        );
        assert_eq!(
            receive_frame(iface_id, &vec![0; I2C_MAX_FRAME_SIZE + 1]).await,
            Err(Error::BufferOverflow)
        );
        receive_frame(iface_id, &frame).await.unwrap();
        let received = crate::qfifo::read().await.unwrap();

        assert_eq!(received.iface, iface_id);
        assert_eq!(received.packet.id, packet.id);
        assert_eq!(received.packet.data(), b"i2c");
    }
}
