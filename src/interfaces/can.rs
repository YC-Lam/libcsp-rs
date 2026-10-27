use core::task::{Context, Poll};

use crate::buffer::CSP_BUFFER_SIZE;
use crate::id::CspId;
use crate::{Error, Packet};

use super::{TxState, Interface, InterfaceID, InterfacePrivate};

const CAN_FRAME_SIZE: usize = 8;
const RX_BUFFER_TIMEOUT_MS: u32 = 1_000;
const CFP2_PRIO_OFFSET: u32 = 27;
const CFP2_DST_OFFSET: u32 = 13;
const CFP2_SENDER_OFFSET: u32 = 7;
const CFP2_PACKET_COUNT_OFFSET: u32 = 5;
const CFP2_FRAGMENT_COUNT_OFFSET: u32 = 2;
const CFP2_BEGIN_OFFSET: u32 = 1;
const CFP2_END_OFFSET: u32 = 0;
const CFP2_IDENTITY_MASK: u32 = (0x3fff << CFP2_DST_OFFSET)
    | (0x3f << CFP2_SENDER_OFFSET)
    | (0x3 << CFP2_PRIO_OFFSET)
    | (0x3 << CFP2_PACKET_COUNT_OFFSET);
const MAX_ALIASES: usize = 8;

/// Driver interface for an extended (29-bit) CAN controller.
///
/// The driver must only use `data` and `packet` for the duration of this call. If
/// transmission is pending, it must retain any frame data it needs and arrange for
/// the supplied waker to be notified when it can be polled again.
pub trait CanInterfaceDriver: Sync + Send + 'static {
    fn poll_tx_frame(
        &mut self,
        cx: &mut Context<'_>,
        id: u32,
        data: &[u8],
        packet: Option<&Packet>,
    ) -> Poll<Result<(), Error>>;

    fn spawn_rx_task(&mut self, id: InterfaceID);
}

pub struct CanInterface<D: CanInterfaceDriver> {
    addr: u16,
    netmask: u16,
    name: &'static str,
    is_default: bool,
    iface: InterfacePrivate,
    driver: D,
    packet_counter: u8,
    rx_packets: [Option<Packet>; crate::buffer::CSP_BUFFER_COUNT],
    aliases: [u16; MAX_ALIASES],
    alias_count: usize,
}

impl<D: CanInterfaceDriver> CanInterface<D> {
    pub const fn new(addr: u16, name: &'static str, is_default: bool, driver: D) -> Self {
        Self {
            addr,
            netmask: 0,
            name,
            is_default,
            iface: InterfacePrivate::new(),
            driver,
            packet_counter: 0,
            rx_packets: [const { None }; crate::buffer::CSP_BUFFER_COUNT],
            aliases: [0; MAX_ALIASES],
            alias_count: 0,
        }
    }

    fn process_frame(
        &mut self,
        id: u32,
        data: &[u8],
        timestamp_rx: u32,
    ) -> Result<Option<Packet>, Error> {
        if data.len() > CAN_FRAME_SIZE || id > 0x1fff_ffff {
            self.iface.frame += 1;
            return Err(Error::InvalidOperation);
        }

        self.cleanup_rx_buffers();
        let is_begin = id & (1 << CFP2_BEGIN_OFFSET) != 0;
        if is_begin && data.len() < 4 {
            self.iface.frame += 1;
            return Err(Error::InvalidOperation);
        }

        let mut slot = self.rx_packets.iter().position(|entry| {
            entry
                .as_ref()
                .is_some_and(|packet| packet.cfpid & CFP2_IDENTITY_MASK == id & CFP2_IDENTITY_MASK)
        });

        if slot.is_none() {
            if !is_begin {
                self.iface.frame += 1;
                return Err(Error::InvalidOperation);
            }

            let csp_id = Self::decode_csp_id(id, data);

            let packet = match Packet::get() {
                Some(packet) => packet,
                None => {
                    self.iface.drop += 1;
                    return Err(Error::AllocError);
                }
            };
            let now = crate::arch::get_ms();
            let free_slot = match self.rx_packets.iter().position(Option::is_none) {
                Some(free_slot) => free_slot,
                None => {
                    self.iface.drop += 1;
                    return Err(Error::AllocError);
                }
            };
            let packet = self.rx_packets[free_slot].insert(packet);
            packet.setup_rx();
            packet.id = csp_id;
            packet.cfpid = id;
            packet.last_used = now;
            packet.rx_count = 1;
            slot = Some(free_slot);
        }

        let slot = slot.expect("receive slot was allocated or found");
        let packet = self.rx_packets[slot]
            .as_mut()
            .expect("receive slot is occupied");
        packet.last_used = crate::arch::get_ms();

        if is_begin {
            packet.setup_rx();
            packet.id = Self::decode_csp_id(id, data);
            packet.cfpid = id;
            packet.rx_count = 1;
        }

        if !is_begin {
            let fragment_count = (id >> CFP2_FRAGMENT_COUNT_OFFSET) & 0x7;
            if packet.rx_count as u32 != fragment_count {
                self.rx_packets[slot] = None;
                self.iface.frame += 1;
                return Err(Error::InvalidOperation);
            }
            packet.rx_count = (packet.rx_count + 1) & 0x7;
        }

        let payload = if is_begin { &data[4..] } else { data };
        if packet.data_length() + payload.len() > CSP_BUFFER_SIZE {
            self.rx_packets[slot] = None;
            self.iface.rx_error += 1;
            return Err(Error::BufferOverflow);
        }
        packet.append_data(payload)?;

        if id & (1 << CFP2_END_OFFSET) != 0 {
            packet.timestamp_rx = timestamp_rx;
            if packet.id.dst == 0x3fff {
                packet.id.dst = self.addr;
            }
            return Ok(Some(
                self.rx_packets[slot]
                    .take()
                    .expect("receive slot is occupied"),
            ));
        }

        Ok(None)
    }

    fn decode_csp_id(id: u32, data: &[u8]) -> CspId {
        let mut header = [0; 6];
        let first_two = ((id >> CFP2_DST_OFFSET) as u16).to_be_bytes();
        header[..2].copy_from_slice(&first_two);
        header[2..].copy_from_slice(&data[..4]);
        CspId::from_header(&header)
    }

    fn cleanup_rx_buffers(&mut self) {
        let now = crate::arch::get_ms();
        for packet in &mut self.rx_packets {
            if packet
                .as_ref()
                .is_some_and(|packet| now.wrapping_sub(packet.last_used) > RX_BUFFER_TIMEOUT_MS)
            {
                *packet = None;
            }
        }
    }

    fn is_local_address(&self, addr: u16) -> bool {
        addr == self.addr || self.aliases[..self.alias_count].contains(&addr)
    }

    fn poll_tx(
        &mut self,
        cx: &mut Context<'_>,
        packet: &Packet,
        state: &mut TxState,
    ) -> Poll<Result<(), Error>> {
        if !state.started {
            state.started = true;
            state.sender_count = self.packet_counter;
            self.packet_counter = self.packet_counter.wrapping_add(1) & 0x3;
        }

        let mut can_id = (((packet.id.prio as u32) & 0x3) << CFP2_PRIO_OFFSET)
            | (((packet.id.dst as u32) & 0x3fff) << CFP2_DST_OFFSET)
            | (((self.addr as u32) & 0x3f) << CFP2_SENDER_OFFSET)
            | (((state.sender_count as u32) & 0x3) << CFP2_PACKET_COUNT_OFFSET);

        let payload = packet.data();
        let first_frame = !state.first_frame_sent;
        let mut frame = [0; CAN_FRAME_SIZE];
        let (data, packet_for_driver, next_tx_count) = if first_frame {
            can_id |= 1 << CFP2_BEGIN_OFFSET;
            let header = packet.id.to_header();
            frame[..4].copy_from_slice(&header[2..]);
            let count = payload.len().min(4);
            frame[4..4 + count].copy_from_slice(&payload[..count]);
            if count == payload.len() {
                can_id |= 1 << CFP2_END_OFFSET;
                (&frame[..4 + count], Some(packet), count)
            } else {
                (&frame[..4 + count], None, count)
            }
        } else {
            let count = (payload.len() - state.tx_count).min(CAN_FRAME_SIZE);
            frame[..count].copy_from_slice(&payload[state.tx_count..state.tx_count + count]);
            let next_tx_count = state.tx_count + count;
            if next_tx_count == payload.len() {
                can_id |= 1 << CFP2_END_OFFSET;
                (&frame[..count], Some(packet), next_tx_count)
            } else {
                (&frame[..count], None, next_tx_count)
            }
        };

        if !first_frame {
            can_id |= ((state.fragment_count as u32) & 0x7) << CFP2_FRAGMENT_COUNT_OFFSET;
        }

        match self
            .driver
            .poll_tx_frame(cx, can_id, data, packet_for_driver)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.iface.tx_error += 1;
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(())) => {
                state.tx_count = next_tx_count;
                if first_frame {
                    state.first_frame_sent = true;
                    state.fragment_count = 1;
                } else {
                    state.fragment_count = (state.fragment_count + 1) & 0x7;
                }
                if state.tx_count == payload.len() {
                    Poll::Ready(Ok(()))
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
    }
}

impl<D: CanInterfaceDriver> Interface for CanInterface<D> {
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
        _via: Option<u16>,
        packet: &Packet,
        _from_me: bool,
        state: &mut TxState,
    ) -> Poll<Result<(), Error>> {
        self.poll_tx(cx, packet, state)
    }

    fn is_loopback_destination(&self, packet: &Packet) -> bool {
        self.is_local_address(packet.id.dst)
    }

    fn process_rx_frame(
        &mut self,
        id: u32,
        data: &[u8],
        timestamp_rx: u32,
    ) -> Result<Option<Packet>, Error> {
        self.process_frame(id, data, timestamp_rx)
    }

    fn alias_add(&mut self, addr: u16) -> Result<(), Error> {
        if self.is_local_address(addr) {
            return Ok(());
        }
        if self.alias_count == MAX_ALIASES {
            return Err(Error::BufferOverflow);
        }
        self.aliases[self.alias_count] = addr;
        self.alias_count += 1;
        Ok(())
    }

    fn is_default(&self) -> bool {
        self.is_default
    }

    fn private(&mut self) -> &mut InterfacePrivate {
        &mut self.iface
    }
}

/// Submit an incoming CAN frame to a registered CAN interface.
pub async fn receive(
    iface: InterfaceID,
    id: u32,
    data: &[u8],
    timestamp_rx: u32,
) -> Result<(), Error> {
    let interface = crate::interfaces::get_interface_by_id(iface).ok_or(Error::InvalidOperation)?;
    let packet = interface.process_rx_frame(id, data, timestamp_rx)?;
    if let Some(packet) = packet {
        crate::qfifo::write(packet, iface).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Flags, Priority};
    use core::task::Waker;
    use std::sync::{Arc, Mutex};
    use std::task::Wake;
    use std::vec;
    use std::vec::Vec;

    struct Frame {
        id: u32,
        data: Vec<u8>,
        has_packet: bool,
    }

    #[derive(Default)]
    struct TestDriver {
        frames: Mutex<Vec<Frame>>,
    }

    impl CanInterfaceDriver for TestDriver {
        fn poll_tx_frame(
            &mut self,
            _cx: &mut Context<'_>,
            id: u32,
            data: &[u8],
            packet: Option<&Packet>,
        ) -> Poll<Result<(), Error>> {
            self.frames.lock().unwrap().push(Frame {
                id,
                data: data.to_vec(),
                has_packet: packet.is_some(),
            });
            Poll::Ready(Ok(()))
        }

        fn spawn_rx_task(&mut self, _id: InterfaceID) {
            
        }
    }

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn test_packet(payload: &[u8]) -> Packet {
        let mut packet = Packet::get().expect("packet pool has capacity");
        packet.id.prio = Priority::Normal;
        packet.id.src = 0x456;
        packet.id.dst = 0x123;
        packet.id.dport = 12;
        packet.id.sport = 34;
        packet.id.flags = Flags::CSP_FCRC32;
        packet.append_data(payload).unwrap();
        packet
    }

    fn cfp2_id(
        csp_id: CspId,
        sender: u8,
        packet_count: u8,
        fragment: u8,
        begin: bool,
        end: bool,
    ) -> u32 {
        ((csp_id.prio as u32) << CFP2_PRIO_OFFSET)
            | ((csp_id.dst as u32) << CFP2_DST_OFFSET)
            | ((sender as u32) << CFP2_SENDER_OFFSET)
            | ((packet_count as u32) << CFP2_PACKET_COUNT_OFFSET)
            | ((fragment as u32) << CFP2_FRAGMENT_COUNT_OFFSET)
            | ((begin as u32) << CFP2_BEGIN_OFFSET)
            | end as u32
    }

    #[test]
    #[serial_test::serial]
    fn tx_frames_match_cfp2_header_and_fragment_fields() {
        let payload = (0..13).collect::<Vec<u8>>();
        let packet = test_packet(&payload);
        let header = packet.id.to_header();
        let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());
        let mut state = TxState::default();
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);

        assert!(can.poll_tx(&mut cx, &packet, &mut state).is_pending());
        assert!(can.poll_tx(&mut cx, &packet, &mut state).is_pending());
        assert!(can.poll_tx(&mut cx, &packet, &mut state).is_ready());

        let frames = can.driver.frames.lock().unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(&frames[0].data[..4], &header[2..]);
        assert_eq!(&frames[0].data[4..], &payload[..4]);
        assert_ne!(frames[0].id & (1 << CFP2_BEGIN_OFFSET), 0);
        assert_eq!(frames[0].id & (1 << CFP2_END_OFFSET), 0);
        assert_eq!((frames[1].id >> CFP2_FRAGMENT_COUNT_OFFSET) & 0x7, 1);
        assert_eq!(frames[1].data, payload[4..12]);
        assert_eq!((frames[2].id >> CFP2_FRAGMENT_COUNT_OFFSET) & 0x7, 2);
        assert_eq!(frames[2].data, payload[12..]);
        assert_ne!(frames[2].id & (1 << CFP2_END_OFFSET), 0);
        assert!(!frames[0].has_packet);
        assert!(!frames[1].has_packet);
        assert!(frames[2].has_packet);
    }

    #[test]
    #[serial_test::serial]
    fn receive_reassembles_cfp2_packet_and_records_end_timestamp() {
        let payload = (0..13).collect::<Vec<u8>>();
        let packet = test_packet(&payload);
        let csp_id = packet.id;
        let header = csp_id.to_header();
        assert_eq!(CspId::from_header(&header), csp_id);
        let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());

        let mut first_data = header[2..].to_vec();
        first_data.extend_from_slice(&payload[..4]);
        assert!(
            can.process_frame(cfp2_id(csp_id, 3, 1, 0, true, false), &first_data, 10)
                .unwrap()
                .is_none()
        );
        assert!(
            can.process_frame(cfp2_id(csp_id, 3, 1, 1, false, false), &payload[4..12], 20)
                .unwrap()
                .is_none()
        );
        let received = can
            .process_frame(cfp2_id(csp_id, 3, 1, 2, false, true), &payload[12..], 30)
            .unwrap()
            .unwrap();
        assert_eq!(received.data(), payload);
        assert_eq!(received.timestamp_rx, 30);
        assert_eq!(received.id, csp_id);
    }
}
