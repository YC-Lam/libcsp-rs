use core::task::{Context, Poll};

use crate::buffer::CSP_BUFFER_SIZE;
use crate::id::CspId;
use crate::{Error, Packet};

use super::{Interface, InterfaceID, InterfacePrivate, TxState};

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
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use std::task::Wake;
    use std::vec;
    use std::vec::Vec;

    enum DriverResult {
        Ready,
        Pending,
        Error(Error),
    }

    struct Frame {
        id: u32,
        data: Vec<u8>,
        has_packet: bool,
    }

    #[derive(Default)]
    struct TestDriver {
        frames: Mutex<Vec<Frame>>,
        results: Mutex<VecDeque<DriverResult>>,
    }

    impl CanInterfaceDriver for TestDriver {
        fn poll_tx_frame(
            &mut self,
            _cx: &mut Context<'_>,
            id: u32,
            data: &[u8],
            packet: Option<&Packet>,
        ) -> Poll<Result<(), Error>> {
            let result = self
                .results
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(DriverResult::Ready);

            match result {
                DriverResult::Ready => {
                    self.frames.lock().unwrap().push(Frame {
                        id,
                        data: data.to_vec(),
                        has_packet: packet.is_some(),
                    });
                    Poll::Ready(Ok(()))
                }
                DriverResult::Pending => Poll::Pending,
                DriverResult::Error(error) => Poll::Ready(Err(error)),
            }
        }

        fn spawn_rx_task(&mut self, _id: InterfaceID) {}
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
        packet.id.flags = Flags::CRC32;
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

    fn begin_data(packet: &Packet, payload: &[u8]) -> Vec<u8> {
        let header = packet.id.to_header();
        let mut data = header[2..].to_vec();
        data.extend_from_slice(payload);
        data
    }

    fn receive_buffer_count<D: CanInterfaceDriver>(can: &CanInterface<D>) -> usize {
        can.rx_packets
            .iter()
            .filter(|packet| packet.is_some())
            .count()
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

    #[test]
    #[serial_test::serial]
    fn tx_handles_cfp2_fragment_boundaries() {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);

        for length in [0usize, 1, 4, 5, 12, 13, 20, 21, 80, CSP_BUFFER_SIZE] {
            let payload = (0..length).map(|byte| byte as u8).collect::<Vec<_>>();
            let packet = test_packet(&payload);
            let csp_header = packet.id.to_header();
            let packet_prio = packet.id.prio as u32;
            let packet_dst = packet.id.dst;
            let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());
            let mut state = TxState::default();
            let mut polls = 0;

            while can.poll_tx(&mut cx, &packet, &mut state).is_pending() {
                polls += 1;
                assert!(polls <= 36, "transmit did not finish");
            }

            let frames = can.driver.frames.lock().unwrap();
            let expected_frame_count = if length <= 4 {
                1
            } else {
                1 + (length - 4).div_ceil(CAN_FRAME_SIZE)
            };
            assert_eq!(
                frames.len(),
                expected_frame_count,
                "payload length {length}"
            );
            assert_eq!(&frames[0].data[..4], &csp_header[2..]);
            assert_eq!(&frames[0].data[4..], &payload[..length.min(4)]);
            assert_eq!((frames[0].id >> CFP2_PRIO_OFFSET) & 0x3, packet_prio);
            assert_eq!(
                (frames[0].id >> CFP2_DST_OFFSET) & 0x3fff,
                packet_dst as u32
            );
            assert_eq!((frames[0].id >> CFP2_SENDER_OFFSET) & 0x3f, 0x234 & 0x3f);
            assert_eq!((frames[0].id >> CFP2_PACKET_COUNT_OFFSET) & 0x3, 0);
            assert_ne!(frames[0].id & (1 << CFP2_BEGIN_OFFSET), 0);
            assert_eq!(frames[0].id & (1 << CFP2_END_OFFSET) != 0, length <= 4);
            assert_eq!(frames[0].has_packet, length <= 4);

            let mut payload_offset = 4.min(length);
            for (fragment_index, frame) in frames.iter().enumerate().skip(1) {
                let count = (length - payload_offset).min(CAN_FRAME_SIZE);
                assert_eq!(
                    frame.data,
                    payload[payload_offset..payload_offset + count],
                    "payload length {length}, fragment {fragment_index}"
                );
                assert_eq!(
                    (frame.id >> CFP2_FRAGMENT_COUNT_OFFSET) & 0x7,
                    (fragment_index as u32) & 0x7
                );
                let is_last = payload_offset + count == length;
                assert_eq!(frame.id & (1 << CFP2_END_OFFSET) != 0, is_last);
                assert_eq!(frame.has_packet, is_last);
                payload_offset += count;
            }
            assert_eq!(payload_offset, length);
        }
    }

    #[test]
    #[serial_test::serial]
    fn tx_packet_counter_wraps_after_two_bits() {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());

        for expected_count in 0..6 {
            let packet = test_packet(&[]);
            let mut state = TxState::default();
            assert!(can.poll_tx(&mut cx, &packet, &mut state).is_ready());
            let frames = can.driver.frames.lock().unwrap();
            assert_eq!(
                (frames.last().unwrap().id >> CFP2_PACKET_COUNT_OFFSET) & 0x3,
                (expected_count & 0x3) as u32
            );
        }
    }

    #[test]
    #[serial_test::serial]
    fn tx_keeps_fragment_when_driver_is_pending_and_reports_errors() {
        let payload = (0..13).collect::<Vec<u8>>();
        let packet = test_packet(&payload);
        let driver = TestDriver::default();
        driver.results.lock().unwrap().extend([
            DriverResult::Pending,
            DriverResult::Ready,
            DriverResult::Error(Error::CanBusError),
        ]);
        let mut can = CanInterface::new(0x234, "CAN", false, driver);
        let mut state = TxState::default();
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);

        assert!(can.poll_tx(&mut cx, &packet, &mut state).is_pending());
        assert!(!state.first_frame_sent);
        assert_eq!(state.tx_count, 0);
        assert!(can.driver.frames.lock().unwrap().is_empty());

        assert!(can.poll_tx(&mut cx, &packet, &mut state).is_pending());
        assert!(state.first_frame_sent);
        assert_eq!(state.tx_count, 4);

        assert!(matches!(
            can.poll_tx(&mut cx, &packet, &mut state),
            Poll::Ready(Err(Error::CanBusError))
        ));
        assert_eq!(state.tx_count, 4);
        assert_eq!(can.iface.tx_error, 1);
        assert_eq!(can.driver.frames.lock().unwrap().len(), 1);
    }

    #[test]
    #[serial_test::serial]
    fn rx_rejects_non_begin_or_malformed_begin_frames() {
        let packet = test_packet(&[]);
        let id = cfp2_id(packet.id, 3, 0, 0, false, false);
        let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());

        assert!(matches!(
            can.process_frame(id, &[1, 2, 3], 10),
            Err(Error::InvalidOperation)
        ));
        let malformed_begin = cfp2_id(packet.id, 3, 0, 0, true, true);
        assert!(matches!(
            can.process_frame(malformed_begin, &[1, 2, 3], 10),
            Err(Error::InvalidOperation)
        ));
        assert_eq!(can.iface.frame, 2);
        assert_eq!(receive_buffer_count(&can), 0);
    }

    #[test]
    #[serial_test::serial]
    fn rx_drops_sequence_mismatch_and_accepts_restarted_packet() {
        let payload = [1, 2, 3, 4, 5];
        let packet = test_packet(&payload);
        let csp_id = packet.id;
        let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());

        assert!(
            can.process_frame(
                cfp2_id(csp_id, 3, 1, 0, true, false),
                &begin_data(&packet, &payload[..4]),
                10
            )
            .unwrap()
            .is_none()
        );
        assert_eq!(receive_buffer_count(&can), 1);

        assert!(matches!(
            can.process_frame(cfp2_id(csp_id, 3, 1, 2, false, true), &payload[4..], 20),
            Err(Error::InvalidOperation)
        ));
        assert_eq!(receive_buffer_count(&can), 0);

        assert!(
            can.process_frame(
                cfp2_id(csp_id, 3, 1, 0, true, false),
                &begin_data(&packet, &payload[..4]),
                30
            )
            .unwrap()
            .is_none()
        );
        let received = can
            .process_frame(cfp2_id(csp_id, 3, 1, 1, false, true), &payload[4..], 40)
            .unwrap()
            .unwrap();
        assert_eq!(received.data(), payload);
        assert_eq!(received.timestamp_rx, 40);
        assert_eq!(can.iface.frame, 1);
    }

    #[test]
    #[serial_test::serial]
    fn rx_restarts_duplicate_begin_and_rewrites_broadcast_destination() {
        let payload = [9, 8, 7, 6, 5];
        let mut packet = test_packet(&payload);
        packet.id.dst = 0x3fff;
        let csp_id = packet.id;
        let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());

        assert!(
            can.process_frame(
                cfp2_id(csp_id, 4, 2, 0, true, false),
                &begin_data(&packet, &[1, 2, 3, 4]),
                10
            )
            .unwrap()
            .is_none()
        );
        assert!(
            can.process_frame(
                cfp2_id(csp_id, 4, 2, 0, true, false),
                &begin_data(&packet, &payload[..4]),
                20
            )
            .unwrap()
            .is_none()
        );
        let received = can
            .process_frame(cfp2_id(csp_id, 4, 2, 1, false, true), &payload[4..], 30)
            .unwrap()
            .unwrap();

        assert_eq!(received.data(), payload);
        let received_dst = received.id.dst;
        assert_eq!(received_dst, 0x234);
        assert_eq!(received.timestamp_rx, 30);
        assert_eq!(receive_buffer_count(&can), 0);
    }

    #[test]
    #[serial_test::serial]
    fn rx_drops_oversized_packets_and_cleans_expired_reassemblies() {
        let payload = vec![0x5a; CSP_BUFFER_SIZE];
        let packet = test_packet(&payload);
        let csp_id = packet.id;
        let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());
        let first = begin_data(&packet, &[0x5a; 4]);
        assert!(
            can.process_frame(cfp2_id(csp_id, 5, 1, 0, true, false), &first, 10)
                .unwrap()
                .is_none()
        );

        let mut fragment = 1u8;
        let mut received_bytes = 4usize;
        while received_bytes + CAN_FRAME_SIZE <= CSP_BUFFER_SIZE {
            assert!(
                can.process_frame(
                    cfp2_id(csp_id, 5, 1, fragment, false, false),
                    &[0x5a; CAN_FRAME_SIZE],
                    20
                )
                .unwrap()
                .is_none()
            );
            received_bytes += CAN_FRAME_SIZE;
            fragment = (fragment + 1) & 0x7;
        }

        assert!(matches!(
            can.process_frame(
                cfp2_id(csp_id, 5, 1, fragment, false, true),
                &[0x5a; CAN_FRAME_SIZE],
                30
            ),
            Err(Error::BufferOverflow)
        ));
        assert_eq!(can.iface.rx_error, 1);
        assert_eq!(receive_buffer_count(&can), 0);

        assert!(
            can.process_frame(cfp2_id(csp_id, 5, 2, 0, true, false), &first, 40)
                .unwrap()
                .is_none()
        );
        can.rx_packets
            .iter_mut()
            .flatten()
            .next()
            .expect("partial packet allocated")
            .last_used = crate::arch::get_ms().wrapping_sub(RX_BUFFER_TIMEOUT_MS + 1);
        assert!(matches!(
            can.process_frame(cfp2_id(csp_id, 5, 2, 1, false, true), &[1], 50),
            Err(Error::InvalidOperation)
        ));
        assert_eq!(receive_buffer_count(&can), 0);
    }

    #[test]
    #[serial_test::serial]
    fn rx_rejects_invalid_dlc_and_extended_identifier_range() {
        let packet = test_packet(&[]);
        let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());

        assert!(matches!(
            can.process_frame(0, &[0; CAN_FRAME_SIZE + 1], 0),
            Err(Error::InvalidOperation)
        ));
        assert!(matches!(
            can.process_frame(0x2000_0000, &[], 0),
            Err(Error::InvalidOperation)
        ));
        let short_id = cfp2_id(packet.id, 1, 0, 0, true, true);
        assert!(
            can.process_frame(short_id, &packet.id.to_header()[2..], 0)
                .unwrap()
                .is_some()
        );
        assert_eq!(can.iface.frame, 2);
    }

    #[test]
    #[serial_test::serial]
    fn aliases_are_local_destinations_and_duplicate_aliases_are_ignored() {
        let mut can = CanInterface::new(0x234, "CAN", false, TestDriver::default());
        let mut packet = test_packet(&[]);

        packet.id.dst = 0x234;
        assert!(can.is_loopback_destination(&packet));
        can.alias_add(0x345).unwrap();
        can.alias_add(0x345).unwrap();
        assert!(can.is_local_address(0x345));
        packet.id.dst = 0x345;
        assert!(can.is_loopback_destination(&packet));
        assert!(!can.is_local_address(0x456));
        assert_eq!(can.alias_count, 1);

        for addr in 0x400..0x407 {
            can.alias_add(addr).unwrap();
        }
        assert_eq!(can.alias_count, MAX_ALIASES);
        assert!(matches!(can.alias_add(0x407), Err(Error::BufferOverflow)));
    }
}
