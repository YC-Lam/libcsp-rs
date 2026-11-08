use core::task::{Context, Poll};

use crate::buffer::CSP_BUFFER_SIZE;
use crate::id::CspId;
use crate::{Error, Packet};

use super::can::CanInterfaceDriver;
use super::{Interface, InterfaceID, InterfacePrivate, TxState};

const CAN_FRAME_SIZE: usize = 8;
const CAN_FD_FRAME_SIZE: usize = 64;
const CFP2_HEADER_EXTENSION_SIZE: usize = 4;
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

const fn canfd_frame_size(bytes: usize) -> usize {
    if bytes <= CAN_FRAME_SIZE {
        return bytes;
    }

    let sizes = [64, 48, 32, 24, 20, 16, 12];
    let mut index = 0;
    while index < sizes.len() {
        if sizes[index] <= bytes {
            return sizes[index];
        }
        index += 1;
    }

    CAN_FRAME_SIZE
}

/// CFP2 CAN-FD interface using extended 29-bit CAN identifiers.
///
/// The driver is shared with [`super::can::CanInterfaceDriver`]. It must accept
/// payloads up to 64 bytes and only use the frame data for the duration of a
/// `poll_tx_frame` call.
pub struct CanFdInterface<D: CanInterfaceDriver> {
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

impl<D: CanInterfaceDriver> CanFdInterface<D> {
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
        if data.len() > CAN_FD_FRAME_SIZE || id > 0x1fff_ffff {
            self.iface.frame += 1;
            return Err(Error::InvalidOperation);
        }

        self.cleanup_rx_buffers();
        let is_begin = id & (1 << CFP2_BEGIN_OFFSET) != 0;
        if is_begin && data.len() < CFP2_HEADER_EXTENSION_SIZE {
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

        let payload = if is_begin {
            &data[CFP2_HEADER_EXTENSION_SIZE..]
        } else {
            data
        };
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
        header[2..].copy_from_slice(&data[..CFP2_HEADER_EXTENSION_SIZE]);
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
        let mut frame = [0; CAN_FD_FRAME_SIZE];

        let (data, packet_for_driver, next_tx_count) = if first_frame {
            can_id |= 1 << CFP2_BEGIN_OFFSET;
            let header = packet.id.to_header();
            frame[..CFP2_HEADER_EXTENSION_SIZE].copy_from_slice(&header[2..]);
            let count = (canfd_frame_size(CFP2_HEADER_EXTENSION_SIZE + payload.len())
                - CFP2_HEADER_EXTENSION_SIZE)
                .min(payload.len());
            frame[CFP2_HEADER_EXTENSION_SIZE..CFP2_HEADER_EXTENSION_SIZE + count]
                .copy_from_slice(&payload[..count]);
            if count == payload.len() {
                can_id |= 1 << CFP2_END_OFFSET;
                (
                    &frame[..CFP2_HEADER_EXTENSION_SIZE + count],
                    Some(packet),
                    count,
                )
            } else {
                (&frame[..CFP2_HEADER_EXTENSION_SIZE + count], None, count)
            }
        } else {
            let remaining = payload.len() - state.tx_count;
            let count = canfd_frame_size(remaining);
            let next_tx_count = state.tx_count + count;
            if next_tx_count == payload.len() {
                can_id |= 1 << CFP2_END_OFFSET;
                (
                    &payload[state.tx_count..next_tx_count],
                    Some(packet),
                    next_tx_count,
                )
            } else {
                (&payload[state.tx_count..next_tx_count], None, next_tx_count)
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

impl<D: CanInterfaceDriver> Interface for CanFdInterface<D> {
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

    fn contains_address(&self, addr: u16) -> bool {
        self.is_local_address(addr)
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

/// Submit an incoming CAN-FD frame to a registered CAN-FD interface.
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
    use std::sync::Arc;
    use std::task::Wake;
    use std::vec;
    use std::vec::Vec;

    #[derive(Default)]
    struct TestDriver {
        frames: Vec<(u32, Vec<u8>, bool)>,
    }

    impl CanInterfaceDriver for TestDriver {
        fn poll_tx_frame(
            &mut self,
            _cx: &mut Context<'_>,
            id: u32,
            data: &[u8],
            packet: Option<&Packet>,
        ) -> Poll<Result<(), Error>> {
            self.frames.push((id, data.to_vec(), packet.is_some()));
            Poll::Ready(Ok(()))
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

    #[test]
    #[serial_test::serial]
    fn tx_uses_valid_can_fd_frame_sizes_and_fragments() {
        let wake = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&wake);

        for length in [
            0usize,
            1,
            4,
            5,
            8,
            9,
            12,
            16,
            20,
            21,
            60,
            61,
            64,
            65,
            128,
            CSP_BUFFER_SIZE,
        ] {
            let payload = (0..length).map(|byte| byte as u8).collect::<Vec<_>>();
            let packet = test_packet(&payload);
            let header = packet.id.to_header();
            let mut can = CanFdInterface::new(0x234, "CANFD", false, TestDriver::default());
            let mut state = TxState::default();

            let mut polls = 0;
            while can.poll_tx(&mut cx, &packet, &mut state).is_pending() {
                polls += 1;
                assert!(polls <= CSP_BUFFER_SIZE + 1, "payload length {length}");
            }

            assert!(!can.driver.frames.is_empty(), "payload length {length}");
            assert_eq!(&can.driver.frames[0].1[..4], &header[2..]);
            assert_eq!(
                can.driver.frames[0].1.len(),
                canfd_frame_size(length + 4),
                "first frame DLC for payload length {length}"
            );
            let first_payload_count =
                (canfd_frame_size(length + 4) - CFP2_HEADER_EXTENSION_SIZE).min(length);
            assert_eq!(can.driver.frames[0].1[4..], payload[..first_payload_count]);
            assert_ne!(can.driver.frames[0].0 & (1 << CFP2_BEGIN_OFFSET), 0);
            assert_eq!(
                can.driver.frames[0].0 & (1 << CFP2_END_OFFSET) != 0,
                first_payload_count == length
            );
            assert_eq!(can.driver.frames.last().unwrap().2, true);

            let mut received = can.driver.frames[0].1[4..].to_vec();
            for (fragment_index, frame) in can.driver.frames.iter().enumerate().skip(1) {
                assert_eq!(
                    (frame.0 >> CFP2_FRAGMENT_COUNT_OFFSET) & 0x7,
                    fragment_index as u32 & 0x7
                );
                assert_eq!(
                    frame.0 & (1 << CFP2_END_OFFSET) != 0,
                    fragment_index + 1 == can.driver.frames.len()
                );
                assert_eq!(frame.2, fragment_index + 1 == can.driver.frames.len());
                received.extend_from_slice(&frame.1);
            }
            assert_eq!(received, payload, "payload length {length}");
            for (_, data, _) in &can.driver.frames {
                assert!(data.len() <= CAN_FD_FRAME_SIZE);
                assert_eq!(canfd_frame_size(data.len()), data.len());
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn rx_reassembles_can_fd_payload_and_rejects_oversized_frames() {
        let payload = (0..100).map(|byte| byte as u8).collect::<Vec<_>>();
        let packet = test_packet(&payload);
        let csp_id = packet.id;
        let mut can = CanFdInterface::new(0x234, "CANFD", false, TestDriver::default());
        let first_count = 60;
        let first = {
            let header = csp_id.to_header();
            let mut first = header[2..].to_vec();
            first.extend_from_slice(&payload[..first_count]);
            first
        };

        assert!(
            can.process_frame(cfp2_id(csp_id, 3, 1, 0, true, false), &first, 10)
                .unwrap()
                .is_none()
        );
        assert!(
            can.process_frame(
                cfp2_id(csp_id, 3, 1, 1, false, false),
                &payload[first_count..first_count + 32],
                20,
            )
            .unwrap()
            .is_none()
        );
        let received = can
            .process_frame(
                cfp2_id(csp_id, 3, 1, 2, false, true),
                &payload[first_count + 32..],
                30,
            )
            .unwrap()
            .unwrap();
        assert_eq!(received.data(), payload);
        assert_eq!(received.timestamp_rx, 30);

        assert!(matches!(
            can.process_frame(0, &[0; CAN_FD_FRAME_SIZE + 1], 0),
            Err(Error::InvalidOperation)
        ));
        assert_eq!(can.iface.frame, 1);
    }
}
