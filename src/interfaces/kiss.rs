use core::task::{Context, Poll};

use crate::buffer::{CSP_BUFFER_SIZE, Packet};
use crate::id::CspId;
use crate::{Error, InterfaceID};

use super::{Interface, InterfacePrivate, TxState};

const CSP_ID_HEADER_SIZE: usize = 6;
const KISS_FEND: u8 = 0xc0;
const KISS_FESC: u8 = 0xdb;
const KISS_TFEND: u8 = 0xdc;
const KISS_TFESC: u8 = 0xdd;
const KISS_DATA: u8 = 0x00;

/// Default KISS interface name.
pub const KISS_DEFAULT_NAME: &str = "KISS";
/// Maximum unescaped CSP frame accepted by the KISS interface.
pub const KISS_MAX_FRAME_SIZE: usize = CSP_ID_HEADER_SIZE + CSP_BUFFER_SIZE;
/// Maximum encoded KISS frame, including delimiters, command byte, and escapes.
pub const KISS_MAX_ENCODED_SIZE: usize = 2 * KISS_MAX_FRAME_SIZE + 3;

/// Driver contract for a KISS-backed CSP interface.
pub trait KissInterfaceDriver: Send + Sync + 'static {
    /// Poll transmission of one encoded KISS frame.
    ///
    /// If this returns `Pending`, the driver must copy the frame and arrange
    /// for the supplied waker to be notified when transmission completes.
    fn poll_tx_frame(
        &mut self,
        cx: &mut Context<'_>,
        frame: &[u8],
        state: &mut TxState,
    ) -> Poll<Result<(), Error>>;

    /// Start reception for the registered interface.
    fn spawn_rx_task(&mut self, iface: InterfaceID);
}

/// CSP interface transported as KISS data frames over a serial link.
pub struct KissInterface<D: KissInterfaceDriver> {
    addr: u16,
    netmask: u16,
    name: &'static str,
    is_default: bool,
    private: InterfacePrivate,
    driver: D,
}

impl<D: KissInterfaceDriver> KissInterface<D> {
    /// Create a KISS interface.
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
        packet: &Packet,
        state: &mut TxState,
    ) -> Poll<Result<(), Error>> {
        let header = packet.id.to_header();
        let data = packet.data();
        let mut frame = [0; KISS_MAX_ENCODED_SIZE];
        let length = match encode_frame(&header, data, &mut frame) {
            Ok(length) => length,
            Err(error) => return Poll::Ready(Err(error)),
        };
        self.driver.poll_tx_frame(cx, &frame[..length], state)
    }
}

impl<D: KissInterfaceDriver> Interface for KissInterface<D> {
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

/// Persistent state for decoding a byte stream into KISS frames.
pub struct KissRxState {
    mode: RxMode,
    first: bool,
    length: usize,
    frame: [u8; KISS_MAX_FRAME_SIZE],
}

impl KissRxState {
    /// Create an idle KISS decoder.
    pub const fn new() -> Self {
        Self {
            mode: RxMode::NotStarted,
            first: false,
            length: 0,
            frame: [0; KISS_MAX_FRAME_SIZE],
        }
    }

    fn begin(&mut self) {
        self.mode = RxMode::Started;
        self.first = true;
        self.length = 0;
    }
}

impl Default for KissRxState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RxMode {
    NotStarted,
    Started,
    Escaped,
    SkipFrame,
}

/// Decode received KISS bytes and enqueue each complete CSP frame for routing.
pub async fn receive_bytes(
    iface_id: InterfaceID,
    state: &mut KissRxState,
    bytes: &[u8],
) -> Result<(), Error> {
    let mut first_error = None;
    for &byte in bytes {
        let result = receive_byte(iface_id, state, byte).await;
        if first_error.is_none() {
            first_error = result.err();
        }
    }
    first_error.map_or(Ok(()), Err)
}

async fn receive_byte(
    iface_id: InterfaceID,
    state: &mut KissRxState,
    byte: u8,
) -> Result<(), Error> {
    match state.mode {
        RxMode::NotStarted => {
            if byte == KISS_FEND {
                state.begin();
            }
        }
        RxMode::Started => {
            if byte == KISS_FEND {
                if state.first {
                    // A repeated delimiter is a valid start; no command or data preceded it.
                    state.begin();
                    return Ok(());
                }
                let result = finish_frame(iface_id, state).await;
                state.mode = RxMode::NotStarted;
                state.length = 0;
                return result;
            }
            if state.first {
                state.first = false;
                if byte != KISS_DATA {
                    state.mode = RxMode::SkipFrame;
                    return Err(count_frame_error(iface_id, Error::InvalidOperation));
                }
                return Ok(());
            }
            if byte == KISS_FESC {
                state.mode = RxMode::Escaped;
            } else {
                append_byte(iface_id, state, byte)?;
            }
        }
        RxMode::Escaped => {
            state.mode = RxMode::Started;
            match byte {
                KISS_TFEND => append_byte(iface_id, state, KISS_FEND)?,
                KISS_TFESC => append_byte(iface_id, state, KISS_FESC)?,
                KISS_FEND => {
                    state.begin();
                    return Err(count_frame_error(iface_id, Error::InvalidOperation));
                }
                _ => {
                    state.mode = RxMode::SkipFrame;
                    return Err(count_frame_error(iface_id, Error::InvalidOperation));
                }
            }
        }
        RxMode::SkipFrame => {
            if byte == KISS_FEND {
                state.mode = RxMode::NotStarted;
                state.length = 0;
            }
        }
    }
    Ok(())
}

fn append_byte(iface_id: InterfaceID, state: &mut KissRxState, byte: u8) -> Result<(), Error> {
    if state.length == state.frame.len() {
        state.mode = RxMode::SkipFrame;
        count_rx_error(iface_id);
        return Err(Error::BufferOverflow);
    }
    state.frame[state.length] = byte;
    state.length += 1;
    Ok(())
}

async fn finish_frame(iface_id: InterfaceID, state: &KissRxState) -> Result<(), Error> {
    if state.length < CSP_ID_HEADER_SIZE {
        count_frame_error(iface_id, Error::InvalidOperation);
        return Err(Error::InvalidOperation);
    }

    let packet = match Packet::get() {
        Some(packet) => packet,
        None => {
            if let Some(iface) = super::get_interface_by_id(iface_id) {
                iface.private().drop += 1;
            }
            return Err(Error::AllocError);
        }
    };
    let mut packet = packet;
    packet.setup_rx();
    packet.id = CspId::from_header(&state.frame[..CSP_ID_HEADER_SIZE]);
    packet.timestamp_rx = crate::arch::get_ms();
    packet.append_data(&state.frame[CSP_ID_HEADER_SIZE..state.length])?;
    crate::qfifo::write(packet, iface_id).await;
    Ok(())
}

fn count_frame_error(iface_id: InterfaceID, error: Error) -> Error {
    if let Some(iface) = super::get_interface_by_id(iface_id) {
        iface.private().frame += 1;
    }
    error
}

fn count_rx_error(iface_id: InterfaceID) {
    if let Some(iface) = super::get_interface_by_id(iface_id) {
        iface.private().rx_error += 1;
    }
}

fn encode_frame(
    header: &[u8; CSP_ID_HEADER_SIZE],
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, Error> {
    let mut cursor = 0;
    output[cursor] = KISS_FEND;
    cursor += 1;
    output[cursor] = KISS_DATA;
    cursor += 1;
    for &byte in header.iter().chain(payload) {
        if byte == KISS_FEND || byte == KISS_FESC {
            if cursor + 2 >= output.len() {
                return Err(Error::BufferOverflow);
            }
            output[cursor] = KISS_FESC;
            output[cursor + 1] = if byte == KISS_FEND {
                KISS_TFEND
            } else {
                KISS_TFESC
            };
            cursor += 2;
        } else {
            if cursor + 1 >= output.len() {
                return Err(Error::BufferOverflow);
            }
            output[cursor] = byte;
            cursor += 1;
        }
    }
    output[cursor] = KISS_FEND;
    Ok(cursor + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::{Flags, Priority};
    use core::task::Waker;
    use std::sync::{Arc, Mutex};
    use std::vec;
    use std::vec::Vec;

    struct TestDriver(Arc<Mutex<Vec<u8>>>);

    impl KissInterfaceDriver for TestDriver {
        fn poll_tx_frame(
            &mut self,
            _cx: &mut Context<'_>,
            frame: &[u8],
            _state: &mut TxState,
        ) -> Poll<Result<(), Error>> {
            self.0.lock().unwrap().extend_from_slice(frame);
            Poll::Ready(Ok(()))
        }

        fn spawn_rx_task(&mut self, _iface: InterfaceID) {}
    }

    struct RxOnlyDriver;

    impl KissInterfaceDriver for RxOnlyDriver {
        fn poll_tx_frame(
            &mut self,
            _cx: &mut Context<'_>,
            _frame: &[u8],
            _state: &mut TxState,
        ) -> Poll<Result<(), Error>> {
            Poll::Ready(Ok(()))
        }

        fn spawn_rx_task(&mut self, _iface: InterfaceID) {}
    }

    #[test]
    fn encoding_escapes_delimiters_and_escape_bytes() {
        let mut output = [0; KISS_MAX_ENCODED_SIZE];
        let length = encode_frame(
            &[KISS_FEND, KISS_FESC, 1, 2, 3, 4],
            &[KISS_FEND, KISS_FESC],
            &mut output,
        )
        .unwrap();
        assert_eq!(
            &output[..length],
            &[
                KISS_FEND, KISS_DATA, KISS_FESC, KISS_TFEND, KISS_FESC, KISS_TFESC, 1, 2, 3, 4,
                KISS_FESC, KISS_TFEND, KISS_FESC, KISS_TFESC, KISS_FEND
            ]
        );
    }

    #[test]
    fn transmit_wraps_header_and_payload_in_kiss_frame() {
        let sent = Arc::new(Mutex::new(Vec::new()));
        let mut iface =
            KissInterface::new(1, 14, KISS_DEFAULT_NAME, false, TestDriver(sent.clone()));
        let mut packet = Packet::get().unwrap();
        packet.id = CspId {
            prio: Priority::Normal,
            flags: Flags::CSP_FCRC32,
            src: 2,
            dst: 1,
            dport: 10,
            sport: 11,
        };
        packet.append_data(b"test").unwrap();
        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        assert_eq!(
            iface.poll_tx(&mut cx, &packet, &mut TxState::default()),
            Poll::Ready(Ok(()))
        );

        let mut expected = vec![KISS_FEND, KISS_DATA];
        expected.extend_from_slice(&packet.id.to_header());
        expected.extend_from_slice(b"test");
        expected.push(KISS_FEND);
        assert_eq!(*sent.lock().unwrap(), expected);
    }

    #[test]
    fn max_encoded_length_covers_every_byte_escaped() {
        let header = [KISS_FEND; CSP_ID_HEADER_SIZE];
        let payload = [KISS_FESC; CSP_BUFFER_SIZE];
        let mut output = [0; KISS_MAX_ENCODED_SIZE];
        let length = encode_frame(&header, &payload, &mut output).unwrap();
        assert_eq!(length, KISS_MAX_ENCODED_SIZE);
    }

    #[tokio::test]
    #[serial_test::serial]
    #[allow(static_mut_refs)]
    async fn receive_decodes_stream_chunks_and_enqueues_complete_packet() {
        use crate::interfaces::INTERFACES;

        INTERFACES.get_or_init().clear();
        static mut IFACE: KissInterface<RxOnlyDriver> =
            KissInterface::new(1, 14, KISS_DEFAULT_NAME, false, RxOnlyDriver);
        let iface_id = unsafe { crate::add_interface(&mut IFACE) };
        let packet_id = CspId {
            prio: Priority::High,
            flags: Flags::CSP_FCRC32,
            src: 2,
            dst: 1,
            dport: 10,
            sport: 11,
        };
        let mut encoded = [0; KISS_MAX_ENCODED_SIZE];
        let length = encode_frame(
            &packet_id.to_header(),
            &[KISS_FEND, KISS_FESC],
            &mut encoded,
        )
        .unwrap();
        let mut decoder = KissRxState::new();

        receive_bytes(iface_id, &mut decoder, &encoded[..3])
            .await
            .unwrap();
        receive_bytes(iface_id, &mut decoder, &encoded[3..length])
            .await
            .unwrap();
        let received = crate::qfifo::read().await.unwrap();

        assert_eq!(received.iface, iface_id);
        assert_eq!(received.packet.id, packet_id);
        assert_eq!(received.packet.data(), &[KISS_FEND, KISS_FESC]);
    }
}
