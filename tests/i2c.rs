use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use csp::interfaces::i2c::{I2C_MAX_FRAME_SIZE, I2cInterface, I2cInterfaceDriver, receive_frame};
use csp::interfaces::{InterfaceID, TxState};
use csp::{Error, Priority, add_interface, route_work};
use static_cell::StaticCell;

#[derive(Default)]
struct MockState {
    started: Option<InterfaceID>,
    transmitted: Vec<(u8, Vec<u8>)>,
}

struct MockDriver(Arc<Mutex<MockState>>);

impl I2cInterfaceDriver for MockDriver {
    fn poll_tx_frame(
        &mut self,
        _cx: &mut Context<'_>,
        address: u8,
        frame: &[u8],
        _state: &mut TxState,
    ) -> Poll<Result<(), Error>> {
        self.0
            .lock()
            .unwrap()
            .transmitted
            .push((address, frame.to_vec()));
        Poll::Ready(Ok(()))
    }

    fn spawn_rx_task(&mut self, iface: InterfaceID) {
        self.0.lock().unwrap().started = Some(iface);
    }
}

fn csp_header(
    priority: Priority,
    dst: u16,
    src: u16,
    dst_port: u8,
    src_port: u8,
    flags: u8,
) -> [u8; 6] {
    // Encode the CSP fields in network byte order for the mock driver's input frame.
    let id = ((priority as u64) << 46)
        | ((dst as u64) << 32)
        | ((src as u64) << 18)
        | ((dst_port as u64) << 12)
        | ((src_port as u64) << 6)
        | flags as u64;
    let bytes = (id << 16).to_be_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
}

#[tokio::test]
async fn received_i2c_frame_is_routed_to_another_i2c_interface() {
    static SOURCE_INTERFACE: StaticCell<I2cInterface<MockDriver>> = StaticCell::new();
    static TARGET_INTERFACE: StaticCell<I2cInterface<MockDriver>> = StaticCell::new();

    // The router retains interface references, so both mocks use process-lifetime storage.
    let source_state = Arc::new(Mutex::new(MockState::default()));
    let target_state = Arc::new(Mutex::new(MockState::default()));

    let source = SOURCE_INTERFACE.init(I2cInterface::new(
        2,
        1,
        "I2C-source",
        false,
        MockDriver(source_state.clone()),
    ));
    let source_id = add_interface(source);
    assert_eq!(source_state.lock().unwrap().started, Some(source_id));

    let target = TARGET_INTERFACE.init(I2cInterface::new(
        0x2000,
        1,
        "I2C-target",
        false,
        MockDriver(target_state.clone()),
    ));
    let target_id = add_interface(target);
    assert_eq!(target_state.lock().unwrap().started, Some(target_id));

    // Address 0x2001 is routed over the target subnet; the I2C next-hop is 1.
    let mut frame = csp_header(Priority::High, 0x2001, 1, 42, 7, 0).to_vec();
    frame.extend_from_slice(b"forwarded");
    receive_frame(source_id, &frame).await.unwrap();
    route_work().await;

    let target_state = target_state.lock().unwrap();
    assert_eq!(target_state.transmitted.len(), 1);
    let (address, transmitted) = &target_state.transmitted[0];
    assert_eq!(*address, 1);
    assert_eq!(
        &transmitted[..6],
        &csp_header(Priority::High, 0x2001, 1, 42, 7, 0)
    );
    assert_eq!(&transmitted[6..], b"forwarded");
    assert!(transmitted.len() <= I2C_MAX_FRAME_SIZE);

    // Reject malformed short headers and frames that exceed the interface's fixed limit.
    assert_eq!(
        receive_frame(source_id, &[0; 5]).await,
        Err(Error::InvalidOperation)
    );
    let oversized = vec![0; I2C_MAX_FRAME_SIZE + 1];
    assert_eq!(
        receive_frame(source_id, &oversized).await,
        Err(Error::BufferOverflow)
    );
}
