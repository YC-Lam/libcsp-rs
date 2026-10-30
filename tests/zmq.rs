#![cfg(feature = "zmq")]

use csp::interfaces::InterfaceID;
use csp::interfaces::zmq::{ZmqInterface, ZmqInterfaceDriver};
use csp::{ConnOptions, Error, Priority, UdpSocket, add_interface, route_work};
use static_cell::StaticCell;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct MockState {
    started: Option<InterfaceID>,
    frames: Vec<Vec<u8>>,
}

struct MockDriver(Arc<Mutex<MockState>>);

impl ZmqInterfaceDriver for MockDriver {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), Error> {
        self.0.lock().unwrap().frames.push(frame.to_vec());
        Ok(())
    }

    fn spawn_rx_task(&mut self, iface: InterfaceID) {
        self.0.lock().unwrap().started = Some(iface);
    }
}

fn csp_header(priority: Priority, dst: u16, src: u16, dst_port: u8, src_port: u8) -> [u8; 6] {
    // Build the exact CSP header bytes expected at the start of the published ZMQ frame.
    let id = ((priority as u64) << 46)
        | ((dst as u64) << 32)
        | ((src as u64) << 18)
        | ((dst_port as u64) << 12)
        | ((src_port as u64) << 6);
    let bytes = (id << 16).to_be_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
}

#[tokio::test]
async fn zmq_interface_publishes_a_complete_csp_frame() {
    static INTERFACE: StaticCell<ZmqInterface<MockDriver>> = StaticCell::new();

    // Keep the registered interface alive while its mock captures the published frame.
    let state = Arc::new(Mutex::new(MockState::default()));
    let interface = INTERFACE.init(ZmqInterface::new(
        0x2000,
        0,
        false,
        MockDriver(state.clone()),
    ));
    let iface_id = add_interface(interface);
    assert_eq!(state.lock().unwrap().started, Some(iface_id));

    let mut socket = UdpSocket::bind(10).await.unwrap();
    assert_eq!(
        socket
            .send_to(
                Priority::Normal,
                0x2001,
                20,
                ConnOptions::NONE,
                b"zmq-frame",
            )
            .await,
        Ok(9)
    );
    {
        let state = state.lock().unwrap();
        assert_eq!(state.frames.len(), 1);
        let frame = &state.frames[0];
        assert_eq!(
            &frame[..6],
            &csp_header(Priority::Normal, 0x2001, 0x2000, 20, 10)
        );
        assert_eq!(&frame[6..], b"zmq-frame");
    }

    route_work().await;
    socket.close().await;
}
