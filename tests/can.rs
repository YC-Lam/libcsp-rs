use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use csp::interfaces::InterfaceID;
use csp::interfaces::can::{CanInterface, CanInterfaceDriver, receive};
use csp::{ConnOptions, Error, Packet, Priority, UdpSocket, add_interface, route_work};
use static_cell::StaticCell;

#[derive(Default)]
struct MockState {
    started: Option<InterfaceID>,
    frames: Vec<(u32, Vec<u8>)>,
}

struct MockDriver(Arc<Mutex<MockState>>);

impl CanInterfaceDriver for MockDriver {
    fn poll_tx_frame(
        &mut self,
        _cx: &mut Context<'_>,
        id: u32,
        data: &[u8],
        _packet: Option<&Packet>,
    ) -> Poll<Result<(), Error>> {
        self.0.lock().unwrap().frames.push((id, data.to_vec()));
        Poll::Ready(Ok(()))
    }

    fn spawn_rx_task(&mut self, iface: InterfaceID) {
        self.0.lock().unwrap().started = Some(iface);
    }
}

fn csp_header(priority: Priority, dst: u16, src: u16, dst_port: u8, src_port: u8) -> [u8; 6] {
    // Pack the CSP header fields into the same six-byte network-order form used on the wire.
    let id = ((priority as u64) << 46)
        | ((dst as u64) << 32)
        | ((src as u64) << 18)
        | ((dst_port as u64) << 12)
        | ((src_port as u64) << 6);
    let bytes = (id << 16).to_be_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
}

fn cfp2_id(
    priority: Priority,
    dst: u16,
    sender: u8,
    packet_count: u8,
    fragment: u8,
    begin: bool,
    end: bool,
) -> u32 {
    // CFP2 carries the CSP header tail in the first CAN frame, with begin/end flags in its ID.
    ((priority as u32) << 27)
        | ((dst as u32) << 13)
        | ((sender as u32) << 7)
        | ((packet_count as u32) << 5)
        | ((fragment as u32) << 2)
        | ((begin as u32) << 1)
        | end as u32
}

#[tokio::test]
async fn can_interface_transmits_fragments_and_routes_received_packets() {
    static INTERFACE: StaticCell<CanInterface<MockDriver>> = StaticCell::new();

    // Registered interfaces must outlive the test because the router stores their references.
    let state = Arc::new(Mutex::new(MockState::default()));
    let interface = INTERFACE.init(CanInterface::new(
        0x2000,
        "CAN-test",
        false,
        MockDriver(state.clone()),
    ));
    let iface_id = add_interface(interface);
    assert_eq!(state.lock().unwrap().started, Some(iface_id));

    // This payload crosses the first-frame capacity, so transmission must emit two CAN frames.
    let mut tx_socket = UdpSocket::bind(10).await.unwrap();
    assert_eq!(
        tx_socket
            .send_to(
                Priority::High,
                0x2001,
                20,
                ConnOptions::CSP_O_NONE,
                b"12345",
            )
            .await,
        Ok(5)
    );
    {
        let state = state.lock().unwrap();
        assert_eq!(state.frames.len(), 2);
        let (begin_id, begin_data) = &state.frames[0];
        assert_eq!((begin_id >> 27) & 0x3, Priority::High as u32);
        assert_eq!((begin_id >> 13) & 0x3fff, 0x2001);
        assert_ne!(begin_id & 0x2, 0);
        assert_eq!(begin_id & 1, 0);
        let mut expected = csp_header(Priority::High, 0x2001, 0x2000, 20, 10)[2..].to_vec();
        expected.extend_from_slice(b"1234");
        assert_eq!(begin_data, &expected);

        let (end_id, end_data) = &state.frames[1];
        assert_ne!(end_id & 1, 0);
        assert_eq!(end_data, b"5");
    }
    tx_socket.close().await;
    route_work().await;

    // Feed the matching begin/end fragments and verify the reassembled datagram's data and peer.
    let mut rx_socket = UdpSocket::bind(42).await.unwrap();
    let header = csp_header(Priority::Normal, 0x2000, 0x123, 42, 7);
    let mut first_data = header[2..].to_vec();
    first_data.extend_from_slice(b"can-");
    receive(
        iface_id,
        cfp2_id(Priority::Normal, 0x2000, 0x23, 0, 0, true, false),
        &first_data,
        123,
    )
    .await
    .unwrap();
    receive(
        iface_id,
        cfp2_id(Priority::Normal, 0x2000, 0x23, 0, 1, false, true),
        b"rx",
        456,
    )
    .await
    .unwrap();
    route_work().await;

    let mut payload = [0; 16];
    let (length, peer) = rx_socket.recv_from(&mut payload, 100).await.unwrap();
    assert_eq!(&payload[..length], b"can-rx");
    assert_eq!(peer.addr, 0x123);
    assert_eq!(peer.port, 7);
    rx_socket.close().await;

    assert_eq!(
        receive(iface_id, 0x2000, &[0; 9], 0).await,
        Err(Error::InvalidOperation)
    );
}
