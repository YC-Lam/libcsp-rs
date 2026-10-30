#![cfg(feature = "rdp")]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use csp::interfaces::InterfaceID;
use csp::interfaces::can::{CanInterface, CanInterfaceDriver};
use csp::{ConnOptions, CspListener, CspStream, Error, Packet, Priority, add_interface};
use serial_test::serial;
use static_cell::StaticCell;
use tokio::sync::mpsc;

const LOCAL_ADDR: u16 = 0x2000;
const REMOTE_ADDR: u16 = 0x2001;

struct CapturedPacket {
    frames: Vec<(u32, Vec<u8>)>,
    is_rdp_data: bool,
}

struct LossyCanDriver {
    tx: mpsc::UnboundedSender<CapturedPacket>,
    frames: Vec<(u32, Vec<u8>)>,
}

impl CanInterfaceDriver for LossyCanDriver {
    fn poll_tx_frame(
        &mut self,
        _cx: &mut Context<'_>,
        id: u32,
        data: &[u8],
        packet: Option<&Packet>,
    ) -> Poll<Result<(), Error>> {
        self.frames.push((id, data.to_vec()));

        if let Some(packet) = packet {
            let payload = packet.data();
            let is_rdp_data = payload.len() > 5 && payload[payload.len() - 5] & 0x0f == 0x04;
            let captured = CapturedPacket {
                frames: core::mem::take(&mut self.frames),
                is_rdp_data,
            };
            if self.tx.send(captured).is_err() {
                return Poll::Ready(Err(Error::ConnectionClosed));
            }
        }

        Poll::Ready(Ok(()))
    }

    fn spawn_rx_task(&mut self, _iface: InterfaceID) {}
}

async fn relay_with_one_lost_data_packet(
    iface: InterfaceID,
    mut rx: mpsc::UnboundedReceiver<CapturedPacket>,
    dropped_data: Arc<AtomicBool>,
    observed_data: Arc<AtomicUsize>,
) {
    while let Some(packet) = rx.recv().await {
        if packet.is_rdp_data {
            observed_data.fetch_add(1, Ordering::Relaxed);
            if !dropped_data.swap(true, Ordering::AcqRel) {
                continue;
            }
        }

        // Reflect this frame sequence through a mock remote node. The interface
        // address becomes the destination and the mock peer becomes the source.
        for (frame_index, (mut id, mut data)) in packet.frames.into_iter().enumerate() {
            id &= !((0x3fff << 13) | (0x3f << 7));
            id |= (LOCAL_ADDR as u32) << 13;
            id |= ((REMOTE_ADDR as u32) & 0x3f) << 7;

            if frame_index == 0 {
                data[0] = (REMOTE_ADDR >> 6) as u8;
                data[1] = ((REMOTE_ADDR as u8 & 0x3f) << 2) | (data[1] & 0x03);
            }

            csp::interfaces::can::receive(iface, id, &data, 0)
                .await
                .unwrap();
        }
    }
}

async fn drive_router<T>(future: impl core::future::Future<Output = T>) -> T {
    tokio::pin!(future);

    loop {
        tokio::select! {
            result = &mut future => return result,
            _ = csp::route_work() => {}
        }
    }
}

#[tokio::test]
#[serial]
async fn rdp_stream_connects_and_reports_empty_read_timeout() {
    let listener = CspListener::bind(30).await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), async {
        let mut client = drive_router(CspStream::connect(
            Priority::Normal,
            0,
            30,
            ConnOptions::RDP,
        ))
        .await
        .unwrap();

        assert!(client.is_active());
        let mut buffer = [0; 32];
        let started = Instant::now();
        assert_eq!(client.read(&mut buffer, 25).await, Err(Error::Timeout));
        assert!(started.elapsed() >= Duration::from_millis(20));
        client.close().await;
    })
    .await;

    result.expect("RDP handshake or empty-read timeout failed");
    let mut listener = listener;
    listener.close().await;
}

#[tokio::test]
#[serial]
async fn rdp_stream_sends_and_receives_in_both_directions() {
    let listener = CspListener::bind(31).await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(3), async {
        // Keep routing active while the client completes the RDP handshake.
        let mut client = drive_router(CspStream::connect(
            Priority::Normal,
            0,
            31,
            ConnOptions::RDP,
        ))
        .await
        .unwrap();
        let mut server = drive_router(listener.accept(1_000)).await.unwrap();

        // Route each data packet and its acknowledgments while reading the peer.
        drive_router(async {
            assert_eq!(client.send(b"client to server").await, Ok(16));

            let mut request = [0; 32];
            let length = server.read(&mut request, 1_000).await.unwrap();
            assert_eq!(&request[..length], b"client to server");

            assert_eq!(server.send(b"server to client").await, Ok(16));

            let mut response = [0; 32];
            let length = client.read(&mut response, 1_000).await.unwrap();
            assert_eq!(&response[..length], b"server to client");
        })
        .await;

        client.close().await;
        server.close().await;
    })
    .await;

    result.expect("RDP send/receive exchange failed");
    let mut listener = listener;
    listener.close().await;
}

#[tokio::test]
#[serial]
async fn rdp_retransmits_data_after_mock_interface_drops_first_transmission() {
    static INTERFACE: StaticCell<CanInterface<LossyCanDriver>> = StaticCell::new();

    let (tx, rx) = mpsc::unbounded_channel();
    let interface = INTERFACE.init(CanInterface::new(
        LOCAL_ADDR,
        "RDP-loss-test",
        true,
        LossyCanDriver {
            tx,
            frames: Vec::new(),
        },
    ));
    let iface_id = add_interface(interface);
    let dropped_data = Arc::new(AtomicBool::new(false));
    let observed_data = Arc::new(AtomicUsize::new(0));
    let relay = tokio::spawn(relay_with_one_lost_data_packet(
        iface_id,
        rx,
        dropped_data.clone(),
        observed_data.clone(),
    ));
    let listener = CspListener::bind(32).await.unwrap();

    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut client = drive_router(CspStream::connect(
            Priority::Normal,
            REMOTE_ADDR,
            32,
            ConnOptions::RDP,
        ))
        .await
        .unwrap();
        let mut server = drive_router(listener.accept(2_000)).await.unwrap();

        drive_router(async {
            assert_eq!(client.send(b"retry after loss").await, Ok(16));

            let mut received = [0; 32];
            let length = server.read(&mut received, 3_000).await.unwrap();
            assert_eq!(&received[..length], b"retry after loss");
        })
        .await;

        assert!(dropped_data.load(Ordering::Acquire));
        assert!(
            observed_data.load(Ordering::Relaxed) >= 2,
            "expected the initial transmission and at least one retransmission"
        );

        client.close().await;
        server.close().await;
    })
    .await;

    relay.abort();
    let mut listener = listener;
    listener.close().await;
    result.expect("RDP did not recover from the dropped data packet");
}
