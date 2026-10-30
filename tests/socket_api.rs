use csp::{
    CSP_ANY, ConnOptions, CspListener, CspStream, Error, Priority, SfpListener, SfpStream,
    UdpSocket,
};

#[tokio::test]
async fn listener_stream_udp_and_sfp_apis_work_over_loopback() {
    let listener = CspListener::bind(20).await.unwrap();
    assert_eq!(listener.local_port(), csp::SocketPort::Port(20));
    assert_eq!(listener.accept(0).await.err(), Some(Error::Timeout));

    // Pump the router explicitly so each loopback send is delivered before the matching read.
    let mut client = CspStream::connect(Priority::Normal, 0, 20, ConnOptions::NONE)
        .await
        .unwrap();
    assert_eq!(client.peer_addr(), 0);
    assert_eq!(client.peer_port(), 20);
    assert_eq!(client.send(b"request").await, Ok(7));
    csp::route_work().await;

    let mut server = listener.accept(1_000).await.unwrap();
    assert_eq!(server.peer_addr(), 0);
    assert_eq!(server.local_port(), 20);
    let mut request = [0; 16];
    let length = server.read(&mut request, 1_000).await.unwrap();
    assert_eq!(&request[..length], b"request");

    assert_eq!(server.send(b"response").await, Ok(8));
    csp::route_work().await;
    let mut response = [0; 16];
    let length = client.read(&mut response, 1_000).await.unwrap();
    assert_eq!(&response[..length], b"response");
    server.close().await;
    client.close().await;

    let mut datagram_receiver = UdpSocket::bind(21).await.unwrap();
    let mut datagram_sender = UdpSocket::bind(22).await.unwrap();
    assert_eq!(UdpSocket::bind(21).await.err(), Some(Error::PortBusy));
    assert_eq!(datagram_sender.local_port(), 22);
    assert_eq!(
        datagram_sender
            .send_to(Priority::High, 0, 21, ConnOptions::NONE, b"datagram",)
            .await,
        Ok(8)
    );
    csp::route_work().await;
    let mut datagram = [0; 16];
    let (length, peer) = datagram_receiver
        .recv_from(&mut datagram, 1_000)
        .await
        .unwrap();
    assert_eq!(&datagram[..length], b"datagram");
    assert_eq!(peer.addr, 0);
    assert_eq!(peer.port, 22);
    datagram_receiver.close().await;
    datagram_sender.close().await;
    let mut rebound_socket = UdpSocket::bind(21).await.unwrap();
    rebound_socket.close().await;
    assert_eq!(
        UdpSocket::bind(CSP_ANY).await.err(),
        Some(Error::InvalidOperation)
    );

    // SFP splits a message into 8-byte chunks and reassembles them at the listener.
    let sfp_listener = SfpListener::bind(23).await.unwrap();
    assert_eq!(sfp_listener.local_port(), csp::SocketPort::Port(23));
    let mut sfp_client = SfpStream::connect(Priority::Normal, 0, 23, ConnOptions::NONE)
        .await
        .unwrap();
    assert_eq!(sfp_client.max_mtu().unwrap(), 248);
    assert_eq!(sfp_client.send(1, 0, |_, _| Ok(())).await, Err(Error::Mtu));
    let data: Vec<u8> = (0..35).map(|byte| byte as u8).collect();
    sfp_client
        .send(data.len() as u32, 8, |fragment, offset| {
            let start = offset as usize;
            fragment.copy_from_slice(&data[start..start + fragment.len()]);
            Ok(())
        })
        .await
        .unwrap();

    for _ in 0..data.len().div_ceil(8) {
        csp::route_work().await;
    }

    let mut sfp_server = sfp_listener.accept(1_000).await.unwrap();
    let mut received = vec![0; data.len()];
    sfp_server
        .receive(1_000, |fragment, offset, total| {
            assert_eq!(total as usize, received.len());
            let start = offset as usize;
            received[start..start + fragment.len()].copy_from_slice(fragment);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(received, data);
    sfp_server.close().await;
    sfp_client.close().await;

    let mut listener = listener;
    listener.close().await;
    let mut sfp_listener = sfp_listener;
    sfp_listener.close().await;
}
