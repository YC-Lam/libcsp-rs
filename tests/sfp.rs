use csp::{ConnOptions, Error, Priority, SfpListener, SfpStream};
use serial_test::serial;

#[tokio::test]
#[serial]
async fn sfp_stream_fragments_and_reassembles_a_transfer() {
    let listener = SfpListener::bind(14).await.unwrap();
    let mut client = SfpStream::connect(Priority::Normal, 0, 14, ConnOptions::NONE)
        .await
        .unwrap();
    assert_eq!(client.max_mtu(), Ok(248));

    let data: Vec<u8> = (0..37).map(|byte| byte as u8).collect();
    let mut read_offsets = Vec::new();
    client
        .send(data.len() as u32, 8, |fragment, offset| {
            read_offsets.push(offset);
            let start = offset as usize;
            fragment.copy_from_slice(&data[start..start + fragment.len()]);
            Ok(())
        })
        .await
        .unwrap();
    assert_eq!(read_offsets, [0, 8, 16, 24, 32]);

    for _ in 0..read_offsets.len() {
        csp::route_work().await;
    }

    let mut server = listener.accept(1_000).await.unwrap();
    let mut received = Vec::new();
    let mut write_offsets = Vec::new();
    server
        .receive(1_000, |fragment, offset, total_size| {
            assert_eq!(total_size, data.len() as u32);
            write_offsets.push(offset);
            received.extend_from_slice(fragment);
            Ok(())
        })
        .await
        .unwrap();

    assert_eq!(write_offsets, [0, 8, 16, 24, 32]);
    assert_eq!(received, data);

    server.close().await;
    client.close().await;
    let mut listener = listener;
    listener.close().await;
}

#[tokio::test]
#[serial]
async fn sfp_send_validates_mtu_and_propagates_callback_errors() {
    let listener = SfpListener::bind(15).await.unwrap();
    let mut client = SfpStream::connect(Priority::Normal, 0, 15, ConnOptions::NONE)
        .await
        .unwrap();
    let max_mtu = client.max_mtu().unwrap();

    assert_eq!(
        client.send(1, max_mtu + 1, |_, _| Ok(())).await,
        Err(Error::Mtu)
    );
    assert_eq!(
        client.send(1, 1, |_, _| Err(Error::Timeout)).await,
        Err(Error::Timeout)
    );

    client.close().await;
    let mut listener = listener;
    listener.close().await;
}
