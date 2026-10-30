use csp::Error;
use csp::cmp::{self, Identity};
use csp::services::{self, ServiceHooks};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

async fn drive_router<T>(future: impl core::future::Future<Output = T>) -> T {
    tokio::pin!(future);

    loop {
        tokio::select! {
            result = &mut future => return result,
            _ = csp::route_work() => {}
        }
    }
}

fn memory_free() -> u32 {
    0x1234_5678
}

fn clock_get() -> (u32, u32) {
    (1_700_000_000, 123_456_789)
}

fn process_list(output: &mut [u8]) -> Result<usize, Error> {
    let listing = b"worker: running\n";
    output[..listing.len()].copy_from_slice(listing);
    Ok(listing.len())
}

static REBOOT_CALLED: AtomicBool = AtomicBool::new(false);

fn reboot() {
    REBOOT_CALLED.store(true, Ordering::Release);
}

static HOOKS: ServiceHooks = ServiceHooks {
    identity: Identity::new(
        *b"test-node\0\0\0\0\0\0\0",
        *b"test-model\0\0\0\0\0\0",
        *b"revision-1\0\0\0\0\0\0\0\0\0\0",
        *b"Oct 28 2026\0",
        *b"19:49:59\0",
    ),
    memory_free: Some(memory_free),
    process_list: Some(process_list),
    reboot: Some(reboot),
    shutdown: None,
    clock_get: Some(clock_get),
    clock_set: None,
};

#[tokio::test]
async fn built_in_services_and_cmp_requests_round_trip_over_loopback() {
    // Keep platform hooks alive for the entire test, as required by the API.
    services::set_hooks(&HOOKS);

    let result = tokio::time::timeout(Duration::from_secs(3), async {
        // Drive the local router alongside each client request to emulate a node.
        let mut ping_payload = *b"ping-test";
        assert!(
            drive_router(services::ping(0, 1_000, &mut ping_payload))
                .await
                .unwrap()
                < 1_000
        );

        assert_eq!(
            drive_router(services::get_memfree(0, 1_000)).await,
            Ok(0x1234_5678)
        );
        assert!(drive_router(services::get_uptime(0, 1_000)).await.unwrap() > 0);
        let free_buffers = drive_router(services::get_buffer_free(0, 1_000))
            .await
            .unwrap();
        assert!(free_buffers > 0);

        let identity = drive_router(cmp::get_identity(0, 1_000)).await.unwrap();
        assert_eq!(identity.hostname, HOOKS.identity.hostname);
        assert_eq!(identity.model, HOOKS.identity.model);

        let stats = drive_router(cmp::get_interface_stats(0, 1_000, "LOOP"))
            .await
            .unwrap();
        assert!(stats.tx > 0 && stats.rx > 0);
        assert_eq!(stats.tx_error, 0);
        assert_eq!(stats.rx_error, 0);

        let clock = drive_router(cmp::clock(0, 1_000, None)).await.unwrap();
        assert_eq!(clock, (1_700_000_000, 123_456_789));

        #[cfg(feature = "rtable")]
        {
            // Route installation is available only when the route-table feature is enabled.
            drive_router(cmp::set_route_v2(0, 1_000, 0x1234, 14, None, "LOOP"))
                .await
                .unwrap();
            let installed = csp::rtable::find_route(0x1234).await.unwrap();
            assert_eq!(installed.netmask, 14);
            assert_eq!(installed.via, None);
            csp::rtable::clear().await;
        }

        let mut process_data = [0; 32];
        let length = drive_router(services::process_list(0, 1_000, &mut process_data))
            .await
            .unwrap();
        assert_eq!(&process_data[..length], b"worker: running\n");

        drive_router(services::reboot(0)).await.unwrap();
        csp::route_work().await;
        assert!(REBOOT_CALLED.swap(false, Ordering::AcqRel));

        let mut unsupported = [0; 1];
        // PEEK is intentionally unsupported because it exposes arbitrary memory.
        assert_eq!(
            drive_router(cmp::request(0, 50, cmp::PEEK, &mut unsupported)).await,
            Err(Error::Timeout)
        );
    })
    .await;

    services::clear_hooks();
    result.expect("service or CMP request timed out");
}
