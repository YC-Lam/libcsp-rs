use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::{Context, Poll};

use embassy_executor::SendSpawner;
use embassy_stm32::mode::Async;
use embassy_stm32::usart::{Uart, UartRx, UartTx};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::AtomicWaker;

use crate::Error;
use crate::interfaces::InterfaceID;
use crate::interfaces::kiss::{self, KISS_MAX_ENCODED_SIZE, KissInterfaceDriver, KissRxState};

const TX_SLOT_COUNT: usize = 4;
const TX_FREE: u8 = 0;
const TX_WRITING: u8 = 1;
const TX_QUEUED: u8 = 2;
const TX_RUNNING: u8 = 3;
const TX_OK: u8 = 4;
const TX_ERROR: u8 = 5;

struct TxSlot {
    status: AtomicU8,
    waker: AtomicWaker,
    length: UnsafeCell<usize>,
    bytes: UnsafeCell<[u8; KISS_MAX_ENCODED_SIZE]>,
}

impl TxSlot {
    const fn new() -> Self {
        Self {
            status: AtomicU8::new(TX_FREE),
            waker: AtomicWaker::new(),
            length: UnsafeCell::new(0),
            bytes: UnsafeCell::new([0; KISS_MAX_ENCODED_SIZE]),
        }
    }
}

unsafe impl Sync for TxSlot {}

/// Static work queue shared by the interface's TX path and Embassy worker.
pub struct UartTxQueue {
    requests: Channel<CriticalSectionRawMutex, usize, TX_SLOT_COUNT>,
    slots: [TxSlot; TX_SLOT_COUNT],
    queue_waker: AtomicWaker,
    stopped: AtomicBool,
}

impl UartTxQueue {
    /// Create an empty, statically allocatable KISS TX queue.
    pub const fn new() -> Self {
        Self {
            requests: Channel::new(),
            slots: [const { TxSlot::new() }; TX_SLOT_COUNT],
            queue_waker: AtomicWaker::new(),
            stopped: AtomicBool::new(false),
        }
    }

    fn reserve_slot(&self) -> Option<usize> {
        self.slots.iter().position(|slot| {
            slot.status
                .compare_exchange(TX_FREE, TX_WRITING, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        })
    }
}

/// Embassy STM32 UART driver for [`KissInterface`](crate::interfaces::kiss::KissInterface).
///
/// The application configures an asynchronous UART, provides a static
/// [`UartTxQueue`], and supplies a send-capable Embassy spawner. Registering
/// the interface starts independent receive and transmit tasks.
pub struct UartStm32Driver {
    tx: Option<UartTx<'static, Async>>,
    rx: Option<UartRx<'static, Async>>,
    tx_queue: &'static UartTxQueue,
    spawner: SendSpawner,
}

impl UartStm32Driver {
    /// Split an async UART into its transmit and receive halves.
    pub fn new(
        uart: Uart<'static, Async>,
        tx_queue: &'static UartTxQueue,
        spawner: SendSpawner,
    ) -> Self {
        let (tx, rx) = uart.split();
        Self {
            tx: Some(tx),
            rx: Some(rx),
            tx_queue,
            spawner,
        }
    }
}

impl KissInterfaceDriver for UartStm32Driver {
    fn poll_tx_frame(
        &mut self,
        cx: &mut Context<'_>,
        frame: &[u8],
        state: &mut crate::interfaces::TxState,
    ) -> Poll<Result<(), Error>> {
        if frame.len() > KISS_MAX_ENCODED_SIZE {
            return Poll::Ready(Err(Error::BufferOverflow));
        }
        if self.tx_queue.stopped.load(Ordering::Acquire) {
            return Poll::Ready(Err(Error::Uart));
        }

        if state.started {
            let slot = &self.tx_queue.slots[state.ticket];
            match slot.status.load(Ordering::Acquire) {
                TX_OK => {
                    slot.status.store(TX_FREE, Ordering::Release);
                    state.started = false;
                    self.tx_queue.queue_waker.wake();
                    return Poll::Ready(Ok(()));
                }
                TX_ERROR => {
                    slot.status.store(TX_FREE, Ordering::Release);
                    state.started = false;
                    self.tx_queue.queue_waker.wake();
                    return Poll::Ready(Err(Error::Uart));
                }
                _ => {
                    slot.waker.register(cx.waker());
                    if matches!(slot.status.load(Ordering::Acquire), TX_OK | TX_ERROR) {
                        cx.waker().wake_by_ref();
                    }
                    return Poll::Pending;
                }
            }
        }

        let Some(slot_index) = self.tx_queue.reserve_slot() else {
            self.tx_queue.queue_waker.register(cx.waker());
            if self
                .tx_queue
                .slots
                .iter()
                .any(|slot| slot.status.load(Ordering::Acquire) == TX_FREE)
            {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        };
        let slot = &self.tx_queue.slots[slot_index];
        slot.waker.register(cx.waker());

        // TX_WRITING gives this call exclusive access until the worker sees QUEUED.
        unsafe {
            *slot.length.get() = frame.len();
            (&mut *slot.bytes.get())[..frame.len()].copy_from_slice(frame);
        }
        slot.status.store(TX_QUEUED, Ordering::Release);

        if self.tx_queue.requests.try_send(slot_index).is_err() {
            slot.status.store(TX_FREE, Ordering::Release);
            self.tx_queue.queue_waker.register(cx.waker());
            if self.tx_queue.requests.free_capacity() != 0 {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }

        state.ticket = slot_index;
        state.started = true;
        Poll::Pending
    }

    fn spawn_rx_task(&mut self, iface: InterfaceID) {
        let tx = self
            .tx
            .take()
            .expect("KISS transmit task can only be spawned once");
        let tx_task = kiss_tx_task(tx, self.tx_queue)
            .unwrap_or_else(|error| panic!("failed to create KISS transmit task: {error}"));
        self.spawner.spawn(tx_task);

        let rx = self
            .rx
            .take()
            .expect("KISS receive task can only be spawned once");
        let rx_task = kiss_rx_task(rx, iface)
            .unwrap_or_else(|error| panic!("failed to create KISS receive task: {error}"));
        self.spawner.spawn(rx_task);
    }
}

#[embassy_executor::task(pool_size = 4)]
async fn kiss_tx_task(mut tx: UartTx<'static, Async>, tx_queue: &'static UartTxQueue) {
    loop {
        let slot_index = tx_queue.requests.receive().await;
        tx_queue.queue_waker.wake();
        let slot = &tx_queue.slots[slot_index];
        if slot
            .status
            .compare_exchange(TX_QUEUED, TX_RUNNING, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            continue;
        }

        let length = unsafe { *slot.length.get() };
        let result = if tx
            .write(unsafe { &(&*slot.bytes.get())[..length] })
            .await
            .is_ok()
        {
            tx.flush().await.is_ok()
        } else {
            false
        };
        if !result {
            tx_queue.stopped.store(true, Ordering::Release);
        }
        slot.status
            .store(if result { TX_OK } else { TX_ERROR }, Ordering::Release);
        slot.waker.wake();

        if !result {
            for slot in &tx_queue.slots {
                if slot
                    .status
                    .compare_exchange(TX_QUEUED, TX_ERROR, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    slot.waker.wake();
                }
            }
            tx_queue.queue_waker.wake();
            return;
        }
    }
}

#[embassy_executor::task(pool_size = 4)]
async fn kiss_rx_task(mut rx: UartRx<'static, Async>, iface: InterfaceID) {
    let mut decoder = KissRxState::new();
    let mut bytes = [0; 64];
    loop {
        match rx.read_until_idle(&mut bytes).await {
            Ok(length) => {
                if let Err(error) = kiss::receive_bytes(iface, &mut decoder, &bytes[..length]).await
                {
                    defmt::debug!("KISS frame rejected: {:?}", error);
                }
            }
            Err(_) => {
                defmt::warn!("KISS UART receive failed");
                return;
            }
        }
    }
}
