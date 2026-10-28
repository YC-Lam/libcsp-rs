use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::{Context, Poll};

use embassy_executor::SendSpawner;
use embassy_stm32::i2c::{I2c, Master, MultiMaster, SlaveAddrConfig, SlaveCommandKind};
use embassy_stm32::mode::Async;
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::waitqueue::AtomicWaker;

use crate::Error;
use crate::interfaces::InterfaceID;
use crate::interfaces::i2c::{self, I2C_MAX_FRAME_SIZE, I2cInterfaceDriver};

const TX_SLOT_COUNT: usize = crate::buffer::CSP_BUFFER_COUNT;
const TX_FREE: u8 = 0;
const TX_WRITING: u8 = 1;
const TX_QUEUED: u8 = 2;
const TX_RUNNING: u8 = 3;
const TX_OK: u8 = 4;
const TX_ERROR: u8 = 5;

struct TxFrame {
    address: u8,
    len: usize,
    bytes: [u8; I2C_MAX_FRAME_SIZE],
}

impl TxFrame {
    const fn new() -> Self {
        Self {
            address: 0,
            len: 0,
            bytes: [0; I2C_MAX_FRAME_SIZE],
        }
    }
}

struct TxSlot {
    status: AtomicU8,
    waker: AtomicWaker,
    frame: UnsafeCell<TxFrame>,
}

impl TxSlot {
    const fn new() -> Self {
        Self {
            status: AtomicU8::new(TX_FREE),
            waker: AtomicWaker::new(),
            frame: UnsafeCell::new(TxFrame::new()),
        }
    }
}

unsafe impl Sync for TxSlot {}

/// Static work queue shared by the interface's TX path and its Embassy task.
pub struct I2cTxQueue {
    requests: Channel<CriticalSectionRawMutex, usize, TX_SLOT_COUNT>,
    slots: [TxSlot; TX_SLOT_COUNT],
    queue_waker: AtomicWaker,
    stopped: AtomicBool,
}

impl I2cTxQueue {
    /// Create an empty, statically allocatable TX queue.
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

/// Embassy STM32 driver for an I2C peripheral operating as both controller and target.
///
/// The application configures the peripheral in async master mode, then supplies
/// its local seven-bit target address. The driver converts it to Embassy's
/// multimaster mode and starts a task when the CSP interface is registered.
pub struct I2cStm32Driver {
    i2c: Option<I2c<'static, Async, MultiMaster>>,
    tx_queue: &'static I2cTxQueue,
    spawner: SendSpawner,
}

impl I2cStm32Driver {
    /// Configure an async Embassy I2C peripheral for controller and target operation.
    pub fn new(
        i2c: I2c<'static, Async, Master>,
        own_address: u8,
        tx_queue: &'static I2cTxQueue,
        spawner: SendSpawner,
    ) -> Self {
        let i2c = i2c.into_slave_multimaster(SlaveAddrConfig::basic(own_address & 0x7f));
        Self {
            i2c: Some(i2c),
            tx_queue,
            spawner,
        }
    }
}

impl I2cInterfaceDriver for I2cStm32Driver {
    fn poll_tx_frame(
        &mut self,
        cx: &mut Context<'_>,
        address: u8,
        frame: &[u8],
        state: &mut crate::interfaces::TxState,
    ) -> Poll<Result<(), Error>> {
        if address > 0x7f {
            return Poll::Ready(Err(Error::InvalidOperation));
        }
        if frame.len() > I2C_MAX_FRAME_SIZE {
            return Poll::Ready(Err(Error::BufferOverflow));
        }
        if self.tx_queue.stopped.load(Ordering::Acquire) {
            return Poll::Ready(Err(Error::CanBusError));
        }

        if state.started {
            let slot = &self.tx_queue.slots[state.ticket];
            let status = slot.status.load(Ordering::Acquire);
            match status {
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
                    return Poll::Ready(Err(Error::CanBusError));
                }
                _ => {
                    slot.waker.register(cx.waker());
                    let status = slot.status.load(Ordering::Acquire);
                    if status == TX_OK || status == TX_ERROR {
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

        // The WRITING state gives this caller exclusive access until the request
        // is published to the worker using the QUEUED release store.
        unsafe {
            let tx = &mut *slot.frame.get();
            tx.address = address;
            tx.len = frame.len();
            tx.bytes[..frame.len()].copy_from_slice(frame);
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
        let i2c = self
            .i2c
            .take()
            .expect("I2C receive task can only be spawned once");
        let task = i2c_task(i2c, iface, self.tx_queue)
            .unwrap_or_else(|error| panic!("failed to create I2C task: {error}"));
        self.spawner.spawn(task);
    }
}

#[embassy_executor::task(pool_size = 4)]
async fn i2c_task(
    mut i2c: I2c<'static, Async, MultiMaster>,
    iface: InterfaceID,
    tx_queue: &'static I2cTxQueue,
) {
    loop {
        match embassy_futures::select::select(i2c.listen(), tx_queue.requests.receive()).await {
            embassy_futures::select::Either::First(Ok(command)) => match command.kind {
                SlaveCommandKind::Write => {
                    let mut frame = [0; I2C_MAX_FRAME_SIZE + 1];
                    match i2c.respond_to_write(&mut frame).await {
                        Ok(length) => {
                            if let Err(error) = i2c::receive_frame(iface, &frame[..length]).await {
                                defmt::warn!("I2C frame rejected: {:?}", error);
                            }
                        }
                        Err(_) => defmt::warn!("I2C target receive failed"),
                    }
                }
                // CSP I2C frames are delivered to the target using controller writes.
                // Return an invalid one-byte frame to release the bus for unsupported reads.
                SlaveCommandKind::Read => {
                    if i2c.respond_to_read(&[0]).await.is_err() {
                        defmt::warn!("I2C target read response failed");
                    }
                }
            },
            embassy_futures::select::Either::First(Err(_)) => {
                defmt::warn!("I2C listen failed; stopping I2C task");
                tx_queue.stopped.store(true, Ordering::Release);
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
            embassy_futures::select::Either::Second(slot_index) => {
                tx_queue.queue_waker.wake();
                let slot = &tx_queue.slots[slot_index];
                if slot
                    .status
                    .compare_exchange(TX_QUEUED, TX_RUNNING, Ordering::AcqRel, Ordering::Acquire)
                    .is_err()
                {
                    continue;
                }

                // TX_RUNNING reserves the frame until the write finishes.
                let tx = unsafe { &*slot.frame.get() };
                let result = i2c.write(tx.address, &tx.bytes[..tx.len]).await;
                slot.status.store(
                    if result.is_ok() { TX_OK } else { TX_ERROR },
                    Ordering::Release,
                );
                slot.waker.wake();
            }
        }
    }
}
