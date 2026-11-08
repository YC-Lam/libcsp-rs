use core::task::{Context, Poll};

use embassy_executor::SendSpawner;
use embassy_stm32::can::frame::{FdFrame, Header};
use embassy_stm32::can::{BufferedFdCanReceiver, BufferedFdCanSender};
use embedded_can::{ExtendedId, Id};

use crate::interfaces::InterfaceID;
use crate::interfaces::can::CanInterfaceDriver;
use crate::interfaces::canfd;
use crate::{Error, Packet};

/// Embassy STM32 FDCAN driver for [`canfd::CanFdInterface`].
///
/// Configure the peripheral to allow CAN-FD and bit-rate-switching frames
/// before calling `buffered_fd` (for example, with
/// `CanConfigurator::set_fd_data_bitrate`), and keep the buffered peripheral
/// and its backing queues alive for the lifetime of the interface. Registering
/// the CSP interface starts its receive task.
pub struct CanFdStm32Driver {
    spawner: SendSpawner,
    rx: BufferedFdCanReceiver,
    tx: BufferedFdCanSender,
}

impl CanFdStm32Driver {
    /// Create a driver from buffered FDCAN writer, receiver, and task spawner.
    pub const fn new(
        tx: BufferedFdCanSender,
        rx: BufferedFdCanReceiver,
        spawner: SendSpawner,
    ) -> Self {
        Self { tx, rx, spawner }
    }
}

impl CanInterfaceDriver for CanFdStm32Driver {
    fn spawn_rx_task(&mut self, id: InterfaceID) {
        let token = can_fd_rx_task(self.rx.clone(), id)
            .unwrap_or_else(|error| panic!("failed to create CAN-FD receive task: {error}"));
        self.spawner.spawn(token);
    }

    fn poll_tx_frame(
        &mut self,
        cx: &mut Context<'_>,
        id: u32,
        data: &[u8],
        _packet: Option<&Packet>,
    ) -> Poll<Result<(), Error>> {
        let Some(extended_id) = ExtendedId::new(id) else {
            return Poll::Ready(Err(Error::InvalidOperation));
        };
        let header = Header::new_fd(Id::Extended(extended_id), data.len() as u8, false, true);
        let frame = FdFrame::new(header, data).map_err(|_| Error::InvalidOperation)?;

        match self.tx.try_write(frame) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(embassy_sync::channel::TrySendError::Full(frame)) => {
                if self.tx.poll_ready_to_send(cx).is_pending() {
                    return Poll::Pending;
                }

                match self.tx.try_write(frame) {
                    Ok(()) => Poll::Ready(Ok(())),
                    Err(embassy_sync::channel::TrySendError::Full(_frame)) => {
                        if self.tx.poll_ready_to_send(cx).is_ready() {
                            cx.waker().wake_by_ref();
                        }
                        Poll::Pending
                    }
                }
            }
        }
    }
}

#[embassy_executor::task(pool_size = 6)]
async fn can_fd_rx_task(rx: BufferedFdCanReceiver, iface: InterfaceID) {
    loop {
        match rx.receive().await {
            Ok(envelope) => {
                let timestamp_rx = timestamp_to_ms(envelope.ts);
                let frame = envelope.frame;
                let id = match *frame.id() {
                    Id::Extended(id) => id.as_raw(),
                    Id::Standard(_) => continue,
                };
                if let Err(error) = canfd::receive(iface, id, frame.data(), timestamp_rx).await {
                    defmt::debug!("CAN-FD frame rejected: {:?}", error);
                }
            }
            Err(_) => defmt::warn!("CAN-FD receive error"),
        }
    }
}

fn timestamp_to_ms(timestamp: embassy_time::Instant) -> u32 {
    timestamp.as_millis().min(u32::MAX as u64) as u32
}
