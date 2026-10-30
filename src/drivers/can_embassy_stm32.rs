use core::task::{Context, Poll};

use embassy_executor::SendSpawner;
use embassy_stm32::can::{BufferedCanReceiver, BufferedCanSender, Frame};
use embedded_can::Id;

use crate::interfaces::InterfaceID;
use crate::interfaces::can::{self, CanInterfaceDriver};
use crate::{Error, Packet};

/// Embassy STM32 CAN transmitter backed by the HAL's buffered classic CAN
/// interface. The application owns peripheral initialization and buffer storage.
///
/// For example, with an FDCAN peripheral, configure it and allocate the HAL's
/// TX/RX queues before creating the CSP interface. Keep the buffered peripheral
/// and buffers alive for as long as the interface is in use. Registering the
/// interface starts its receive task:
///
/// ```ignore
/// use embassy_stm32::can::fdcan::{CanConfigurator, RxBuf, TxBuf};
/// use embassy_executor::Spawner;
/// use embassy_sync::channel::Channel;
/// use static_cell::StaticCell;
/// use csp::interfaces::{add_interface, can::CanInterface};
/// use csp::drivers::embassy_stm32::CanStm32Driver;
///
/// static TX_BUF: StaticCell<TxBuf<16>> = StaticCell::new();
/// static RX_BUF: StaticCell<RxBuf<16>> = StaticCell::new();
/// static CAN_IFACE: StaticCell<CanInterface<CanStm32Driver>> = StaticCell::new();
///
/// // In your Embassy main/task, construct it for your MCU, pins, and IRQ bindings.
/// let mut configurator =
///     CanConfigurator::new(peripherals.FDCAN1, peripherals.PA11, peripherals.PA12, Irqs);
/// configurator.set_bitrate(500_000);
/// let can = configurator.into_normal_mode();
///
/// let can = can.buffered(
///     TX_BUF.init(Channel::new()),
///     RX_BUF.init(Channel::new()),
/// );
/// let driver = CanStm32Driver::new(
///     can.writer(),
///     can.reader(),
///     spawner.make_send(),
/// );
///
/// let iface = CAN_IFACE.init(CanInterface::new(1, "CAN", true, driver));
/// let iface_id = add_interface(iface);
///
/// // `add_interface` calls the interface's start hook, which spawns the RX task.
/// // Keep `can` in scope while CSP uses this interface.
/// ```
pub struct CanStm32Driver {
    spawner: SendSpawner,
    rx: BufferedCanReceiver,
    tx: BufferedCanSender,
}

impl CanStm32Driver {
    /// Create a driver from a buffered CAN writer, receiver, and task spawner.
    ///
    /// The receive task is spawned automatically when the CSP interface is
    /// registered with `add_interface`.
    pub const fn new(tx: BufferedCanSender, rx: BufferedCanReceiver, spawner: SendSpawner) -> Self {
        Self { tx, rx, spawner }
    }
}

impl CanInterfaceDriver for CanStm32Driver {
    fn spawn_rx_task(&mut self, id: InterfaceID) {
        let token = can_rx_task(self.rx.clone(), id)
            .unwrap_or_else(|error| panic!("failed to create CAN receive task: {error}"));
        self.spawner.spawn(token);
    }

    fn poll_tx_frame(
        &mut self,
        cx: &mut Context<'_>,
        id: u32,
        data: &[u8],
        _packet: Option<&Packet>,
    ) -> Poll<Result<(), Error>> {
        let frame = Frame::new_extended(id, data).map_err(|_| Error::InvalidOperation)?;

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
async fn can_rx_task(rx: BufferedCanReceiver, iface: InterfaceID) {
    loop {
        if let Ok(envelope) = rx.receive().await {
            let timestamp_rx = timestamp_to_ms(envelope.ts);
            let frame = envelope.frame;

            let id = match *frame.id() {
                Id::Extended(id) => id.as_raw(),
                // ignore standard ID
                Id::Standard(_) => continue,
            };

            let _ = can::receive(iface, id, frame.data(), timestamp_rx).await;
        };
    }
}

//#[cfg(feature = "embassy_stm32_time")]
fn timestamp_to_ms(timestamp: embassy_time::Instant) -> u32 {
    timestamp.as_millis().min(u32::MAX as u64) as u32
}

/*
#[cfg(not(feature = "embassy_stm32_time"))]
fn timestamp_to_ms(timestamp: u16) -> u32 {
    timestamp as u32
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_feature_uses_timestamp_conversion() {
        #[cfg(not(feature = "embassy_stm32_time"))]
        assert_eq!(timestamp_to_ms(0x1234), 0x1234);

        #[cfg(feature = "embassy_stm32_time")]
        assert_eq!(
            timestamp_to_ms(embassy_time::Instant::from_millis(1234)),
            1234
        );
    }
}
