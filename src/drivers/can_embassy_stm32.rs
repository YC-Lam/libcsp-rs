use core::task::{Context, Poll};

use embassy_stm32::can::{BufferedCanSender, BufferedCanReceiver, Frame};
use embedded_can::Id;
use embassy_executor::SendSpawner;

use crate::interfaces::InterfaceID;
use crate::interfaces::can::{self, CanInterfaceDriver};
use crate::{Error, Packet};

/// Embassy STM32 CAN transmitter backed by the HAL's buffered classic CAN
/// interface. The application owns peripheral initialization and buffer storage.
///
/// For example, with a bxCAN peripheral, allocate the HAL's TX/RX queues and
/// turn the peripheral into a `BufferedCan`. The peripheral and buffers must
/// remain alive while the CSP interface is in use:
///
/// ```ignore
/// use embassy_stm32::can::CanConfigurator;
/// use static_cell::StaticCell;
/// use csp::{add_interface, CanInterface};
/// use csp::drivers::embassy_stm32::CanStm32Driver;
///
/// static CAN_IFACE: StaticCell<CanInterface<CanStm32Driver>> = StaticCell::new();
///
/// // Construct the peripheral for your MCU, pins, and CAN interrupts.
/// let mut can = CanConfigurator::new(peripherals.FDCAN1, peripherals.PA11, peripherals.PA12, Irqs);
///
/// let driver = CanStm32Driver::new(can, spawner, 500_000, filter_addr, filter_netmask);
///
/// let iface = CAN_IFACE.init(CanInterface::new(addr, "CAN", true, driver));
/// let iface_id = add_interface(iface);
///
/// ```
pub struct CanStm32Driver {
    spawner: SendSpawner,
    rx: BufferedCanReceiver,
    tx: BufferedCanSender,
}

impl CanStm32Driver {
    /// Create a driver from the transmitter returned by
    /// `embassy_stm32::can::BufferedCan::writer()`.
    pub const fn new(tx: BufferedCanSender, rx: BufferedCanReceiver, spawner: SendSpawner) -> Self {
        Self { 
            tx,
            rx,
            spawner
        }
    }
}

impl CanInterfaceDriver for CanStm32Driver {
    fn spawn_rx_task(&mut self, id: InterfaceID){
        // start can interface
        if let Ok(token) = can_rx_task(self.rx.clone(), id){
            self.spawner.spawn(token);
        } else{
            // todo
        }
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
async fn can_rx_task(rx: BufferedCanReceiver, iface: InterfaceID){
    loop{
        if let Ok(envelope) = rx.receive().await{
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

#[cfg(feature = "embassy_stm32_time")]
fn timestamp_to_ms(timestamp: embassy_time::Instant) -> u32 {
    timestamp.as_millis().min(u32::MAX as u64) as u32
}

#[cfg(not(feature = "embassy_stm32_time"))]
fn timestamp_to_ms(timestamp: u16) -> u32 {
    timestamp as u32
}

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
