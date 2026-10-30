#[cfg(feature = "embassy_stm32")]
pub mod can_embassy_stm32;
#[cfg(feature = "embassy_stm32")]
pub mod i2c_embassy_stm32;
#[cfg(feature = "embassy_stm32")]
pub mod kiss_embassy_stm32;

#[cfg(feature = "zmq")]
pub mod zmq;

#[cfg(feature = "embassy_stm32")]
pub mod embassy_stm32 {
    pub use super::can_embassy_stm32::CanStm32Driver;
    pub use super::i2c_embassy_stm32::{I2cStm32Driver, I2cTxQueue};
    pub use super::kiss_embassy_stm32::{UartTxQueue, UartStm32Driver};
}
