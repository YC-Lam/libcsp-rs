#[cfg(feature = "embassy_stm32")]
pub mod can_embassy_stm32;

#[cfg(feature = "embassy_stm32")]
pub mod embassy_stm32{
    pub use super::can_embassy_stm32::CanStm32Driver;
}