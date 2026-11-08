#![no_std]
#![no_main]

use embassy_executor::Spawner;
use embassy_stm32::peripherals::*;
use embassy_stm32::{Config, bind_interrupts, can};
use embassy_time::Timer;
use static_cell::StaticCell;

use csp::drivers::embassy_stm32::CanFdStm32Driver;
use csp::interfaces::CanFdInterface;
use csp::{add_interface, init};

static TX_BUF: StaticCell<can::TxFdBuf<16>> = StaticCell::new();
static RX_BUF: StaticCell<can::RxFdBuf<16>> = StaticCell::new();
static CAN_IFACE: StaticCell<CanFdInterface<CanFdStm32Driver>> = StaticCell::new();

bind_interrupts!(struct Irqs {
    FDCAN1_IT0 => can::IT0InterruptHandler<FDCAN1>;
    FDCAN1_IT1 => can::IT1InterruptHandler<FDCAN1>;
});

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let peripherals = embassy_stm32::init(Config::default());
    let mut configurator =
        can::CanConfigurator::new(peripherals.FDCAN1, peripherals.PA11, peripherals.PA12, Irqs);
    configurator.set_bitrate(500_000);
    configurator.set_fd_data_bitrate(2_000_000, false);

    let can = configurator.into_normal_mode();
    let can = can.buffered_fd(
        TX_BUF.init(can::TxFdBuf::new()),
        RX_BUF.init(can::RxFdBuf::new()),
    );
    let driver = CanFdStm32Driver::new(can.writer(), can.reader(), spawner.make_send());
    let interface = CAN_IFACE.init(CanFdInterface::new(1, "CANFD", true, driver));

    init().await;
    add_interface(interface);

    loop {
        Timer::after_secs(3600).await;
    }
}
