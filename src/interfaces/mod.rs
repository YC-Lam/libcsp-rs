pub mod can;
pub mod i2c;
pub mod kiss;
pub(crate) mod loopback;
#[cfg(feature = "zmq")]
pub mod zmq;

use core::any::Any;
use core::future::poll_fn;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use core::task::{Context, Poll};

use crate::arch::LazyLock;
use crate::{Error, Packet};

static mut LOOPBACK: loopback::Loopback = loopback::Loopback::new();

fn init_interfaces() -> IfList {
    // The loopback instance is static and remains valid for the lifetime of the interface list.
    let loopback = unsafe { &mut *core::ptr::addr_of_mut!(LOOPBACK) };
    IfList::new(loopback)
}

pub(crate) static INTERFACES: LazyLock<IfList, fn() -> IfList> = LazyLock::new(init_interfaces);

/// Add interface to interface list
///
/// The interface must remain valid as long as the application is running.
pub fn add_interface(iface: &'static mut dyn Interface) -> InterfaceID {
    INTERFACES.add(iface)
}

pub fn remove_interface(iface: InterfaceID) -> bool {
    INTERFACES.remove(iface)
}

pub(crate) fn get_interface_by_id(id: InterfaceID) -> Option<&'static mut dyn Interface> {
    // loop through interfaces
    for iface in INTERFACES.get_or_init() {
        if core::ptr::addr_eq(id.0 as *const InterfacePrivate, iface) {
            return Some(iface.inner());
        }
    }

    return None;
}

fn get_interface_by_isdfl() -> Option<&'static mut dyn Interface> {
    // loop through interfaces
    for iface in INTERFACES.get_or_init() {
        if iface.is_default() {
            return Some(iface.inner());
        }
    }

    return None;
}

pub fn check_dfl() {
    // If we find a default interface,
    // we assume user has setup the configuration correctly
    if get_interface_by_isdfl().is_some() {
        return;
    }
    // If there was not found a default interface,
    // go through all interfaces and set them as default (except for LOOP)
    for iface in INTERFACES.get_or_init() {
        if iface.is_loop_back {
            continue;
        }

        iface.override_default = true;
    }
}

pub(crate) fn get_interface_by_addr(addr: u16) -> Option<&'static mut dyn Interface> {
    for iface in INTERFACES.get_or_init() {
        if iface.addr() == addr {
            return Some(iface.inner());
        }
    }

    return None;
}

pub(crate) fn interface_id_by_name(name: &[u8]) -> Option<InterfaceID> {
    for iface in INTERFACES.get_or_init() {
        if iface.name().as_bytes() == name {
            return Some(iface.id());
        }
    }

    return None;
}

pub(crate) struct InterfaceStats {
    pub tx: u32,
    pub rx: u32,
    pub tx_error: u32,
    pub rx_error: u32,
    pub drop: u32,
    pub autherr: u32,
    pub frame: u32,
    pub txbytes: u32,
    pub rxbytes: u32,
    pub irq: u32,
}

pub(crate) fn interface_stats(name: &[u8]) -> Option<InterfaceStats> {
    for iface in INTERFACES.get_or_init() {
        if iface.name().as_bytes() == name {
            return Some(InterfaceStats {
                tx: iface.tx,
                rx: iface.rx,
                tx_error: iface.tx_error,
                rx_error: iface.rx_error,
                drop: iface.drop,
                autherr: iface.autherr,
                frame: iface.frame,
                txbytes: iface.txbytes,
                rxbytes: iface.rxbytes,
                irq: iface.irq,
            });
        }
    }

    None
}

pub fn print_interface_list(writer: &mut impl core::fmt::Write) -> core::fmt::Result {
    // util to convert bytes to unit and unit size
    let bytesize = |bytes: u32, postfix: &mut char| {
        let size: u32;
        if bytes >= 1024 * 1024 {
            size = bytes / (1024 * 1024);
            *postfix = 'M';
        } else if bytes >= 1024 {
            size = bytes / 1024;
            *postfix = 'K';
        } else {
            size = bytes;
            *postfix = 'B';
        };

        return size;
    };

    let mut tx_postfix = 'B';
    let mut rx_postfix = 'B';

    for i in INTERFACES.get_or_init() {
        let tx = bytesize(i.txbytes, &mut tx_postfix);
        let rx = bytesize(i.rxbytes, &mut rx_postfix);

        writer.write_fmt(format_args!(
            "{:<10} addr: {} netmask: {} dfl: {}\r\n\
               tx: {:05} rx: {:05} txe: {:05} rxe: {:05}\r\n\
               drop: {:05} autherr: {:05} frame: {:05}\r\n\
               txb: {} ({}{}) rxb: {} ({}{})\r\n",
            i.name(),
            i.addr(),
            i.netmask(),
            i.is_default(),
            i.tx,
            i.rx,
            i.tx_error,
            i.rx_error,
            i.drop,
            i.autherr,
            i.frame,
            i.txbytes,
            tx,
            tx_postfix,
            i.rxbytes,
            rx,
            rx_postfix
        ))?
    }

    return Ok(());
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceID(usize);

#[cfg(all(test, feature = "rtable"))]
impl InterfaceID {
    pub(crate) const fn from_raw(id: usize) -> Self {
        Self(id)
    }
}

pub trait Interface: Send + Sync + Any {
    fn start(&mut self, _id: InterfaceID) {}

    /// Host address on this subnet
    fn addr(&self) -> u16;
    /// Subnet mask
    fn netmask(&self) -> u16;
    /// Name, max compare length is #CSP_IFLIST_NAME_MAX
    fn name(&self) -> &str;
    /// Next hop (Tx) function
    fn next_hop(&mut self, via: Option<u16>, packet: &Packet, from_me: bool) -> Result<(), Error>;
    /// Poll an asynchronous next-hop operation.
    fn poll_next_hop(
        &mut self,
        _cx: &mut Context<'_>,
        via: Option<u16>,
        packet: &Packet,
        from_me: bool,
        _state: &mut TxState,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(self.next_hop(via, packet, from_me))
    }
    /// Whether this packet should be delivered locally rather than transmitted.
    fn is_loopback_destination(&self, _packet: &Packet) -> bool {
        false
    }
    /// Process one received frame. Implementations return a packet only when it is complete.
    #[doc(hidden)]
    fn process_rx_frame(
        &mut self,
        _id: u32,
        _data: &[u8],
        _timestamp_rx: u32,
    ) -> Result<Option<Packet>, Error> {
        Err(Error::InvalidOperation)
    }
    /// Add receive address to interface (could be multicast receptions)
    fn alias_add(&mut self, addr: u16) -> Result<(), Error>;
    /// Set default IF flag (CSP supports multiple defaults)
    fn is_default(&self) -> bool;
    /// private data for internal use only
    fn private(&mut self) -> &mut InterfacePrivate;
}

#[doc(hidden)]
#[derive(Default)]
pub struct TxState {
    pub(crate) started: bool,
    pub(crate) first_frame_sent: bool,
    pub(crate) sender_count: u8,
    pub(crate) fragment_count: u8,
    pub(crate) tx_count: usize,
    #[cfg(feature = "embassy_stm32")]
    pub(crate) ticket: usize,
}

pub struct InterfacePrivate {
    pub(crate) iface: Option<*mut dyn Interface>,

    /// loop back interface
    pub(crate) is_loop_back: bool,
    /// override default
    override_default: bool,

    /// Successfully transmitted packets
    pub(crate) tx: u32,
    /// Successfully received packets
    pub(crate) rx: u32,
    /// Transmit errors (packets)
    pub(crate) tx_error: u32,
    /// Receive errors, e.g. too large message
    pub(crate) rx_error: u32,
    /// Dropped packets
    pub(crate) drop: u32,
    /// Authentication errors (packets)
    pub(crate) autherr: u32,
    /// Frame format errors (packets)
    pub(crate) frame: u32,
    /// Transmitted bytes
    pub(crate) txbytes: u32,
    /// Received bytes
    pub(crate) rxbytes: u32,
    /// Interrupts
    pub(crate) irq: u32,
    /// for linked list
    pub(crate) next: AtomicPtr<InterfacePrivate>,
    pub(crate) removed: AtomicBool,
}

unsafe impl Send for InterfacePrivate {}
unsafe impl Sync for InterfacePrivate {}

impl Default for InterfacePrivate {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfacePrivate {
    pub const fn new() -> Self {
        Self {
            iface: None,
            is_loop_back: false,
            override_default: false,
            tx: 0,
            rx: 0,
            tx_error: 0,
            rx_error: 0,
            drop: 0,
            autherr: 0,
            frame: 0,
            txbytes: 0,
            rxbytes: 0,
            irq: 0,
            next: AtomicPtr::new(core::ptr::null_mut()),
            removed: AtomicBool::new(false),
        }
    }

    /// binds the dyn Interface address for easy access.
    /// This must be called before any method call
    const fn bind(&mut self, iface: *mut dyn Interface) {
        self.iface = Some(iface)
    }

    pub(crate) fn id(&self) -> InterfaceID {
        InterfaceID(self as *const Self as usize)
    }

    /// get the parent Interface reference.
    /// This will panic if bind was not called beforehand
    fn inner(&self) -> &'static mut dyn Interface {
        // unsafe required to convert pointer as reference
        self.iface
            .and_then(|i| unsafe { i.as_mut() })
            .expect("Interface not registered")
    }

    pub(crate) fn addr(&self) -> u16 {
        self.inner().addr()
    }

    pub(crate) fn netmask(&self) -> u16 {
        self.inner().netmask()
    }

    pub(crate) fn name(&self) -> &str {
        self.inner().name()
    }

    /// is default interface (csp supports multiple defaults)
    pub(crate) fn is_default(&self) -> bool {
        // check if is_default has been override
        self.inner().is_default() || self.override_default
    }

    /// check if interface is within address subnet
    pub(crate) fn is_within_subnet(&self, addr: u16) -> bool {
        // Netmask values are prefix lengths in the 14-bit CSP node address.
        let network_mask = crate::id::address_mask(self.netmask() as usize);
        (self.addr() & network_mask) == (addr & network_mask)
    }

    pub(crate) async fn next_hop(
        &self,
        via: Option<u16>,
        packet: &Packet,
        from_me: bool,
    ) -> Result<(), Error> {
        if self.inner().is_loopback_destination(packet) {
            let copy = packet.buffer_clone().ok_or(Error::AllocError)?;
            crate::qfifo::write(copy, self.id()).await;
            return Ok(());
        }

        let iface = self.inner();
        let mut state = TxState::default();
        poll_fn(|cx| iface.poll_next_hop(cx, via, packet, from_me, &mut state)).await
    }
}

/// Linked list to store Interfaces
pub(crate) struct IfList {
    iface: AtomicPtr<InterfacePrivate>,
    loopback: AtomicPtr<InterfacePrivate>,
}

impl IfList {
    fn new(loopback: &'static mut dyn Interface) -> Self {
        let loopback_interface = loopback as *mut dyn Interface;
        let (loopback_ptr, loopback_id) = {
            let loopback_private = loopback.private();
            loopback_private.bind(loopback_interface);
            loopback_private.is_loop_back = true;
            loopback_private.removed.store(false, Ordering::Release);
            (
                loopback_private as *mut InterfacePrivate,
                loopback_private.id(),
            )
        };
        loopback.start(loopback_id);
        Self {
            iface: AtomicPtr::new(loopback_ptr),
            loopback: AtomicPtr::new(loopback_ptr),
        }
    }

    #[cfg(test)]
    fn clear(&self) {
        let loopback = self.loopback.load(Ordering::Acquire);
        if let Some(loopback) = unsafe { loopback.as_ref() } {
            loopback
                .next
                .store(core::ptr::null_mut(), Ordering::Release);
            loopback.removed.store(false, Ordering::Release);
        }
        self.iface.store(loopback, Ordering::Release);
    }

    fn last(&self) -> Option<&InterfacePrivate> {
        // get starting interface pointer
        let mut next = self.iface.load(Ordering::Acquire);

        // unsafe required to convert pointer to refernce
        // iterate linked list
        while let Some(iface) = unsafe { next.as_ref() } {
            // get next pointer
            next = iface.next.load(Ordering::Acquire);

            // end when pointer is null
            if next.is_null() {
                return Some(iface);
            }
        }

        return None;
    }

    /// Add interface to IfList.
    /// This will also setup InterfacePrivate
    fn add(&self, iface: &'static mut dyn Interface) -> InterfaceID {
        let ptr = iface as *mut dyn Interface;
        let new = iface.private();
        // bind parent Interface to InterfacePrivate
        new.bind(ptr);

        new.removed.store(false, Ordering::Release);

        // loop until compare exchange success
        let id = loop {
            let store = match self.last() {
                Some(last_iface) => &last_iface.next,
                None => &self.iface,
            };

            let current = store.load(Ordering::Acquire);
            new.next.store(current, Ordering::Release);
            let re =
                store.compare_exchange(current, new as *mut _, Ordering::SeqCst, Ordering::Relaxed);
            // list changed, try again
            if re.is_ok() {
                break InterfaceID(new as *mut InterfacePrivate as usize);
            }
        };

        // start interface
        iface.start(id);

        return id;
    }

    fn remove(&self, iface: InterfaceID) -> bool {
        if core::ptr::addr_eq(
            iface.0 as *const InterfacePrivate,
            self.loopback.load(Ordering::Acquire),
        ) {
            return false;
        }

        for i in self {
            if core::ptr::addr_eq(iface.0 as *const InterfacePrivate, i) {
                i.removed.store(true, Ordering::Release);
                return true;
            }
        }
        return false;
    }
}

impl IntoIterator for &IfList {
    type IntoIter = IfListIterator;
    type Item = &'static mut InterfacePrivate;
    fn into_iter(self) -> Self::IntoIter {
        IfListIterator {
            next: self.iface.load(Ordering::Acquire),
        }
    }
}

pub(crate) struct IfListIterator {
    next: *mut InterfacePrivate,
}

impl Iterator for IfListIterator {
    type Item = &'static mut InterfacePrivate;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let current = unsafe { self.next.as_mut()? };

            self.next = current.next.load(Ordering::Acquire);

            if !current.removed.load(Ordering::Acquire) {
                return Some(current);
            }
        }
    }
}

/// Used to represent an alias reception address, bound to a particular interface
/// todo
#[allow(unused)]
pub(crate) struct AliasAddr {
    pub addr: u16,
    pub iface: &'static dyn Interface,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::vec;

    struct TestInterface {
        private_: InterfacePrivate,
    }

    impl TestInterface {
        const fn new() -> Self {
            Self {
                private_: InterfacePrivate::new(),
            }
        }
    }

    impl Interface for TestInterface {
        fn addr(&self) -> u16 {
            10
        }

        fn netmask(&self) -> u16 {
            8
        }

        fn name(&self) -> &str {
            "TEST"
        }

        fn is_default(&self) -> bool {
            false
        }

        fn next_hop(
            &mut self,
            _via: Option<u16>,
            _packet: &Packet,
            _from_me: bool,
        ) -> Result<(), Error> {
            unimplemented!()
        }

        fn alias_add(&mut self, _addr: u16) -> Result<(), Error> {
            unimplemented!()
        }

        fn private(&mut self) -> &mut InterfacePrivate {
            &mut self.private_
        }
    }

    #[test]
    #[serial]
    fn test_iflist_add() {
        INTERFACES.get_or_init().clear();

        static mut INTERFACES_ARRAY: [TestInterface; 10] = [
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
        ];

        unsafe {
            for i in 0..10 {
                add_interface(&mut INTERFACES_ARRAY[i]);
            }
        }

        // verify count
        assert_eq!(INTERFACES.get_or_init().into_iter().count(), 11);

        // verify pointer
        for (i, iface) in INTERFACES.get_or_init().into_iter().skip(1).enumerate() {
            unsafe {
                assert!(core::ptr::eq(iface.inner(), &INTERFACES_ARRAY[i]));
            }
        }
    }

    #[test]
    #[serial]
    fn lookup_empty_list() {
        INTERFACES.get_or_init().clear();

        assert!(get_interface_by_addr(1).is_none());
        assert!(interface_id_by_name(b"eth0").is_none());
        assert_eq!(get_interface_by_addr(0).unwrap().name(), "LOOP");
        assert!(get_interface_by_isdfl().is_none());
    }

    #[tokio::test]
    #[serial]
    async fn loopback_next_hop_enqueues_a_packet() {
        INTERFACES.get_or_init().clear();

        let loopback_private = get_interface_by_addr(loopback::LOOPBACK_ADDR)
            .unwrap()
            .private() as *mut InterfacePrivate;
        let mut packet = Packet::get().unwrap();
        packet.append_data(b"loopback").unwrap();

        unsafe {
            (&*loopback_private)
                .next_hop(None, &packet, true)
                .await
                .unwrap();
        }

        let received = crate::qfifo::read().await.unwrap();
        assert_eq!(received.iface, unsafe { (&*loopback_private).id() });
        assert_eq!(received.packet.data(), b"loopback");
    }

    #[test]
    #[serial]
    fn loopback_cannot_be_removed() {
        INTERFACES.get_or_init().clear();

        let loopback = get_interface_by_addr(loopback::LOOPBACK_ADDR)
            .unwrap()
            .private()
            .id();
        assert!(!remove_interface(loopback));
        assert_eq!(
            get_interface_by_addr(loopback::LOOPBACK_ADDR)
                .unwrap()
                .name(),
            "LOOP"
        );
    }

    #[test]
    #[serial]
    #[allow(static_mut_refs)]
    fn remove_nonexistent() {
        INTERFACES.get_or_init().clear();

        static mut IFACE: TestInterface = TestInterface::new();

        unsafe {
            let iface0 = add_interface(&mut IFACE);
            assert!(remove_interface(iface0));
            assert!(!remove_interface(iface0));
        }
    }

    #[test]
    #[serial]
    fn remove_head() {
        INTERFACES.get_or_init().clear();

        static mut IFACES: [TestInterface; 3] = [
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
        ];

        unsafe {
            let iface0 = add_interface(&mut IFACES[0]);
            add_interface(&mut IFACES[1]);
            add_interface(&mut IFACES[2]);

            assert!(remove_interface(iface0));
            assert_eq!(INTERFACES.get_or_init().into_iter().count(), 3);
            assert!(
                !INTERFACES
                    .get_or_init()
                    .into_iter()
                    .any(|p| core::ptr::eq(p.inner(), &IFACES[0]))
            );
        }
    }

    #[test]
    #[serial]
    fn remove_middle() {
        INTERFACES.get_or_init().clear();

        static mut IFACES: [TestInterface; 3] = [
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
        ];

        unsafe {
            add_interface(&mut IFACES[0]);
            let iface1 = add_interface(&mut IFACES[1]);
            add_interface(&mut IFACES[2]);

            assert!(remove_interface(iface1));
            assert_eq!(INTERFACES.get_or_init().into_iter().count(), 3);
            assert!(
                !INTERFACES
                    .get_or_init()
                    .into_iter()
                    .any(|p| core::ptr::eq(p.inner(), &IFACES[1]))
            );
        }
    }

    #[test]
    #[serial]
    fn remove_tail() {
        INTERFACES.get_or_init().clear();

        static mut IFACES: [TestInterface; 3] = [
            TestInterface::new(),
            TestInterface::new(),
            TestInterface::new(),
        ];

        unsafe {
            add_interface(&mut IFACES[0]);
            add_interface(&mut IFACES[1]);
            let iface2 = add_interface(&mut IFACES[2]);

            assert!(remove_interface(iface2));
            assert_eq!(INTERFACES.get_or_init().into_iter().count(), 3);
            assert!(
                !INTERFACES
                    .get_or_init()
                    .into_iter()
                    .any(|p| core::ptr::eq(p.inner(), &IFACES[2]))
            );
        }
    }

    #[test]
    #[serial]
    #[allow(static_mut_refs)]
    fn remove_single() {
        INTERFACES.get_or_init().clear();

        static mut IFACE: TestInterface = TestInterface::new();

        unsafe {
            let iface0 = add_interface(&mut IFACE);

            assert_eq!(INTERFACES.get_or_init().into_iter().count(), 2);

            assert!(remove_interface(iface0));

            assert_eq!(INTERFACES.get_or_init().into_iter().count(), 1);
        }
    }

    #[test]
    #[serial]
    #[allow(static_mut_refs)]
    fn within_subnet() {
        INTERFACES.get_or_init().clear();

        static mut IFACE: TestInterface = TestInterface::new();

        unsafe {
            add_interface(&mut IFACE);

            assert!(IFACE.private().is_within_subnet(11));
            assert!(!IFACE.private().is_within_subnet(500));
        }
    }

    #[test]
    #[serial]
    #[allow(static_mut_refs)]
    fn check_default_sets_override() {
        INTERFACES.get_or_init().clear();

        static mut IFACE: TestInterface = TestInterface::new();

        unsafe {
            add_interface(&mut IFACE);

            check_dfl();

            assert!(IFACE.private().is_default());
        }
    }
}
