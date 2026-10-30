use crate::{Error, Packet};

use super::{Interface, InterfaceID, InterfacePrivate};

pub(crate) const LOOPBACK_ADDR: u16 = 0;

pub(crate) struct Loopback {
    private: InterfacePrivate,
}

impl Loopback {
    pub(crate) const fn new() -> Self {
        Self {
            private: InterfacePrivate::new(),
        }
    }
}

impl Interface for Loopback {
    fn addr(&self) -> u16 {
        LOOPBACK_ADDR
    }

    fn netmask(&self) -> u16 {
        crate::id::get_host_bits() as u16
    }

    fn name(&self) -> &str {
        "LOOP"
    }

    fn next_hop(
        &mut self,
        _via: Option<u16>,
        _packet: &Packet,
        _from_me: bool,
    ) -> Result<(), Error> {
        Err(Error::InvalidOperation)
    }

    fn is_loopback_destination(&self, _packet: &Packet) -> bool {
        true
    }

    fn alias_add(&mut self, _addr: u16) -> Result<(), Error> {
        Err(Error::InvalidOperation)
    }

    fn is_default(&self) -> bool {
        false
    }

    fn private(&mut self) -> &mut InterfacePrivate {
        &mut self.private
    }

    fn start(&mut self, _id: InterfaceID) {}
}

#[cfg(test)]
mod tests {
    use super::{LOOPBACK_ADDR, Loopback};
    use crate::interfaces::Interface;
    use crate::{Error, Packet};

    #[test]
    fn loopback_has_local_identity_and_rejects_transmit() {
        let mut loopback = Loopback::new();
        let packet = Packet::get().unwrap();

        assert_eq!(loopback.addr(), LOOPBACK_ADDR);
        assert_eq!(loopback.name(), "LOOP");
        assert!(loopback.is_loopback_destination(&packet));
        assert!(!loopback.is_default());
        assert_eq!(
            loopback.next_hop(None, &packet, true),
            Err(Error::InvalidOperation)
        );
        assert_eq!(loopback.alias_add(1), Err(Error::InvalidOperation));
    }
}
