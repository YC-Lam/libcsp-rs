use crate::arch::Mutex;
use crate::interfaces::InterfaceID;
use crate::{Error, id};

pub const CSP_RTABLE_SIZE: usize = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    pub address: u16,
    pub netmask: u16,
    pub iface: InterfaceID,
    pub via: Option<u16>,
}

struct RouteTable {
    entries: [Option<Route>; CSP_RTABLE_SIZE],
    len: usize,
}

impl RouteTable {
    const fn new() -> Self {
        Self {
            entries: [None; CSP_RTABLE_SIZE],
            len: 0,
        }
    }

    fn set(&mut self, route: Route) -> Result<(), Error> {
        if let Some(entry) = self.entries[..self.len].iter_mut().flatten().find(|entry| {
            entry.address == route.address
                && entry.netmask == route.netmask
                && entry.iface == route.iface
        }) {
            *entry = route;
            return Ok(());
        }

        if self.len == CSP_RTABLE_SIZE {
            return Err(Error::BufferOverflow);
        }

        self.entries[self.len] = Some(route);
        self.len += 1;
        Ok(())
    }

    fn clear(&mut self) {
        self.entries = [None; CSP_RTABLE_SIZE];
        self.len = 0;
    }

    fn find(&self, address: u16) -> RouteList {
        let best_mask = self.entries[..self.len]
            .iter()
            .flatten()
            .filter(|route| matches_prefix(route.address, route.netmask, address))
            .map(|route| route.netmask)
            .max();

        let mut routes = RouteList::new();
        if let Some(best_mask) = best_mask {
            for route in self.entries[..self.len].iter().rev().flatten() {
                if route.netmask == best_mask
                    && matches_prefix(route.address, route.netmask, address)
                {
                    routes.push(*route);
                }
            }
        }
        routes
    }
}

#[derive(Clone, Copy)]
pub struct RouteList {
    entries: [Option<Route>; CSP_RTABLE_SIZE],
    len: usize,
}

impl RouteList {
    const fn new() -> Self {
        Self {
            entries: [None; CSP_RTABLE_SIZE],
            len: 0,
        }
    }

    fn push(&mut self, route: Route) {
        self.entries[self.len] = Some(route);
        self.len += 1;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn get(&self, index: usize) -> Option<Route> {
        self.entries.get(index).copied().flatten()
    }
}

static ROUTES: Mutex<RouteTable> = Mutex::new(RouteTable::new());

fn matches_prefix(route_address: u16, netmask: u16, address: u16) -> bool {
    let host_bits = id::get_host_bits() - netmask as usize;
    let mask = if host_bits == id::get_host_bits() {
        0
    } else {
        (((1u32 << id::get_host_bits()) - 1) ^ ((1u32 << host_bits) - 1)) as u16
    };
    route_address & mask == address & mask
}

/// Add or replace a route. `netmask` is the number of prefix bits; values
/// outside the CSP address width are treated as a host route, matching libcsp.
pub async fn set(
    address: u16,
    netmask: i16,
    iface: InterfaceID,
    via: Option<u16>,
) -> Result<(), Error> {
    if crate::interfaces::get_interface_by_id(iface).is_none() {
        return Err(Error::InvalidOperation);
    }

    let host_bits = id::get_host_bits() as i16;
    let netmask = if !(0..=host_bits).contains(&netmask) {
        host_bits as u16
    } else {
        netmask as u16
    };
    ROUTES.lock().await.set(Route {
        address,
        netmask,
        iface,
        via,
    })
}

/// Remove all configured routes.
pub async fn free() {
    ROUTES.lock().await.clear();
}

/// Clear the routing table. This currently has the same behavior as [`free`].
pub async fn clear() {
    free().await;
}

/// Return the most recently configured route with the longest matching prefix.
pub async fn find_route(address: u16) -> Option<Route> {
    find_routes(address).await.get(0)
}

/// Return all matching routes with the longest prefix, ordered from most
/// recently configured to least recently configured. Multiple matches are
/// useful for equal-cost forwarding.
pub async fn find_routes(address: u16) -> RouteList {
    ROUTES.lock().await.find(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(address: u16, netmask: u16, iface: usize, via: Option<u16>) -> Route {
        Route {
            address,
            netmask,
            iface: InterfaceID::from_raw(iface),
            via,
        }
    }

    #[test]
    fn prefix_matching_handles_host_and_default_routes() {
        assert!(matches_prefix(0x1234, 14, 0x1234));
        assert!(!matches_prefix(0x1234, 14, 0x1235));
        assert!(matches_prefix(0, 0, 0x1234));
        assert!(matches_prefix(0x1200, 6, 0x1234));
        assert!(!matches_prefix(0x1200, 6, 0x1634));
    }

    #[test]
    fn route_table_replaces_exact_routes_and_selects_longest_prefix() {
        let mut table = RouteTable::new();
        table.set(route(0, 0, 1, None)).unwrap();
        table.set(route(0x1200, 6, 2, Some(0x22))).unwrap();
        table.set(route(0x1234, 14, 3, None)).unwrap();
        table.set(route(0x1200, 6, 2, Some(0x23))).unwrap();

        let exact = table.find(0x1234);
        assert_eq!(exact.len(), 1);
        assert_eq!(exact.get(0).unwrap().iface, InterfaceID::from_raw(3));

        let broader = table.find(0x1235);
        assert_eq!(broader.len(), 1);
        let route = broader.get(0).unwrap();
        assert_eq!(route.iface, InterfaceID::from_raw(2));
        assert_eq!(route.via, Some(0x23));
    }

    #[test]
    fn route_table_returns_equal_prefix_routes_in_reverse_order() {
        let mut table = RouteTable::new();
        table.set(route(0x1000, 4, 1, None)).unwrap();
        table.set(route(0x1000, 4, 2, Some(5))).unwrap();

        let routes = table.find(0x1234);
        assert_eq!(routes.len(), 2);
        assert_eq!(routes.get(0).unwrap().iface, InterfaceID::from_raw(2));
        assert_eq!(routes.get(1).unwrap().iface, InterfaceID::from_raw(1));
    }

    #[test]
    fn route_table_enforces_capacity_and_can_be_cleared() {
        let mut table = RouteTable::new();
        for index in 0..CSP_RTABLE_SIZE {
            table.set(route(index as u16, 14, index, None)).unwrap();
        }
        assert_eq!(
            table.set(route(100, 14, 100, None)),
            Err(Error::BufferOverflow)
        );
        table.clear();
        assert_eq!(table.len, 0);
        table.set(route(100, 14, 100, None)).unwrap();
        assert_eq!(table.find(100).len(), 1);
    }
}
