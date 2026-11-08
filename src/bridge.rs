use crate::InterfaceID;

static mut BIF_A: Option<InterfaceID> = None;
static mut BIF_B: Option<InterfaceID> = None;

pub fn bridge_set_interfaces(if_a: InterfaceID, if_b: InterfaceID) {
    // unsafe required to access static mut
    unsafe {
        BIF_A = Some(if_a);
        BIF_B = Some(if_b);
    }
}

pub async fn bridge_work() {
    // unsafe required to access static mut
    let (bif_a, bif_b) = unsafe {
        match (BIF_A, BIF_B) {
            (Some(a), Some(b)) => (a, b),
            _ => {
                #[cfg(feature = "defmt")]
                defmt::warn!("Bridge interfaces are not configured");
                return;
            }
        }
    };

    let Some(input) = crate::qfifo::read().await else {
        return;
    };

    let mut packet = input.packet;
    if let Some(iface) = crate::interfaces::get_interface_by_id(input.iface) {
        crate::route::csp_input_hook(iface.private(), &packet);
    }

    if crate::dedup::is_duplicate(&mut packet) {
        #[cfg(feature = "defmt")]
        defmt::trace!("Bridge dropped duplicate packet");
        drop(packet);
        return;
    }

    //csp_input_hook(input.iface, packet);

    #[cfg(feature = "promisc")]
    {
        crate::promisc::add(&packet).await;
    }

    let destif = if input.iface == bif_a { bif_b } else { bif_a };

    if let Some(iface) = crate::interfaces::get_interface_by_id(destif) {
        /* Send to the interface directly, no hassle */
        let id = packet.id;
        let _ = crate::io::send_direct_iface(&id, packet, iface.private(), None, false).await;
    }
}

#[cfg(test)]
mod tests {
    use super::{bridge_set_interfaces, bridge_work};
    use crate::interfaces::INTERFACES;
    use serial_test::serial;
    use std::vec;

    #[tokio::test]
    #[serial]
    async fn bridge_work_handles_unconfigured_and_configured_paths() {
        bridge_work().await;

        let loopback = INTERFACES.get_or_init().into_iter().next().unwrap();
        let iface_id = loopback.id();
        bridge_set_interfaces(iface_id, iface_id);

        let mut packet = crate::Packet::get().unwrap();
        packet.append_data(b"bridge coverage").unwrap();
        crate::qfifo::write(packet, iface_id).await;
        bridge_work().await;

        let forwarded = crate::qfifo::read().await.unwrap();
        assert_eq!(forwarded.iface, iface_id);
        assert_eq!(forwarded.packet.data(), b"bridge coverage");
    }
}
