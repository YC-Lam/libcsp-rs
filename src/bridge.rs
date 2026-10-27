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
                //csp_print(
                //    "Bridge interfaces are not setup yet. Make sure to call csp_bridge_set_interfaces()\n",
                //);
                return;
            }
        }
    };

    let Some(input) = crate::qfifo::read().await else {
        return;
    };

    let mut packet = input.packet;
    if crate::dedup::is_duplicate(&mut packet) {
        // csp_print("Retrieved packet is a duplicate\n");
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
