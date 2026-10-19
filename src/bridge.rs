use crate::InterfaceID;

static mut BIF_A: Option<InterfaceID> = None;
static mut BIF_B: Option<InterfaceID> = None;

pub fn csp_bridge_set_interfaces(if_a: InterfaceID, if_b: InterfaceID) {
    unsafe {
        BIF_A = Some(if_a);
        BIF_B = Some(if_b);
    }
}

pub fn csp_bridge_work() {
    let (bif_a, bif_b) = unsafe {
        match unsafe { (BIF_A, BIF_B) } {
            (Some(a), Some(b)) => (a, b),
            _ => {
                todo!(); //csp_print(
                todo!(); //    "Bridge interfaces are not setup yet. Make sure to call csp_bridge_set_interfaces()\n",
                todo!(); //);
                return;
            }
        }
    };

    todo!(); //let Some(input) = csp_qfifo_read() else {
    todo!(); //    return;
    todo!(); //};

    todo!(); //let Some(packet) = input.packet else {
    todo!(); //csp_print("Packet of router queue item is NULL\n");
    todo!(); //    return;
    todo!(); //};

    todo!(); //if csp_dedup_is_duplicate(packet) {
    todo!(); //    csp_print("Retrieved packet is a duplicate\n");
    todo!(); //    csp_buffer_free(packet);
    todo!(); //    return;
    todo!(); //}

    todo!(); //csp_input_hook(input.iface, packet);

    #[cfg(feature = "promisc")]
    todo!(); // csp_promisc(packet);

    /* Send to the interface directly, no hassle */
    todo!(); //csp_send_direct_iface(&packet.id, packet, destif, CSP_NO_VIA_ADDRESS, 0);
}
