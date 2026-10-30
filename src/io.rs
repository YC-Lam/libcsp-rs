use crate::conn::{ConnOptions, Connection};
use crate::id::CspId;
use crate::interfaces::loopback::LOOPBACK_ADDR;
use crate::interfaces::{INTERFACES, InterfacePrivate};
use crate::*;

fn is_same_subnet(iface: &InterfacePrivate, routed_from: &InterfacePrivate) -> bool {
    if core::ptr::eq(iface, routed_from) {
        return true;
    }

    return routed_from.is_within_subnet(iface.addr());
}

fn convert_broadcast(idout: &CspId, idout_copy: &mut CspId, snd_iface: &InterfacePrivate) {
    if crate::id::is_broadcast(idout.dst, snd_iface.addr(), snd_iface.netmask()) {
        idout_copy.dst = crate::id::get_max_nodeid();
    }
}

async fn send_packet(
    idout_copy: &mut CspId,
    snd_pkt: Packet,
    snd_iface: &mut InterfacePrivate,
    via: Option<u16>,
    from_me: bool,
) -> Result<(), Error> {
    // Apply outgoing interface address to packet
    if from_me && (idout_copy.src == 0) {
        idout_copy.src = snd_iface.addr();
    }

    send_direct_iface(idout_copy, snd_pkt, snd_iface, via, from_me).await
}

pub(crate) async fn send_direct(
    idout: &CspId,
    packet: Packet,
    routed_from: Option<&InterfacePrivate>,
) -> Result<(), Error> {
    let from_me = routed_from.is_none();
    let via = None;

    /* Quickly send on loopback */
    if idout.dst == LOOPBACK_ADDR {
        let loopback = crate::interfaces::get_interface_by_addr(LOOPBACK_ADDR)
            .ok_or(Error::InvalidOperation)?;
        send_direct_iface(idout, packet, loopback.private(), via, from_me).await?;
        return Ok(());
    }
    let mut next_iface: Option<&mut InterfacePrivate> = None;
    // Broadcast function procedure modifies destination
    let mut idout_copy = *idout;
    // Try to find the destination on any local subnets
    let mut local_found = false;
    // iterate interfaces
    for iface in INTERFACES.get_or_init().into_iter() {
        // skip interfaces not in subnet
        if !iface.is_within_subnet(idout.dst) {
            continue;
        }
        local_found = true;

        // Do not send back to same interface (split horizon)
        if routed_from.is_some_and(|rf| is_same_subnet(iface, rf)) {
            continue;
        }

        if let Some(next_iface) = next_iface {
            let copy = packet.buffer_clone().ok_or(Error::AllocError)?;

            convert_broadcast(idout, &mut idout_copy, next_iface);
            if let Err(e) = send_packet(&mut idout_copy, copy, next_iface, via, from_me).await {
                // free packet before exit
                drop(packet);
                return Err(e);
            };
        }
        next_iface = Some(iface);
    }

    if local_found {
        if let Some(next_iface) = next_iface {
            convert_broadcast(idout, &mut idout_copy, next_iface);
            send_packet(&mut idout_copy, packet, next_iface, via, from_me).await?;
        } else {
            drop(packet);
        }
        /* If a match was found, we don't want to look at the routing table */
        return Ok(());
    }

    #[cfg(feature = "rtable")]
    {
        let routes = crate::rtable::find_routes(idout.dst).await;
        if routes.len() > 0 {
            let mut original_packet = Some(packet);
            let mut candidates = [None; crate::rtable::CSP_RTABLE_SIZE];
            let mut candidate_count = 0;

            for index in 0..routes.len() {
                let Some(route) = routes.get(index) else {
                    continue;
                };
                let Some(iface) = crate::interfaces::get_interface_by_id(route.iface) else {
                    continue;
                };
                if routed_from.is_some_and(|source| is_same_subnet(iface.private(), source)) {
                    continue;
                }
                candidates[candidate_count] = Some(route);
                candidate_count += 1;
            }

            for index in 0..candidate_count {
                let route = candidates[index].expect("candidate route is populated");
                let iface = crate::interfaces::get_interface_by_id(route.iface)
                    .expect("registered route interface remains available");
                let outgoing_packet = if index + 1 == candidate_count {
                    original_packet.take().expect("original packet is retained")
                } else {
                    original_packet
                        .as_ref()
                        .expect("original packet is retained")
                        .buffer_clone()
                        .ok_or(Error::AllocError)?
                };
                send_packet(
                    &mut idout_copy,
                    outgoing_packet,
                    iface.private(),
                    route.via,
                    from_me,
                )
                .await?;
            }

            // A matching route suppresses default-route fallback, even when
            // split horizon excludes every route.
            return Ok(());
        }
    }

    next_iface = None;

    /* Try to send via default interfaces */
    for iface in INTERFACES.get_or_init().into_iter() {
        // skip non-default interfaces
        if !iface.is_default() {
            continue;
        }

        if routed_from.is_some_and(|rf| is_same_subnet(iface, rf)) {
            continue;
        }

        if let Some(next_iface) = next_iface {
            let copy = packet.buffer_clone().ok_or(Error::AllocError)?;
            // send packet to interface
            if let Err(e) = send_packet(&mut idout_copy, copy, next_iface, via, from_me).await {
                // free packet before exit
                drop(packet);
                return Err(e);
            }
        }
        next_iface = Some(iface);
    }

    if let Some(next_iface) = next_iface {
        send_packet(&mut idout_copy, packet, next_iface, via, from_me).await?;
        return Ok(());
    }

    return Ok(());
}

pub(crate) async fn send_direct_iface(
    idout: &CspId,
    mut packet: Packet,
    iface: &mut InterfacePrivate,
    via: Option<u16>,
    from_me: bool,
) -> Result<(), Error> {
    #[cfg(feature = "defmt")]
    {
        let src = idout.src;
        let dst = idout.dst;
        let dst_port = idout.dport;
        let src_port = idout.sport;
        let priority = idout.prio as u8;
        let flags = idout.flags.bits();
        let length = packet.data_length() as u16;
        let next_hop = via.unwrap_or(dst);
        defmt::trace!(
            "CSP tx src={=u16}:{=u8} dst={=u16}:{=u8} prio={=u8} flags={=u8} len={=u16} iface={=str} via={=u16} time={=u32}",
            src,
            src_port,
            dst,
            dst_port,
            priority,
            flags,
            length,
            iface.name(),
            next_hop,
            crate::arch::get_ms()
        );
    }

    /* Copy identifier to packet (before crc and hmac) */
    if idout != &packet.id {
        packet.id = *idout;
    }

    /* Add authentication and checksums only to packets originated here. */
    if from_me {
        /* Append HMAC */
        if idout.flags.contains(Flags::CSP_FHMAC) {
            // Calculate and add HMAC (does not include header for backwards compatibility with csp1.x)
            #[cfg(feature = "hmac")]
            if crate::crypto::hmac::append(&mut packet, false).is_err() {
                iface.tx_error += 1;
                return Err(Error::BufferOverflow);
            }

            if !cfg!(feature = "hmac") {
                drop(packet);
                iface.tx_error += 1;
                return Err(Error::FeatureDisabled);
            }
        }

        /* Append CRC32 */
        if idout.flags.contains(Flags::CSP_FCRC32) {
            /* New CRC32 trailers cover the packed header and payload. */
            if packet.append_crc32().is_err() {
                /* CRC32 append failed */
                drop(packet);
                iface.tx_error += 1;
                return Err(Error::CRC32);
            }
        }

        // Loopback traffic is added to promisc queue by the router
        #[cfg(feature = "promisc")]
        if !iface.is_loop_back {
            crate::promisc::add(&packet).await;
        }
    }

    /* Store length before passing to interface */
    let bytes = packet.data_length();

    if let Err(e) = iface.next_hop(via, &packet, from_me).await {
        iface.tx_error += 1;
        return Err(e);
    }

    iface.tx += 1;
    iface.txbytes += bytes as u32;

    return Ok(());
}

#[allow(unused_mut)]
pub(crate) async fn send(conn: &mut Connection, mut packet: Packet) -> Result<(), Error> {
    // check if connection is closed
    if conn.is_closed() {
        return Err(Error::ConnectionClosed);
    }

    #[cfg(feature = "rdp")]
    if conn.idout().flags.contains(Flags::CSP_FRDP) {
        if let Err(e) = crate::rdp::send(conn, &mut packet).await {
            return Err(e);
        }
    }

    send_direct(conn.idout(), packet, None).await
}

pub(crate) async fn send_prio(
    prio: Priority,
    conn: &mut Connection,
    packet: Packet,
) -> Result<(), Error> {
    conn.set_idout_prio(prio);
    send(conn, packet).await
}

/// Perform an entire request & reply transaction on an existing connection.
///
/// Send outbuf, wait for reply and copy reply to inbuf.
async fn transaction_persistent(
    conn: &mut Connection,
    timeout: u32,
    inbuf: &[u8],
    outbuf: &mut [u8],
) -> Result<usize, Error> {
    // allocate packet
    let mut packet = Packet::get().ok_or(Error::AllocError)?;

    // Copy the request
    packet.append_data(inbuf)?;

    send(conn, packet).await?;

    // If no reply is expected, return now
    if outbuf.len() == 0 {
        return Ok(0);
    }
    packet = conn.read(timeout).await?;

    if packet.data_length() > outbuf.len() {
        return Err(Error::BufferOverflow);
    }

    // copy data to out buffer
    outbuf[..packet.data_length()].copy_from_slice(packet.data());

    let length = packet.data_length();
    return Ok(length);
}

/// Perform an entire request & reply transaction.
///
/// Creates a connection, send outbuf, wait for reply, copy reply to inbuf and close the connection.
pub(crate) async fn transaction_w_opts(
    prio: Priority,
    dest: u16,
    port: u8,
    timeout: u32,
    outbuf: &[u8],
    inbuf: &mut [u8],
    opts: ConnOptions,
) -> Result<usize, Error> {
    let mut conn = Connection::connect(prio, dest, port, timeout, opts).await?;

    let length = transaction_persistent(&mut conn, timeout, outbuf, inbuf).await?;

    conn.close().await;

    return Ok(length);
}

pub(crate) async fn send_to(
    prio: Priority,
    dest: u16,
    dport: u8,
    src_port: u8,
    opts: ConnOptions,
    mut packet: Packet,
) -> Result<(), Error> {
    // reset flags if not same
    if !opts.contains(ConnOptions::CSP_O_SAME) {
        packet.id.flags = Flags::empty();
    }

    if opts.contains(ConnOptions::CSP_O_RDP) {
        return Err(Error::InvalidOperation);
    }

    if opts.contains(ConnOptions::CSP_O_HMAC) {
        if cfg!(feature = "hmac") {
            packet.id.flags |= Flags::CSP_FHMAC;
        } else {
            return Err(Error::FeatureDisabled);
        }
    }

    if opts.contains(ConnOptions::CSP_O_CRC32) {
        packet.id.flags |= Flags::CSP_FCRC32;
    }

    packet.id.dst = dest;
    packet.id.dport = dport;
    packet.id.sport = src_port;
    packet.id.prio = prio;

    let id = packet.id.clone();

    send_direct(&id, packet, None).await
}

pub(crate) async fn send_service_reply(
    mut packet: Packet,
    request_was_broadcast: bool,
) -> Result<(), Error> {
    let request_id = packet.id;
    // Reuse the request packet, reversing endpoints and preserving negotiated flags.
    // A broadcast address is not a valid source address; let routing select the
    // outgoing interface's address instead.
    packet.id.src = if request_was_broadcast {
        0
    } else {
        request_id.dst
    };
    packet.id.dst = request_id.src;
    packet.id.sport = request_id.dport;
    packet.id.dport = request_id.sport;
    packet.id.prio = request_id.prio;
    let id = packet.id;
    send_direct(&id, packet, None).await
}
