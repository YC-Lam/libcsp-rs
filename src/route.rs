use crate::conn::{ConnType, Connection};
use crate::id::CspId;
use crate::interfaces::InterfacePrivate;
use crate::port::{ConnOrPacket, SocketOptions, SocketState};
use crate::*;

/**
 * Check supported packet options
 * @param iface pointer to incoming interface
 * @param packet pointer to packet
 * @return CSP_ERR_NONE is all options are supported, CSP_ERR_NOTSUP if not
 */
#[allow(unused)]
fn check_options(iface: &mut InterfacePrivate, packet: &Packet) -> Result<(), Error> {
    /* Drop HMAC packets */
    #[cfg(not(feature = "hmac"))]
    if (packet.id.flags.contains(Flags::CSP_FHMAC)) {
        iface.autherr += 1;
        return Err(Error::FeatureDisabled);
    }

    /* Drop RDP packets */
    #[cfg(not(feature = "rdp"))]
    if (packet.id.flags.contains(Flags::CSP_FRDP)) {
        iface.rx_error += 1;
        return Err(Error::FeatureDisabled);
    }
    return Ok(());
}

/**
 * Helper function to decrypt, check auth and CRC32
 * @param security_opts either socket_opts or conn_opts
 * @param iface pointer to incoming interface
 * @param packet pointer to packet
 * @return #CSP_ERR_NONE on success, otherwise an error code.
 */
fn security_check(
    security_opts: SocketOptions,
    iface: &mut InterfacePrivate,
    packet: &mut Packet,
) -> Result<(), Error> {
    /* CRC32 verified packet */
    if packet.id.flags.contains(Flags::CSP_FCRC32) {
        /* Verify CRC32 (does not include header for backwards compatibility with csp1.x) */
        if !packet.verify_crc32() {
            iface.rx_error += 1;
            return Err(Error::CRC32);
        }
    } else if security_opts.contains(SocketOptions::CSP_SO_CRC32REQ) {
        iface.rx_error += 1;
        return Err(Error::CRC32);
    }

    /* HMAC authenticated packet */
    #[cfg(feature = "hmac")]
    if packet.id.flags.contains(Flags::CSP_FHMAC) {
        /* Verify HMAC (does not include header for backwards compatibility with csp1.x) */
        if crate::crypto::hmac::verify(packet, false).is_err() {
            /* HMAC failed */
            iface.autherr += 1;
            return Err(Error::HMAC);
        }
    } else if security_opts.contains(SocketOptions::CSP_SO_HMACREQ) {
        iface.autherr += 1;
        return Err(Error::HMAC);
    }

    /* RDP packet */
    #[cfg(feature = "rdp")]
    if !(packet.id.flags.contains(Flags::CSP_FRDP)) {
        if security_opts.contains(SocketOptions::CSP_SO_RDPREQ) {
            iface.rx_error += 1;
            return Err(Error::InvalidOperation);
        }
    }

    return Ok(());
}

pub(crate) fn csp_input_hook(iface: &mut InterfacePrivate, packet: &Packet) {
    #[cfg(feature = "defmt")]
    {
        let src = packet.id.src;
        let dst = packet.id.dst;
        let dst_port = packet.id.dport;
        let src_port = packet.id.sport;
        let priority = packet.id.prio as u8;
        let flags = packet.id.flags.bits();
        let length = packet.data_length() as u16;
        defmt::trace!(
            "CSP rx src={=u16}:{=u8} dst={=u16}:{=u8} prio={=u8} flags={=u8} len={=u16} iface={=str}",
            src,
            src_port,
            dst,
            dst_port,
            priority,
            flags,
            length,
            iface.name()
        );
    }

    #[cfg(not(feature = "defmt"))]
    let _ = (iface, packet);
}

/* Deliver the packet to a connection-less socket.  The socket is the
 * endpoint, so delivery terminates here. */
async fn deliver_conn_less(socket: &SocketState, packet: Packet) {
    let _ = socket.rx_queue.push(ConnOrPacket::Packet(packet)).await;
}

/* Deliver the packet to a connection.  The connection is the
 * endpoint: an existing connection, when given, was matched by
 * identifier (client or server side), otherwise the socket acts as
 * the factory for a new server-side connection, which is posted to
 * the socket rx_queue for csp_accept(). */
async fn deliver_connection(
    conn: Option<Connection>,
    socket: Option<&SocketState>,
    packet: Packet,
) {
    /* If this is an incoming packet on a new connection */
    let mut conn = if let Some(c) = conn {
        c
    } else {
        /* New incoming connection accepted */
        let idout = CspId {
            prio: packet.id.prio,
            flags: packet.id.flags,
            src: packet.id.dst,
            dst: packet.id.src,
            dport: packet.id.sport,
            sport: packet.id.dport,
        };
        /* Create connection */
        let Some(mut conn) = Connection::new(packet.id, idout, ConnType::Server).await else {
            return;
        };

        /* Store the socket queue and options */
        conn.set_socket_deliverd(false);
        conn.set_options(ConnOptions::from_bits_truncate(
            socket.unwrap().options().bits(),
        ));

        conn
    };

    /* Pass packet to RDP module */
    #[cfg(feature = "rdp")]
    if packet.id.flags.contains(Flags::CSP_FRDP) {
        let close_connection = crate::rdp::new_packet(&mut conn, socket, packet).await;
        if close_connection {
            conn.close().await;
        }
        return;
    }

    /* Otherwise, enqueue directly */
    conn.enqueue_package(Some(packet)).await;

    /* Try to queue up the new connection pointer */
    if !conn.socket_delivered() {
        if let Some(socket) = socket {
            conn.set_socket_deliverd(true);
            let _ = socket.rx_queue.push(ConnOrPacket::Connection(conn)).await;
        }
    }
}

pub async fn route_work() {
    /* Check connection timeouts (currently only for RDP) */
    if cfg!(feature = "rdp") {
        crate::conn::check_timeouts().await;
    }

    /* Get next packet to route */
    let input = match crate::qfifo::read().await {
        Some(i) => i,
        None => return,
    };

    let mut packet = input.packet;
    let iface = match crate::interfaces::get_interface_by_id(input.iface) {
        Some(i) => i.private(),
        None => return,
    };

    csp_input_hook(iface, &packet);

    /* Count the message */
    iface.rx += 1;
    iface.rxbytes += packet.data_length() as u32;

    /* The packet is to me, if the address matches that of any interface,
     * or the address matches the broadcast address of the incoming interface */
    let is_to_me = crate::interfaces::get_interface_by_addr(packet.id.dst).is_some()
        || crate::id::is_broadcast(packet.id.dst, iface.addr(), iface.netmask());
    //todo: || csp_addr_is_alias(packet.id.dst);

    /* Deduplication */
    if cfg!(feature = "dedup_all")
        || (is_to_me && cfg!(feature = "dedup_incoming"))
        || (!is_to_me && cfg!(feature = "dedup_forward"))
    {
        if crate::dedup::is_duplicate(&mut packet) {
            /* Discard packet */
            iface.drop += 1;
            drop(packet);
            return;
        }
    }

    /* Here there be promiscuous mode */
    #[cfg(feature = "promisc")]
    crate::promisc::add(&packet).await;

    /* If the message is not to me, route the message to the correct interface */
    if !is_to_me {
        /* Otherwise, actually send the message */
        let id = packet.id;
        let _ = crate::io::send_direct(&id, packet, Some(iface)).await;
        return;
    }

    /* Discard packets with unsupported options */
    if check_options(iface, &packet).is_err() {
        return;
    }

    /* Callback delivery */

    //if deliver_callback(iface, packet).await {
    //	return;
    //}

    if let Some(callback) = crate::port::get_callback(packet.id.dport) {
        // security check
        if let Err(_) = security_check(SocketOptions::CSP_SO_CRC32REQ, iface, &mut packet) {
            return;
        }

        callback(packet);
        return;
    }

    /* Socket delivery */
    let socket = crate::port::get_socket(packet.id.dport);

    /* Resolve the endpoint: an existing connection first, otherwise
     * the bound socket.  Drop the packet if neither exists. */
    let conn = Connection::find_existing(&packet.id);

    if conn.is_none() {
        let Some(socket) = socket else {
            return;
        };
        /* Connection-less sockets are ready from csp_bind(),
         * connection-oriented ones from csp_listen(). */
        if !socket.is_ready_to_recieve() {
            return;
        }
    }

    /* Security check with the endpoint options */
    if let Some(conn) = &conn {
        if let Err(_) = security_check(
            SocketOptions::from_bits_retain(conn.options().bits()),
            iface,
            &mut packet,
        ) {
            return;
        }
    } else {
        if let Err(_) = security_check(socket.unwrap().options(), iface, &mut packet) {
            return;
        }
    };

    /* The packet itself does not tell connection-less from
     * connection-oriented; only the bound socket does.  Without a
     * conn-less socket, the connection pool is the last possible
     * match. */
    if socket.is_some_and(|s| s.is_conn_less()) {
        /* Connection-less delivery, the socket is the endpoint */
        deliver_conn_less(socket.unwrap(), packet).await;
    } else {
        /* Connection-oriented delivery, a connection is the
         * endpoint and the socket, when present, only accepts new
         * connections */
        deliver_connection(conn, socket, packet).await;
    }
}
