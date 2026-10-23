use bitflags::bitflags;

use crate::conn::{CSP_CONN_RXQUEUE_LEN, ConnOptions, ConnState, Connection};
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
    snd_pkt: &'static mut Packet,
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

async fn send_direct(
    idout: &CspId,
    packet: &'static mut Packet,
    routed_from: Option<&InterfacePrivate>,
) -> Result<(), Error> {
    let from_me = routed_from.is_none();
    let via = None;

    /* Quickly send on loopback */
    if idout.dst == LOOPBACK_ADDR {
        send_direct_iface(idout, packet, todo!(), via, from_me).await?;
        return Ok(());
    }
    let mut next_iface: Option<&mut InterfacePrivate> = None;
    // Broadcast function procedure modifies destination
    let mut idout_copy = *idout;
    // Try to find the destination on any local subnets
    let mut local_found = false;
    // iterate interfaces
    for iface in INTERFACES.into_iter() {
        // skip interfaces not in subnet
        if !iface.is_within_subnet(idout.dst) {
            continue;
        }
        local_found = true;

        // Do not send back to same interface (split horizon)
        if routed_from.is_none_or(|rf| is_same_subnet(iface, rf)) {
            continue;
        }

        if let Some(next_iface) = next_iface {
            let copy = packet.buffer_clone().await;

            convert_broadcast(idout, &mut idout_copy, next_iface);
            if let Err(e) = send_packet(&mut idout_copy, copy, next_iface, via, from_me).await {
                // free packet before exit
                packet.free();
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
            packet.free();
        }
        /* If a match was found, we don't want to look at the routing table */
        return Ok(());
    }

    #[cfg(feature = "rtable")]
    {
        /* Try to send via routing table */
        let mut route_found = false;
        let mut route = csp_rtable_find_route(idout.dst);

        while let Some(route) = route {
            route_found = 1;

            /* Do not send back to same interface (split horizon)  */
            if (is_same_subnet(route.iface, routed_from)) {
                continue;
            }

            if (next_iface != NULL) {
                csp_packet_t * copy = csp_buffer_clone(packet);
                send_packet(&idout_copy, copy, next_iface, via, from_me);
            }
            next_iface = route.iface;
            via = route.via;

            route = csp_rtable_search_backward(route);
        }

        /* If the above worked, we don't want to look at default interfaces */
        if (route_found == 1) {
            if (next_iface != NULL) {
                send_packet(&idout_copy, packet, next_iface, via, from_me);
            } else {
                csp_buffer_free(packet);
            }
            return;
        }
    }

    next_iface = None;

    /* Try to send via default interfaces */
    for iface in INTERFACES.into_iter() {
        // skip non-default interfaces
        if !iface.is_default() {
            continue;
        }

        if routed_from.is_none_or(|rf| is_same_subnet(iface, rf)) {
            continue;
        }

        if let Some(next_iface) = next_iface {
            let copy = packet.buffer_clone().await;
            // send packet to interface
            if let Err(e) = send_packet(&mut idout_copy, copy, next_iface, via, from_me).await {
                // free packet before exit
                packet.free();
                return Err(e);
            }
        }
        next_iface = Some(iface);
    }

    if let Some(next_iface) = next_iface {
        send_packet(&mut idout_copy, packet, next_iface, via, from_me).await?;
        return Ok(());
    }

    packet.free();

    return Ok(());
}

async fn send_direct_iface(
    idout: &CspId,
    packet: &'static mut Packet,
    iface: &mut InterfacePrivate,
    via: Option<u16>,
    from_me: bool,
) -> Result<(), Error> {
    /* Copy identifier to packet (before crc and hmac) */
    if idout != &packet.id {
        packet.id = *idout;
    }

    /* Only encrypt packets from the current node */
    if from_me {
        /* Append HMAC */
        if idout.flags.contains(Flags::CSP_FHMAC) {
            // Calculate and add HMAC (does not include header for backwards compatibility with csp1.x)
            #[cfg(feature = "hmac")]
            //if (csp_hmac_append(packet, false) != CSP_ERR_NONE) {
            /* HMAC append failed */
            //    packet.free();
            //    iface.tx_error +=1;
            //}
            todo!();

            if !cfg!(feature = "hmac") {
                packet.free();
                iface.tx_error += 1;
                return Err(Error::FeatureDisabled);
            }
        }

        /* Append CRC32 */
        if idout.flags.contains(Flags::CSP_FCRC32) {
            /* Calculate and add CRC32 (does not include header for backwards compatibility with csp1.x) */
            if packet.append_crc32().is_err() {
                /* CRC32 append failed */
                packet.free();
                iface.tx_error += 1;
                return Err(Error::CRC32);
            }
        }

        // Loopback traffic is added to promisc queue by the router
        #[cfg(feature = "promisc")]
        if !iface.is_loop_back {
            todo!() // csp_promisc_add(packet);
        }
    }

    /* Store length before passing to interface */
    let bytes = packet.data_length();

    if let Err(e) = iface.next_hop(via, packet, from_me).await {
        packet.free();
        iface.tx_error += 1;
        return Err(e);
    }

    // original libcsp does not free, but we do beacause iface does not take ownership
    packet.free();
    iface.tx += 1;
    iface.txbytes += bytes as u32;

    return Ok(());
}

async fn send(conn: &Connection, packet: &'static mut Packet) -> Result<(), Error> {
    if conn.state() != ConnState::Open {
        packet.free();
        return Err(Error::ConnectionClosed);
    }

    #[cfg(feature = "rdp")]
    if conn.idout().flags.contains(Flags::CSP_FRDP){
        todo!() // if let Err(e) = rdp_send(conn, packet){
        // packet.free();
        // return Err(e)
        // }
    }

    send_direct(conn.idout(), packet, None).await
}

async fn send_prio(prio: Priority, conn: &mut Connection, packet: &'static mut Packet) -> Result<(), Error>{
    conn.set_idout_prio(prio);
    send(conn, packet).await
}

/// Perform an entire request & reply transaction on an existing connection.
/// 
/// Send outbuf, wait for reply and copy reply to inbuf.
async fn transaction_persistent(conn: &Connection, timeout: u32, inbuf: &[u8], outbuf: &mut [u8]) -> Result<usize, Error>{
    // allocate packet
	let mut packet = Packet::get().await;

	// Copy the request
	packet.append_data(inbuf)?;

	send(conn, packet).await?;

	// If no reply is expected, return now
	if outbuf.len() == 0{
        return Ok(0);
    }
	packet = conn.read(timeout).await?;

	if packet.data_length() > outbuf.len() {
		packet.free();
		return Err(Error::BufferOverflow);
	}

    // copy data to out buffer
    outbuf[..packet.data_length()].copy_from_slice(packet.data());
	
    let length = packet.data_length();
    packet.free();

	return Ok(length);
}

/// Perform an entire request & reply transaction.
/// 
/// Creates a connection, send outbuf, wait for reply, copy reply to inbuf and close the connection.
async fn transaction_w_opts(prio: Priority, dest: u16, port: u8, timeout: u32, outbuf: &[u8], inbuf: &mut [u8], opts: ConnOptions) -> Result<usize, Error>{

	let conn = Connection::connect(prio, dest, port, timeout, opts).await?;

	let length = transaction_persistent(conn, timeout, outbuf, inbuf).await?;

	conn.close();

	return Ok(length);
}

async fn send_to(prio: Priority, dest: u16, dport: u8, src_port: u8, opts: ConnOptions, packet: &'static mut Packet) -> Result<(), Error>{
    // reset flags if not same
	if !opts.contains(ConnOptions::CSP_O_SAME){
        packet.id.flags = Flags::empty();
    }

	if opts.contains(ConnOptions::CSP_O_RDP) {
		packet.free();
		return Err(Error::InvalidOperation);
	}

	if opts.contains(ConnOptions::CSP_O_HMAC) {
        if cfg!(feature = "hmac"){
            packet.id.flags |= Flags::CSP_FHMAC;
        } else{
            packet.free();
            return Err(Error::FeatureDisabled)
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

async fn sendto_reply(request_packet: &'static mut Packet, reply_packet: &'static mut Packet, opts: ConnOptions) -> Result<(), Error>{
    // check same
	if opts.contains(ConnOptions::CSP_O_SAME) {
		reply_packet.id.flags = request_packet.id.flags;
	}
	let dst = request_packet.id.src;
	if request_packet.id.dst != crate::id::get_max_nodeid() {
		reply_packet.id.src = request_packet.id.dst;
	} else {
		reply_packet.id.src = 0;
	}
	send_to(request_packet.id.prio, dst, request_packet.id.sport, request_packet.id.dport, opts, reply_packet).await
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct SocketOptions: u32{
        /// No socket options
        const CSP_SO_NONE = 0x0000;
        /// Require RDP
        const CSP_SO_RDPREQ = 0x0001;
        /// Prohibit RDP
        const CSP_SO_RDPPROHIB = 0x0002;
        /// Require HMAC
        const CSP_SO_HMACREQ = 0x0004;
        /// Prohibit HMAC
        const CSP_SO_HMACPROHIB = 0x0008;
        /// Require CRC32
        const CSP_SO_CRC32REQ = 0x0040;
        /// Prohibit CRC32
        const CSP_SO_CRC32PROHIB = 0x0080;
        /// Enable Connection Less mode
        const CSP_SO_CONN_LESS = 0x0100;
        /// Copy opts from incoming packet only applies to csp_sendto_reply()
        const CSP_SO_SAME = 0x8000;
    }
}

pub(crate) struct Socket {
    pub(crate) rx_queue: arch::Queue<&'static mut Connection, CSP_CONN_RXQUEUE_LEN>,
    pub(crate) opts: SocketOptions,
}

impl Socket {
    pub async fn accept(&self, timeout: u32) -> Result<&'static mut Connection, Error> {
        match self.rx_queue.pop_with_timeout(timeout).await {
            Some(conn) => Ok(conn),
            None => Err(Error::Timeout),
        }
    }

    ///  Read data from a connection-less server socket.
    pub async fn recv_packet(&self, timeout: u32) -> Result<&'static Packet, Error>{
        // 
        if !self.opts.contains(SocketOptions::CSP_SO_CONN_LESS){
            return Err(Error::InvalidOperation)
        }

        let ptr = match self.rx_queue.pop_with_timeout(timeout).await{
            Some(ptr) => ptr,
            None => return Err(Error::Timeout)
        };
        unsafe{
            // cast as packet
            let packet = (ptr as *mut _ as *mut Packet).as_mut_unchecked();

            return Ok(packet)
        }
    }
}