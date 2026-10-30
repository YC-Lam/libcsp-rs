//! CSP Management Protocol (CMP) requests and response handling.
//!
//! Typed helpers encode multi-byte fields in network byte order. The generic
//! [`request`] API accepts only the payload; it adds and validates the CMP header.

use crate::{CspStream, Error, Priority};

pub const IDENT_REV_LEN: usize = 20;
pub const IDENT_DATE_LEN: usize = 12;
pub const IDENT_TIME_LEN: usize = 9;
pub const ROUTE_IFACE_LEN: usize = 11;
pub const IDENT_HOSTNAME_LEN: usize = 16;
pub const IDENT_MODEL_LEN: usize = 16;

pub const IDENT: u8 = 1;
pub const ROUTE_SET_V1: u8 = 2;
pub const IF_STATS: u8 = 3;
pub const PEEK: u8 = 4;
pub const POKE: u8 = 5;
pub const CLOCK: u8 = 6;
pub const ROUTE_SET_V2: u8 = 7;
pub const PEEK_V2: u8 = 8;
pub const POKE_V2: u8 = 9;

// CMP messages begin with a type byte followed by a request code.
const REQUEST: u8 = 0;
const REPLY: u8 = 0xff;
const MAX_CMP_MSG: usize = crate::buffer::CSP_BUFFER_SIZE;
const MAX_CMP_REQUEST: usize = MAX_CMP_MSG - 4;
const IDENT_MSG_LEN: usize =
    2 + IDENT_HOSTNAME_LEN + IDENT_MODEL_LEN + IDENT_REV_LEN + IDENT_DATE_LEN + IDENT_TIME_LEN;
const IF_STATS_PAYLOAD_LEN: usize = ROUTE_IFACE_LEN + 10 * 4;

/// Fixed-width identification strings returned by the CMP IDENT request.
///
/// The byte arrays use the lengths defined by the CMP wire format and may
/// contain NUL padding.
#[derive(Clone, Copy)]
pub struct Identity {
    pub hostname: [u8; IDENT_HOSTNAME_LEN],
    pub model: [u8; IDENT_MODEL_LEN],
    pub revision: [u8; IDENT_REV_LEN],
    pub date: [u8; IDENT_DATE_LEN],
    pub time: [u8; IDENT_TIME_LEN],
}

/// Interface counters returned by the CMP IF_STATS request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceStats {
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

impl Identity {
    /// Create an identity containing only zero bytes.
    pub const fn empty() -> Self {
        Self {
            hostname: [0; IDENT_HOSTNAME_LEN],
            model: [0; IDENT_MODEL_LEN],
            revision: [0; IDENT_REV_LEN],
            date: [0; IDENT_DATE_LEN],
            time: [0; IDENT_TIME_LEN],
        }
    }

    /// Create an identity from its fixed-width wire-format fields.
    pub const fn new(
        hostname: [u8; IDENT_HOSTNAME_LEN],
        model: [u8; IDENT_MODEL_LEN],
        revision: [u8; IDENT_REV_LEN],
        date: [u8; IDENT_DATE_LEN],
        time: [u8; IDENT_TIME_LEN],
    ) -> Self {
        Self {
            hostname,
            model,
            revision,
            date,
            time,
        }
    }
}

/// Request the remote node's fixed-width identification fields.
pub async fn get_identity(node: u16, timeout: u32) -> Result<Identity, Error> {
    let mut payload = [0; IDENT_MSG_LEN - 2];
    request(node, timeout, IDENT, &mut payload).await?;
    let mut offset = 0;
    let mut hostname = [0; IDENT_HOSTNAME_LEN];
    hostname.copy_from_slice(&payload[offset..offset + IDENT_HOSTNAME_LEN]);
    offset += IDENT_HOSTNAME_LEN;
    let mut model = [0; IDENT_MODEL_LEN];
    model.copy_from_slice(&payload[offset..offset + IDENT_MODEL_LEN]);
    offset += IDENT_MODEL_LEN;
    let mut revision = [0; IDENT_REV_LEN];
    revision.copy_from_slice(&payload[offset..offset + IDENT_REV_LEN]);
    offset += IDENT_REV_LEN;
    let mut date = [0; IDENT_DATE_LEN];
    date.copy_from_slice(&payload[offset..offset + IDENT_DATE_LEN]);
    offset += IDENT_DATE_LEN;
    let mut time = [0; IDENT_TIME_LEN];
    time.copy_from_slice(&payload[offset..offset + IDENT_TIME_LEN]);
    Ok(Identity::new(hostname, model, revision, date, time))
}

/// Request counters for an interface identified by its ASCII name.
pub async fn get_interface_stats(
    node: u16,
    timeout: u32,
    interface: &str,
) -> Result<InterfaceStats, Error> {
    if interface.len() >= ROUTE_IFACE_LEN || !interface.is_ascii() {
        return Err(Error::InvalidOperation);
    }

    let mut payload = [0; IF_STATS_PAYLOAD_LEN];
    payload[..interface.len()].copy_from_slice(interface.as_bytes());
    request(node, timeout, IF_STATS, &mut payload).await?;
    let mut fields = [0; 10];
    for (index, field) in fields.iter_mut().enumerate() {
        let start = ROUTE_IFACE_LEN + index * 4;
        *field = u32::from_be_bytes(payload[start..start + 4].try_into().unwrap());
    }
    Ok(InterfaceStats {
        tx: fields[0],
        rx: fields[1],
        tx_error: fields[2],
        rx_error: fields[3],
        drop: fields[4],
        autherr: fields[5],
        frame: fields[6],
        txbytes: fields[7],
        rxbytes: fields[8],
        irq: fields[9],
    })
}

/// Install a version-1 route, using the local node's configured host-bit width.
pub async fn set_route_v1(
    node: u16,
    timeout: u32,
    address: u8,
    via: Option<u8>,
    interface: &str,
) -> Result<(), Error> {
    if interface.len() >= ROUTE_IFACE_LEN || !interface.is_ascii() {
        return Err(Error::InvalidOperation);
    }
    let mut payload = [0; 2 + ROUTE_IFACE_LEN];
    payload[0] = address;
    payload[1] = via.unwrap_or(u8::MAX);
    payload[2..2 + interface.len()].copy_from_slice(interface.as_bytes());
    request(node, timeout, ROUTE_SET_V1, &mut payload).await
}

/// Install a version-2 route with an explicit address mask.
pub async fn set_route_v2(
    node: u16,
    timeout: u32,
    address: u16,
    netmask: u16,
    via: Option<u16>,
    interface: &str,
) -> Result<(), Error> {
    if interface.len() >= ROUTE_IFACE_LEN || !interface.is_ascii() {
        return Err(Error::InvalidOperation);
    }
    let mut payload = [0; 6 + ROUTE_IFACE_LEN];
    payload[..2].copy_from_slice(&address.to_be_bytes());
    payload[2..4].copy_from_slice(&via.unwrap_or(u16::MAX).to_be_bytes());
    payload[4..6].copy_from_slice(&netmask.to_be_bytes());
    payload[6..6 + interface.len()].copy_from_slice(interface.as_bytes());
    request(node, timeout, ROUTE_SET_V2, &mut payload).await
}

/// Read the remote clock, or set it first when `set_time` is provided.
///
/// A seconds value of zero is interpreted by the protocol as a read request.
pub async fn clock(
    node: u16,
    timeout: u32,
    set_time: Option<(u32, u32)>,
) -> Result<(u32, u32), Error> {
    let mut payload = [0; 8];
    if let Some((seconds, nanos)) = set_time {
        payload[..4].copy_from_slice(&seconds.to_be_bytes());
        payload[4..].copy_from_slice(&nanos.to_be_bytes());
    }
    request(node, timeout, CLOCK, &mut payload).await?;
    Ok((
        u32::from_be_bytes(payload[..4].try_into().unwrap()),
        u32::from_be_bytes(payload[4..].try_into().unwrap()),
    ))
}

/// Send a CMP request and replace `message` with the response.
///
/// `message` is the payload excluding the two-byte CMP type/code header.
/// The request and response payloads must have equal lengths. The request uses
/// CRC32, and the reply must carry the matching response type and request code.
pub async fn request(node: u16, timeout: u32, code: u8, message: &mut [u8]) -> Result<(), Error> {
    if message.len() + 2 > MAX_CMP_REQUEST {
        return Err(Error::BufferOverflow);
    }

    let message_len = message.len();
    let mut buffer = [0; MAX_CMP_MSG];
    buffer[0] = REQUEST;
    buffer[1] = code;
    buffer[2..message_len + 2].copy_from_slice(message);

    let mut stream = CspStream::connect(
        Priority::Normal,
        node,
        crate::CSP_CMP,
        crate::ConnOptions::CSP_O_CRC32,
    )
    .await?;
    let sent = stream.send(&buffer[..message_len + 2]).await?;
    if sent != message_len + 2 {
        stream.close().await;
        return Err(Error::InvalidOperation);
    }

    let result = stream.read(&mut buffer, timeout).await;
    stream.close().await;
    let response_len = result?;
    if response_len != message_len + 2 || buffer[0] != REPLY || buffer[1] != code {
        return Err(Error::InvalidOperation);
    }
    message.copy_from_slice(&buffer[2..response_len]);
    Ok(())
}

/// Handle a CMP request; return whether routing should reply, consume, or continue.
pub(crate) async fn handle(packet: &mut crate::Packet) -> Result<Option<bool>, Error> {
    if packet.data_length() < 2 {
        return Err(Error::InvalidOperation);
    }

    let data = packet.data();
    if data[0] != REQUEST {
        return Err(Error::InvalidOperation);
    }
    let code = data[1];
    let payload = &data[2..];
    let mut reply = [0; MAX_CMP_MSG];
    reply[..2].copy_from_slice(&[REPLY, code]);
    let response_len = match code {
        IDENT => {
            if payload.len() != IDENT_MSG_LEN - 2 {
                return Err(Error::InvalidOperation);
            }
            let identity = crate::services::identity().ok_or(Error::FeatureDisabled)?;
            let mut cursor = 2;
            for value in [
                &identity.hostname[..],
                &identity.model[..],
                &identity.revision[..],
                &identity.date[..],
                &identity.time[..],
            ] {
                reply[cursor..cursor + value.len()].copy_from_slice(value);
                cursor += value.len();
            }
            cursor
        }
        IF_STATS => {
            if payload.len() != IF_STATS_PAYLOAD_LEN {
                return Err(Error::InvalidOperation);
            }
            let name = fixed_name(&payload[..ROUTE_IFACE_LEN]);
            let stats = crate::interfaces::interface_stats(&name).ok_or(Error::InvalidOperation)?;
            reply[2..2 + ROUTE_IFACE_LEN].copy_from_slice(&payload[..ROUTE_IFACE_LEN]);
            let fields = [
                stats.tx,
                stats.rx,
                stats.tx_error,
                stats.rx_error,
                stats.drop,
                stats.autherr,
                stats.frame,
                stats.txbytes,
                stats.rxbytes,
                stats.irq,
            ];
            let mut cursor = 2 + ROUTE_IFACE_LEN;
            for field in fields {
                reply[cursor..cursor + 4].copy_from_slice(&field.to_be_bytes());
                cursor += 4;
            }
            cursor
        }
        ROUTE_SET_V1 => {
            if payload.len() != 2 + ROUTE_IFACE_LEN {
                return Err(Error::InvalidOperation);
            }
            let address = payload[0] as u16;
            // Version 1 uses 0xff to mean that the route has no next hop.
            let via = (payload[1] != u8::MAX).then_some(payload[1] as u16);
            set_route(
                address,
                crate::id::get_host_bits() as u16,
                &payload[2..],
                via,
            )
            .await?;
            2 + payload.len()
        }
        ROUTE_SET_V2 => {
            if payload.len() != 6 + ROUTE_IFACE_LEN {
                return Err(Error::InvalidOperation);
            }
            let address = u16::from_be_bytes([payload[0], payload[1]]);
            let via_raw = u16::from_be_bytes([payload[2], payload[3]]);
            let netmask = u16::from_be_bytes([payload[4], payload[5]]);
            // Version 2 uses 0xffff as the no-next-hop sentinel.
            let via = (via_raw != u16::MAX).then_some(via_raw);
            set_route(address, netmask, &payload[6..], via).await?;
            2 + payload.len()
        }
        CLOCK => {
            if payload.len() != 8 {
                return Err(Error::InvalidOperation);
            }
            let seconds = u32::from_be_bytes(payload[..4].try_into().unwrap());
            let nanos = u32::from_be_bytes(payload[4..8].try_into().unwrap());
            let hooks = crate::services::hooks().ok_or(Error::FeatureDisabled)?;
            if seconds != 0 {
                (hooks.clock_set.ok_or(Error::FeatureDisabled)?)(seconds, nanos)?;
            }
            let (seconds, nanos) = (hooks.clock_get.ok_or(Error::FeatureDisabled)?)();
            reply[2..6].copy_from_slice(&seconds.to_be_bytes());
            reply[6..10].copy_from_slice(&nanos.to_be_bytes());
            10
        }
        // Arbitrary memory access is deliberately not implemented.
        PEEK | POKE | PEEK_V2 | POKE_V2 => return Err(Error::FeatureDisabled),
        _ => return Err(Error::InvalidOperation),
    };

    let old_len = packet.data_length();
    packet.remove_data(old_len);
    packet.append_data(&reply[..response_len])?;
    Ok(Some(true))
}

fn fixed_name(name: &[u8]) -> &[u8] {
    // Interface names are NUL-padded in CMP's fixed-width fields.
    let len = name
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(name.len());
    &name[..len]
}

async fn set_route(address: u16, netmask: u16, name: &[u8], via: Option<u16>) -> Result<(), Error> {
    let interface_name = fixed_name(name);
    let interface =
        crate::interfaces::interface_id_by_name(&interface_name).ok_or(Error::InvalidOperation)?;
    #[cfg(feature = "rtable")]
    crate::rtable::set(address, netmask as i16, interface, via).await?;
    // Match builds where the C route table is disabled: validate the interface,
    // but do not attempt to install a route.
    #[cfg(not(feature = "rtable"))]
    let _ = (address, netmask, interface, via);
    Ok(())
}
