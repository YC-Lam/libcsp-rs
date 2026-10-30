use crate::buffer::CSP_BUFFER_SIZE;
use crate::conn::{ConnOptions, Connection};
use crate::id::Flags;
use crate::{Error, Packet};

const SFP_HEADER_SIZE: usize = 8;
const CRC32_SIZE: usize = 4;
const HMAC_SIZE: usize = 4;
#[cfg(feature = "rdp")]
const RDP_HEADER_SIZE: usize = 5;

/// Return the largest SFP payload that fits in one packet with these options.
pub(crate) fn opts_max_mtu(options: ConnOptions) -> u32 {
    let mut overhead = SFP_HEADER_SIZE;
    if options.contains(ConnOptions::RDP) {
        #[cfg(feature = "rdp")]
        {
            overhead += RDP_HEADER_SIZE;
        }
        #[cfg(not(feature = "rdp"))]
        {
            overhead += 5;
        }
    }
    if options.contains(ConnOptions::CRC32) {
        overhead += CRC32_SIZE;
    }
    if options.contains(ConnOptions::HMAC) {
        overhead += HMAC_SIZE;
    }
    (CSP_BUFFER_SIZE - overhead) as u32
}

/// Read callback used by [`send`]. `offset` identifies the next source byte.
pub type ReadCallback<'a> = dyn FnMut(&mut [u8], u32) -> Result<(), Error> + 'a;

/// Write callback used by [`receive`]. `offset` is the destination offset and
/// `total_size` is constant for all fragments in one transfer.
pub type WriteCallback<'a> = dyn FnMut(&[u8], u32, u32) -> Result<(), Error> + 'a;

/// Send a data transfer in SFP fragments over an established connection.
pub(crate) async fn send(
    conn: &mut Connection,
    totalsize: u32,
    mtu: u32,
    read: &mut ReadCallback<'_>,
) -> Result<(), Error> {
    if conn.is_closed() {
        return Err(Error::ConnectionClosed);
    }

    let max_mtu = opts_max_mtu(conn.options());
    if mtu == 0 || mtu > max_mtu {
        return Err(Error::Mtu);
    }

    conn.set_fragmented();
    let mut offset = 0u32;
    while offset < totalsize {
        if !conn.is_active() {
            return Err(Error::ConnectionClosed);
        }

        let length = (totalsize - offset).min(mtu) as usize;
        let mut bytes = [0u8; CSP_BUFFER_SIZE];
        read(&mut bytes[..length], offset)?;

        let mut packet = Packet::get().ok_or(Error::AllocError)?;
        packet.append_data(&bytes[..length])?;
        packet.append_data(&offset.to_be_bytes())?;
        packet.append_data(&totalsize.to_be_bytes())?;
        crate::io::send(conn, packet).await?;
        offset += length as u32;
    }

    Ok(())
}

/// Receive an SFP transfer over an established connection.
///
/// The callback receives each payload fragment, its destination offset, and
/// the total transfer size. The first packet is read with `timeout`; each
/// following packet uses the same timeout.
pub(crate) async fn receive(
    conn: &mut Connection,
    timeout: u32,
    write: &mut WriteCallback<'_>,
) -> Result<(), Error> {
    let first_packet = conn.read(timeout).await?;
    receive_packets(conn, first_packet, timeout, write).await
}

async fn receive_packets(
    conn: &mut Connection,
    first_packet: Packet,
    timeout: u32,
    write: &mut WriteCallback<'_>,
) -> Result<(), Error> {
    let max_mtu = opts_max_mtu(conn.options());
    let mut packet = first_packet;
    let mut expected_offset = 0u32;
    let mut total_size = None;

    loop {
        let (offset, packet_total, payload_size) =
            validate_fragment(&packet, expected_offset, total_size, max_mtu)?;

        let total_size = *total_size.get_or_insert(packet_total);
        packet.remove_data(SFP_HEADER_SIZE);
        write(packet.data(), offset, total_size)?;
        expected_offset += payload_size as u32;

        if expected_offset == total_size {
            return Ok(());
        }

        packet = conn.read(timeout).await?;
    }
}

fn validate_fragment(
    packet: &Packet,
    expected_offset: u32,
    expected_total: Option<u32>,
    max_mtu: u32,
) -> Result<(u32, u32, usize), Error> {
    if !packet.id.flags.contains(Flags::FRAG) || packet.data_length() < SFP_HEADER_SIZE {
        return Err(Error::Sfp);
    }

    let (offset, packet_total) = decode_header(packet)?;
    let payload_size = packet.data_length() - SFP_HEADER_SIZE;
    if payload_size == 0
        || payload_size as u32 > max_mtu
        || packet_total == 0
        || offset != expected_offset
        || offset > packet_total
        || payload_size as u32 > packet_total - offset
        || expected_total.is_some_and(|total| total != packet_total)
    {
        return Err(Error::Sfp);
    }

    Ok((offset, packet_total, payload_size))
}

fn decode_header(packet: &Packet) -> Result<(u32, u32), Error> {
    if packet.data_length() < SFP_HEADER_SIZE {
        return Err(Error::Sfp);
    }

    let data = packet.data();
    let header = &data[data.len() - SFP_HEADER_SIZE..];
    let offset = u32::from_be_bytes(header[..4].try_into().map_err(|_| Error::Sfp)?);
    let total = u32::from_be_bytes(header[4..].try_into().map_err(|_| Error::Sfp)?);
    if offset > total {
        return Err(Error::Sfp);
    }
    Ok((offset, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::Priority;
    use std::vec;

    #[test]
    fn maximum_mtu_accounts_for_all_enabled_options() {
        assert_eq!(opts_max_mtu(ConnOptions::empty()), 248);
        assert_eq!(opts_max_mtu(ConnOptions::CRC32), 244);
        assert_eq!(
            opts_max_mtu(ConnOptions::CRC32 | ConnOptions::RDP),
            239
        );
        assert_eq!(
            opts_max_mtu(
                ConnOptions::CRC32 | ConnOptions::RDP | ConnOptions::HMAC
            ),
            235
        );
    }

    #[test]
    #[serial_test::serial]
    fn sfp_header_is_big_endian() {
        let mut packet = Packet::get().unwrap();
        packet.id.prio = Priority::Normal;
        packet.id.flags = Flags::FRAG;
        packet.append_data(&[1, 2, 3]).unwrap();
        packet.append_data(&5u32.to_be_bytes()).unwrap();
        packet.append_data(&10u32.to_be_bytes()).unwrap();

        assert_eq!(decode_header(&packet), Ok((5, 10)));
    }

    #[test]
    #[serial_test::serial]
    fn sfp_header_rejects_short_packet_and_offset_beyond_total() {
        let packet = Packet::get().unwrap();
        assert!(matches!(decode_header(&packet), Err(Error::Sfp)));

        let mut packet = Packet::get().unwrap();
        packet.append_data(&11u32.to_be_bytes()).unwrap();
        packet.append_data(&10u32.to_be_bytes()).unwrap();
        assert!(matches!(decode_header(&packet), Err(Error::Sfp)));
    }

    #[test]
    #[serial_test::serial]
    fn receive_validation_rejects_unfragmented_packets() {
        let mut packet = Packet::get().unwrap();
        packet.append_data(&[1]).unwrap();
        packet.append_data(&0u32.to_be_bytes()).unwrap();
        packet.append_data(&1u32.to_be_bytes()).unwrap();

        let validation = validate_fragment(&packet, 0, None, opts_max_mtu(ConnOptions::empty()));
        assert_eq!(validation, Err(Error::Sfp));
    }

    #[test]
    #[serial_test::serial]
    fn receive_validation_checks_offset_total_and_payload_mtu() {
        let mut packet = Packet::get().unwrap();
        packet.id.flags = Flags::FRAG;
        packet.append_data(&[1, 2]).unwrap();
        packet.append_data(&0u32.to_be_bytes()).unwrap();
        packet.append_data(&4u32.to_be_bytes()).unwrap();

        assert_eq!(validate_fragment(&packet, 0, Some(4), 2), Ok((0, 4, 2)));
        assert_eq!(validate_fragment(&packet, 1, Some(4), 2), Err(Error::Sfp));
        assert_eq!(validate_fragment(&packet, 0, Some(5), 2), Err(Error::Sfp));
        assert_eq!(validate_fragment(&packet, 0, Some(4), 1), Err(Error::Sfp));
    }
}
