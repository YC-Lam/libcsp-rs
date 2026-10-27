use crate::{Packet, arch, crc32::CRC32};

/// Check the last CSP_DEDUP_COUNT packets for duplicates
const CSP_DEDUP_COUNT: usize = 16;
/// Only consider packet a duplicate if received under CSP_DEDUP_WINDOW_MS ago
const CSP_DEDUP_WINDOW_MS: u32 = 100;

static mut DEDUP_ARRAY: [u32; CSP_DEDUP_COUNT] = [0; _];
static mut DEDUP_TIMESTAMP: [u32; CSP_DEDUP_COUNT] = [0; _];
static mut DEDUP_IN: usize = 0;

pub(crate) fn is_duplicate(packet: &mut Packet) -> bool {
    // prepend header
    packet.prepend_id();

    // calculate CRC
    let mut crc = CRC32::new();
    crc.update(packet.frame());
    let crc_value = crc.finish();

    let time = arch::get_ms();

    unsafe {
        // Check if we have received this packet before, start looking from newest packet
        let mut i = DEDUP_IN.wrapping_sub(1) % CSP_DEDUP_COUNT;

        for _ in 0..CSP_DEDUP_COUNT {
            // check timestamp
            if time - DEDUP_TIMESTAMP[i] > CSP_DEDUP_WINDOW_MS {
                break;
            }

            if crc_value == DEDUP_ARRAY[i] {
                return true;
            }

            i = i.wrapping_sub(1) & CSP_DEDUP_COUNT.wrapping_sub(1);
        }

        DEDUP_ARRAY[DEDUP_IN] = crc_value;
        DEDUP_TIMESTAMP[DEDUP_IN] = time;
        DEDUP_IN = (DEDUP_IN + 1) % CSP_DEDUP_COUNT;
    }

    return false;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dedup() {
        let mut packet = Packet::get().unwrap();

        packet.append_data("hello world".as_bytes()).unwrap();

        let mut cloned = packet.buffer_clone().unwrap();

        assert_eq!(is_duplicate(&mut packet), false);
        assert_eq!(is_duplicate(&mut cloned), true);
    }
}
