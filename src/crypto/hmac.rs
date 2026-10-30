use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use crate::{Error, Packet};

pub const HMAC_LENGTH: usize = 4;
pub const SHA1_DIGEST_SIZE: usize = 20;
const SHA1_BLOCK_SIZE: usize = 64;
const KEY_SIZE: usize = 16;

static KEY_VERSION: AtomicU32 = AtomicU32::new(0);
static KEY: [AtomicU8; KEY_SIZE] = [const { AtomicU8::new(0) }; KEY_SIZE];

/// Configure the CSP HMAC key. libcsp derives its 16-byte key from SHA-1(key).
pub fn set_key(key: &[u8]) -> Result<(), Error> {
    let derived = sha1(key);
    let mut version = KEY_VERSION.load(Ordering::Acquire);
    loop {
        if version & 1 != 0 {
            version = KEY_VERSION.load(Ordering::Acquire);
            continue;
        }
        match KEY_VERSION.compare_exchange_weak(
            version,
            version.wrapping_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => break,
            Err(actual) => version = actual,
        }
    }

    for (slot, value) in KEY.iter().zip(derived) {
        slot.store(value, Ordering::Relaxed);
    }
    KEY_VERSION.store(version.wrapping_add(2), Ordering::Release);
    Ok(())
}

/// Return a full HMAC-SHA1 digest for an arbitrary key and message.
pub fn compute(key: &[u8], data: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    let mut normalized_key = [0; SHA1_BLOCK_SIZE];
    if key.len() > SHA1_BLOCK_SIZE {
        normalized_key[..SHA1_DIGEST_SIZE].copy_from_slice(&sha1(key));
    } else {
        normalized_key[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36; SHA1_BLOCK_SIZE];
    let mut outer_pad = [0x5c; SHA1_BLOCK_SIZE];
    for index in 0..SHA1_BLOCK_SIZE {
        inner_pad[index] ^= normalized_key[index];
        outer_pad[index] ^= normalized_key[index];
    }

    let mut inner = Sha1::new();
    inner.update(&inner_pad);
    inner.update(data);
    let inner_digest = inner.finish();

    let mut outer = Sha1::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);
    outer.finish()
}

/// Append the 4-byte CSP HMAC-SHA1 tag to a packet.
///
/// With `include_header`, the packed CSP identifier is part of the MAC input.
pub fn append(packet: &mut Packet, include_header: bool) -> Result<(), Error> {
    if packet.data_length() + HMAC_LENGTH > crate::buffer::CSP_BUFFER_SIZE {
        return Err(Error::BufferOverflow);
    }
    let key = current_key();
    if include_header {
        packet.prepend_id();
    }
    let digest = if include_header {
        compute(&key, packet.frame())
    } else {
        compute(&key, packet.data())
    };
    packet.append_data(&digest[..HMAC_LENGTH])?;
    Ok(())
}

/// Verify and remove a packet's 4-byte CSP HMAC-SHA1 tag.
///
/// CRC32 verification must run first, as in libcsp; its verifier removes the
/// CRC trailer before this function processes the HMAC.
pub fn verify(packet: &mut Packet, include_header: bool) -> Result<(), Error> {
    let length = packet.data_length();
    if length < HMAC_LENGTH {
        return Err(Error::HMAC);
    }

    let key = current_key();
    if include_header {
        packet.prepend_id();
    }
    let frame = if include_header {
        packet.frame()
    } else {
        packet.data()
    };
    if matches_tag(
        &key,
        &frame[..frame.len() - HMAC_LENGTH],
        &packet.data()[length - HMAC_LENGTH..],
    ) {
        packet.remove_data(HMAC_LENGTH);
        return Ok(());
    }

    Err(Error::HMAC)
}

fn matches_tag(key: &[u8], data: &[u8], actual: &[u8]) -> bool {
    let expected = compute(key, data);
    let mut difference = 0u8;
    for index in 0..HMAC_LENGTH {
        difference |= expected[index] ^ actual[index];
    }
    difference == 0
}

fn current_key() -> [u8; KEY_SIZE] {
    loop {
        let version = KEY_VERSION.load(Ordering::Acquire);
        if version & 1 != 0 {
            continue;
        }

        let mut key = [0; KEY_SIZE];
        for (byte, slot) in key.iter_mut().zip(KEY.iter()) {
            *byte = slot.load(Ordering::Relaxed);
        }

        if KEY_VERSION.load(Ordering::Acquire) == version {
            return key;
        }
    }
}

fn sha1(data: &[u8]) -> [u8; SHA1_DIGEST_SIZE] {
    let mut state = Sha1::new();
    state.update(data);
    state.finish()
}

struct Sha1 {
    state: [u32; 5],
    buffer: [u8; SHA1_BLOCK_SIZE],
    buffered: usize,
    length: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            buffer: [0; SHA1_BLOCK_SIZE],
            buffered: 0,
            length: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);

        if self.buffered != 0 {
            let count = (SHA1_BLOCK_SIZE - self.buffered).min(data.len());
            self.buffer[self.buffered..self.buffered + count].copy_from_slice(&data[..count]);
            self.buffered += count;
            data = &data[count..];
            if self.buffered == SHA1_BLOCK_SIZE {
                compress(&mut self.state, &self.buffer);
                self.buffered = 0;
            }
        }

        while data.len() >= SHA1_BLOCK_SIZE {
            let block: &[u8; SHA1_BLOCK_SIZE] = data[..SHA1_BLOCK_SIZE]
                .try_into()
                .expect("block has fixed size");
            compress(&mut self.state, block);
            data = &data[SHA1_BLOCK_SIZE..];
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    fn finish(mut self) -> [u8; SHA1_DIGEST_SIZE] {
        let bit_length = self.length.wrapping_mul(8);
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;

        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            compress(&mut self.state, &self.buffer);
            self.buffered = 0;
        }

        self.buffer[self.buffered..56].fill(0);
        self.buffer[56..].copy_from_slice(&bit_length.to_be_bytes());
        compress(&mut self.state, &self.buffer);

        let mut digest = [0; SHA1_DIGEST_SIZE];
        for (chunk, word) in digest.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        digest
    }
}

fn compress(state: &mut [u32; 5], block: &[u8; SHA1_BLOCK_SIZE]) {
    let mut words = [0u32; 80];
    for (word, bytes) in words.iter_mut().take(16).zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(bytes.try_into().expect("word has fixed size"));
    }
    for index in 16..80 {
        words[index] =
            (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                .rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (index, word) in words.iter().enumerate() {
        let (function, constant) = match index {
            0..=19 => ((b & c) | (!b & d), 0x5a827999),
            20..=39 => (b ^ c ^ d, 0x6ed9eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
            _ => (b ^ c ^ d, 0xca62c1d6),
        };
        let next = a
            .rotate_left(5)
            .wrapping_add(function)
            .wrapping_add(e)
            .wrapping_add(constant)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = next;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Flags, Priority};
    use std::vec;

    fn hex(bytes: &[u8]) -> std::string::String {
        use core::fmt::Write;
        let mut output = std::string::String::new();
        for byte in bytes {
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }

    #[test]
    fn hmac_sha1_matches_rfc_2202() {
        let digest = compute(&[0x0b; 20], b"Hi There");
        assert_eq!(hex(&digest), "b617318655057264e28bc0b6fb378c8ef146be00");
    }

    #[test]
    fn hmac_sha1_handles_long_keys_and_messages() {
        let digest = compute(&[0xaa; 80], &[0xdd; 50]);
        assert_eq!(hex(&digest), "a0e147e8bd6edef15f7cb1bdc761d85e29bfcf70");
    }

    #[test]
    #[serial_test::serial]
    fn packet_hmac_round_trip_and_rejects_corruption() {
        set_key(b"csp test key").unwrap();
        let mut packet = Packet::get().unwrap();
        packet.id.prio = Priority::Normal;
        packet.id.flags = Flags::HMAC;
        packet.append_data(b"authenticated payload").unwrap();
        append(&mut packet, false).unwrap();
        assert_eq!(
            packet.data_length(),
            b"authenticated payload".len() + HMAC_LENGTH
        );
        verify(&mut packet, false).unwrap();
        assert_eq!(packet.data(), b"authenticated payload");

        set_key(b"different key").unwrap();
        assert_eq!(verify(&mut packet, false), Err(Error::HMAC));
    }

    #[test]
    #[serial_test::serial]
    fn verification_strips_hmac_and_trailing_crc() {
        set_key(b"crc hmac key").unwrap();
        let mut packet = Packet::get().unwrap();
        packet.id.flags = Flags::HMAC | Flags::CRC32;
        packet.append_data(b"authenticated payload").unwrap();
        append(&mut packet, false).unwrap();
        packet.append_crc32().unwrap();
        assert!(packet.verify_crc32());
        verify(&mut packet, false).unwrap();
        assert_eq!(packet.data(), b"authenticated payload");
    }

    #[test]
    #[serial_test::serial]
    fn packet_hmac_can_authenticate_the_packed_header() {
        set_key(b"header hmac key").unwrap();
        let mut packet = Packet::get().unwrap();
        packet.id.prio = Priority::High;
        packet.id.src = 12;
        packet.id.dst = 34;
        packet.id.sport = 5;
        packet.id.dport = 6;
        packet.append_data(b"payload").unwrap();
        append(&mut packet, true).unwrap();
        verify(&mut packet, true).unwrap();
        assert_eq!(packet.data(), b"payload");

        append(&mut packet, true).unwrap();
        packet.id.dst = 35;
        assert_eq!(verify(&mut packet, true), Err(Error::HMAC));
    }
}
