use core::sync::atomic::{AtomicUsize, Ordering};

use crate::Error;
use crate::conn::ConnectionID;
use crate::crc32::CRC32;
use crate::id::CspId;

pub(crate) const CSP_BUFFER_SIZE: usize = 256;
pub(crate) const CSP_BUFFER_COUNT: usize = 15;

const CSP_PACKET_PADDING_BYTES: usize = 8;

/// static memory packet pool, packets are safe to be zeroed.
/// initialisation is done by buffer_init()
static mut PACKET_POOL: [PacketBuf; CSP_BUFFER_COUNT] = unsafe { core::mem::zeroed() };

#[repr(C)]
pub struct PacketBuf {
    /// reference counter
    ref_count: AtomicUsize,
    /// index in packet pool
    index: usize,

    conn: Option<ConnectionID>,

    /// Time the message was sent
    pub timestamp_tx: u32,
    /// Time the message was received
    pub timestamp_rx: u32,

    /// Received bytes
    pub(crate) rx_count: u16,
    /// Remaining packets
    pub(crate) remain: u16,
    /// Connection CFP identification number
    pub(crate) cfpid: u32,
    /// Timestamp in ms for last use of buffer
    pub(crate) last_used: u32,

    /// CSP id (unpacked version CPU readable)
    pub(crate) id: CspId,

    /// header length
    header_length: u8,
    /// Data length
    length: u16,

    /// Additional header bytes, to prepend packed data before transmission
    /// This must be minimum 6 bytes to accommodate CSP 2.0. But some implementations
    /// require much more scratch working area for encryption for example.
    ///
    /// Ultimately after csp_id_pack() this area will be filled with the CSP header
    header: [u8; CSP_PACKET_PADDING_BYTES],
    /// Data part of packet
    data: [u8; CSP_BUFFER_SIZE],
}

// header and data must be continuous
const _: () = {
    assert!(
        core::mem::offset_of!(PacketBuf, data)
            == core::mem::offset_of!(PacketBuf, header) + CSP_PACKET_PADDING_BYTES
    );
};

impl PacketBuf {
    pub(crate) fn remaining() -> usize {
        let pool = core::ptr::addr_of!(PACKET_POOL).cast::<PacketBuf>();
        // This is a concurrent count, so allocations may change it during the scan.
        (0..CSP_BUFFER_COUNT)
            .filter(|index| {
                // SAFETY: Each pool entry has static storage and the atomic counter
                // can be read independently while packets are allocated or released.
                unsafe { (*pool.add(*index)).ref_count.load(Ordering::Acquire) == 0 }
            })
            .count()
    }

    /// allocate packet from packet pool
    fn get() -> Option<&'static mut Self> {
        // loop through
        for i in 0..CSP_BUFFER_COUNT {
            // unsafe required to access packet pool
            let packet = unsafe { &mut PACKET_POOL[i] };

            packet.index = i;

            if packet
                .ref_count
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                // store index
                packet.index = i;

                return Some(packet);
            }
        }

        None
    }

    fn free(&mut self) {
        self.ref_count.store(0, Ordering::Release);
    }

    /// initialise fields in packet
    fn init(&mut self) {
        // clear data
        self.data.fill(0);
        self.header.fill(0);

        // length of data
        self.length = 0;
        // begins in main data
        self.header_length = 0;

        self.conn = None;

        // clear id
        self.clear_id();
    }

    /// copy content into other packet
    fn copy_to(&self, buffer: &mut PacketBuf) {
        // unsafe copy to reduce code
        buffer.conn = self.conn;
        buffer.timestamp_rx = self.timestamp_rx;
        buffer.timestamp_tx = self.timestamp_tx;
        buffer.rx_count = self.rx_count;
        buffer.remain = self.remain;
        buffer.cfpid = self.cfpid;
        buffer.last_used = self.last_used;
        buffer.id = self.id;
        buffer.header_length = self.header_length;
        buffer.length = self.length;

        buffer.header.copy_from_slice(&self.header);
        buffer.data.copy_from_slice(&self.data);
    }

    /// returns the updated packet length if successful,
    /// Error if out of memory
    pub fn append_data(&mut self, data: &[u8]) -> Result<usize, Error> {
        if self.length as usize + data.len() > CSP_BUFFER_SIZE {
            return Err(Error::BufferOverflow);
        }

        // get destination slice
        let dst = &mut self.data[self.length as usize..];

        // copy data
        for i in 0..data.len() {
            dst[i] = data[i];
        }

        self.length += data.len() as u16;

        return Ok(self.length as usize);
    }

    pub(crate) fn remove_data(&mut self, len: usize) {
        if (self.length as usize) < len {
            self.length = 0;
            return;
        }

        self.length -= len as u16;
    }

    pub(crate) fn data_length(&self) -> usize {
        self.length as _
    }

    pub fn data(&self) -> &[u8] {
        &self.data[..self.data_length()]
    }

    pub(crate) fn frame_length(&self) -> usize {
        self.length as usize + self.header_length as usize
    }

    pub(crate) fn frame(&self) -> &[u8] {
        // get offset
        let offset = CSP_PACKET_PADDING_BYTES - self.header_length as usize;
        // a bit of hack to merge two slices
        unsafe {
            let ptr = self.header.as_ptr().add(offset);
            core::slice::from_raw_parts(ptr, self.frame_length())
        }
    }

    fn set_crc32(&mut self, crc_data: [u8; 4]) {
        // copy checksum to packet
        (&mut self.data[(self.length as usize)..(self.length as usize + 4)])
            .copy_from_slice(&crc_data);
    }

    fn get_crc32(&self) -> [u8; 4] {
        debug_assert!(self.length >= 4);

        let mut crc = [0; 4];
        // get data
        for i in 0..4 {
            crc[i] = self.data[(self.length - 4) as usize + i];
        }

        return crc;
    }

    /// Append the CSP CRC32 trailer.
    ///
    /// New transmissions checksum the packed CSP header and payload. The
    /// receiver also accepts the legacy payload-only checksum format.
    pub(crate) fn append_crc32(&mut self) -> Result<(), ()> {
        if self.length as usize + size_of::<u32>() > CSP_BUFFER_SIZE {
            return Err(());
        }

        // we only implement v2.1 CRC, which includes header
        self.prepend_id();

        let mut crc = CRC32::new();
        crc.update(self.frame());
        let crc_value = crc.finish();

        // convert to network byte order
        let crc_data = crc_value.to_be_bytes();

        self.set_crc32(crc_data);

        self.length += size_of::<u32>() as u16;

        return Ok(());
    }

    /// verify CRC32, return true on success
    pub(crate) fn verify_crc32(&mut self) -> bool {
        // not valid CRC
        if (self.length as usize) < size_of::<u32>() {
            return false;
        }

        // make sure id is prepended
        self.prepend_id();

        // exclude crc bytes
        let frame = self.frame();
        let frame = &frame[..frame.len() - size_of::<u32>()];

        // calculate CRC
        let mut crc = CRC32::new();
        crc.update(frame);
        let crc_value = crc.finish();

        // convert to network byte order
        let crc_data = crc_value.to_be_bytes();
        // check if equal
        let re = crc_data.eq(&self.get_crc32());

        // Compare calculated checksum without packet header if failed
        let valid = if !re {
            // calculate CRC without header
            let mut crc = CRC32::new();
            crc.update(&self.data[..((self.length as usize) - size_of::<u32>())]);
            let crc_value = crc.finish();

            // convert to network byte order
            let crc_data = crc_value.to_be_bytes();

            crc_data.eq(&self.get_crc32())
        } else {
            true
        };

        if valid {
            self.remove_data(size_of::<u32>());
        }
        valid
    }

    /// convert id into header
    pub(crate) fn prepend_id(&mut self) {
        self.header.fill(0);

        let header = self.id.to_header();

        let offset = CSP_PACKET_PADDING_BYTES - header.len();

        for i in offset..CSP_PACKET_PADDING_BYTES {
            self.header[i] = header[i - offset]
        }

        self.header_length = header.len() as _;
    }

    /// setup packet for rx
    pub(crate) fn setup_rx(&mut self) {
        self.header = [0; _];
        self.header_length = 0;
        self.length = 0;
    }

    pub(crate) fn clear_id(&mut self) {
        self.id.clear()
    }

    pub(crate) fn connection(&self) -> Option<ConnectionID> {
        return self.conn;
    }

    pub(crate) fn set_connection(&mut self, conn: Option<ConnectionID>) {
        self.conn = conn;
    }
}

pub struct Packet {
    inner: &'static mut PacketBuf,
}

impl Packet {
    /// Allocate a packet from the fixed buffer pool.
    pub fn get() -> Option<Self> {
        let inner = PacketBuf::get()?;
        let mut packet = Self { inner };
        packet.init();
        Some(packet)
    }

    /// Allocate a packet and copy this packet's contents into it.
    pub(crate) fn buffer_clone(&self) -> Option<Self> {
        let mut clone = Self::get()?;
        self.copy_to(&mut clone);
        Some(clone)
    }
}

impl core::ops::Deref for Packet {
    type Target = PacketBuf;

    fn deref(&self) -> &Self::Target {
        self.inner
    }
}

impl core::ops::DerefMut for Packet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner
    }
}

impl Drop for Packet {
    fn drop(&mut self) {
        self.inner.free();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::vec;

    #[test]
    fn test_packet_frame() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        packet.header = [0x00, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        packet.header_length = 6;

        packet.append_data(&[1, 2, 3, 4]).unwrap();

        assert_eq!(packet.length, 4);
        assert_eq!(packet.frame_length(), 10);

        assert_eq!(packet.frame().len(), 10);
        assert!(
            packet
                .frame()
                .iter()
                .eq(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 1, 2, 3, 4])
        );
    }

    #[test]
    fn test_packet_crc32() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        packet.append_data(&[0xAA, 0xBB, 0xCC]).unwrap();

        assert_eq!(packet.length, 3);

        packet.append_crc32().unwrap();

        assert_eq!(packet.length, 7);

        assert!(packet.verify_crc32());
    }

    #[test]
    fn test_crc32_detects_payload_corruption() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        packet.append_data(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        packet.append_crc32().unwrap();

        packet.data[1] ^= 0xFF;

        assert!(!packet.verify_crc32());
    }

    #[test]
    fn test_crc32_detects_crc_corruption() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        packet.append_data(&[1, 2, 3, 4]).unwrap();
        packet.append_crc32().unwrap();

        let crc_start = packet.length as usize - 4;
        packet.data[crc_start] ^= 1;

        assert!(!packet.verify_crc32());
    }

    #[test]
    fn test_crc32_empty_payload() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        packet.append_crc32().unwrap();

        assert_eq!(packet.length, 4);
        assert!(packet.verify_crc32());
    }

    #[test]
    fn test_crc32_max_payload() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        let data = [0x55; CSP_BUFFER_SIZE - 4];

        packet.append_data(&data).unwrap();
        packet.append_crc32().unwrap();

        assert_eq!(packet.length as usize, CSP_BUFFER_SIZE);
        assert!(packet.verify_crc32());
    }

    #[test]
    fn test_crc32_no_room() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        let data = [0x55; CSP_BUFFER_SIZE];

        packet.append_data(&data).unwrap();

        assert!(packet.append_crc32().is_err());
    }

    #[test]
    fn test_crc32_verify_too_short() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        packet.append_data(&[1, 2, 3]).unwrap();

        assert!(!packet.verify_crc32());
    }

    #[test]
    fn test_crc32_detects_header_corruption() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        packet.append_data(&[1, 2, 3]).unwrap();
        packet.append_crc32().unwrap();

        packet.id.dst ^= 1;

        assert!(!packet.verify_crc32());
    }

    #[test]
    fn test_crc32_after_strip_id() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        packet.append_data(&[1, 2, 3, 4]).unwrap();
        packet.append_crc32().unwrap();

        packet.header_length = 0;

        assert!(packet.verify_crc32());
    }

    #[test]
    fn test_append_data_overflow() {
        let mut packet: PacketBuf = unsafe { core::mem::zeroed() };

        let data = [0u8; CSP_BUFFER_SIZE];

        packet.append_data(&data).unwrap();

        assert!(packet.append_data(&[1]).is_err());
    }

    /* https://github.com/libcsp/libcsp/#[serial_test::serial]issues/734 */
    #[tokio::test]
    #[serial]
    async fn test_alloc_clean_734() {
        let expected = [0u8; CSP_BUFFER_SIZE];

        /* use all buffer and free them */
        for _ in 0..CSP_BUFFER_COUNT {
            let mut packet = Packet::get().unwrap();
            packet.data = [0u8; _]; /* clear buffer data */
            packet.append_data("previous_data!!".as_bytes()).unwrap(); /* put some data inside */
            drop(packet);
        }

        /* access the data of previously used buffers */
        for _ in 0..CSP_BUFFER_COUNT {
            let packet = Packet::get().unwrap();
            assert_eq!(packet.data, expected);
            assert_eq!(packet.length, 0);
            drop(packet);
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_clone_frame_begin_fixed() {
        let mut src = Packet::get().unwrap();

        /* Simulate a packet with no header*/
        src.append_data("hello".as_bytes()).unwrap();

        /* Add header to simulate a prepared to send packet */
        src.prepend_id();

        let clone = src.buffer_clone().unwrap();

        /* Verify that the data content is identical */
        assert_eq!(clone.frame(), src.frame());

        /* Modify source data to verify that pointer not pointing the same area */
        src.remove_data(6);
        src.append_data("world".as_bytes())
            .expect("buffer overflow");

        /* Check that clone is unaffected by src modification */
        assert_ne!(clone.frame(), src.frame());
        assert_eq!(clone.data(), "hello".as_bytes());

        /* Ensure that frame_begin does NOT point to the same address as the original */
        assert_ne!(clone.frame().as_ptr(), src.frame().as_ptr());

        drop(src);
        drop(clone);
    }
}
