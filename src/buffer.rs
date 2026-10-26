use core::sync::atomic::AtomicUsize;

use crate::Error;
use crate::arch::Queue;
use crate::conn::ConnectionID;
use crate::crc32::CRC32;
use crate::id::CspId;

pub(crate) const CSP_BUFFER_SIZE: usize = 256;
pub(crate) const CSP_BUFFER_COUNT: usize = 15;

const CSP_PACKET_PADDING_BYTES: usize = 8;

static PACKET_QUEUE: Queue<usize, CSP_BUFFER_COUNT> = Queue::new();
/// static memory packet pool, packets are safe to be zeroed.
/// initialisation is done by buffer_init()
static mut PACKET_POOL: [Packet; CSP_BUFFER_COUNT] = unsafe { core::mem::zeroed() };

#[repr(C)]
pub struct Packet {
    ref_count: AtomicUsize,

    /// Time the message was sent
    pub timestamp_tx: u32,
    /// Time the message was received
    pub timestamp_rx: u32,

    conn: Option<ConnectionID>,

    /// index in packet pool
    index: usize,

    /// Received bytes
    pub(crate) rx_count: u16,
    /// Remaining packets
    pub(crate) remain: u16,
    /// Connection CFP identification number
    pub(crate) cfpid: u32,
    /// Timestamp in ms for last use of buffer
    pub(crate) last_used: u32,

    /// header length
    header_length: u8,
    /// Data length
    length: u16,
    /// CSP id (unpacked version CPU readable)
    pub(crate) id: CspId,

    // next: Option<&'static mut Packet>,
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
        core::mem::offset_of!(Packet, data)
            == core::mem::offset_of!(Packet, header) + CSP_PACKET_PADDING_BYTES
    );
};

/// initalise all packet buffers, only called by crate::init()
pub(super) async fn buffer_init() {
    for i in 0..CSP_BUFFER_COUNT {
        PACKET_QUEUE.push(i).await;
    }
}

impl Packet {
    /// allocate packet from packet pool
    pub(crate) async fn get() -> &'static mut Self {
        // get next packet index
        let index = PACKET_QUEUE.pop().await;
        // unsafe required to access packet pool
        let packet = unsafe { &mut PACKET_POOL[index] };

        // store index
        packet.index = index;
        packet.init();

        return packet;
    }

    /// free packet back to packet pool.
    /// packet should not be used after this call
    pub(crate) async fn free(&'static mut self) {
        // push packet index to queue
        PACKET_QUEUE.push(self.index).await;
    }

    /// initialise fields in packet
    pub(crate) fn init(&mut self) {
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

    /// allocate a new packet and copy content into buffer
    pub(crate) async fn buffer_clone(&self) -> &'static mut Self {
        let clone = Self::get().await;
        self.copy_to(clone);

        return clone;
    }

    /// copy content into other packet
    pub(crate) fn copy_to(&self, buffer: &mut Packet) {
        // unsafe copy to reduce code
        unsafe { core::ptr::copy(self, buffer, 1) };
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

    pub fn remove_data(&mut self, len: usize) {
        if (self.length as usize) < len {
            self.length = 0;
            return;
        }

        self.length -= len as u16;
    }

    pub(crate) fn data_length(&self) -> usize {
        self.length as _
    }

    pub(crate) fn data(&self) -> &[u8] {
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
        let mut crc = [0; 4];
        // get data
        for i in 0..4 {
            crc[i] = self.data[(self.length - 4) as usize + i];
        }

        return crc;
    }

    /// Calculate and append CRC32, returns error if not enough memory
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
        let frame = &self.frame()[..self.frame().len() - size_of::<u32>()];

        // calculate CRC
        let mut crc = CRC32::new();
        crc.update(frame);
        let crc_value = crc.finish();

        // convert to network byte order
        let crc_data = crc_value.to_be_bytes();
        // check if equal
        let re = crc_data.eq(&self.get_crc32());

        // Compare calculated checksum without packet header if failed
        if !re {
            // calculate CRC without header
            let mut crc = CRC32::new();
            crc.update(&self.data[..((self.length as usize) - size_of::<u32>())]);
            let crc_value = crc.finish();

            // convert to network byte order
            let crc_data = crc_value.to_be_bytes();

            return crc_data.eq(&self.get_crc32());
        }

        return true;
    }

    /// convert id into header
    pub(crate) fn prepend_id(&mut self) {
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

    /// extract and store ID, calculate data length
    pub(crate) fn strip_id(&mut self) {
        self.id = CspId::from_header(self.frame());
        self.length = (self.frame_length() - crate::id::get_header_size()) as _;
    }

    pub(crate) fn clear_id(&mut self) {
        self.id.clear()
    }

    pub(crate) fn connection(&self) -> Option<ConnectionID>{
        return self.conn
    }

    pub(crate) fn set_connection(&mut self, conn: Option<ConnectionID>){
        self.conn = conn;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::vec;

    #[test]
    fn test_packet_frame() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

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
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        packet.append_data(&[0xAA, 0xBB, 0xCC]).unwrap();

        assert_eq!(packet.length, 3);

        packet.append_crc32().unwrap();

        assert_eq!(packet.length, 7);

        assert!(packet.verify_crc32());
    }

    #[test]
    fn test_crc32_detects_payload_corruption() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        packet.append_data(&[0xAA, 0xBB, 0xCC, 0xDD]).unwrap();
        packet.append_crc32().unwrap();

        packet.data[1] ^= 0xFF;

        assert!(!packet.verify_crc32());
    }

    #[test]
    fn test_crc32_detects_crc_corruption() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        packet.append_data(&[1, 2, 3, 4]).unwrap();
        packet.append_crc32().unwrap();

        let crc_start = packet.length as usize - 4;
        packet.data[crc_start] ^= 1;

        assert!(!packet.verify_crc32());
    }

    #[test]
    fn test_crc32_empty_payload() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        packet.append_crc32().unwrap();

        assert_eq!(packet.length, 4);
        assert!(packet.verify_crc32());
    }

    #[test]
    fn test_crc32_max_payload() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        let data = [0x55; CSP_BUFFER_SIZE - 4];

        packet.append_data(&data).unwrap();
        packet.append_crc32().unwrap();

        assert_eq!(packet.length as usize, CSP_BUFFER_SIZE);
        assert!(packet.verify_crc32());
    }

    #[test]
    fn test_crc32_no_room() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        let data = [0x55; CSP_BUFFER_SIZE];

        packet.append_data(&data).unwrap();

        assert!(packet.append_crc32().is_err());
    }

    #[test]
    fn test_crc32_verify_too_short() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        packet.append_data(&[1, 2, 3]).unwrap();

        assert!(!packet.verify_crc32());
    }

    #[test]
    fn test_crc32_detects_header_corruption() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        packet.append_data(&[1, 2, 3]).unwrap();
        packet.append_crc32().unwrap();

        packet.id.dst ^= 1;

        assert!(!packet.verify_crc32());
    }

    #[test]
    fn test_crc32_after_strip_id() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        packet.append_data(&[1, 2, 3, 4]).unwrap();
        packet.append_crc32().unwrap();

        packet.strip_id();

        assert!(packet.verify_crc32());
    }

    #[test]
    fn test_append_data_overflow() {
        let mut packet: Packet = unsafe { core::mem::zeroed() };

        let data = [0u8; CSP_BUFFER_SIZE];

        packet.append_data(&data).unwrap();

        assert!(packet.append_data(&[1]).is_err());
    }

    /* https://github.com/libcsp/libcsp/#[serial_test::serial]issues/734 */
    #[test]
    #[serial]
    fn test_alloc_clean_734() {
        let rt = tokio::runtime::Builder::new_multi_thread().build().unwrap();

        rt.block_on(async{
            let expected = [0u8;CSP_BUFFER_SIZE];

            crate::init().await;

            /* use all buffer and free them */
            for _ in 0..CSP_BUFFER_COUNT{
                let packet = Packet::get().await;
                packet.data = [0u8;_]; /* clear buffer data */
                packet.append_data("previous_data!!".as_bytes()).unwrap();  /* put some data inside */
                packet.free().await;
            }

            /* access the data of previously used buffers */
            for _ in 0..CSP_BUFFER_COUNT {
                let packet = Packet::get().await;
                assert_eq!(packet.data, expected);
                assert_eq!(packet.length, 0);
                packet.free().await;
            }
        })
    }

    #[test]
    #[serial]
    fn test_clone_frame_begin_fixed() {
        let rt = tokio::runtime::Builder::new_multi_thread().build().unwrap();

        rt.block_on(async {
            buffer_init().await;

            let src = Packet::get().await;

            /* Simulate a packet with no header*/
            src.append_data("hello".as_bytes()).unwrap();

            /* Add header to simulate a prepared to send packet */
            src.prepend_id();

            let clone = src.buffer_clone().await;

            /* Verify that the data content is identical */
            assert_eq!(clone.frame(), src.frame());

            /* Modify source data to verify that pointer not pointing the same area */
            src.remove_data(6);
            src.append_data("world".as_bytes())
                .expect("buffer overflow");

            /* Check that clone is unaffected by src modification */
            assert_ne!(clone.frame(), src.frame());
            assert_eq!(clone.frame(), "hello".as_bytes());

            /* Ensure that frame_begin does NOT point to the same address as the original */
            assert_ne!(clone.frame().as_ptr(), src.frame().as_ptr());

            src.free().await;
            clone.free().await;
        })
    }
}
