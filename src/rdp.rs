use crate::arch::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RdpState {
    Closed,
    SynSent,
    SynRecv,
    Open,
    CloseWait,
}

pub(crate) struct RdpConnection {
    /// Connection state
    state: RdpState,
    /// Tracks 'who' have closed the RDP connection
    closed_by: u8,
    /// The sequence number of the next segment that is to be sent
    snd_nxt: u16,
    /// The sequence number of the oldest unacknowledged segment
    snd_una: u16,
    /// The initial send sequence number
    snd_iss: u16,
    /// The sequence number of the last segment received correctly and in sequence
    rcv_cur: u16,
    /// The initial receive sequence number
    rcv_irs: u16,
    /// The last sequence number acknowledged by the receiver
    rcv_lsa: u16,
    window_size: u32,
    conn_timeout: u32,
    packet_timeout: u32,
    delayed_acks: u32,
    ack_timeout: u32,
    ack_delay_count: u32,
    ack_timestamp: u32,
    tx_wait: Mutex<()>,
}

impl RdpConnection {
    pub(crate) const fn const_new() -> Self {
        Self {
            state: RdpState::Closed,
            closed_by: 0,
            snd_nxt: 0,
            snd_una: 0,
            snd_iss: 0,
            rcv_cur: 0,
            rcv_irs: 0,
            rcv_lsa: 0,
            window_size: 0,
            conn_timeout: 0,
            packet_timeout: 0,
            delayed_acks: 0,
            ack_timeout: 0,
            ack_delay_count: 0,
            ack_timestamp: 0,
            tx_wait: Mutex::new(()),
        }
    }
}
