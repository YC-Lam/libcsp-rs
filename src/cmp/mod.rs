//! CSP Management Protocol (CMP).

use core::ffi::c_void;

// Replace these with the values from your CSP configuration.
pub(crate) const CSP_HOSTNAME_LEN: usize = 16;
pub(crate) const CSP_MODEL_LEN: usize = 16;

// Replace this alias with the actual type of csp_timestamp_t.
pub(crate) type CspTimestamp = u64;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

pub(crate) const CSP_CMP_IDENT_REV_LEN: usize = 20;
pub(crate) const CSP_CMP_IDENT_DATE_LEN: usize = 12;
pub(crate) const CSP_CMP_IDENT_TIME_LEN: usize = 9;

pub(crate) const CSP_CMP_ROUTE_IFACE_LEN: usize = 11;

pub(crate) const CSP_CMP_PEEK_MAX_LEN: usize = 200;
pub(crate) const CSP_CMP_POKE_MAX_LEN: usize = 200;
pub(crate) const CSP_CMP_PEEK_V2_MAX_LEN: usize = 196;
pub(crate) const CSP_CMP_POKE_V2_MAX_LEN: usize = 196;

// -----------------------------------------------------------------------------
// Enumerations
// -----------------------------------------------------------------------------

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CspCmpType {
    Request = 0x00,
    Reply = 0xff,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CspCmpCode {
    Ident = 1,
    RouteSetV1 = 2,
    IfStats = 3,
    Peek = 4,
    Poke = 5,
    Clock = 6,
    RouteSetV2 = 7,
    PeekV2 = 8,
    PokeV2 = 9,
}

// -----------------------------------------------------------------------------
// Wire message headers
// -----------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpHeader {
    pub(crate) type_: u8,
    pub(crate) code: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpIdentMsg {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) hostname: [u8; CSP_HOSTNAME_LEN],
    pub(crate) model: [u8; CSP_MODEL_LEN],
    pub(crate) revision: [u8; CSP_CMP_IDENT_REV_LEN],
    pub(crate) date: [u8; CSP_CMP_IDENT_DATE_LEN],
    pub(crate) time: [u8; CSP_CMP_IDENT_TIME_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpRouteSetV1Msg {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) dest_node: u8,
    pub(crate) next_hop_via: u8,
    pub(crate) interface: [u8; CSP_CMP_ROUTE_IFACE_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpRouteSetV2Msg {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) dest_node: u16,
    pub(crate) next_hop_via: u16,
    pub(crate) netmask: u16,
    pub(crate) interface: [u8; CSP_CMP_ROUTE_IFACE_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpIfStatsMsg {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) interface: [u8; CSP_CMP_ROUTE_IFACE_LEN],
    pub(crate) tx: u32,
    pub(crate) rx: u32,
    pub(crate) tx_error: u32,
    pub(crate) rx_error: u32,
    pub(crate) drop: u32,
    pub(crate) autherr: u32,
    pub(crate) frame: u32,
    pub(crate) txbytes: u32,
    pub(crate) rxbytes: u32,
    pub(crate) irq: u32,
}

// Flexible-array messages: these structs describe only the fixed prefix.
// The trailing data bytes follow immediately after the prefix on the wire.

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpPeekMsg {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) addr: u32,
    pub(crate) len: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpPokeMsg {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) addr: u32,
    pub(crate) len: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpPeekV2Msg {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) vaddr: u64,
    pub(crate) len: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpPokeV2Msg {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) vaddr: u64,
    pub(crate) len: u8,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpClockMsg {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) clock: CspTimestamp,
}

// -----------------------------------------------------------------------------
// Legacy aggregate message
// -----------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpIdent {
    pub(crate) hostname: [u8; CSP_HOSTNAME_LEN],
    pub(crate) model: [u8; CSP_MODEL_LEN],
    pub(crate) revision: [u8; CSP_CMP_IDENT_REV_LEN],
    pub(crate) date: [u8; CSP_CMP_IDENT_DATE_LEN],
    pub(crate) time: [u8; CSP_CMP_IDENT_TIME_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpRouteSetV1 {
    pub(crate) dest_node: u8,
    pub(crate) next_hop_via: u8,
    pub(crate) interface: [u8; CSP_CMP_ROUTE_IFACE_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpRouteSetV2 {
    pub(crate) dest_node: u16,
    pub(crate) next_hop_via: u16,
    pub(crate) netmask: u16,
    pub(crate) interface: [u8; CSP_CMP_ROUTE_IFACE_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpIfStats {
    pub(crate) interface: [u8; CSP_CMP_ROUTE_IFACE_LEN],
    pub(crate) tx: u32,
    pub(crate) rx: u32,
    pub(crate) tx_error: u32,
    pub(crate) rx_error: u32,
    pub(crate) drop: u32,
    pub(crate) autherr: u32,
    pub(crate) frame: u32,
    pub(crate) txbytes: u32,
    pub(crate) rxbytes: u32,
    pub(crate) irq: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpPeek {
    pub(crate) addr: u32,
    pub(crate) len: u8,
    pub(crate) data: [u8; CSP_CMP_PEEK_MAX_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpPoke {
    pub(crate) addr: u32,
    pub(crate) len: u8,
    pub(crate) data: [u8; CSP_CMP_POKE_MAX_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpPeekV2 {
    pub(crate) vaddr: u64,
    pub(crate) len: u8,
    pub(crate) data: [u8; CSP_CMP_PEEK_V2_MAX_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpPokeV2 {
    pub(crate) vaddr: u64,
    pub(crate) len: u8,
    pub(crate) data: [u8; CSP_CMP_POKE_V2_MAX_LEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) union CspCmpPayload {
    pub(crate) ident: CspCmpIdent,
    pub(crate) route_set_v1: CspCmpRouteSetV1,
    pub(crate) route_set_v2: CspCmpRouteSetV2,
    pub(crate) if_stats: CspCmpIfStats,
    pub(crate) peek: CspCmpPeek,
    pub(crate) poke: CspCmpPoke,
    pub(crate) peek_v2: CspCmpPeekV2,
    pub(crate) poke_v2: CspCmpPokeV2,
    pub(crate) clock: CspTimestamp,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct CspCmpMessage {
    pub(crate) type_: u8,
    pub(crate) code: u8,
    pub(crate) payload: CspCmpPayload,
}

// -----------------------------------------------------------------------------
// Message size calculations
// -----------------------------------------------------------------------------

#[inline]
pub(crate) const fn cmp_align_up_32(len: usize) -> usize {
    (len + 3) & !3
}

/// Equivalent to CMP_VARIABLE_SIZE for a flexible-array message.
///
/// `struct_size` includes the fixed prefix but not the data array.
/// `fixed_payload_size` is the size of the prefix after the 2-byte header.
#[inline]
pub(crate) const fn cmp_variable_size(
    struct_size: usize,
    fixed_payload_size: usize,
    len: usize,
) -> usize {
    let tail_size = cmp_align_up_32(fixed_payload_size)
        - fixed_payload_size;

    struct_size + tail_size + len
}

pub(crate) const fn cmp_peek_size(len: usize) -> usize {
    cmp_variable_size(7, 5, len)
}

pub(crate) const fn cmp_poke_size(len: usize) -> usize {
    cmp_variable_size(7, 5, len)
}

pub(crate) const fn cmp_peek_v2_size(len: usize) -> usize {
    cmp_variable_size(11, 9, len)
}

pub(crate) const fn cmp_poke_v2_size(len: usize) -> usize {
    cmp_variable_size(11, 9, len)
}

// -----------------------------------------------------------------------------
// FFI
// -----------------------------------------------------------------------------

unsafe extern "C" {
    pub(crate) fn csp_cmp(
        node: u16,
        timeout: u32,
        code: u8,
        msg_size: i32,
        msg: *mut c_void,
    ) -> i32;
}

// -----------------------------------------------------------------------------
// Safe-size, unsafe-call wrappers
// -----------------------------------------------------------------------------

/// Sends a CMP request using the specified fixed-size message.
///
/// # Safety
///
/// `msg` must point to a writable buffer of at least `msg_size` bytes.
/// The buffer must remain valid for the duration of the C call.
pub(crate) unsafe fn cmp(
    node: u16,
    timeout: u32,
    code: CspCmpCode,
    msg_size: usize,
    msg: *mut c_void,
) -> i32 {
    let Ok(msg_size) = i32::try_from(msg_size) else {
        return -1;
    };

    // SAFETY: The caller guarantees that the pointer and size are valid.
    unsafe { csp_cmp(node, timeout, code as u8, msg_size, msg) }
}

/// Calls CMP with an identification message.
pub(crate) unsafe fn cmp_ident(
    node: u16,
    timeout: u32,
    msg: *mut CspCmpIdentMsg,
) -> i32 {
    // SAFETY: The caller guarantees that msg points to a valid message.
    unsafe {
        cmp(
            node,
            timeout,
            CspCmpCode::Ident,
            core::mem::size_of::<CspCmpIdentMsg>(),
            msg.cast(),
        )
    }
}

/// Calls CMP with a route-set V1 message.
pub(crate) unsafe fn cmp_route_set_v1(
    node: u16,
    timeout: u32,
    msg: *mut CspCmpRouteSetV1Msg,
) -> i32 {
    unsafe {
        cmp(
            node,
            timeout,
            CspCmpCode::RouteSetV1,
            core::mem::size_of::<CspCmpRouteSetV1Msg>(),
            msg.cast(),
        )
    }
}

/// Calls CMP with an interface statistics message.
pub(crate) unsafe fn cmp_if_stats(
    node: u16,
    timeout: u32,
    msg: *mut CspCmpIfStatsMsg,
) -> i32 {
    unsafe {
        cmp(
            node,
            timeout,
            CspCmpCode::IfStats,
            core::mem::size_of::<CspCmpIfStatsMsg>(),
            msg.cast(),
        )
    }
}

/// Calls CMP with a clock message.
pub(crate) unsafe fn cmp_clock(
    node: u16,
    timeout: u32,
    msg: *mut CspCmpClockMsg,
) -> i32 {
    unsafe {
        cmp(
            node,
            timeout,
            CspCmpCode::Clock,
            core::mem::size_of::<CspCmpClockMsg>(),
            msg.cast(),
        )
    }
}

/// Calls CMP with a route-set V2 message.
pub(crate) unsafe fn cmp_route_set_v2(
    node: u16,
    timeout: u32,
    msg: *mut CspCmpRouteSetV2Msg,
) -> i32 {
    unsafe {
        cmp(
            node,
            timeout,
            CspCmpCode::RouteSetV2,
            core::mem::size_of::<CspCmpRouteSetV2Msg>(),
            msg.cast(),
        )
    }
}

/// Calls CMP with a PEEK message and its trailing data buffer.
///
/// # Safety
///
/// `msg` must point to a buffer large enough for the fixed prefix,
/// alignment padding, and `len` data bytes.
pub(crate) unsafe fn cmp_peek(
    node: u16,
    timeout: u32,
    msg: *mut CspCmpPeekMsg,
    len: u8,
) -> i32 {
    unsafe {
        cmp(
            node,
            timeout,
            CspCmpCode::Peek,
            cmp_peek_size(len as usize),
            msg.cast(),
        )
    }
}

/// Calls CMP with a POKE message and its trailing data buffer.
///
/// # Safety
///
/// `msg` must point to a buffer large enough for the fixed prefix,
/// alignment padding, and `len` data bytes.
pub(crate) unsafe fn cmp_poke(
    node: u16,
    timeout: u32,
    msg: *mut CspCmpPokeMsg,
    len: u8,
) -> i32 {
    unsafe {
        cmp(
            node,
            timeout,
            CspCmpCode::Poke,
            cmp_poke_size(len as usize),
            msg.cast(),
        )
    }
}

/// Calls CMP with a PEEK V2 message and its trailing data buffer.
///
/// # Safety
///
/// `msg` must point to a buffer large enough for the fixed prefix,
/// alignment padding, and `len` data bytes.
pub(crate) unsafe fn cmp_peek_v2(
    node: u16,
    timeout: u32,
    msg: *mut CspCmpPeekV2Msg,
    len: u8,
) -> i32 {
    unsafe {
        cmp(
            node,
            timeout,
            CspCmpCode::PeekV2,
            cmp_peek_v2_size(len as usize),
            msg.cast(),
        )
    }
}

/// Calls CMP with a POKE V2 message and its trailing data buffer.
///
/// # Safety
///
/// `msg` must point to a buffer large enough for the fixed prefix,
/// alignment padding, and `len` data bytes.
pub(crate) unsafe fn cmp_poke_v2(
    node: u16,
    timeout: u32,
    msg: *mut CspCmpPokeV2Msg,
    len: u8,
) -> i32 {
    unsafe {
        cmp(
            node,
            timeout,
            CspCmpCode::PokeV2,
            cmp_poke_v2_size(len as usize),
            msg.cast(),
        )
    }
}