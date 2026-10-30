//! Built-in CSP service handlers and clients.

use core::sync::atomic::{AtomicPtr, Ordering};

use crate::{CspStream, Error, Packet, Priority};

/// Platform-specific callbacks for services that require application or OS support.
///
/// Store this value in static storage before registering it with [`set_hooks`].
/// Missing callbacks leave their platform-dependent operation unavailable.
pub struct ServiceHooks {
    pub identity: crate::cmp::Identity,
    pub memory_free: Option<fn() -> u32>,
    pub process_list: Option<fn(&mut [u8]) -> Result<usize, Error>>,
    pub reboot: Option<fn()>,
    pub shutdown: Option<fn()>,
    pub clock_get: Option<fn() -> (u32, u32)>,
    pub clock_set: Option<fn(u32, u32) -> Result<(), Error>>,
}

impl ServiceHooks {
    /// Create a hook table with no platform callbacks configured.
    pub const fn new(identity: crate::cmp::Identity) -> Self {
        Self {
            identity,
            memory_free: None,
            process_list: None,
            reboot: None,
            shutdown: None,
            clock_get: None,
            clock_set: None,
        }
    }
}

static HOOKS: AtomicPtr<ServiceHooks> = AtomicPtr::new(core::ptr::null_mut());

/// Register platform hooks. The referenced configuration must remain valid forever.
pub fn set_hooks(hooks: &'static ServiceHooks) {
    HOOKS.store(
        hooks as *const ServiceHooks as *mut ServiceHooks,
        Ordering::Release,
    );
}

/// Disable all platform hooks.
pub fn clear_hooks() {
    HOOKS.store(core::ptr::null_mut(), Ordering::Release);
}

pub(crate) fn hooks() -> Option<&'static ServiceHooks> {
    let hooks = HOOKS.load(Ordering::Acquire);
    // SAFETY: set_hooks only publishes references with static lifetime.
    unsafe { hooks.as_ref() }
}

pub(crate) fn identity() -> Option<&'static crate::cmp::Identity> {
    hooks().map(|hooks| &hooks.identity)
}

/// Dispatch built-in ports: reply, consume without reply, or pass through.
pub async fn handle(packet: &mut Packet) -> Result<Option<bool>, Error> {
    let port = packet.id.dport;
    if port == crate::CSP_CMP {
        return crate::cmp::handle(packet).await;
    }

    match port {
        crate::CSP_PING => Ok(Some(true)),
        crate::CSP_MEMFREE => {
            if packet.data_length() != 0 {
                return Err(Error::InvalidOperation);
            }
            let memory = (hooks()
                .and_then(|hooks| hooks.memory_free)
                .ok_or(Error::FeatureDisabled)?)();
            set_u32(packet, memory)?;
            Ok(Some(true))
        }
        crate::CSP_PS => {
            let callback = hooks()
                .and_then(|hooks| hooks.process_list)
                .ok_or(Error::FeatureDisabled)?;
            let mut output = [0; crate::buffer::CSP_BUFFER_SIZE];
            let length = callback(&mut output)?;
            if length == 0 || length > output.len() - 4 {
                return Err(Error::InvalidOperation);
            }
            replace_data(packet, &output[..length])?;
            Ok(Some(true))
        }
        crate::CSP_REBOOT => {
            if packet.data_length() != 4 {
                return Err(Error::InvalidOperation);
            }
            let magic = u32::from_be_bytes(packet.data().try_into().unwrap());
            if let Some(hooks) = hooks() {
                match magic {
                    crate::CSP_REBOOT_MAGIC => {
                        if let Some(reboot) = hooks.reboot {
                            reboot();
                        }
                    }
                    crate::CSP_REBOOT_SHUTDOWN_MAGIC => {
                        if let Some(shutdown) = hooks.shutdown {
                            shutdown();
                        }
                    }
                    _ => {}
                }
            }
            // Reboot and shutdown are one-way requests and have no reply packet.
            Ok(Some(false))
        }
        crate::CSP_BUF_FREE => {
            if packet.data_length() != 0 {
                return Err(Error::InvalidOperation);
            }
            set_u32(packet, crate::buffer::PacketBuf::remaining() as u32)?;
            Ok(Some(true))
        }
        crate::CSP_UPTIME => {
            if packet.data_length() != 0 {
                return Err(Error::InvalidOperation);
            }
            set_u32(packet, crate::arch::get_seconds())?;
            Ok(Some(true))
        }
        _ => Ok(None),
    }
}

/// Echo a payload through the ping service and return elapsed milliseconds.
pub async fn ping(node: u16, timeout: u32, payload: &mut [u8]) -> Result<u32, Error> {
    if payload.len() > crate::buffer::CSP_BUFFER_SIZE - 4 {
        return Err(Error::BufferOverflow);
    }
    let mut stream = CspStream::connect(
        Priority::Normal,
        node,
        crate::CSP_PING,
        crate::ConnOptions::CSP_O_CRC32,
    )
    .await?;
    let started = crate::arch::get_ms();
    stream.send(payload).await?;
    let mut response = [0; crate::buffer::CSP_BUFFER_SIZE];
    let result = stream.read(&mut response, timeout).await;
    stream.close().await;
    let length = result?;
    if length != payload.len() || response[..length] != *payload {
        return Err(Error::InvalidOperation);
    }
    Ok(crate::arch::get_ms().wrapping_sub(started))
}

/// Request the remote node's free-memory count.
pub async fn get_memfree(node: u16, timeout: u32) -> Result<u32, Error> {
    request_u32(node, crate::CSP_MEMFREE, timeout).await
}

/// Request the number of currently available packet buffers.
pub async fn get_buffer_free(node: u16, timeout: u32) -> Result<u32, Error> {
    request_u32(node, crate::CSP_BUF_FREE, timeout).await
}

/// Request the remote node's uptime in seconds.
pub async fn get_uptime(node: u16, timeout: u32) -> Result<u32, Error> {
    request_u32(node, crate::CSP_UPTIME, timeout).await
}

/// Request the process list and copy it into `output`.
pub async fn process_list(node: u16, timeout: u32, output: &mut [u8]) -> Result<usize, Error> {
    let mut stream = CspStream::connect(
        Priority::Normal,
        node,
        crate::CSP_PS,
        crate::ConnOptions::CSP_O_CRC32,
    )
    .await?;
    // The service expects this marker before returning its process-list payload.
    match stream.send(&[0x55]).await {
        Ok(1) => {}
        Ok(_) => {
            stream.close().await;
            return Err(Error::InvalidOperation);
        }
        Err(error) => {
            stream.close().await;
            return Err(error);
        }
    }
    let result = stream.read(output, timeout).await;
    stream.close().await;
    result
}

/// Send a one-way reboot request.
pub async fn reboot(node: u16) -> Result<(), Error> {
    send_magic(node, crate::CSP_REBOOT_MAGIC).await
}

/// Send a one-way shutdown request.
pub async fn shutdown(node: u16) -> Result<(), Error> {
    send_magic(node, crate::CSP_REBOOT_SHUTDOWN_MAGIC).await
}

async fn request_u32(node: u16, port: u8, timeout: u32) -> Result<u32, Error> {
    let mut stream = CspStream::connect(
        Priority::Normal,
        node,
        port,
        crate::ConnOptions::CSP_O_CRC32,
    )
    .await?;
    stream.send(&[]).await?;
    let mut response = [0; 4];
    let result = stream.read(&mut response, timeout).await;
    stream.close().await;
    if result? != response.len() {
        return Err(Error::InvalidOperation);
    }
    Ok(u32::from_be_bytes(response))
}

async fn send_magic(node: u16, magic: u32) -> Result<(), Error> {
    let mut packet = Packet::get().ok_or(Error::AllocError)?;
    packet.append_data(&magic.to_be_bytes())?;
    crate::io::send_to(
        Priority::Normal,
        node,
        crate::CSP_REBOOT,
        0,
        crate::ConnOptions::CSP_O_CRC32,
        packet,
    )
    .await
}

fn set_u32(packet: &mut Packet, value: u32) -> Result<(), Error> {
    replace_data(packet, &value.to_be_bytes())
}

fn replace_data(packet: &mut Packet, data: &[u8]) -> Result<(), Error> {
    let old_len = packet.data_length();
    packet.remove_data(old_len);
    packet.append_data(data)?;
    Ok(())
}
