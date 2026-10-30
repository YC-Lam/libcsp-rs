use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicBool, Ordering};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::semaphore::{GreedySemaphore, Semaphore as _};

use crate::Error;

pub fn get_ms() -> u32 {
    embassy_time::Instant::now().as_millis() as u32
}

pub fn get_seconds() -> u32 {
    embassy_time::Instant::now().as_secs() as u32
}

pub struct Queue<T, const N: usize> {
    inner: embassy_sync::channel::Channel<CriticalSectionRawMutex, Option<T>, N>,
    closed: AtomicBool,
}

impl<T, const N: usize> Queue<T, N> {
    pub const fn new() -> Self {
        Self {
            inner: embassy_sync::channel::Channel::new(),
            closed: AtomicBool::new(false),
        }
    }

    pub async fn push(&self, item: T) -> Result<(), Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::ConnectionClosed);
        }

        self.inner.send(Some(item)).await;

        if self.closed.load(Ordering::Acquire) {
            self.signal_closed();
            return Err(Error::ConnectionClosed);
        }

        Ok(())
    }

    pub fn try_pop(&self) -> Option<T> {
        match self.inner.try_receive() {
            Ok(Some(item)) => Some(item),
            Ok(None) => {
                self.signal_closed();
                None
            }
            Err(_) => None,
        }
    }

    pub async fn pop(&self) -> Result<T, Error> {
        if self.closed.load(Ordering::Acquire) {
            return Err(Error::ConnectionClosed);
        }

        match self.inner.receive().await {
            Some(item) => {
                if self.closed.load(Ordering::Acquire) {
                    self.signal_closed();
                    Err(Error::ConnectionClosed)
                } else {
                    Ok(item)
                }
            }
            None => {
                self.signal_closed();
                Err(Error::ConnectionClosed)
            }
        }
    }

    pub async fn pop_with_timeout(&self, timeout: u32) -> Result<T, Error> {
        if timeout == u32::MAX {
            return self.pop().await;
        }
        if timeout == 0 {
            return self.try_pop().ok_or(Error::Timeout);
        }

        embassy_time::with_timeout(
            embassy_time::Duration::from_millis(timeout as u64),
            self.pop(),
        )
        .await
        .map_err(|_| Error::Timeout)?
    }

    pub fn free_capacity(&self) -> usize {
        self.inner.free_capacity()
    }

    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.signal_closed();
        }
    }

    fn signal_closed(&self) {
        let _ = self.inner.try_send(None);
    }
}

pub struct Semaphore {
    inner: GreedySemaphore<CriticalSectionRawMutex>,
}

impl Semaphore {
    /// Create an initially available binary semaphore.
    pub const fn new() -> Self {
        Self {
            inner: GreedySemaphore::new(1),
        }
    }

    /// Equivalent to csp_bin_sem_wait(). `u32::MAX` waits indefinitely.
    pub async fn wait(&self, timeout_ms: u32) -> Result<(), Error> {
        if let Some(permit) = self.inner.try_acquire(1) {
            permit.disarm();
            return Ok(());
        }

        if timeout_ms == 0 {
            return Err(Error::Timeout);
        }

        if timeout_ms == u32::MAX {
            self.acquire_inner().await;
            return Ok(());
        }

        embassy_time::with_timeout(
            embassy_time::Duration::from_millis(timeout_ms as u64),
            self.acquire_inner(),
        )
        .await
        .map_err(|_| Error::Timeout)
    }

    async fn acquire_inner(&self) {
        match self.inner.acquire(1).await {
            Ok(permit) => {
                permit.disarm();
            }
            Err(never) => match never {},
        }
    }

    /// Release the binary semaphore; repeated posts do not accumulate permits.
    pub fn post(&self) {
        self.inner.set(1);
    }
}
