use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::TrySendError;
use embassy_sync::signal::Signal;
use embassy_time::Duration;

use crate::Error;

pub fn get_ms() -> u32 {
    embassy_time::Instant::now().as_millis() as u32
}

pub fn get_seconds() -> u32 {
    embassy_time::Instant::now().as_secs() as u32
}

type EmbassyMutex<T> = embassy_sync::mutex::Mutex<CriticalSectionRawMutex, T>;

pub struct Mutex<T> {
    inner: EmbassyMutex<T>,
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: EmbassyMutex::new(value),
        }
    }

    pub async fn lock<'a>(&'a self) -> MutexGuard<'a, T> {
        MutexGuard {
            inner: self.inner.lock().await,
        }
    }
}

pub struct MutexGuard<'a, T> {
    inner: embassy_sync::mutex::MutexGuard<'a, CriticalSectionRawMutex, T>,
}

impl<'a, T> core::ops::Deref for MutexGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T> core::ops::DerefMut for MutexGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct Queue<T, const N: usize> {
    inner: embassy_sync::channel::Channel<CriticalSectionRawMutex, T, N>,
}

impl<T, const N: usize> Queue<T, N> {
    pub const fn new() -> Self {
        Self {
            inner: embassy_sync::channel::Channel::new(),
        }
    }

    pub async fn push(&self, item: T) {
        self.inner.send(item).await
    }

    pub async fn pop(&self) -> T {
        self.inner.receive().await
    }

    pub async fn try_pop(&self) -> Option<T> {
        self.inner.try_receive().ok()
    }

    pub async fn pop_with_timeout(&self, timeout: u32) -> Option<T> {
        embassy_time::with_timeout(
            embassy_time::Duration::from_millis(timeout as _),
            self.pop(),
        )
        .await
        .ok()
    }

    pub fn free_capacity(&self) -> usize {
        self.inner.free_capacity()
    }
}

pub struct Semaphore {}

impl Semaphore {
    /// Initially available, equivalent to sem_init(..., 1).
    pub const fn new() -> Self {
        Self {
            available: EmbassyMutex::new(true),
            notify: Signal::new(),
        }
    }

    /// Wait indefinitely or for the specified timeout in milliseconds.
    ///
    /// CSP_MAX_TIMEOUT means wait indefinitely.
    pub async fn wait(&self, timeout_ms: u32) -> Result<(), Error> {
        if timeout_ms == u32::MAX {
            self.wait_inner().await;
            return Ok(());
        }

        embassy_time::with_timeout(Duration::from_millis(timeout_ms as u64), self.wait_inner())
            .await
            .map_err(|_| Error::Timeout)
    }

    async fn wait_inner(&self) {
        loop {
            // Check and acquire the binary semaphore atomically.
            {
                let mut available = self.available.lock().await;

                if *available {
                    *available = false;
                    return;
                }
            }

            // Signal retains a pending notification if no task
            // is currently waiting. Always recheck the state.
            self.notify.wait().await;
        }
    }

    /// Release the semaphore. Repeated posts do not accumulate.
    pub fn post(&self) {
        todo!()
    }
}
