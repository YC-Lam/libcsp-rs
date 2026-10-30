extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;

use crate::Error;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn get_ms() -> u32 {
    unsafe {
        let mut ts = libc::timespec {
            tv_nsec: 0,
            tv_sec: 0,
        };

        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) == 0 {
            return ((ts.tv_sec * 1000) + (ts.tv_nsec / 1000000)) as u32;
        }
    }

    return 0;
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn get_seconds() -> u32 {
    unsafe {
        let mut ts = libc::timespec {
            tv_nsec: 0,
            tv_sec: 0,
        };

        if libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) == 0 {
            return ts.tv_sec as u32;
        }
    }

    return 0;
}

#[cfg(target_os = "windows")]
pub fn get_ms() -> u32 {
    use winapi::shared::minwindef::LARGE_INTEGER;
    use winapi::um::profileapi::{QueryPerformanceCounter, QueryPerformanceFrequency};

    unsafe {
        let mut freq: LARGE_INTEGER = std::mem::zeroed();
        let mut counter: LARGE_INTEGER = std::mem::zeroed();

        QueryPerformanceFrequency(&mut freq);
        QueryPerformanceCounter(&mut counter);

        ((*counter.QuadPart() as u64 * 1_000) / *freq.QuadPart() as u64) as u32
    }
}

#[cfg(target_os = "windows")]
pub fn get_seconds() -> u32 {
    get_ms() / 1000
}

#[cfg(target_os = "macos")]
pub fn get_ms() -> u32 {
    unsafe {
        let mut ts = libc::timespec {
            tv_nsec: 0,
            tv_sec: 0,
        };

        if libc::clock_gettime(libc::CLOCK_UPTIME_RAW, &mut ts) == 0 {
            return ((ts.tv_sec * 1000) + (ts.tv_nsec / 1000000)) as u32;
        }
    }

    return 0;
}

#[cfg(target_os = "macos")]
pub fn get_seconds() -> u32 {
    get_ms() / 1000
}

pub struct Queue<T, const N: usize> {
    inner: super::LazyLock<(smol::channel::Sender<T>, smol::channel::Receiver<T>)>,
}

impl<T, const N: usize> Queue<T, N> {
    pub const fn new() -> Self {
        Self {
            inner: super::LazyLock::new(|| smol::channel::bounded(N)),
        }
    }

    pub fn close(&self) {
        self.inner.0.close();
    }

    pub async fn push(&self, item: T) -> Result<(), Error> {
        self.inner
            .0
            .send(item)
            .await
            .map_err(|_| Error::ConnectionClosed)
    }

    pub fn try_pop(&self) -> Option<T> {
        self.inner.1.try_recv().ok()
    }

    pub async fn pop(&self) -> Result<T, Error> {
        self.inner
            .1
            .recv()
            .await
            .map_err(|_| Error::ConnectionClosed)
    }

    pub async fn pop_with_timeout(&self, timeout: u32) -> Result<T, Error> {
        match tokio::time::timeout(Duration::from_millis(timeout as _), self.pop()).await {
            Ok(v) => v,
            Err(_) => Err(Error::Timeout),
        }
    }

    pub fn free_capacity(&self) -> usize {
        usize::MAX
    }
}

#[allow(unused)]
pub struct Semaphore {
    available: AtomicBool,
    notify: tokio::sync::Notify,
}

#[allow(unused)]
impl Semaphore {
    /// Equivalent to csp_bin_sem_init(): initially unlocked.
    pub const fn new() -> Self {
        Self {
            available: AtomicBool::new(true),
            notify: tokio::sync::Notify::const_new(),
        }
    }

    /// Equivalent to csp_bin_sem_wait().
    /// timeout_ms == CSP_MAX_TIMEOUT means wait indefinitely.
    pub async fn wait(&self, timeout_ms: u32) -> Result<(), Error> {
        if self.available.swap(false, Ordering::AcqRel) {
            return Ok(());
        }

        if timeout_ms == 0 {
            return Err(Error::Timeout);
        }

        if timeout_ms == u32::MAX {
            self.wait_inner().await;
            return Ok(());
        }

        tokio::time::timeout(Duration::from_millis(timeout_ms as u64), self.wait_inner())
            .await
            .map_err(|_| Error::Timeout)
    }

    async fn wait_inner(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            if self.available.swap(false, Ordering::AcqRel) {
                return;
            }

            notified.await;
        }
    }

    /// Equivalent to csp_bin_sem_post().
    /// Posting an already available semaphore is a no-op.
    pub fn post(&self) {
        if !self.available.swap(true, Ordering::AcqRel) {
            self.notify.notify_one();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn semaphore_wait_consumes_and_post_releases_a_single_permit() {
        let semaphore = Semaphore::new();

        assert_eq!(semaphore.wait(0).await, Ok(()));
        assert_eq!(semaphore.wait(0).await, Err(Error::Timeout));

        semaphore.post();
        assert_eq!(semaphore.wait(0).await, Ok(()));
        assert_eq!(semaphore.wait(0).await, Err(Error::Timeout));
    }
}
