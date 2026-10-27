extern crate alloc;

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

pub struct Mutex<T> {
    inner: tokio::sync::Mutex<T>,
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: tokio::sync::Mutex::const_new(value),
        }
    }

    pub async fn lock<'a>(&'a self) -> MutexGuard<'a, T> {
        MutexGuard {
            inner: self.inner.lock().await,
        }
    }
}

pub struct MutexGuard<'a, T> {
    inner: tokio::sync::MutexGuard<'a, T>,
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

pub struct Semaphore<const N: usize> {
    inner: tokio::sync::Semaphore,
}

impl<const N: usize> Semaphore<N> {
    /// Equivalent to csp_bin_sem_init(): initially unlocked.
    pub const fn new() -> Self {
        Self {
            inner: tokio::sync::Semaphore::const_new(1),
        }
    }

    /// Equivalent to csp_bin_sem_wait().
    /// timeout_ms == CSP_MAX_TIMEOUT means wait indefinitely.
    pub async fn wait(&self, timeout_ms: u32) -> Result<(), Error> {
        if timeout_ms == u32::MAX {
            self.wait_inner().await;
            return Ok(());
        }

        tokio::time::timeout(Duration::from_millis(timeout_ms as u64), self.wait_inner())
            .await
            .map_err(|_| Error::Timeout)
    }

    async fn wait_inner(&self) {
        let _ = self.inner.acquire().await;
    }

    /// Equivalent to csp_bin_sem_post().
    /// Posting an already available semaphore is a no-op.
    pub fn post(&self) {
        self.inner.add_permits(1);
    }
}
