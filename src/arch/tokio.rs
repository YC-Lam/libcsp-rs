extern crate alloc;

use core::time::Duration;

use alloc::collections::VecDeque;

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
    inner: smol::lock::Mutex<VecDeque<T>>,
    notify: tokio::sync::Notify,
}

impl<T, const N: usize> Queue<T, N> {
    pub const fn new() -> Self {
        Self {
            inner: smol::lock::Mutex::new(VecDeque::new()),
            notify: tokio::sync::Notify::const_new(),
        }
    }

    pub async fn push(&self, item: T) {
        let mut guard = self.inner.lock().await;
        guard.push_back(item);

        drop(guard);

        self.notify.notify_one();
    }

    pub async fn try_pop(&self) -> Option<T> {
        self.inner.lock().await.pop_front()
    }

    pub async fn pop(&self) -> T {
        let future = self.notify.notified();
        tokio::pin!(future);

        loop {
            // Make sure that no wakeup is lost if we get
            // `None` from `try_pop`.
            future.as_mut().enable();

            if let Some(msg) = self.try_pop().await {
                return msg;
            }

            // Wait for a call to `notify_one`.
            //
            // This uses `.as_mut()` to avoid consuming the future,
            // which lets us call `Pin::set` below.
            future.as_mut().await;

            // Reset the future in case another call to
            // `try_recv` got the message before us.
            future.set(self.notify.notified());
        }
    }

    pub async fn pop_with_timeout(&self, timeout: u32) -> Option<T> {
        match tokio::time::timeout(Duration::from_millis(timeout as _), self.pop()).await {
            Ok(v) => Some(v),
            Err(_) => None,
        }
    }

    pub fn free_capacity(&self) -> usize {
        usize::MAX
    }
}

pub struct Semaphore {
    inner: tokio::sync::Semaphore,
}

impl Semaphore {
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
