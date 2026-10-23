use embassy_sync::{blocking_mutex::raw::CriticalSectionRawMutex, channel::TrySendError};

pub fn get_ms() -> u32 {
    embassy_time::Instant::now().as_millis() as u32
}

pub fn get_seconds() -> u32 {
    embassy_time::Instant::now().as_secs() as u32
}

pub struct Mutex<T> {
    inner: embassy_sync::mutex::Mutex<CriticalSectionRawMutex, T>,
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            inner: embassy_sync::mutex::Mutex::new(value),
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

    pub fn push_blocking(&self, mut item: T) {
        while let Err(TrySendError::Full(v)) = self.inner.try_send(item) {
            item = v;
        }
    }

    pub async fn pop(&self) -> T {
        self.inner.receive().await
    }

    pub fn try_pop(&self) -> Option<T> {
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
}
