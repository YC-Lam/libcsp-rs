#[cfg(feature = "embassy")]
mod embassy;

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(feature = "embassy")]
pub use embassy::*;

#[cfg(all(feature = "std", not(feature = "embassy")))]
mod tokio;

#[cfg(all(feature = "std", not(feature = "embassy")))]
pub use tokio::*;

const UNINIT: u8 = 0;
const RUNNING: u8 = 1;
const DONE: u8 = 2;

pub struct LazyLock<T, F = fn() -> T> {
    state: AtomicU8,
    init: UnsafeCell<Option<F>>,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: Only one thread initializes the value, and it is published
// with a Release store. Readers require an Acquire load of DONE.
unsafe impl<T: Send + Sync, F: Send + Sync> Sync for LazyLock<T, F> {}
unsafe impl<T: Send, F: Send> Send for LazyLock<T, F> {}

impl<T, F> LazyLock<T, F>
where
    F: FnOnce() -> T,
{
    pub const fn new(f: F) -> Self {
        Self {
            state: AtomicU8::new(UNINIT),
            init: UnsafeCell::new(Some(f)),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == DONE {
            // SAFETptr as *mut TY: DONE is published only after the value is initialized.
            Some(unsafe { (&*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }

    pub fn get_or_init(&self) -> &T {
        loop {
            match self.state.load(Ordering::Acquire) {
                DONE => return self.get().unwrap(),

                UNINIT => {
                    if self
                        .state
                        .compare_exchange(UNINIT, RUNNING, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok()
                    {
                        struct Reset<'a>(&'a AtomicU8);

                        impl Drop for Reset<'_> {
                            fn drop(&mut self) {
                                self.0.store(UNINIT, Ordering::Release);
                            }
                        }

                        let reset = Reset(&self.state);

                        // SAFETY: This thread exclusively owns initialization.
                        unsafe {
                            let value = (&mut *self.init.get()).take().unwrap()();

                            (*self.value.get()).write(value);
                        }

                        self.state.store(DONE, Ordering::Release);
                        core::mem::forget(reset);

                        return self.get().unwrap();
                    }
                }

                RUNNING => core::hint::spin_loop(),

                _ => unreachable!(),
            }
        }
    }
}

impl<T, F> Drop for LazyLock<T, F> {
    fn drop(&mut self) {
        if *self.state.get_mut() == DONE {
            // SAFETY: DONE guarantees the value was initialized.
            unsafe {
                self.value.get_mut().assume_init_drop();
            }
        }
    }
}

impl<T, F> core::ops::Deref for LazyLock<T, F>
where
    F: FnOnce() -> T,
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        self.get_or_init()
    }
}

impl<T, F> core::ops::DerefMut for LazyLock<T, F>
where
    F: FnOnce() -> T,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        let ptr = self.get_or_init() as *const T;
        return unsafe { (ptr as *mut T).as_mut_unchecked() };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lazylock_called_once() {
        let mut i = 0;

        let lock = LazyLock::new(|| i += 1);

        lock.get_or_init();
        lock.get_or_init();

        drop(lock);

        assert_eq!(i, 1);
    }
}
