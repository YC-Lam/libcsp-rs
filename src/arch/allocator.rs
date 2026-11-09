use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering, fence};

pub struct StaticAllocator<T, const SIZE: usize> {
    data: [AllocatorSlot<T>; SIZE],
}

unsafe impl<T, const SIZE: usize> Sync for StaticAllocator<T, SIZE> {}
unsafe impl<T, const SIZE: usize> Send for StaticAllocator<T, SIZE> {}

impl<T, const SIZE: usize> StaticAllocator<T, SIZE> {
    pub const fn new() -> Self {
        Self {
            data: [const { AllocatorSlot::new() }; SIZE],
        }
    }

    pub fn allocate(&'static self, data: T) -> Option<StaticBox<T>> {
        for inner in &self.data {
            if inner
                .allocated
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                // The allocation flag reserves this slot until the last strong
                // reference finishes dropping its value.
                unsafe { (*inner.data.get()).write(data) };

                return Some(StaticBox {
                    ptr: NonNull::from_ref(inner),
                });
            }
        }

        None
    }

    #[allow(dead_code)]
    pub fn allocate_arc(&'static self, data: T) -> Option<StaticArc<T>> {
        for inner in &self.data {
            if inner
                .allocated
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                unsafe { (*inner.data.get()).write(data) };
                inner.ref_count.store(1, Ordering::Relaxed);

                return Some(StaticArc {
                    ptr: NonNull::from_ref(inner),
                });
            }
        }

        None
    }

    pub fn available(&self) -> usize {
        self.data
            .iter()
            .filter(|inner| !inner.allocated.load(Ordering::Acquire))
            .count()
    }
}

pub struct StaticBox<T> {
    ptr: NonNull<AllocatorSlot<T>>,
}

unsafe impl<T: Sync + Send> Sync for StaticBox<T> {}
unsafe impl<T: Sync + Send> Send for StaticBox<T> {}

impl<T> StaticBox<T> {
    fn inner(&self) -> &AllocatorSlot<T> {
        // SAFETY: StaticBox is created only for an allocated static pool slot.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> core::ops::Deref for StaticBox<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: A live strong reference guarantees the slot contains an
        // initialized value and prevents its destruction or reuse.
        unsafe { (&*self.inner().data.get()).assume_init_ref() }
    }
}

impl<T> core::ops::DerefMut for StaticBox<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { (&mut *self.inner().data.get()).assume_init_mut() }
    }
}

impl<T> Drop for StaticBox<T> {
    fn drop(&mut self) {
        drop_slot_value(self.inner());
    }
}

#[allow(dead_code)]
pub struct StaticArc<T> {
    ptr: NonNull<AllocatorSlot<T>>,
}

unsafe impl<T: Sync + Send> Sync for StaticArc<T> {}
unsafe impl<T: Sync + Send> Send for StaticArc<T> {}

#[allow(dead_code)]
impl<T> StaticArc<T> {
    fn inner(&self) -> &AllocatorSlot<T> {
        // SAFETY: StaticArc is created only for an allocated static pool slot.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> Clone for StaticArc<T> {
    fn clone(&self) -> Self {
        let ref_count = &self.inner().ref_count;
        let mut current = ref_count.load(Ordering::Relaxed);

        loop {
            assert!(current != 0, "cannot clone a released StaticArc");
            assert!(
                current < isize::MAX as usize,
                "StaticArc reference count overflow"
            );

            match ref_count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Self { ptr: self.ptr },
                Err(actual) => current = actual,
            }
        }
    }
}

impl<T> core::ops::Deref for StaticArc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        // SAFETY: This strong reference keeps the initialized slot alive.
        unsafe { (&*self.inner().data.get()).assume_init_ref() }
    }
}

impl<T> Drop for StaticArc<T> {
    fn drop(&mut self) {
        let inner = self.inner();
        if inner.ref_count.fetch_sub(1, Ordering::Release) == 1 {
            fence(Ordering::Acquire);
            drop_slot_value(inner);
        }
    }
}

fn drop_slot_value<T>(inner: &AllocatorSlot<T>) {
    struct ReleaseAllocation<'a>(&'a AtomicBool);

    impl Drop for ReleaseAllocation<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    let _release_allocation = ReleaseAllocation(&inner.allocated);
    // SAFETY: The final owner is dropping, so no other code can access the
    // value. The guard reserves the slot until its destructor has completed.
    unsafe { core::ptr::drop_in_place((*inner.data.get()).as_mut_ptr()) };
}

struct AllocatorSlot<T> {
    allocated: AtomicBool,
    #[allow(dead_code)]
    ref_count: AtomicUsize,
    data: UnsafeCell<MaybeUninit<T>>,
}

impl<T> AllocatorSlot<T> {
    const fn new() -> Self {
        Self {
            allocated: AtomicBool::new(false),
            ref_count: AtomicUsize::new(0),
            data: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    static BOX_POOL: StaticAllocator<usize, 1> = StaticAllocator::new();
    static ARC_CLONE_POOL: StaticAllocator<usize, 1> = StaticAllocator::new();
    static ARC_EXHAUSTION_POOL: StaticAllocator<usize, 1> = StaticAllocator::new();
    static DROP_POOL: StaticAllocator<DropCounter, 1> = StaticAllocator::new();

    struct DropCounter(&'static AtomicUsize);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn static_box_owns_and_releases_a_slot() {
        let value = BOX_POOL.allocate(42).unwrap();
        assert_eq!(*value, 42);
        assert_eq!(BOX_POOL.available(), 0);

        drop(value);
        assert_eq!(BOX_POOL.available(), 1);
    }

    #[test]
    fn static_arc_releases_slot_after_last_clone() {
        let value = ARC_CLONE_POOL.allocate_arc(42).unwrap();
        let clone = value.clone();

        assert_eq!(*value, 42);
        assert_eq!(*clone, 42);
        assert_eq!(ARC_CLONE_POOL.available(), 0);

        drop(value);
        assert_eq!(ARC_CLONE_POOL.available(), 0);
        assert_eq!(*clone, 42);

        drop(clone);
        assert_eq!(ARC_CLONE_POOL.available(), 1);
    }

    #[test]
    fn static_arc_drops_value_once_and_reuses_slot() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);

        let value = DROP_POOL.allocate_arc(DropCounter(&DROPS)).unwrap();
        let clone = value.clone();
        drop(value);
        assert_eq!(DROPS.load(Ordering::Relaxed), 0);

        drop(clone);
        assert_eq!(DROPS.load(Ordering::Relaxed), 1);

        drop(DROP_POOL.allocate_arc(DropCounter(&DROPS)).unwrap());
        assert_eq!(DROPS.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn allocator_reports_exhaustion_until_owner_is_dropped() {
        let value = ARC_EXHAUSTION_POOL.allocate_arc(1).unwrap();
        assert!(ARC_EXHAUSTION_POOL.allocate_arc(2).is_none());

        drop(value);
        assert_eq!(*ARC_EXHAUSTION_POOL.allocate_arc(2).unwrap(), 2);
    }
}
