//! Lock acquisition that shrugs off poisoning.
//!
//! A std lock is poisoned when a thread panics while holding it. The critical
//! sections in this crate cannot panic, and the state behind every lock (the
//! in-memory stores, the session cache, the invalidation-hook cell) stays
//! usable if one ever did, so these helpers take the guard either way rather
//! than propagate someone else's panic into the host.

use std::sync::{Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub(crate) fn lock<T: ?Sized>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn read<T: ?Sized>(lock: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    lock.read().unwrap_or_else(PoisonError::into_inner)
}

pub(crate) fn write<T: ?Sized>(lock: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    lock.write().unwrap_or_else(PoisonError::into_inner)
}
