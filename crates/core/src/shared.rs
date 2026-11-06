//! Config replaced at run time, no restart (presets, alarm rules).
//! Readers -> cheap snapshot. Reload -> swap in new value.

use std::sync::{Arc, RwLock};

/// Value shared by all components that use it. [`Shared::replace`] -> new value for all.
#[derive(Debug)]
pub struct Shared<T>(Arc<RwLock<Arc<T>>>);

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Default> Default for Shared<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> From<T> for Shared<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> Shared<T> {
    pub fn new(value: T) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(value))))
    }

    /// Current value. Snapshot -> later replace has no effect on it.
    pub fn get(&self) -> Arc<T> {
        match self.0.read() {
            Ok(v) => v.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// New value for every holder.
    pub fn replace(&self, value: T) {
        let value = Arc::new(value);
        match self.0.write() {
            Ok(mut v) => *v = value,
            Err(poisoned) => *poisoned.into_inner() = value,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Shared;

    #[test]
    fn replace_reaches_every_clone() {
        let a = Shared::new(1);
        let b = a.clone();
        let before = b.get();
        a.replace(2);
        assert_eq!((*before, *b.get()), (1, 2));
    }
}
