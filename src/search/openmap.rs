use rustc_hash::{FxBuildHasher, FxHasher};
use std::hash::{BuildHasher, Hash, Hasher};

const EMPTY: u8 = 0;
const OCCUPIED: u8 = 1;
const TOMBSTONE: u8 = 2;

type Entry = ([u8; 33], u128, u8);

/// Open-addressing hash map with 33-byte keys and u128 values.
///
/// Stores compressed elliptic curve points as keys and maps them to step
/// indices.  Uses quadratic probing and FxHash for fast lookups.
pub struct OpenMap {
    entries: Vec<Entry>,
    mask: usize,
    len: usize,
    hasher: FxBuildHasher,
}

impl OpenMap {
    /// Create a new map with at least the given logical capacity.
    ///
    /// The underlying table size is the next power of two large enough to
    /// keep the load factor below 0.7.
    pub fn with_capacity(capacity: usize) -> Self {
        let target = (capacity as f64 / 0.7).ceil() as usize;
        let table_cap = target.next_power_of_two();
        let mut entries = Vec::with_capacity(table_cap);
        entries.resize_with(table_cap, || ([0u8; 33], 0u128, EMPTY));
        Self {
            entries,
            mask: table_cap - 1,
            len: 0,
            hasher: FxBuildHasher,
        }
    }

    fn hash(&self, key: &[u8; 33]) -> usize {
        let mut hasher = self.hasher.build_hasher();
        key[..8].hash(&mut hasher);
        (hasher.finish() as usize) & self.mask
    }

    /// Insert a key-value pair into the map.
    ///
    /// If the key already exists, its value is overwritten.
    pub fn insert(&mut self, key: [u8; 33], value: u128) {
        let base = self.hash(&key);
        let mut i = 0usize;
        loop {
            let idx = (base + i * i) & self.mask;
            let entry = &mut self.entries[idx];
            if entry.2 == EMPTY || entry.2 == TOMBSTONE {
                *entry = (key, value, OCCUPIED);
                self.len += 1;
                return;
            }
            if entry.0 == key {
                entry.1 = value;
                return;
            }
            i += 1;
        }
    }

    /// Look up a key and return a reference to its value, if present.
    pub fn get(&self, key: &[u8; 33]) -> Option<&u128> {
        let base = self.hash(key);
        let mut i = 0usize;
        loop {
            let idx = (base + i * i) & self.mask;
            let entry = &self.entries[idx];
            match entry.2 {
                EMPTY => return None,
                OCCUPIED if entry.0 == *key => return Some(&entry.1),
                _ => {
                    i += 1;
                }
            }
        }
    }

    /// Return the number of occupied entries.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return the total number of slots in the table.
    pub fn capacity(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_insert_and_get() {
        let mut map = OpenMap::with_capacity(16);
        let key = [0xABu8; 33];
        map.insert(key, 42);
        assert_eq!(map.get(&key), Some(&42));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn overwrite_existing() {
        let mut map = OpenMap::with_capacity(16);
        let key = [0xCDu8; 33];
        map.insert(key, 1);
        map.insert(key, 2);
        assert_eq!(map.get(&key), Some(&2));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn missing_key() {
        let map = OpenMap::with_capacity(16);
        let key = [0xEFu8; 33];
        assert_eq!(map.get(&key), None);
    }

    #[test]
    fn many_entries() {
        let mut map = OpenMap::with_capacity(1024);
        for i in 0..512u128 {
            let mut key = [0u8; 33];
            key[0..16].copy_from_slice(&i.to_le_bytes());
            key[16..32].copy_from_slice(&i.to_le_bytes());
            map.insert(key, i);
        }
        for i in 0..512u128 {
            let mut key = [0u8; 33];
            key[0..16].copy_from_slice(&i.to_le_bytes());
            key[16..32].copy_from_slice(&i.to_le_bytes());
            assert_eq!(map.get(&key), Some(&i));
        }
        assert_eq!(map.len(), 512);
    }

    #[test]
    fn capacity_is_power_of_two() {
        let map = OpenMap::with_capacity(100);
        let cap = map.capacity();
        assert!(cap.is_power_of_two());
        assert!(cap >= 200);
    }
}
