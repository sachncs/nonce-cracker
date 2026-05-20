use rustc_hash::FxBuildHasher;
use std::hash::BuildHasher;

const EMPTY: u8 = 0;
const OCCUPIED: u8 = 1;

struct Entry {
    key: u128,
    value: u64,
    state: u8,
}

/// Open-addressing hash map with 128-bit keys and 64-bit values.
///
/// Stores the first 16 bytes of a compressed elliptic curve point as the key
/// and maps it to a step index.  Collision probability is negligible for the
/// supported table sizes; any false positive is caught by cryptographic
/// verification downstream.
///
/// Uses quadratic probing and FxHash for fast lookups.
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
        entries.resize_with(table_cap, || Entry {
            key: 0,
            value: 0,
            state: EMPTY,
        });
        Self {
            entries,
            mask: table_cap - 1,
            len: 0,
            hasher: FxBuildHasher,
        }
    }

    fn hash(&self, key: u128) -> usize {
        ((self.hasher.hash_one(key) as usize) ^ (key as usize)) & self.mask
    }

    /// Insert a key-value pair into the map.
    ///
    /// If the key already exists, its value is overwritten.
    /// Automatically grows the table when the load factor reaches ~0.7.
    pub fn insert(&mut self, key: u128, value: u64) {
        if self.entries.is_empty() || self.len * 10 >= self.entries.len() * 7 {
            self.grow();
        }
        self.insert_internal(key, value);
    }

    fn insert_internal(&mut self, key: u128, value: u64) {
        let base = self.hash(key);
        let mut i = 0usize;
        loop {
            let step = i.wrapping_mul(i + 1) / 2;
            let idx = (base + step) & self.mask;
            let entry = &mut self.entries[idx];
            if entry.state == EMPTY {
                *entry = Entry {
                    key,
                    value,
                    state: OCCUPIED,
                };
                self.len += 1;
                return;
            }
            if entry.key == key {
                entry.value = value;
                return;
            }
            i += 1;
        }
    }

    fn grow(&mut self) {
        let old_entries = std::mem::take(&mut self.entries);
        let new_cap = old_entries.len().max(1).next_power_of_two() * 2;
        let mut new_entries = Vec::with_capacity(new_cap);
        new_entries.resize_with(new_cap, || Entry {
            key: 0,
            value: 0,
            state: EMPTY,
        });
        self.entries = new_entries;
        self.mask = new_cap - 1;
        self.len = 0;
        for entry in old_entries {
            if entry.state == OCCUPIED {
                self.insert_internal(entry.key, entry.value);
            }
        }
    }

    /// Look up a key and return a reference to its value, if present.
    pub fn get(&self, key: u128) -> Option<&u64> {
        let base = self.hash(key);
        let mut i = 0usize;
        loop {
            let step = i.wrapping_mul(i + 1) / 2;
            let idx = (base + step) & self.mask;
            let entry = &self.entries[idx];
            match entry.state {
                EMPTY => return None,
                OCCUPIED if entry.key == key => return Some(&entry.value),
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

    /// Return whether the map contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the total number of slots in the table.
    pub fn table_capacity(&self) -> usize {
        self.entries.len()
    }
}

impl IntoIterator for OpenMap {
    type Item = (u128, u64);
    type IntoIter = OpenMapIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        OpenMapIntoIter {
            entries: self.entries,
            index: 0,
        }
    }
}

/// Iterator over the entries of an [`OpenMap`].
pub struct OpenMapIntoIter {
    entries: Vec<Entry>,
    index: usize,
}

impl Iterator for OpenMapIntoIter {
    type Item = (u128, u64);

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.entries.len() {
            let entry = &self.entries[self.index];
            self.index += 1;
            if entry.state == OCCUPIED {
                return Some((entry.key, entry.value));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn basic_insert_and_get() {
        let mut map = OpenMap::with_capacity(16);
        let key: u128 = 0xABABABABABABABABABABABABABABABABu128;
        map.insert(key, 42);
        assert_eq!(map.get(key), Some(&42));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn overwrite_existing() {
        let mut map = OpenMap::with_capacity(16);
        let key: u128 = 0xCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDu128;
        map.insert(key, 1);
        map.insert(key, 2);
        assert_eq!(map.get(key), Some(&2));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn missing_key() {
        let map = OpenMap::with_capacity(16);
        let key: u128 = 0xEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFu128;
        assert_eq!(map.get(key), None);
    }

    #[test]
    fn many_entries() {
        let mut map = OpenMap::with_capacity(1024);
        for i in 0..512u64 {
            let key = u128::from(i) | (u128::from(i) << 64);
            map.insert(key, i);
        }
        for i in 0..512u64 {
            let key = u128::from(i) | (u128::from(i) << 64);
            assert_eq!(map.get(key), Some(&i));
        }
        assert_eq!(map.len(), 512);
    }

    #[test]
    fn capacity_is_power_of_two() {
        let map = OpenMap::with_capacity(100);
        let cap = map.table_capacity();
        assert!(cap.is_power_of_two());
        assert_eq!(cap, 256);
    }

    #[test]
    fn collision_and_deep_probing() {
        let mut map = OpenMap::with_capacity(128);
        let n: u64 = 32;
        for i in 0..n {
            let key = 0xCAFEBABEDEADBEEF0000000000000000u128 | u128::from(i);
            map.insert(key, i);
        }
        for i in 0..n {
            let key = 0xCAFEBABEDEADBEEF0000000000000000u128 | u128::from(i);
            assert_eq!(map.get(key), Some(&i));
        }
        assert_eq!(map.len(), n as usize);
    }

    proptest! {
        #[test]
        fn prop_insert_get_roundtrip(key in any::<u128>(), value in any::<u64>()) {
            let mut map = OpenMap::with_capacity(1024);
            map.insert(key, value);
            prop_assert_eq!(map.get(key), Some(&value));
            prop_assert_eq!(map.len(), 1);
        }

        #[test]
        fn prop_overwrite(key in any::<u128>(), v1 in any::<u64>(), v2 in any::<u64>()) {
            let mut map = OpenMap::with_capacity(1024);
            map.insert(key, v1);
            map.insert(key, v2);
            prop_assert_eq!(map.get(key), Some(&v2));
            prop_assert_eq!(map.len(), 1);
        }

        #[test]
        fn prop_many_entries(
            entries in prop::collection::vec((any::<u128>(), any::<u64>()), 1..512)
        ) {
            let mut map = OpenMap::with_capacity(entries.len());
            let mut expected = std::collections::HashMap::new();
            for (key, value) in &entries {
                map.insert(*key, *value);
                expected.insert(*key, *value);
            }
            for (key, value) in &expected {
                prop_assert_eq!(map.get(*key), Some(value));
            }
            prop_assert_eq!(map.len(), expected.len());
        }
    }
}
