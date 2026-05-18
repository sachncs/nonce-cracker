#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut map = nonce_cracker::search::openmap::OpenMap::with_capacity(64);
    for chunk in data.chunks_exact(41) {
        let mut key = [0u8; 33];
        key.copy_from_slice(&chunk[..33]);
        let value = u128::from_le_bytes([
            chunk[33], chunk[34], chunk[35], chunk[36],
            chunk[37], chunk[38], chunk[39], chunk[40],
            0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        map.insert(key, value);
        let _ = map.get(&key);
    }
});
