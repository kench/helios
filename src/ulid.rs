//! ULIDs for message IDs (LLD 2, section 3): 48 bits of milliseconds and 80 random bits, as 26
//! Crockford base32 characters, so IDs sort by time.

use std::time::{SystemTime, UNIX_EPOCH};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// A new ULID for `time`.
///
/// # Panics
///
/// Panics if the operating system's random number generator fails, which Helios can't work
/// without anyway.
#[must_use]
pub fn new(time: SystemTime) -> String {
    let mut random = [0u8; 10];
    getrandom::fill(&mut random).expect("the OS random number generator failed");
    encode(time, random)
}

/// The ULID for `time` and `random`.
fn encode(time: SystemTime, random: [u8; 10]) -> String {
    let millis = time
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        & 0xffff_ffff_ffff;
    let mut value = u128::from(millis) << 80;
    for (i, byte) in random.iter().enumerate() {
        value |= u128::from(*byte) << (72 - 8 * i);
    }
    (0..26)
        .rev()
        .map(|i| char::from(ALPHABET[((value >> (5 * i)) & 31) as usize]))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn encodes_the_time_as_in_the_ulid_spec() {
        // From the ULID spec: 1469918176385 ms is 01ARYZ6S41.
        let time = UNIX_EPOCH + Duration::from_millis(1_469_918_176_385);

        assert_eq!(&encode(time, [0; 10])[..10], "01ARYZ6S41");
        assert_eq!(&encode(time, [0xff; 10])[10..], "ZZZZZZZZZZZZZZZZ");
    }

    #[test]
    fn is_26_crockford_characters_and_sorts_by_time() {
        let earlier = new(UNIX_EPOCH + Duration::from_secs(1));
        let later = new(UNIX_EPOCH + Duration::from_secs(2));

        assert_eq!(earlier.len(), 26);
        assert!(earlier.bytes().all(|b| ALPHABET.contains(&b)), "{earlier}");
        assert!(earlier < later);
        assert_ne!(new(UNIX_EPOCH), new(UNIX_EPOCH));
    }
}
