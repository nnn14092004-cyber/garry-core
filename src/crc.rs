//! Compile-time IEEE 802.3 CRC-32 implementation for deterministic verification.

pub const CRC32_POLYNOMIAL: u32 = 0xEDB8_8320;

/// Generates the 256-entry lookup table for IEEE 802.3 CRC-32 at compile time.
pub const fn make_crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0usize;
        while j < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (CRC32_POLYNOMIAL & mask);
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Static lookup table embedded directly into the binary's read-only data segment.
pub static CRC_TABLE: [u32; 256] = make_crc_table();

/// Computes the IEEE 802.3 CRC-32 checksum of a byte slice using the compile-time lookup table.
#[inline]
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        let index = ((crc ^ (byte as u32)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC_TABLE[index];
    }
    crc ^ 0xFFFF_FFFFu32
}

/// Backward-compatible alias matching the original engine naming convention.
#[inline]
pub fn calculate_crc32(data: &[u8]) -> u32 {
    crc32(data)
}

/// Backward-compatible alias for hashing pipeline integration.
#[inline]
pub fn compute_crc32(data: &[u8]) -> u32 {
    crc32(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_bitwise_crc32(data: &[u8]) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in data {
            crc ^= byte as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (CRC32_POLYNOMIAL & mask);
            }
        }
        !crc
    }

    #[test]
    fn test_crc32_empty_slice() {
        assert_eq!(crc32(&[]), 0x0000_0000);
        assert_eq!(calculate_crc32(&[]), 0x0000_0000);
    }

    #[test]
    fn test_crc32_ieee_standard_test_vector() {
        let input = b"123456789";
        assert_eq!(crc32(input), 0xCBF4_3926);
        assert_eq!(calculate_crc32(input), 0xCBF4_3926);
    }

    #[test]
    fn test_table_matches_reference_bitwise_equivalence() {
        let test_cases: &[&[u8]] = &[
            b"",
            b"a",
            b"Garry Autonomous Agent Engine",
            b"Local-First, Air-gapped, Deterministic Finite State Machine",
        ];

        for &case in test_cases {
            let expected = reference_bitwise_crc32(case);
            let actual = crc32(case);
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_large_synthetic_payload_parity() {
        let mut buffer = [0u8; 7861];
        for (i, slot) in buffer.iter_mut().enumerate() {
            *slot = ((i * 31 + 17) & 0xFF) as u8;
        }

        let expected = reference_bitwise_crc32(&buffer);
        let actual = crc32(&buffer);
        assert_eq!(actual, expected);
    }
}