//! Haiku's four-character type codes for attributes (`<TypeConstants.h>`).

const fn type_code(c: &[u8; 4]) -> u32 {
    (c[0] as u32) << 24 | (c[1] as u32) << 16 | (c[2] as u32) << 8 | c[3] as u32
}

pub const B_BOOL_TYPE: u32 = type_code(b"BOOL");
pub const B_DOUBLE_TYPE: u32 = type_code(b"DBLE");
pub const B_INT64_TYPE: u32 = type_code(b"LLNG");
pub const B_RAW_TYPE: u32 = type_code(b"RAWT");
pub const B_STRING_TYPE: u32 = type_code(b"CSTR");
pub const B_MIME_STRING_TYPE: u32 = type_code(b"MIMS");
pub const B_FLOAT_TYPE: u32 = type_code(b"FLOT");
pub const B_INT16_TYPE: u32 = type_code(b"SHRT");
pub const B_INT32_TYPE: u32 = type_code(b"LONG");
pub const B_UINT32_TYPE: u32 = type_code(b"ULNG");
pub const B_UINT64_TYPE: u32 = type_code(b"ULLG");
pub const B_TIME_TYPE: u32 = type_code(b"TIME");

#[cfg(test)]
mod tests {
    #[test]
    fn codes_match_haiku() {
        // 'CSTR' and 'LLNG' as the C multi-character constants evaluate.
        assert_eq!(super::B_STRING_TYPE, 0x4353_5452);
        assert_eq!(super::B_INT64_TYPE, 0x4c4c_4e47);
    }
}
