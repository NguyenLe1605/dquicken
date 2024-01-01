pub enum VarInt {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    Unknown(u8),
}

impl VarInt {
    pub fn decode(bytes: &[u8]) -> Self {
        // The length of variable-length integers is encoded in the
        // first two bits of the first byte.
        let v = bytes[0];
        let prefix = v >> 6;
        let length = 1 << prefix;

        // Once the length is known, remove these bits and read any
        // remaining bytes.
        let v: u8 = v & 0x3f;
        match length {
            1 => Self::U8(v),
            2 => Self::U16(u16::from_be_bytes([v, bytes[1]])),
            4 => Self::U32(u32::from_be_bytes([v, bytes[1], bytes[2], bytes[3]])),
            8 => Self::U64(u64::from_be_bytes([
                v, bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ])),
            num => Self::Unknown(num),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn decode_nums() {}
}
