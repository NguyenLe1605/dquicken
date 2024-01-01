
#[derive(Debug, Clone, Eq, PartialEq)]
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

    fn encode_bytes(dst: &mut [u8], src: &[u8], mask: u8) {
        if dst.len() < src.len() {
            todo!("Add proper error handling");
        }
        
        dst.copy_from_slice(src);
        dst[0] |= mask
    }

    pub fn encode(&self, bytes: &mut [u8]) {
        match self {
            Self::Unknown(_) => unreachable!(),
            Self::U8(num) => VarInt::encode_bytes(bytes, &num.to_be_bytes()[..], 0x00),
            Self::U16(num) => VarInt::encode_bytes(bytes, &num.to_be_bytes()[..], 0x40),
            Self::U32(num) => VarInt::encode_bytes(bytes, &num.to_be_bytes()[..], 0x80),
            Self::U64(num) => VarInt::encode_bytes(bytes, &num.to_be_bytes()[..], 0xc0),
        } 
    }
}

#[cfg(test)]
mod tests {
    use crate::varint::VarInt;

    #[test]
    fn decode_variable_integers() {
        assert_eq!(VarInt::decode(&0xc2197c5eff14e88cu64.to_be_bytes()), VarInt::U64(151_288_809_941_952_652));
        assert_eq!(VarInt::decode(&0x9d7f3e7du32.to_be_bytes()), VarInt::U32(494_878_333));
        assert_eq!(VarInt::decode(&0x7bbdu16.to_be_bytes()), VarInt::U16(15_293));
        assert_eq!(VarInt::decode(&0x25u8.to_be_bytes()), VarInt::U8(37));
        assert_eq!(VarInt::decode(&0x4025u16.to_be_bytes()), VarInt::U16(37));
    }

    #[test]
    fn encode_variable_integers() {
        let tc = vec![
            (VarInt::U64(151_288_809_941_952_652), 8),
            (VarInt::U32(494_878_333), 4),
            (VarInt::U16(15_293), 2),
            (VarInt::U8(32), 1),
        ];
        for (num, size) in tc.into_iter() {
            let mut buf = vec![0u8; size];
            num.encode(&mut buf);
            assert_eq!(VarInt::decode(&buf), num);
        }
    }
}
