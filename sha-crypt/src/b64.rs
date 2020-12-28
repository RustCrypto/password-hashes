use crate::defs::{MAP, TAB};

pub fn encode(source: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = vec![];
    for entry in &MAP {
        let mut w: usize = 0;
        if entry.3 > 2 {
            w |= source[entry.2 as usize] as usize;
            w <<= 8;
            w |= source[entry.1 as usize] as usize;
            w <<= 8;
        }
        w |= source[entry.0 as usize] as usize;

        for _ in 0..entry.3 {
            out.push(TAB[(w & 0x3f) as usize]);
            w >>= 6;
        }
    }
    out
}

#[cfg(feature = "include_simple")]
pub fn decode(source: &[u8]) -> Vec<u8> {
    let mut out: [u8; 64] = [0; 64];
    for iter in MAP.iter().enumerate() {
        let (i, entry) = iter;

        let mut w: usize = 0;

        for k in (0..entry.3).rev() {
            let pos = TAB
                .iter()
                .position(|&x| x == source[i * 4 + k as usize])
                .unwrap();
            w <<= 6;
            w |= pos as usize;
        }

        out[entry.0 as usize] = (w & 0xff) as u8;
        w >>= 8;
        if entry.3 > 2 {
            out[entry.1 as usize] = (w & 0xff) as u8;
            w >>= 8;
            out[entry.2 as usize] = (w & 0xff) as u8;
        }
    }
    out.to_vec()
}

mod tests {
    #[test]
    fn test_encode_decode() {
        let original: [u8; 64] = [
            0x0b, 0x5b, 0xdf, 0x7d, 0x92, 0xe2, 0xfc, 0xbd, 0xab, 0x57, 0xcb, 0xf3, 0xe0, 0x03,
            0x16, 0x62, 0xd3, 0x6e, 0xa0, 0x57, 0x44, 0x8c, 0xca, 0x35, 0xec, 0x80, 0x75, 0x2a,
            0x37, 0xd4, 0xe6, 0xfa, 0xf7, 0xd7, 0x78, 0xf4, 0x8e, 0x0b, 0x3e, 0xab, 0x23, 0x05,
            0x15, 0xdd, 0x79, 0x14, 0x45, 0xac, 0x66, 0x60, 0x25, 0x94, 0x97, 0x5e, 0x0f, 0x7f,
            0x5f, 0xaf, 0x1a, 0xe5, 0x08, 0xe7, 0x7d, 0xd4,
        ];
        let e = super::encode(&original);

        let d = super::decode(&e);
        for i in 0..d.len() {
            assert_eq!(&original[i], &d[i]);
        }
    }
}
