#[derive(Clone, Copy, Debug)]
pub struct PatternInfo {
    pub id: usize,
    pub len: usize,
    pub data_offset: usize,
    pub anchor_offset: usize,
}

pub fn parse_hex_pattern(pattern: &str) -> (Vec<u8>, Vec<u8>) {
    let mut values = Vec::with_capacity(pattern.len() / 2);
    let mut masks = Vec::with_capacity(pattern.len() / 2);

    for part in pattern.split_whitespace() {
        if part == "??" {
            values.push(0x00);
            masks.push(0x00);
        } else if part.ends_with('?') {
            let val = u8::from_str_radix(&part[0..1], 16).unwrap() << 4;
            values.push(val);
            masks.push(0xF0);
        } else if part.starts_with('?') {
            let val = u8::from_str_radix(&part[1..2], 16).unwrap();
            values.push(val);
            masks.push(0x0F);
        } else {
            let val = u8::from_str_radix(part, 16).unwrap();
            values.push(val);
            masks.push(0xFF);
        }
    }
    (values, masks)
}

pub fn find_best_anchor(values: &[u8], masks: &[u8]) -> (Vec<u8>, usize) {
    let mut best_len = 0;
    let mut best_start = 0;
    let mut current_start = 0;
    let mut current_len = 0;
    for (i, &mask) in masks.iter().enumerate() {
        if mask == 0xFF {
            if current_len == 0 {
                current_start = i;
            }
            current_len += 1;
        } else {
            if current_len > best_len {
                best_len = current_len;
                best_start = current_start;
            }
            current_len = 0;
        }
    }
    if current_len > best_len {
        best_len = current_len;
        best_start = current_start;
    }
    if best_len == 0 {
        return (vec![values[0]], 0);
    }
    (
        values[best_start..best_start + best_len].to_vec(),
        best_start,
    )
}
