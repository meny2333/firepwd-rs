// ─── ASN.1 DER manual parser ─────────────────────────────────────────────────

pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_OCTET: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_SEQUENCE: u8 = 0x30;

#[derive(Debug, Clone)]
pub enum Asn1Value {
    Integer(Vec<u8>),
    OctetString(Vec<u8>),
    Null,
    Oid(String),
    Sequence(Vec<Asn1Value>),
}

// ─── Public helpers ───────────────────────────────────────────────────────────

pub fn seq_get(val: &Asn1Value, idx: usize) -> Result<&Asn1Value, String> {
    match val {
        Asn1Value::Sequence(children) => children.get(idx).ok_or_else(|| {
            format!(
                "seq_get: index {} out of bounds (len={})",
                idx,
                children.len()
            )
        }),
        other => Err(format!("seq_get: expected Sequence, got {:?}", other)),
    }
}

pub fn get_octet(val: &Asn1Value) -> Result<&[u8], String> {
    match val {
        Asn1Value::OctetString(b) => Ok(b),
        other => Err(format!("get_octet: expected OctetString, got {:?}", other)),
    }
}

pub fn get_oid(val: &Asn1Value) -> Result<&str, String> {
    match val {
        Asn1Value::Oid(s) => Ok(s),
        other => Err(format!("get_oid: expected OID, got {:?}", other)),
    }
}

pub fn get_integer(val: &Asn1Value) -> Result<Vec<u8>, String> {
    match val {
        Asn1Value::Integer(b) => Ok(b.clone()),
        other => Err(format!("get_integer: expected Integer, got {:?}", other)),
    }
}

// ─── Parse outer SEQUENCE and return its children ────────────────────────────

pub fn parse_der_sequence(data: &[u8]) -> Result<Vec<Asn1Value>, String> {
    if data.is_empty() {
        return Err("Empty data".to_string());
    }
    if data[0] != TAG_SEQUENCE {
        return Err(format!(
            "Expected SEQUENCE (0x30) at root, got 0x{:02x}",
            data[0]
        ));
    }
    let (length, pos) = parse_length(data, 1)?;
    if pos + length > data.len() {
        return Err(format!(
            "SEQUENCE length {} exceeds available {} bytes",
            length,
            data.len() - pos
        ));
    }
    parse_children(&data[pos..pos + length])
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn parse_length(data: &[u8], pos: usize) -> Result<(usize, usize), String> {
    if pos >= data.len() {
        return Err("EOF reading length".to_string());
    }
    let first = data[pos] as usize;
    if first & 0x80 == 0 {
        Ok((first, pos + 1))
    } else {
        let num_bytes = first & 0x7f;
        if num_bytes == 0 || pos + 1 + num_bytes > data.len() {
            return Err("Invalid long-form length".to_string());
        }
        let mut length = 0usize;
        for i in 0..num_bytes {
            length = (length << 8) | (data[pos + 1 + i] as usize);
        }
        Ok((length, pos + 1 + num_bytes))
    }
}

fn parse_children(data: &[u8]) -> Result<Vec<Asn1Value>, String> {
    let mut values = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let (val, new_pos) = parse_one(data, pos)?;
        values.push(val);
        pos = new_pos;
    }
    Ok(values)
}

fn parse_one(data: &[u8], pos: usize) -> Result<(Asn1Value, usize), String> {
    if pos >= data.len() {
        return Err(format!("EOF at pos {}", pos));
    }
    let tag = data[pos];
    let (length, content_start) = parse_length(data, pos + 1)?;
    let content_end = content_start + length;

    if content_end > data.len() {
        return Err(format!(
            "Data truncated: need {} bytes, have {}",
            length,
            data.len() - content_start
        ));
    }
    let content = &data[content_start..content_end];

    let value = match tag {
        TAG_INTEGER => Asn1Value::Integer(content.to_vec()),
        TAG_OCTET => Asn1Value::OctetString(content.to_vec()),
        TAG_NULL => Asn1Value::Null,
        TAG_OID => Asn1Value::Oid(parse_oid(content)?),
        TAG_SEQUENCE => Asn1Value::Sequence(parse_children(content)?),
        other => {
            if other & 0x20 != 0 {
                // Constructed – treat as sequence
                Asn1Value::Sequence(parse_children(content)?)
            } else {
                Asn1Value::OctetString(content.to_vec())
            }
        }
    };

    Ok((value, content_end))
}

fn parse_oid(data: &[u8]) -> Result<String, String> {
    if data.is_empty() {
        return Err("Empty OID".to_string());
    }
    let mut parts = vec![(data[0] / 40).to_string(), (data[0] % 40).to_string()];
    let mut i = 1;
    while i < data.len() {
        let mut value: u64 = 0;
        loop {
            if i >= data.len() {
                return Err("Truncated OID".to_string());
            }
            let b = data[i];
            i += 1;
            value = (value << 7) | ((b & 0x7f) as u64);
            if b & 0x80 == 0 {
                break;
            }
        }
        parts.push(value.to_string());
    }
    Ok(parts.join("."))
}
