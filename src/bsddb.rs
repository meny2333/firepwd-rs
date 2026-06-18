use hex::encode as hexencode;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn get_short_le(d: &[u8], a: usize) -> u16 {
    u16::from_le_bytes([d[a], d[a + 1]])
}

fn get_long_be(d: &[u8], a: usize) -> u32 {
    u32::from_be_bytes([d[a], d[a + 1], d[a + 2], d[a + 3]])
}

pub fn read_bsddb(
    name: &PathBuf,
    verbose: u8,
) -> Result<HashMap<Vec<u8>, Vec<u8>>, Box<dyn std::error::Error>> {
    let data = fs::read(name)?;

    let magic = get_long_be(&data, 0);
    if magic != 0x61561 {
        return Err("bad magic number".into());
    }

    let version = get_long_be(&data, 4);
    if version != 2 {
        return Err(format!("bad version != 2 (1.85), got {}", version).into());
    }

    let pagesize = get_long_be(&data, 12) as usize;
    let nkeys = get_long_be(&data, 0x38) as usize;

    if verbose > 1 {
        println!("pagesize=0x{:x}", pagesize);
        println!("nkeys={}", nkeys);
    }

    let mut readkeys = 0usize;
    let mut page = 1usize;
    let mut db1: Vec<Vec<u8>> = Vec::new();

    while readkeys < nkeys {
        let base = pagesize * page;
        let offsets_data = &data[base..];
        let mut offset_vals: Vec<usize> = Vec::new();
        let mut i = 0usize;
        let mut nval = 0u16;
        let mut val = 1u16;
        let mut keys = 0usize;

        while nval != val {
            keys += 1;
            let key_off = get_short_le(offsets_data, 2 + i) as usize;
            val = get_short_le(offsets_data, 4 + i);
            nval = get_short_le(offsets_data, 8 + i);
            offset_vals.push(key_off + base);
            offset_vals.push(val as usize + base);
            readkeys += 1;
            i += 4;
        }

        offset_vals.push(pagesize * (page + 1));
        let mut val_key = offset_vals.clone();
        val_key.sort_unstable();

        for idx in 0..(keys * 2) {
            let start = val_key[idx];
            let end = val_key[idx + 1].min(data.len());
            db1.push(if start <= end {
                data[start..end].to_vec()
            } else {
                vec![]
            });
        }
        page += 1;
    }

    let mut db: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    let mut idx = 0;
    while idx + 1 < db1.len() {
        db.insert(db1[idx + 1].clone(), db1[idx].clone());
        idx += 2;
    }

    if verbose > 1 {
        for (k, v) in &db {
            println!("{}: {}", String::from_utf8_lossy(k), hexencode(v));
        }
    }

    Ok(db)
}
