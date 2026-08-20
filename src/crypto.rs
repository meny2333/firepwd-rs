use crate::asn1::{Asn1Value, get_integer, get_octet, get_oid, seq_get};

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::NoPadding};
use des::TdesEde3;
use hex::encode as hexencode;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha256;

type HmacSha1 = Hmac<Sha1>;
type TdesEde3Cbc = cbc::Decryptor<TdesEde3>;
type Aes256Cbc = cbc::Decryptor<Aes256>;

// ─── decryptMoz3DES ───────────────────────────────────────────────────────────

pub fn decrypt_moz_3des(
    global_salt: &[u8],
    master_password: &[u8],
    entry_salt: &[u8],
    encrypted_data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use sha1::Digest;

    // hp = SHA1(globalSalt + masterPassword)
    let mut h = sha1::Sha1::new();
    h.update(global_salt);
    h.update(master_password);
    let hp = h.finalize();

    // pes = entrySalt padded to 20 bytes
    let mut pes = entry_salt.to_vec();
    pes.resize(20, 0x00);

    // chp = SHA1(hp + entrySalt)
    let mut h2 = sha1::Sha1::new();
    h2.update(hp);
    h2.update(entry_salt);
    let chp = h2.finalize();

    // k1 = HMAC-SHA1(chp, pes + entrySalt)
    let mut mac1 = HmacSha1::new_from_slice(&chp)?;
    mac1.update(&pes);
    mac1.update(entry_salt);
    let k1 = mac1.finalize().into_bytes();

    // tk = HMAC-SHA1(chp, pes)
    let mut mac_tk = HmacSha1::new_from_slice(&chp)?;
    mac_tk.update(&pes);
    let tk = mac_tk.finalize().into_bytes();

    // k2 = HMAC-SHA1(chp, tk + entrySalt)
    let mut mac2 = HmacSha1::new_from_slice(&chp)?;
    mac2.update(&tk);
    mac2.update(entry_salt);
    let k2 = mac2.finalize().into_bytes();

    let mut k = k1.to_vec();
    k.extend_from_slice(&k2);

    let iv = &k[k.len() - 8..];
    let key = &k[..24];

    decrypt_3des_cbc(key, iv, encrypted_data)
}

// ─── decryptPBE ───────────────────────────────────────────────────────────────

/// Returns (cleartext, algo_oid_string)
pub fn decrypt_pbe(
    decoded_item: &[Asn1Value],
    master_password: &[u8],
    global_salt: &[u8],
    verbose: u8,
) -> Option<(Vec<u8>, String)> {
    // decoded_item is the children of the outer SEQUENCE
    // Structure: [ SEQUENCE{OID, params}, OCTETSTRING ciphertext ]
    let root = Asn1Value::Sequence(decoded_item.to_vec());

    let algo_seq = match seq_get(&root, 0) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("decrypt_pbe algo_seq: {}", e);
            return None;
        }
    };

    let pbe_algo_str = match seq_get(algo_seq, 0) {
        Ok(v) => match get_oid(v) {
            Ok(s) => s.to_string(),
            Err(e) => {
                eprintln!("decrypt_pbe OID: {}", e);
                return None;
            }
        },
        Err(e) => {
            eprintln!("decrypt_pbe OID node: {}", e);
            return None;
        }
    };

    let cipher_text = match seq_get(&root, 1) {
        Ok(v) => match get_octet(v) {
            Ok(b) => b.to_vec(),
            Err(e) => {
                eprintln!("decrypt_pbe ciphertext: {}", e);
                return None;
            }
        },
        Err(e) => {
            eprintln!("decrypt_pbe ciphertext node: {}", e);
            return None;
        }
    };

    match pbe_algo_str.as_str() {
        // ── pbeWithSha1AndTripleDES-CBC ───────────────────────────────────────
        "1.2.840.113549.1.12.5.1.3" => {
            // algo_seq[1] = SEQUENCE { OCTETSTRING entrySalt, INTEGER }
            let params = seq_get(algo_seq, 1).ok()?;
            let entry_salt = get_octet(seq_get(params, 0).ok()?).ok()?.to_vec();

            if verbose > 0 {
                println!("entrySalt: {}", hexencode(&entry_salt));
            }

            let key =
                decrypt_moz_3des(global_salt, master_password, &entry_salt, &cipher_text).ok()?;

            if verbose > 0 {
                println!("decrypted 3des: {}", hexencode(&key));
            }

            let truncated = key[..key.len().min(24)].to_vec();
            Some((truncated, pbe_algo_str))
        }

        // ── PBES2 (PBKDF2 + AES-256-CBC) ─────────────────────────────────────
        "1.2.840.113549.1.5.13" => {
            // algo_seq[1] = SEQUENCE {
            //   SEQUENCE { OID(PBKDF2), SEQUENCE { salt, iter, keylen, prf } }
            //   SEQUENCE { OID(AES256), OCTETSTRING iv }
            // }
            let outer_params = seq_get(algo_seq, 1).ok()?;

            let pbkdf2_seq = seq_get(outer_params, 0).ok()?;
            let pbkdf2_params = seq_get(pbkdf2_seq, 1).ok()?;

            let entry_salt = get_octet(seq_get(pbkdf2_params, 0).ok()?).ok()?.to_vec();
            let iteration_count = {
                let b = get_integer(seq_get(pbkdf2_params, 1).ok()?).ok()?;
                bytes_to_u64(&b) as u32
            };
            let key_length = {
                let b = get_integer(seq_get(pbkdf2_params, 2).ok()?).ok()?;
                bytes_to_u64(&b) as usize
            };

            assert_eq!(key_length, 32, "expected AES-256 key length 32");

            let aes_seq = seq_get(outer_params, 1).ok()?;
            let aes_iv_raw = get_octet(seq_get(aes_seq, 1).ok()?).ok()?.to_vec();

            // Derive key: k = SHA1(globalSalt + masterPassword), then PBKDF2-SHA256
            use sha1::Digest;
            let mut h = sha1::Sha1::new();
            h.update(global_salt);
            h.update(master_password);
            let k = h.finalize();

            let mut derived_key = vec![0u8; key_length];
            pbkdf2_hmac::<Sha256>(&k, &entry_salt, iteration_count, &mut derived_key);

            // iv = 0x04 0x0e + aes_iv_raw (14 bytes) = 16 bytes total
            let mut iv = vec![0x04u8, 0x0eu8];
            iv.extend_from_slice(&aes_iv_raw);
            iv.resize(16, 0);

            if verbose > 0 {
                println!("entrySalt: {}", hexencode(&entry_salt));
                println!("iterations: {}", iteration_count);
                println!("aes_iv: {}", hexencode(&aes_iv_raw));
            }

            let clear = decrypt_aes256_cbc(&derived_key, &iv[..16], &cipher_text).ok()?;

            if verbose > 0 {
                println!("clearText: {}", hexencode(&clear));
            }

            Some((clear, pbe_algo_str))
        }

        other => {
            eprintln!("Unknown PBE algorithm: {}", other);
            None
        }
    }
}

// ─── Low-level cipher helpers ─────────────────────────────────────────────────

pub fn decrypt_3des_cbc(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() < 24 {
        return Err(format!("3DES key too short: {}", key.len()).into());
    }
    if iv.len() < 8 {
        return Err(format!("3DES IV too short: {}", iv.len()).into());
    }
    if ciphertext.is_empty() {
        return Err("empty ciphertext".into());
    }

    let mut buf = ciphertext.to_vec();
    let rem = buf.len() % 8;
    if rem != 0 {
        buf.resize(buf.len() + (8 - rem), 0);
    }

    let dec = TdesEde3Cbc::new_from_slices(&key[..24], &iv[..8])
        .map_err(|e| format!("3DES init: {:?}", e))?;

    Ok(dec
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| format!("3DES decrypt: {:?}", e))?
        .to_vec())
}

pub fn decrypt_aes256_cbc(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if key.len() < 32 {
        return Err(format!("AES key too short: {}", key.len()).into());
    }
    if iv.len() < 16 {
        return Err(format!("AES IV too short: {}", iv.len()).into());
    }
    if ciphertext.is_empty() {
        return Err("empty ciphertext".into());
    }

    let mut buf = ciphertext.to_vec();
    let rem = buf.len() % 16;
    if rem != 0 {
        buf.resize(buf.len() + (16 - rem), 0);
    }

    let dec = Aes256Cbc::new_from_slices(&key[..32], &iv[..16])
        .map_err(|e| format!("AES init: {:?}", e))?;

    Ok(dec
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|e| format!("AES decrypt: {:?}", e))?
        .to_vec())
}

// ─── Integer bytes → u64 ──────────────────────────────────────────────────────

pub fn bytes_to_u64(b: &[u8]) -> u64 {
    let mut v = 0u64;
    for &byte in b {
        v = (v << 8) | byte as u64;
    }
    v
}
