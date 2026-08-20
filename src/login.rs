use crate::asn1::{get_octet, parse_der_sequence, seq_get};

use base64::{Engine as _, engine::general_purpose};
use rusqlite::{Connection, OpenFlags};
use std::fs;
use std::path::{Path, PathBuf};

// ─── Structs ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LoginField {
    pub key_id: Vec<u8>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct LoginEntry {
    pub username: LoginField,
    pub password: LoginField,
    pub hostname: String,
}

// ─── decode_login_data ────────────────────────────────────────────────────────

/// Decode base64 + ASN.1 DER login field.
///
/// SEQUENCE {
///   OCTETSTRING key_id
///   SEQUENCE { OID, OCTETSTRING iv }
///   OCTETSTRING ciphertext
/// }
pub fn decode_login_data(data: &str) -> Result<LoginField, Box<dyn std::error::Error>> {
    let decoded = general_purpose::STANDARD.decode(data)?;
    let children = parse_der_sequence(&decoded).map_err(|e| format!("decode_login_data: {}", e))?;

    if children.len() < 3 {
        return Err(format!(
            "decode_login_data: expected 3 children, got {}",
            children.len()
        )
        .into());
    }

    let key_id = get_octet(&children[0])
        .map_err(|e| format!("key_id: {}", e))?
        .to_vec();

    // children[1] = SEQUENCE { OID, OCTETSTRING iv }
    let iv_seq = &children[1];
    let iv = get_octet(seq_get(iv_seq, 1).map_err(|e| format!("iv seq: {}", e))?)
        .map_err(|e| format!("iv: {}", e))?
        .to_vec();

    let ciphertext = get_octet(&children[2])
        .map_err(|e| format!("ciphertext: {}", e))?
        .to_vec();

    Ok(LoginField {
        key_id,
        iv,
        ciphertext,
    })
}

// ─── get_login_data ───────────────────────────────────────────────────────────

pub fn get_login_data(directory: &Path, verbose: u8) -> Vec<LoginEntry> {
    let json_file = directory.join("logins.json");
    let sqlite_file = directory.join("signons.sqlite");

    if json_file.exists() {
        return load_from_json(&json_file, verbose);
    }

    if sqlite_file.exists() {
        println!("sqlite");
        return load_from_sqlite(&sqlite_file, verbose);
    }

    eprintln!("missing logins.json or signons.sqlite");
    vec![]
}

// ─── JSON loader (Firefox 32+) ────────────────────────────────────────────────

fn load_from_json(path: &PathBuf, _verbose: u8) -> Vec<LoginEntry> {
    let content = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("read logins.json: {}", e);
            return vec![];
        }
    };

    let json: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("parse logins.json: {}", e);
            return vec![];
        }
    };

    let logins = match json.get("logins").and_then(|v| v.as_array()) {
        Some(l) => l,
        None => {
            eprintln!("no 'logins' key in logins.json");
            return vec![];
        }
    };

    let mut result = Vec::new();
    for row in logins {
        let enc_user = match row.get("encryptedUsername").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let enc_pass = match row.get("encryptedPassword").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => continue,
        };
        let hostname = row
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        match (decode_login_data(enc_user), decode_login_data(enc_pass)) {
            (Ok(u), Ok(p)) => result.push(LoginEntry {
                username: u,
                password: p,
                hostname,
            }),
            (Err(e), _) | (_, Err(e)) => eprintln!("decode error: {}", e),
        }
    }
    result
}

// ─── SQLite loader (Firefox < 32) ─────────────────────────────────────────────

fn load_from_sqlite(path: &PathBuf, verbose: u8) -> Vec<LoginEntry> {
    let conn = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("open signons.sqlite: {}", e);
            return vec![];
        }
    };

    let mut stmt = match conn.prepare("SELECT * FROM moz_logins;") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("prepare: {}", e);
            return vec![];
        }
    };

    let rows: Vec<(String, String, String)> = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
            ))
        })
        .map(|iter| iter.flatten().collect())
        .unwrap_or_default();

    let mut result = Vec::new();
    for (hostname, enc_user, enc_pass) in rows {
        if verbose > 1 {
            println!("{} {} {}", hostname, enc_user, enc_pass);
        }
        match (decode_login_data(&enc_user), decode_login_data(&enc_pass)) {
            (Ok(u), Ok(p)) => result.push(LoginEntry {
                username: u,
                password: p,
                hostname,
            }),
            (Err(e), _) | (_, Err(e)) => eprintln!("decode error: {}", e),
        }
    }
    result
}
