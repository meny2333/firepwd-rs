mod asn1;
mod bsddb;
mod crypto;
mod login;

use clap::Parser;
use hex::encode as hexencode;
use std::path::PathBuf;

use asn1::{Asn1Value, get_integer, get_octet, parse_der_sequence, seq_get};
use bsddb::read_bsddb;
use crypto::{decrypt_3des_cbc, decrypt_aes256_cbc, decrypt_moz_3des, decrypt_pbe};
use login::{LoginEntry, get_login_data};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "firefox_decrypt")]
struct Opts {
    /// Verbosity level (0, 1, 2)
    #[arg(short, long, default_value_t = 0)]
    verbose: u8,

    /// Master password (empty if none)
    #[arg(short = 'p', long = "password", default_value = "")]
    master_password: String,

    /// Firefox profile directory (auto-detected if not specified)
    #[arg(short = 'd', long = "dir", default_value = "")]
    directory: String,
}

// ─── CKA_ID constant ─────────────────────────────────────────────────────────

pub const CKA_ID: [u8; 16] = [
    0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

// ─── Profile discovery ────────────────────────────────────────────────────────

/// Return all candidate Firefox / Thunderbird profile directories
/// found across Windows, macOS, and Linux.
fn find_firefox_profiles() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut search_dirs: Vec<PathBuf> = Vec::new();

    #[cfg(target_os = "windows")]
    {
        if let Ok(app_data) = std::env::var("APPDATA") {
            let app_data_path = PathBuf::from(app_data);
            search_dirs.push(app_data_path.join("Mozilla").join("Firefox"));
            search_dirs.push(app_data_path.join("Thunderbird"));
        }
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            let app_data_path = PathBuf::from(user_profile).join("AppData").join("Roaming");
            search_dirs.push(app_data_path.join("Mozilla").join("Firefox"));
            search_dirs.push(app_data_path.join("Thunderbird"));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Ok(home) = std::env::var("HOME") {
            let home_path = PathBuf::from(home);
            search_dirs.push(home_path.join("Library/Application Support/Firefox"));
            search_dirs.push(home_path.join("Library/Application Support/Thunderbird"));
            search_dirs.push(home_path.join("Library/Mozilla/Firefox"));
        }
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        let profile_parents = [
            ".mozilla/firefox",
            ".mozilla-firefox",
            "snap/firefox/common/.mozilla/firefox",
            ".var/app/org.mozilla.firefox/.mozilla/firefox", // Flatpak
            ".thunderbird",
        ];

        let mut homes: Vec<PathBuf> = Vec::new();

        if let Ok(content) = std::fs::read_to_string("/etc/passwd") {
            for line in content.lines() {
                let fields: Vec<&str> = line.split(':').collect();
                if fields.len() >= 6 {
                    homes.push(PathBuf::from(fields[5]));
                }
            }
        }

        if let Ok(home) = std::env::var("HOME") {
            let p = PathBuf::from(home);
            if !homes.contains(&p) {
                homes.push(p);
            }
        }

        for home in &homes {
            for parent in &profile_parents {
                search_dirs.push(home.join(parent));
            }
        }
    }

    for base in &search_dirs {
        if !base.is_dir() {
            continue;
        }

        // Read profiles.ini to find actual profile sub-directories
        let ini_path = base.join("profiles.ini");
        if ini_path.is_file() {
            let profiles = profiles_from_ini(&ini_path, base);
            if profiles.is_empty() {
                // No ini entries but dir exists — try it directly
                candidates.push(base.clone());
            } else {
                candidates.extend(profiles);
            }
        } else {
            // No profiles.ini — maybe the directory IS the profile
            if base.join("key4.db").exists() || base.join("key3.db").exists() {
                candidates.push(base.clone());
            }
        }
    }

    // De-duplicate while preserving order
    let mut seen = std::collections::HashSet::new();
    candidates.retain(|p| seen.insert(p.clone()));

    candidates
}

/// Parse profiles.ini and return resolved profile directories.
fn profiles_from_ini(ini_path: &PathBuf, base: &PathBuf) -> Vec<PathBuf> {
    let mut result = Vec::new();

    let content = match std::fs::read_to_string(ini_path) {
        Ok(s) => s,
        Err(_) => return result,
    };

    let mut current_path: Option<String> = None;
    let mut current_relative: Option<bool> = None;

    for line in content.lines() {
        let line = line.trim();

        // New section — flush previous
        if line.starts_with('[') {
            if let Some(path_str) = current_path.take() {
                let is_relative = current_relative.unwrap_or(true);
                let full = if is_relative {
                    base.join(&path_str)
                } else {
                    PathBuf::from(&path_str)
                };
                if full.is_dir() {
                    result.push(full);
                }
            }
            current_relative = None;
            continue;
        }

        if let Some((key, val)) = line.split_once('=') {
            let key = key.trim().to_lowercase();
            let val = val.trim();
            match key.as_str() {
                "path" => current_path = Some(val.to_string()),
                "isrelative" => current_relative = Some(val == "1"),
                _ => {}
            }
        }
    }

    // Flush last section
    if let Some(path_str) = current_path {
        let is_relative = current_relative.unwrap_or(true);
        let full = if is_relative {
            base.join(&path_str)
        } else {
            PathBuf::from(&path_str)
        };
        if full.is_dir() {
            result.push(full);
        }
    }

    result
}

// ─── Main ────────────────────────────────────────────────────────────────────

fn main() {
    let opts = Opts::parse();
    let master_password = opts.master_password.as_bytes().to_vec();
    let verbose = opts.verbose;

    // Build list of directories to try
    let directories: Vec<PathBuf> = if opts.directory.is_empty() {
        let found = find_firefox_profiles();
        if found.is_empty() {
            eprintln!("No Firefox profile directories found automatically.");
            eprintln!("Please specify one with -d <path>");
            std::process::exit(1);
        }
        println!("Auto-discovered {} profile(s):", found.len());
        for p in &found {
            println!("  {}", p.display());
        }
        found
    } else {
        vec![PathBuf::from(&opts.directory)]
    };

    // Try each profile directory
    let mut any_found = false;

    for directory in &directories {
        println!("\n─── Profile: {} ───", directory.display());

        // Verify the directory has a key database
        let has_key4 = directory.join("key4.db").exists();
        let has_key3 = directory.join("key3.db").exists();

        if !has_key4 && !has_key3 {
            if verbose > 0 {
                println!("  Skipping: no key4.db or key3.db");
            }
            continue;
        }

        let (key, algo) = match get_key(&master_password, directory, verbose) {
            Some(pair) => pair,
            None => {
                eprintln!("  Could not retrieve key for this profile.");
                continue;
            }
        };

        if verbose > 0 {
            println!("key={} algo={}", hexencode(&key), algo);
        }

        let logins = get_login_data(directory, verbose);
        if logins.is_empty() {
            println!("  No stored passwords in this profile.");
            continue;
        }

        println!("  Decrypting {} login(s):", logins.len());
        any_found = true;

        for entry in &logins {
            decrypt_entry(entry, &key, &algo, verbose);
        }
    }

    if !any_found {
        println!("\nNo credentials found in any profile.");
    }
}

// ─── get_key ─────────────────────────────────────────────────────────────────

fn get_key(master_password: &[u8], directory: &PathBuf, verbose: u8) -> Option<(Vec<u8>, String)> {
    let key4 = directory.join("key4.db");
    let key3 = directory.join("key3.db");

    if key4.exists() {
        println!("  Using key4.db");
        get_key_from_key4(&key4, master_password, verbose)
    } else if key3.exists() {
        println!("  Using key3.db");
        get_key_from_key3(&key3, master_password, verbose)
    } else {
        eprintln!(
            "  cannot find key4.db or key3.db in {}",
            directory.display()
        );
        None
    }
}

// ─── key4.db (SQLite) ────────────────────────────────────────────────────────
fn get_key_from_key4(
    path: &PathBuf,
    master_password: &[u8],
    verbose: u8,
) -> Option<(Vec<u8>, String)> {
    use rusqlite::{Connection, OpenFlags};

    let conn = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  open key4.db: {}", e);
            return None;
        }
    };

    // ── Discover actual table names (case-insensitive) ───────────────────────
    let tables: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table';")
            .ok()?;
        stmt.query_map([], |row| row.get::<_, String>(0))
            .ok()?
            .filter_map(|r| r.ok())
            .collect()
    };

    if verbose > 0 || tables.is_empty() {
        println!("  key4.db tables: {:?}", tables);
    }

    // Find the metadata table name (could be 'metadata' or 'metaData')
    let metadata_table = tables
        .iter()
        .find(|t| t.to_lowercase() == "metadata")
        .cloned();

    // Find the nssPrivate table name (could be 'nssPrivate' or 'nssprivate')
    let nss_table = tables
        .iter()
        .find(|t| t.to_lowercase() == "nssprivate")
        .cloned();

    let metadata_table = match metadata_table {
        Some(t) => t,
        None => {
            eprintln!(
                "  key4.db has no metadata table. Found tables: {:?}",
                tables
            );
            return None;
        }
    };

    let nss_table = match nss_table {
        Some(t) => t,
        None => {
            eprintln!(
                "  key4.db has no nssPrivate table. Found tables: {:?}",
                tables
            );
            return None;
        }
    };

    println!(
        "  metadata table: '{}', nssPrivate table: '{}'",
        metadata_table, nss_table
    );

    // ── Read global salt + password check ────────────────────────────────────
    let query = format!(
        "SELECT item1, item2 FROM {} WHERE id = 'password';",
        metadata_table
    );

    let row: (Vec<u8>, Vec<u8>) = match conn.query_row(&query, [], |row| {
        let item1: Vec<u8> = row.get(0)?;
        let item2: Vec<u8> = row.get(1)?;
        Ok((item1, item2))
    }) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("  metadata query failed: {}", e);
            // Try listing all rows in metadata to see what's there
            if let Ok(mut stmt) =
                conn.prepare(&format!("SELECT id, item1, item2 FROM {};", metadata_table))
            {
                let rows: Vec<String> = stmt
                    .query_map([], |row| row.get::<_, String>(0))
                    .map(|iter| iter.filter_map(|r| r.ok()).collect())
                    .unwrap_or_default();
                eprintln!("  metadata rows (id column): {:?}", rows);
            }
            return None;
        }
    };

    let (global_salt, item2) = row;

    if verbose > 0 {
        println!("  globalSalt: {}", hexencode(&global_salt));
        println!("  item2 hex:  {}", hexencode(&item2));
    }

    // ── Decrypt password-check ───────────────────────────────────────────────
    let decoded_item2 = match parse_der_sequence(&item2) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("  parse item2 ASN1: {}", e);
            return None;
        }
    };

    let (clear_text, _algo) =
        match decrypt_pbe(&decoded_item2, master_password, &global_salt, verbose) {
            Some(v) => v,
            None => {
                eprintln!("  decrypt_pbe (password check) failed");
                return None;
            }
        };

    if verbose > 0 {
        println!("  clearText hex: {}", hexencode(&clear_text));
    }

    let expected = b"password-check\x02\x02";
    let ok = clear_text.len() >= expected.len() && &clear_text[..expected.len()] == expected;

    println!("  password check? {}", if ok { "OK" } else { "FAILED" });

    if !ok {
        eprintln!("  password check error – master password is likely wrong");
        if verbose > 0 {
            eprintln!(
                "  got:      {}",
                hexencode(&clear_text[..clear_text.len().min(20)])
            );
            eprintln!("  expected: {}", hexencode(expected));
        }
        return None;
    }

    // ── Read nssPrivate ──────────────────────────────────────────────────────
    let nss_query = format!("SELECT a11, a102 FROM {};", nss_table);

    let rows: Vec<(Vec<u8>, Vec<u8>)> = {
        let mut stmt = match conn.prepare(&nss_query) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("  prepare nssPrivate: {}", e);
                return None;
            }
        };
        match stmt.query_map([], |row| {
            let a11: Vec<u8> = row.get(0)?;
            let a102: Vec<u8> = row.get(1)?;
            Ok((a11, a102))
        }) {
            Ok(iter) => iter
                .filter_map(|r| r.ok())
                .filter(|(a11, _)| !a11.is_empty())
                .collect(),
            Err(e) => {
                eprintln!("  query nssPrivate: {}", e);
                return None;
            }
        }
    };

    if rows.is_empty() {
        eprintln!("  nssPrivate is empty – no saved logins");
        return None;
    }

    if verbose > 0 {
        println!("  nssPrivate rows: {}", rows.len());
        for (i, (_a11, a102)) in rows.iter().enumerate() {
            println!("    row[{}] a102={}", i, hexencode(a102));
        }
    }

    for (a11, a102) in &rows {
        if a102.as_slice() != CKA_ID {
            if verbose > 0 {
                println!("  skipping a102={} (not CKA_ID)", hexencode(a102));
            }
            continue;
        }

        if verbose > 0 {
            println!("  found CKA_ID match, a11 hex: {}", hexencode(a11));
        }

        let decoded_a11 = match parse_der_sequence(a11) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("  parse a11 ASN1: {}", e);
                continue;
            }
        };

        match decrypt_pbe(&decoded_a11, master_password, &global_salt, verbose) {
            Some((clear, alg)) => {
                println!("  key extracted successfully ({} bytes)", clear.len());
                return Some((clear, alg));
            }
            None => eprintln!("  decrypt_pbe(a11) failed"),
        }
    }

    eprintln!("  no matching CKA_ID in nssPrivate");
    None
}
// ─── key3.db (BSD DB) ────────────────────────────────────────────────────────

fn get_key_from_key3(
    path: &PathBuf,
    master_password: &[u8],
    verbose: u8,
) -> Option<(Vec<u8>, String)> {
    let key_data = match read_bsddb(path, verbose) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("  read_bsddb: {}", e);
            return None;
        }
    };
    let key = extract_secret_key(master_password, &key_data, verbose)?;
    Some((key, "1.2.840.113549.1.12.5.1.3".to_string()))
}

// ─── Extract 3DES key from key3.db ───────────────────────────────────────────

fn extract_secret_key(
    master_password: &[u8],
    key_data: &std::collections::HashMap<Vec<u8>, Vec<u8>>,
    verbose: u8,
) -> Option<Vec<u8>> {
    let pwd_check = key_data.get(b"password-check".as_ref())?;
    let entry_salt_len = pwd_check[1] as usize;
    let entry_salt = &pwd_check[3..3 + entry_salt_len];
    let encrypted_passwd = &pwd_check[pwd_check.len() - 16..];
    let global_salt = key_data.get(b"global-salt".as_ref())?;

    if verbose > 1 {
        println!("  password-check={}", hexencode(pwd_check));
        println!("  entrySalt={}", hexencode(entry_salt));
        println!("  globalSalt={}", hexencode(global_salt));
    }

    let clear =
        decrypt_moz_3des(global_salt, master_password, entry_salt, encrypted_passwd).ok()?;

    if clear.len() < 16 || &clear[..16] != b"password-check\x02\x02" {
        eprintln!("  password check error – provide master password with -p");
        return None;
    }

    let cka_id = CKA_ID.to_vec();
    if !key_data.contains_key(&cka_id) {
        eprintln!("  CKA_ID not found in key3.db");
        return None;
    }

    let priv_key_entry = &key_data[&cka_id];
    if priv_key_entry.len() < 3 {
        return None;
    }

    let salt_len = priv_key_entry[1] as usize;
    let name_len = priv_key_entry[2] as usize;
    let offset = 3 + salt_len + name_len;

    if priv_key_entry.len() <= offset {
        return None;
    }

    let asn1_data = &priv_key_entry[offset..];
    let priv_key_entry_asn1 = parse_der_sequence(asn1_data).ok()?;

    // entrySalt: root[0][0][1][0]
    let entry_salt2 = {
        let root = Asn1Value::Sequence(priv_key_entry_asn1.clone());
        let s0 = seq_get(&root, 0).ok()?;
        let s00 = seq_get(s0, 0).ok()?;
        let s001 = seq_get(s00, 1).ok()?;
        let s0010 = seq_get(s001, 0).ok()?;
        get_octet(s0010).ok()?.to_vec()
    };

    // privKeyData: root[0][1]
    let priv_key_data = {
        let root = Asn1Value::Sequence(priv_key_entry_asn1.clone());
        let s0 = seq_get(&root, 0).ok()?;
        let s01 = seq_get(s0, 1).ok()?;
        get_octet(s01).ok()?.to_vec()
    };

    if verbose > 0 {
        println!("  entrySalt2={}", hexencode(&entry_salt2));
        println!("  privKeyData={}", hexencode(&priv_key_data));
    }

    let priv_key =
        decrypt_moz_3des(global_salt, master_password, &entry_salt2, &priv_key_data).ok()?;

    if verbose > 0 {
        println!("  decrypted priv_key={}", hexencode(&priv_key));
    }

    // Parse: SEQUENCE { INTEGER, SEQUENCE{OID,NULL}, OCTETSTRING }
    let priv_key_asn1 = parse_der_sequence(&priv_key).ok()?;
    let pr_key_bytes = {
        let root = Asn1Value::Sequence(priv_key_asn1);
        let s2 = seq_get(&root, 2).ok()?;
        get_octet(s2).ok()?.to_vec()
    };

    // Parse: SEQUENCE { INT, INT, INT, INT(3des_key), ... }
    let pr_key_asn1 = parse_der_sequence(&pr_key_bytes).ok()?;
    let key_bytes = {
        let root = Asn1Value::Sequence(pr_key_asn1);
        let s3 = seq_get(&root, 3).ok()?;
        get_integer(s3).ok()?
    };

    if verbose > 0 {
        println!("  key={}", hexencode(&key_bytes));
    }

    Some(key_bytes)
}

// ─── Decrypt a single login entry ────────────────────────────────────────────
fn decrypt_entry(entry: &LoginEntry, key: &[u8], _algo: &str, verbose: u8) {
    let cka = CKA_ID.to_vec();
    if entry.username.key_id != cka {
        if verbose > 0 {
            eprintln!("  CKA_ID mismatch for {}", entry.hostname);
        }
        return;
    }

    // Choose cipher based on IV length of the stored credential:
    //   IV =  8 bytes → 3DES-CBC  (key truncated to 24 bytes)
    //   IV = 16 bytes → AES-256-CBC (key truncated to 32 bytes)
    //
    // NOTE: the key returned by decrypt_pbe for PBES2 is the raw cleartext
    // of the a11 blob, which is itself a 3DES key wrapped in ASN.1.
    // Its first 24 bytes are the actual 3DES key used to encrypt logins.
    let decrypt = |iv: &[u8], ct: &[u8]| -> Result<Vec<u8>, String> {
        match iv.len() {
            8 => {
                // 3DES-CBC
                if key.len() < 24 {
                    return Err(format!("3DES key too short: {} bytes", key.len()));
                }
                let raw = decrypt_3des_cbc(&key[..24], iv, ct).map_err(|e| e.to_string())?;
                Ok(pkcs7_unpad(&raw, 8))
            }
            16 => {
                // AES-256-CBC
                if key.len() < 32 {
                    return Err(format!("AES key too short: {} bytes", key.len()));
                }
                let raw = decrypt_aes256_cbc(&key[..32], iv, ct).map_err(|e| e.to_string())?;
                Ok(pkcs7_unpad(&raw, 16))
            }
            n => Err(format!(
                "Unexpected IV length {} for {} (expected 8 for 3DES or 16 for AES)",
                n, entry.hostname
            )),
        }
    };

    let username = match decrypt(&entry.username.iv, &entry.username.ciphertext) {
        Ok(b) => String::from_utf8_lossy(&b)
            .trim_end_matches('\0')
            .to_string(),
        Err(e) => {
            eprintln!("  Error decrypting username for {}: {}", entry.hostname, e);
            return;
        }
    };

    let password = match decrypt(&entry.password.iv, &entry.password.ciphertext) {
        Ok(b) => String::from_utf8_lossy(&b)
            .trim_end_matches('\0')
            .to_string(),
        Err(e) => {
            eprintln!("  Error decrypting password for {}: {}", entry.hostname, e);
            return;
        }
    };

    println!(
        "  {:>40}  user={:<30}  pass={}",
        entry.hostname, username, password
    );
}

// ─── PKCS#7 unpad ────────────────────────────────────────────────────────────

fn pkcs7_unpad(data: &[u8], block_size: usize) -> Vec<u8> {
    if data.is_empty() {
        return data.to_vec();
    }
    let pad = *data.last().unwrap() as usize;
    if pad == 0 || pad > block_size || pad > data.len() {
        return data.to_vec();
    }
    data[..data.len() - pad].to_vec()
}
