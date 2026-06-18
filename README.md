# Firepwd-rs

A Rust implementation of the original [Firepwd](https://github.com/lclevy/firepwd) project by Laurent Levy.

`firepwd-rs` extracts and decrypts credentials stored by Mozilla Firefox by reading Firefox profile data and recovering saved usernames and passwords.

## Features

* Written entirely in Rust
* Cross-platform support
* Reads Firefox profiles automatically
* Parses `key4.db` and `logins.json`
* Decrypts saved credentials
* No Python dependency
* Single static executable

## Installation

### Build from Source

```bash
git clone https://github.com/bkhalifeh/firepwd-rs.git
cd firepwd-rs
cargo build --release
```

The binary will be located at:

```text
target/release/firepwd-rs
```

## Usage

### Automatically Detect Firefox Profiles

```bash
firepwd-rs
```

### Specify a Firefox Profile Directory

```bash
firepwd-rs --profile /path/to/firefox/profile
```

### Example Output

```text
https://example.com user=john@example.com pass=mysecretpassword
https://github.com user=octocat pass=github-password
```

## Supported Files

The program reads:

* `key4.db`
* `logins.json`

from a Firefox profile directory.

<!-- ## Supported Platforms

* Linux
* Windows
* macOS -->


## Credits

This project is a Rust port of:

* **Firepwd**

  * Repository: https://github.com/lclevy/firepwd
  * Author: Laurent Levy

Many thanks to the original author for documenting the Firefox password decryption process.

## Disclaimer

This tool is intended for:

* Digital forensics
* Incident response
* Security research
* Password recovery on systems you own or are authorized to analyze

Users are responsible for ensuring that they comply with applicable laws and regulations. Unauthorized access to credentials or systems may be illegal.

## References

* Mozilla NSS
* SQLite
* PKCS #5
* ASN.1 DER encoding

## License

This project is licensed under the MIT License.

## Acknowledgements

Special thanks to Laurent Levy and contributors of the original Firepwd project:

https://github.com/lclevy/firepwd
