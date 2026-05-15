# .priv - Encrypted File Format

An open encrypted container format designed for privacy. AES-256-GCM encryption, automatic metadata stripping, and hidden filenames.

**[Create .priv file](https://privconvert.com/tools/priv-encrypt/)** | **[Open .priv file](https://privconvert.com/tools/priv-decrypt/)** | **[Full specification](https://topriv.com/priv-format)**

## Why .priv?

Existing archive formats like ZIP and 7z were designed for compression, not privacy.

| Feature | ZIP + password | .priv |
|---|---|---|
| File content encrypted | Yes | Yes |
| Filenames encrypted | No | Yes |
| Metadata stripped | No | Yes |
| Authenticated encryption | Varies | AES-256-GCM |
| Expiry date | No | Yes |
| Browser-based | No | Yes |

## Quick start

### Command line (Linux / macOS)

```bash
# Install
git clone https://github.com/toprivHQ/priv-format.git
cd priv-format
pip install cryptography
sudo cp priv /usr/local/bin/

# Encrypt files
priv encrypt secret.pdf photos/ -o bundle.priv

# Decrypt
priv decrypt bundle.priv -o ./decrypted/

# View file info without decrypting
priv info bundle.priv
```

**One-liner install:**

```bash
curl -sL https://raw.githubusercontent.com/toprivHQ/priv-format/main/priv -o /usr/local/bin/priv && chmod +x /usr/local/bin/priv && pip install cryptography
```

### In the browser

No installation needed. Go to [privconvert.com/tools/priv-encrypt](https://privconvert.com/tools/priv-encrypt/) and drop your files.

### Using the JavaScript library

```js
import { encrypt, decrypt } from './priv.js';

// Encrypt files
const privFile = await encrypt(files, password, { stripMetadata: true });

// Decrypt a .priv file
const originalFiles = await decrypt(privFileBuffer, password);
```

### Run locally

Clone this repo and open `index.html` in your browser. No server needed.

```bash
git clone https://github.com/toprivHQ/priv-format.git
cd priv-format
open index.html
```

## Format specification (v1)

### Header (54 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 bytes | Magic | `PRIV` (0x50 0x52 0x49 0x56) |
| 4 | 1 byte | Version | Format version (0x01) |
| 5 | 1 byte | Flags | Bit 0: has expiry, Bit 1: metadata stripped |
| 6 | 4 bytes | Expiry | Unix timestamp (uint32 BE), 0 if none |
| 10 | 32 bytes | Salt | Random salt for PBKDF2 |
| 42 | 12 bytes | IV | Initialization vector for AES-GCM |
| 54 | variable | Ciphertext | AES-256-GCM encrypted payload + auth tag |

### Encrypted payload

Once decrypted, the payload contains:

- `uint32` - File count (big-endian)
- For each file:
  - `uint16` - Filename length (big-endian)
  - `N bytes` - Filename (UTF-8)
  - `uint32` - File data size (big-endian)
  - `N bytes` - Raw file data

### Cryptographic details

- **Key derivation**: PBKDF2 with SHA-256, 600,000 iterations, 32-byte random salt
- **Encryption**: AES-256-GCM with 12-byte random IV
- **Authentication**: GCM provides authenticated encryption (16-byte auth tag appended to ciphertext)

## Security properties

- **Zero knowledge**: When using the web tool, encryption and decryption happen entirely in the browser. No files or passwords are sent to any server.
- **Authenticated encryption**: AES-256-GCM ensures both confidentiality and integrity. Tampering with any byte causes decryption to fail.
- **Unique per file**: Random salt and IV mean encrypting the same file twice produces completely different output.
- **Brute-force resistant**: 600,000 PBKDF2 iterations make password guessing computationally expensive.

## File structure

```
+--------+---+-------+--------+------+----+--------------------+
| PRIV   | V | Flags | Expiry | Salt | IV | Encrypted Payload  |
| 4B     |1B | 1B    | 4B     | 32B  |12B | Variable           |
+--------+---+-------+--------+------+----+--------------------+
```

## CLI reference

| Command | Description |
|---------|-------------|
| `priv encrypt <files...> -o out.priv` | Encrypt files into a .priv container |
| `priv decrypt file.priv -o ./dir/` | Decrypt a .priv file to a directory |
| `priv info file.priv` | Show metadata without decrypting |
| `priv encrypt dir/ -o out.priv` | Encrypt an entire directory recursively |
| `priv encrypt f.txt --expiry 1735689600` | Set expiry date (Unix timestamp) |

Files encrypted with the CLI are fully compatible with the browser tools and vice versa.

## Requirements

- **Browser**: Any modern browser (Chrome, Firefox, Safari, Edge)
- **CLI**: Python 3.8+ with the `cryptography` package

## License

MIT License. See [LICENSE](LICENSE) for details.

The .priv format specification is open and free to implement.

## Links

- [Create .priv file](https://privconvert.com/tools/priv-encrypt/) - Browser-based encryption
- [Open .priv file](https://privconvert.com/tools/priv-decrypt/) - Browser-based decryption
- [Format documentation](https://topriv.com/priv-format) - Full specification
- [Blog post](https://privconvert.com/blog/introducing-priv-encrypted-file-format/) - Why we built .priv

Built by [topriv](https://topriv.com) - Privacy-first digital tools.
