# .priv File Format Specification

**Version 1** - Published May 2026

## Overview

The `.priv` format is an encrypted container for files. It uses AES-256-GCM authenticated encryption with PBKDF2 key derivation to protect both file contents and filenames. The format is designed to be simple, secure, and implementable in any language with standard cryptographic primitives.

## Goals

- **Encrypt everything**: File contents, filenames, and file count are all encrypted
- **Authenticated**: Any tampering is detected during decryption
- **Simple**: A minimal header followed by a single encrypted blob
- **Open**: Anyone can implement a `.priv` reader/writer without permission or fees
- **No compression**: Encryption output is indistinguishable from random data and cannot be compressed. Adding compression before encryption is an implementation choice, not part of the spec.

## Binary layout

All multi-byte integers are big-endian (network byte order).

### Header (54 bytes, unencrypted)

```
Offset  Size    Field       Description
------  ----    -----       -----------
0       4       Magic       ASCII "PRIV" (0x50 0x52 0x49 0x56)
4       1       Version     0x01
5       1       Flags       Bit field (see below)
6       4       Expiry      Unix timestamp (uint32), 0 = no expiry
10      32      Salt        Random salt for PBKDF2
42      12      IV          Initialization vector for AES-GCM
```

### Flags byte

```
Bit 0 (0x01): Has expiry date
Bit 1 (0x02): Metadata was stripped before encryption
Bits 2-7:     Reserved (must be 0)
```

### Ciphertext (variable length)

Starting at offset 54, the remainder of the file is AES-256-GCM ciphertext with a 16-byte authentication tag appended (as produced by standard AES-GCM implementations).

## Encrypted payload structure

After decryption, the plaintext contains:

```
Offset  Size    Field
------  ----    -----
0       4       File count (uint32)

For each file:
  0     2       Filename length in bytes (uint16)
  2     N       Filename (UTF-8 encoded)
  N+2   4       File data length in bytes (uint32)
  N+6   M       Raw file data
```

## Cryptographic parameters

| Parameter | Value |
|-----------|-------|
| Key derivation | PBKDF2-SHA256 |
| Iterations | 600,000 |
| Salt length | 32 bytes (random) |
| Derived key length | 256 bits |
| Encryption | AES-256-GCM |
| IV length | 12 bytes (random) |
| Auth tag length | 16 bytes (128 bits) |

## Encryption process

1. Generate 32 random bytes for the salt
2. Generate 12 random bytes for the IV
3. Derive a 256-bit key from the password using PBKDF2-SHA256 with the salt and 600,000 iterations
4. Build the plaintext payload (file count, then each file's name and data)
5. Encrypt the payload with AES-256-GCM using the derived key and IV
6. Write the header (magic, version, flags, expiry, salt, IV) followed by the ciphertext

## Decryption process

1. Read and validate the header (check magic bytes and version)
2. If the expiry flag is set and the timestamp has passed, reject the file
3. Extract salt and IV from the header
4. Derive the key from the password using PBKDF2-SHA256 with the salt
5. Decrypt the ciphertext with AES-256-GCM - if the auth tag verification fails, the password is wrong or the file is corrupted
6. Parse the plaintext payload to extract files

## MIME type

`application/x-priv`

## File extension

`.priv`

## Security considerations

- Implementations MUST use cryptographically secure random number generators for salt and IV
- Implementations MUST NOT reuse IV/salt pairs with the same key
- Implementations SHOULD warn users about weak passwords
- Implementations SHOULD clear sensitive data (passwords, plaintext, keys) from memory after use
- The format does not provide protection against an attacker who can observe file size; padding is an implementation choice

## Version history

| Version | Date | Changes |
|---------|------|---------|
| 1 | May 2026 | Initial release |
