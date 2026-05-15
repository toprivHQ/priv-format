/**
 * .priv format - Reference implementation
 * https://topriv.com/priv-format
 *
 * An open encrypted container format using AES-256-GCM.
 * This library works in any modern browser or Node.js 20+ environment.
 */

const MAGIC = new Uint8Array([0x50, 0x52, 0x49, 0x56]); // "PRIV"
const VERSION = 1;
const HEADER_SIZE = 54;
const PBKDF2_ITERATIONS = 600000;

/**
 * Derive an AES-256 key from a password using PBKDF2.
 */
async function deriveKey(password, salt, usage) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage]
  );
}

/**
 * Build the plaintext payload from an array of {name, data} objects.
 */
function buildPayload(files) {
  const enc = new TextEncoder();
  const parts = [];

  const fileCount = new Uint8Array(4);
  new DataView(fileCount.buffer).setUint32(0, files.length, false);
  parts.push(fileCount);

  for (const file of files) {
    const nameBytes = enc.encode(file.name);
    const nameLen = new Uint8Array(2);
    new DataView(nameLen.buffer).setUint16(0, nameBytes.length, false);
    parts.push(nameLen);
    parts.push(nameBytes);

    const data = file.data instanceof Uint8Array ? file.data : new Uint8Array(file.data);
    const sizeBytes = new Uint8Array(4);
    new DataView(sizeBytes.buffer).setUint32(0, data.length, false);
    parts.push(sizeBytes);
    parts.push(data);
  }

  let totalLen = 0;
  for (const p of parts) totalLen += p.length;
  const payload = new Uint8Array(totalLen);
  let offset = 0;
  for (const p of parts) {
    payload.set(p, offset);
    offset += p.length;
  }
  return payload;
}

/**
 * Parse a decrypted payload back into an array of {name, data} objects.
 */
function parsePayload(data) {
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let offset = 0;

  const fileCount = dv.getUint32(offset, false);
  offset += 4;

  const files = [];
  for (let i = 0; i < fileCount; i++) {
    const nameLen = dv.getUint16(offset, false);
    offset += 2;
    const nameBytes = data.slice(offset, offset + nameLen);
    offset += nameLen;
    const name = new TextDecoder().decode(nameBytes);

    const size = dv.getUint32(offset, false);
    offset += 4;
    const fileData = data.slice(offset, offset + size);
    offset += size;

    files.push({ name, data: fileData });
  }
  return files;
}

/**
 * Encrypt files into a .priv container.
 *
 * @param {Array<{name: string, data: Uint8Array|ArrayBuffer}>} files
 * @param {string} password
 * @param {Object} [options]
 * @param {boolean} [options.stripMetadata=true]
 * @param {Date|null} [options.expiry=null]
 * @returns {Promise<Uint8Array>} The .priv file bytes
 */
export async function encrypt(files, password, options = {}) {
  const { stripMetadata = true, expiry = null } = options;

  const payload = buildPayload(files);
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt, 'encrypt');

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    payload
  );

  let flags = 0;
  let expiryTimestamp = 0;
  if (stripMetadata) flags |= 0x02;
  if (expiry) {
    flags |= 0x01;
    expiryTimestamp = Math.floor(expiry.getTime() / 1000);
  }

  const header = new Uint8Array(HEADER_SIZE);
  header.set(MAGIC, 0);
  header[4] = VERSION;
  header[5] = flags;
  new DataView(header.buffer).setUint32(6, expiryTimestamp, false);
  header.set(salt, 10);
  header.set(iv, 42);

  const encryptedArr = new Uint8Array(encrypted);
  const privFile = new Uint8Array(HEADER_SIZE + encryptedArr.length);
  privFile.set(header, 0);
  privFile.set(encryptedArr, HEADER_SIZE);

  return privFile;
}

/**
 * Decrypt a .priv container.
 *
 * @param {Uint8Array|ArrayBuffer} privFile - The .priv file bytes
 * @param {string} password
 * @returns {Promise<{files: Array<{name: string, data: Uint8Array}>, meta: Object}>}
 * @throws {Error} If the file is invalid, expired, or password is wrong
 */
export async function decrypt(privFile, password) {
  const data = privFile instanceof Uint8Array ? privFile : new Uint8Array(privFile);

  if (data.length < HEADER_SIZE) {
    throw new Error('File too small to be a valid .priv file');
  }

  for (let i = 0; i < 4; i++) {
    if (data[i] !== MAGIC[i]) {
      throw new Error('Not a valid .priv file (bad magic bytes)');
    }
  }

  const version = data[4];
  if (version !== 1) {
    throw new Error(`Unsupported .priv version: ${version}`);
  }

  const flags = data[5];
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const expiryTs = dv.getUint32(6, false);

  if ((flags & 0x01) && expiryTs > 0) {
    const now = Math.floor(Date.now() / 1000);
    if (now > expiryTs) {
      throw new Error(`This .priv file expired on ${new Date(expiryTs * 1000).toISOString()}`);
    }
  }

  const salt = data.slice(10, 42);
  const iv = data.slice(42, 54);
  const ciphertext = data.slice(HEADER_SIZE);

  const key = await deriveKey(password, salt, 'decrypt');

  let decrypted;
  try {
    decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv },
      key,
      ciphertext
    );
  } catch {
    throw new Error('Wrong password or corrupted file');
  }

  const files = parsePayload(new Uint8Array(decrypted));

  return {
    files,
    meta: {
      version,
      hasExpiry: !!(flags & 0x01),
      metadataStripped: !!(flags & 0x02),
      expiryDate: expiryTs > 0 ? new Date(expiryTs * 1000) : null,
    }
  };
}

/**
 * Read .priv file metadata without decrypting.
 *
 * @param {Uint8Array|ArrayBuffer} privFile
 * @returns {Object} File metadata
 */
export function readMeta(privFile) {
  const data = privFile instanceof Uint8Array ? privFile : new Uint8Array(privFile);

  if (data.length < HEADER_SIZE) {
    throw new Error('File too small');
  }

  for (let i = 0; i < 4; i++) {
    if (data[i] !== MAGIC[i]) throw new Error('Not a .priv file');
  }

  const flags = data[5];
  const dv = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const expiryTs = dv.getUint32(6, false);

  return {
    version: data[4],
    hasExpiry: !!(flags & 0x01),
    metadataStripped: !!(flags & 0x02),
    expiryDate: expiryTs > 0 ? new Date(expiryTs * 1000) : null,
    fileSize: data.length,
    payloadSize: data.length - HEADER_SIZE,
  };
}
