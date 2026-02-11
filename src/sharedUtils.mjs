/*
 * Copyright 2026 Rishi Kant (Sekant Security Inc.)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import SparkMD5 from 'spark-md5';

/**
 * Detect runtime environment
 */
const isBrowser = typeof crypto !== 'undefined';
const isNode = typeof globalThis.process !== 'undefined' && globalThis.process.versions && globalThis.process.versions.node;

/**
 * Get crypto object based on environment
 * In browser: window.crypto or self.crypto
 * In Node.js: assumes crypto is available in global namespace
 */
function getCrypto() {
  if (isBrowser) {
    return crypto;
  } else if (isNode) {
    // In Node.js, assume crypto has been imported and is available globally
    return globalThis.crypto;
  }
  throw new Error('Crypto API not available in this environment');
}

export function computeEntropy(u8) {
  const counts = new Uint32Array(256);
  for (let i = 0; i < u8.length; i++) counts[u8[i]]++;
  let entropy = 0;
  const len = u8.length;
  if (len === 0) return 0;
  for (let i = 0; i < 256; i++) {
    if (counts[i] === 0) continue;
    const p = counts[i] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function toHex(u8) {
  return Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Calculate hash digest and return as hex string
 * @param {string} algo - Algorithm name (e.g., 'SHA-1', 'SHA-256')
 * @param {Uint8Array} buf - Data to hash
 * @returns {Promise<string>} Hex string
 */
export async function digestHex(algo, buf) {
  const crypto = getCrypto();
  const hash = await crypto.subtle.digest(algo, buf);
  return toHex(new Uint8Array(hash));
}

/**
 * Calculate MD5 hash using SparkMD5
 * @param {Uint8Array} data - Data to hash
 * @returns {string} Hex string
 */
export function calculateMD5(data) {
  const spark = new SparkMD5.ArrayBuffer();
  spark.append(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
  return spark.end();
}

/* Endianness-aware readers */
export function readUint16(view, offset, littleEndian) {
  return view.getUint16(offset, littleEndian);
}

export function readUint32(view, offset, littleEndian) {
  return view.getUint32(offset, littleEndian);
}

export function readUint64(view, offset, littleEndian) {
  const lo = view.getUint32(offset + (littleEndian ? 0 : 4), littleEndian);
  const hi = view.getUint32(offset + (littleEndian ? 4 : 0), littleEndian);
  return hi * 2 ** 32 + lo;
}

/* Null-terminated UTF-8 string */
export function readString(buf, offset, maxLength = 1024) {
  const end = Math.min(buf.length, offset + maxLength);
  let str = "";
  for (let i = offset; i < end; i++) {
    if (buf[i] === 0) break;
    str += String.fromCharCode(buf[i]);
  }
  return str;
}

/* Null-terminated UTF-16 LE string */
export function readUtf16leString(view, offset, maxBytes = 2048) {
  let str = "";
  for (let i = 0; i + 1 < maxBytes; i += 2) {
    const code = view.getUint16(offset + i, true);
    if (code === 0) break;
    str += String.fromCharCode(code);
  }
  return str;
}

/* Find a pattern in Uint8Array */
export function findPattern(buf, pattern) {
  const len = buf.length, plen = pattern.length;
  for (let i = 0; i <= len - plen; i++) {
    let ok = true;
    for (let j = 0; j < plen; j++) if (buf[i + j] !== pattern[j]) { ok = false; break; }
    if (ok) return i;
  }
  return -1;
}
