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

/**
 * YARA Hash Module Implementation
 * 
 * Browser-compatible implementation of YARA's hash module functions.
 * Uses native Web Crypto API for SHA1 and SHA256, and spark-md5 for MD5.
 * 
 * Supported functions:
 * - md5(offset, size)      : Calculate MD5 hash
 * - md5(string)            : Calculate MD5 hash of string
 * - sha1(offset, size)     : Calculate SHA1 hash
 * - sha1(string)           : Calculate SHA1 hash of string
 * - sha256(offset, size)   : Calculate SHA256 hash
 * - sha256(string)         : Calculate SHA256 hash of string
 * - checksum32(offset, size) : Calculate 32-bit checksum
 * - checksum32(string)     : Calculate 32-bit checksum of string
 * - crc32(offset, size)    : Calculate CRC32
 * - crc32(string)          : Calculate CRC32 of string
 * 
 * All hash functions return lowercase hexadecimal strings.
 * 
 * @see https://yara.readthedocs.io/en/stable/modules/hash.html
 */

import { digestHex, calculateMD5 } from './sharedUtils.mjs';

/**
 * Convert string to Uint8Array
 * @param {string} str 
 * @returns {Uint8Array}
 */
function stringToBytes(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

/**
 * Calculate 32-bit checksum (sum of all bytes modulo 2^32)
 * @param {Uint8Array} data 
 * @returns {number}
 */
function calculateChecksum32(data) {
  let sum = 0;
  for (let i = 0; i < data.length; i++) {
    sum = (sum + data[i]) >>> 0; // Keep as 32-bit unsigned
  }
  return sum & 0xFFFFFFFF;
}

/**
 * CRC32 lookup table
 */
const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let crc = i;
    for (let j = 0; j < 8; j++) {
      crc = (crc & 1) ? (0xEDB88320 ^ (crc >>> 1)) : (crc >>> 1);
    }
    table[i] = crc;
  }
  return table;
})();

/**
 * Calculate CRC32 checksum
 * @param {Uint8Array} data 
 * @returns {number}
 */
function calculateCRC32(data) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < data.length; i++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ data[i]) & 0xFF];
  }
  crc = (crc ^ 0xFFFFFFFF) >>> 0;
  return crc;
}

/**
 * Create a hash module instance for a specific data buffer
 * @param {Uint8Array} data - The data to compute hashes on
 * @returns {Object} Hash module with all YARA hash functions
 */
export function createHashModule(data) {
  if (!data || !(data instanceof Uint8Array)) {
    throw new Error('Hash module requires a Uint8Array data buffer');
  }

  return {
    /**
     * Calculate MD5 hash
     * Can be called with (offset, size) or (string)
     */
    md5: async function(...args) {
      if (args.length === 1 && typeof args[0] === 'string') {
        // md5(string)
        const bytes = stringToBytes(args[0]);
        return calculateMD5(bytes);
      } else if (args.length === 2) {
        // md5(offset, size)
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        return calculateMD5(slice);
      } else {
        throw new Error('md5() requires either (offset, size) or (string)');
      }
    },

    /**
     * Calculate SHA1 hash
     * Can be called with (offset, size) or (string)
     */
    sha1: async function(...args) {
      if (args.length === 1 && typeof args[0] === 'string') {
        // sha1(string)
        const bytes = stringToBytes(args[0]);
        return await digestHex('SHA-1', bytes);
      } else if (args.length === 2) {
        // sha1(offset, size)
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0 || offset + size > data.length) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        return await digestHex('SHA-1', slice);
      } else {
        throw new Error('sha1() requires either (offset, size) or (string)');
      }
    },

    /**
     * Calculate SHA256 hash
     * Can be called with (offset, size) or (string)
     */
    sha256: async function(...args) {
      if (args.length === 1 && typeof args[0] === 'string') {
        // sha256(string)
        const bytes = stringToBytes(args[0]);
        return await digestHex('SHA-256', bytes);
      } else if (args.length === 2) {
        // sha256(offset, size)
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0 || offset + size > data.length) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        return await digestHex('SHA-256', slice);
      } else {
        throw new Error('sha256() requires either (offset, size) or (string)');
      }
    },

    /**
     * Calculate 32-bit checksum
     * Can be called with (offset, size) or (string)
     */
    checksum32: function(...args) {
      if (args.length === 1 && typeof args[0] === 'string') {
        // checksum32(string)
        const bytes = stringToBytes(args[0]);
        return calculateChecksum32(bytes);
      } else if (args.length === 2) {
        // checksum32(offset, size)
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        if (slice.length === 0) return 0;
        return calculateChecksum32(slice);
      } else {
        throw new Error('checksum32() requires either (offset, size) or (string)');
      }
    },

    /**
     * Calculate CRC32 checksum
     * Can be called with (offset, size) or (string)
     */
    crc32: function(...args) {
      if (args.length === 1 && typeof args[0] === 'string') {
        // crc32(string)
        const bytes = stringToBytes(args[0]);
        return calculateCRC32(bytes);
      } else if (args.length === 2) {
        // crc32(offset, size)
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        if (slice.length === 0) return 0;
        return calculateCRC32(slice);
      } else {
        throw new Error('crc32() requires either (offset, size) or (string)');
      }
    }
  };
}

/**
 * Standalone hash functions that don't require a data buffer
 * (for string hashing only)
 */
export const hash = {
  /**
   * Calculate MD5 hash of a string
   * @param {string} str 
   * @returns {Promise<string>} Hex string
   */
  md5: async function(str) {
    const bytes = stringToBytes(str);
    return calculateMD5(bytes);
  },

  /**
   * Calculate SHA1 hash of a string
   * @param {string} str 
   * @returns {Promise<string>} Hex string
   */
  sha1: async function(str) {
    const bytes = stringToBytes(str);
    return await digestHex('SHA-1', bytes);
  },

  /**
   * Calculate SHA256 hash of a string
   * @param {string} str 
   * @returns {Promise<string>} Hex string
   */
  sha256: async function(str) {
    const bytes = stringToBytes(str);
    return await digestHex('SHA-256', bytes);
  },

  /**
   * Calculate 32-bit checksum of a string
   * @param {string} str 
   * @returns {string} Hex string
   */
  checksum32: function(str) {
    const bytes = stringToBytes(str);
    return calculateChecksum32(bytes);
  },

  /**
   * Calculate CRC32 of a string
   * @param {string} str 
   * @returns {string} Hex string
   */
  crc32: function(str) {
    const bytes = stringToBytes(str);
    return calculateCRC32(bytes);
  }
};

// Export for convenience
export default {
  createHashModule,
  hash
};
