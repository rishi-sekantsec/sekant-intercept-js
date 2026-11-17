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


// Verification window for Aho-Corasick candidates (text and literal-prefixed regex).
// Mirrors libyara's YR_RE_SCAN_LIMIT (4096); full-buffer scans are unbounded.
const MAX_RE_SCAN_LIMIT = 4096;
export const MAX_MATCHES = 100;
const DEFAULT_MATCH_LIMITS = { maxMatches: MAX_MATCHES };

/**
 * Compile a YARA-like string definition into a matcher function.
 * Supports: text, wide, ascii, xor, base64/base64wide, regex, hex, fullword, nocase
 * @param {Object} [limits] - Shared `{ maxMatches }` object; read live on every match run
 */
export function compileYaraLike(definition, limits = DEFAULT_MATCH_LIMITS) {
  definition = definition.trim();

  const isRegex = definition.startsWith("/");
  const isHex = definition.startsWith("{");
  const quoteMatch = definition.match(/^"(.*)"(.*)$/);

  if (isRegex) {
    return makeRegexMatcher(definition, limits);
  } else if (isHex) {
    const mods = definition.slice(definition.lastIndexOf("}") + 1);
    return makeHexMatcher(definition.slice(1, definition.lastIndexOf("}")).trim(), mods, limits);
  } else if (quoteMatch) {
    const [, text, modsRaw] = quoteMatch;
    const mods = modsRaw.toLowerCase();

    const opts = {
      wide: /\bwide\b/.test(mods),
      xor: parseXorRange(mods),
//      allowKey0: /\bxor\b/.test(mods) && !/\(0\)/.test(mods),
      allowKey0: true,
      ascii: /\bascii\b/.test(mods) || !/\bwide\b/.test(mods),
      base64: /\bbase64\b/.test(mods),
      base64wide: /\bbase64wide\b/.test(mods),
      fullword: /\bfullword\b/.test(mods),
      nocase: /\bnocase\b/.test(mods),
      private: /\bprivate\b/.test(mods),
    };

    return makeTextMatcher(text, opts);
  }

  throw new Error("Unsupported definition: " + definition);
}

function addOptionsToMatcher(matcher) {
  // Public contract: `offset < 0` scans the whole buffer, otherwise the search window starts at
  // `offset` (one byte earlier, so fullword checks at the window start can see the preceding byte).
  const scan = (data, offset = -1, maxLength = MAX_RE_SCAN_LIMIT, exactIndex = -1) => {
    if (offset < 0) return matcher(data, -1);
    const start = Math.max(0, offset - 1);
    return matcher(data.slice(start, start + maxLength), start, exactIndex < 0 ? -1 : exactIndex - start);
  };

  // Aho-Corasick candidates ask "is there a match starting exactly here?", which a window scan
  // cannot answer — its first match may be a neighbouring occurrence.
  scan.verifyAt = (data, offset) => scan(data, offset, MAX_RE_SCAN_LIMIT, offset);
  return scan;
}

// ╭─────────────────────────────╮
// │ REGEX MATCHER               │
// ╰─────────────────────────────╯
function makeRegexMatcher(definition, limits) {
  const mods = definition.split("/").pop().toLowerCase() ?? "";
  const regexFlags = mods.split(" ")[0];
  const isPrivate = /\bprivate\b/.test(mods);
  const pattern = definition.slice(1, definition.lastIndexOf("/"));
  const nocase = regexFlags.includes("i");
  const flags = "g" + (regexFlags.includes("s") ? "s" : "") + (nocase ? "i" : "");
  const literalPrefix = getRegexPrefix(pattern, nocase);
  const re = new RegExp(pattern, flags);

  const matcher = (data, offset = -1, exactIndex = -1) => {
    const encoder = new TextEncoder();
    const text = new TextDecoder().decode(data);
    const results = [];
    const singleRun = offset >= 0;
    const exact = exactIndex >= 0;
    // `re` outlives a call: the matcher runs once per Aho-Corasick candidate plus once per full
    // scan, and an early `break` (or the MAX_MATCHES cap) leaves `lastIndex` mid-text. Position it
    // explicitly on entry instead of inheriting the previous run's position.
    const runIndex = exact ? exactIndex : 0;
    offset = offset < 0 ? 0 : offset;
    re.lastIndex = runIndex;
    let m;
    while ((m = re.exec(text)) !== null && results.length < limits.maxMatches) {
      if (exact && m.index !== runIndex) break; // prefix hit the regex rejects
      const byteIndex  = encoder.encode(text.slice(0, m.index)).length;
      results.push({ offset: byteIndex + offset, length: encoder.encode(m[0]).length });
      re.lastIndex = m.index + 1; // Move forward to find overlapping matches
      if (singleRun) break;
    }
    return results;
  };

  return { matcher: addOptionsToMatcher(matcher), literalPrefix, type: "regex", nocase, private: isPrivate };
}

function getRegexPrefix(pattern, nocase = false) {
  // Remove leading ^ if present
  pattern = pattern.replace(/^\^/, "");
  pattern = nocase ? pattern.toLowerCase() : pattern;

  // Match literal prefix before first meta pattern
  // const match = pattern.match(/^((?:\\.|[^\\[\]()|*+?{}.])+)/);
  // Match literal prefix: either escaped chars (\. \? etc) or non-special chars
  const match = pattern.match(/^((?:\\[^bBdDwWsSAZzGnrtfv0u]|[^\\[\]()|*+?{}.])+)/);
  if (!match || match.length < 2) return "";

  // Unescape hex sequences like \x41 → A
  let prefix = match[1].replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));

  // Unescape escaped characters like \. → .
  return prefix.replace(/\\(.)/g, "$1");
}

// ╭─────────────────────────────╮
// │ TEXT MATCHER GENERATOR      │
// ╰─────────────────────────────╯
function makeTextMatcher(text, opts) {
  const encoder = new TextEncoder();
  const patterns = [];

  // Default to ASCII if wide is not specified
  if (!opts.wide) opts.ascii = true;

  // Skip invalid combinations
  if (opts.base64 || opts.base64wide) {
    opts.nocase = false; // Disable nocase for conflicting base64 types
    opts.fullword = false; // Disable fullword for conflicting base64 types
    opts.xor = null; // Disable xor for conflicting base64 types
  }

  // Unescape YARA string escape sequences
  const unescapedText = text
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/\\\\/g, "\\")
    .replace(/\\"/g, '"')
    .replace(/\\'/g, "'");

  // Handle nocase by forcing to lower case
  const textVariants = opts.nocase ? [unescapedText.toLowerCase()] : [unescapedText];

  for (const variant of textVariants) {
    if (opts.base64 || opts.base64wide) {
      // When using base64/base64wide, generate patterns from the original text
      // in both ASCII and wide forms as needed
      if (opts.base64) {
        if (opts.ascii) {
          patterns.push(...yaraBase64Variants(variant, false).map((bytes) => ({ bytes, isWide: false })));
        }
        if (opts.wide) {
          patterns.push(...yaraBase64Variants(toWideBytes(variant), false).map((bytes) => ({ bytes, isWide: true })));
        }
      }
      if (opts.base64wide) {
        if (opts.ascii) {
          // base64wide returns Uint8Arrays when wide=true, so don't encode again
          patterns.push(...yaraBase64Variants(variant, true).map((bytes) => ({ bytes, isWide: true })));
        }
        if (opts.wide) {
          // base64wide returns Uint8Arrays when wide=true, so don't encode again
          patterns.push(...yaraBase64Variants(toWideBytes(variant), true).map((bytes) => ({ bytes, isWide: true })));
        }
      }
    } else {
      // Regular text patterns
      if (opts.ascii) {
        patterns.push({ bytes: encoder.encode(variant), isWide: false });
      }
      if (opts.wide) {
        patterns.push({ bytes: toWideBytes(variant), isWide: true });
      }
    }
  }

  const matcher = (data, offset = -1, exactIndex = -1) => {
    let matches = [];
    const singleRun = offset >= 0;
    // `exactIndex` (relative to the slice) restricts a single run to the candidate's own byte.
    const runIndex = exactIndex >= 0 ? exactIndex : -1;
    offset = offset < 0 ? 0 : offset;

    for (const { bytes, isWide } of patterns) {
      if (opts.xor) {
        const xorMatches = findXorMatches(data, bytes, opts.xor, opts.allowKey0, singleRun, runIndex);
        matches.push(...xorMatches.map((m) => ({ ...m, length: bytes.length, isWide })));
      } else {
        const plainMatches = findPlainMatches(data, bytes, opts.nocase, singleRun, runIndex);
        matches.push(...plainMatches.map((m) => ({ ...m, length: bytes.length, isWide })));
      }
    }

    if (opts.fullword) {
      matches = matches.filter((m) => isFullWordMatch(data, m.offset, m.length));
    }

    // Adjust the offsets for the original data if offset was specified
    matches.forEach((m) => {
      m.offset += offset;
    });

    return matches;
  };

  return { matcher: addOptionsToMatcher(matcher), patterns, type: "text", xor: opts.xor, nocase: opts.nocase, private: opts.private };
}

// ╭─────────────────────────────╮
// │ XOR-AWARE MATCHING          │
// ╰─────────────────────────────╯
function findXorMatches(data, pattern, keyRange, allowKey0 = true, singleRun = false, exactIndex = -1) {
  const [minKey, maxKey] = keyRange;
  const matches = [];
  const pLen = pattern.length;
  const dLen = data.length;
  const from = exactIndex >= 0 ? exactIndex : 0;
  if (pLen === 0 || pLen > dLen) return matches;

  for (let candidateKey = minKey; candidateKey <= maxKey; candidateKey++) {
    for (let i = from; i <= dLen - pLen; i++) {
      let ok = true;
      for (let j = 0; j < pLen; j++) {
        if ((data[i + j] ^ candidateKey) !== pattern[j]) {
          ok = false;
          break;
        }
      }
      if (ok) {
        // An exact run only accepts the requested offset; a later hit belongs to another candidate.
        if (exactIndex < 0 || i === exactIndex) matches.push({ offset: i, key: candidateKey });
        if (singleRun) break;
      }
    }
  }
  return matches;
}

// ╭─────────────────────────────╮
// │ PLAIN MATCHING              │
// ╰─────────────────────────────╯
function findPlainMatches(data, pattern, nocase = false, singleRun = false, exactIndex = -1) {
  const matches = [];
  const pLen = pattern.length;
  const dLen = data.length;
  const from = exactIndex >= 0 ? exactIndex : 0;
  outer: for (let i = from; i <= dLen - pLen; i++) {
    for (let j = 0; j < pLen; j++) {
      if ((nocase ? lowercaseByte(data[i + j]) : data[i + j]) !== pattern[j]) continue outer;
    }
    // An exact run only accepts the requested offset; a later hit belongs to another candidate.
    if (exactIndex < 0 || i === exactIndex) matches.push({ offset: i });
    if (singleRun) break;
  }
  return matches;
}

function lowercaseByte(b) {
  if (b >= 0x41 && b <= 0x5a) {
    return b + 0x20;
  }
  return b;
}

// ╭─────────────────────────────╮
// │ FULLWORD CHECK              │
// ╰─────────────────────────────╯
function isFullWordMatch(data, offset, length) {
  const isWordChar = (b) =>
    (b >= 0x30 && b <= 0x39) || // 0-9
    (b >= 0x41 && b <= 0x5a) || // A-Z
    (b >= 0x61 && b <= 0x7a); // a-z
  const before = offset === 0 || !isWordChar(data[offset - 1]);
  const after = offset + length >= data.length || !isWordChar(data[offset + length]);
  return before && after;
}

// ╭─────────────────────────────╮
// │ WIDE BYTES                  │
// ╰─────────────────────────────╯
function toWideBytes(text) {
  const buf = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    buf[i * 2] = code & 0xff;
    buf[i * 2 + 1] = code >> 8;
  }
  return buf;
}

// ╭─────────────────────────────╮
// │ PARSE XOR RANGE             │
// ╰─────────────────────────────╯
function parseXorRange(mods) {
  const m = mods.match(/xor(?:\((0x[0-9a-f]+|\d+)(?:-(0x[0-9a-f]+|\d+))?\))?/i);
  if (!m) return null;
  const [, start, end] = m;
  if (!start && !end) return [0, 255]; // YARA starts from 0 if no range specified

  let startVal = start ? parseInt(start, start.startsWith("0x") ? 16 : 10) : null;
  let endVal = end ? parseInt(end, end.startsWith("0x") ? 16 : 10) : null;

  if (startVal !== null && endVal === null) return [startVal, startVal];
  if (endVal !== null && startVal === null) return [endVal, endVal];

  return [startVal, endVal];
}

// ╭─────────────────────────────╮
// │ HEX MATCHER GENERATOR       │
// ╰─────────────────────────────╯

// Global constant for max jump range when not specified
const MAX_HEX_JUMP = 10000;

function makeHexMatcher(hexBody, mods, limits) {
  // Parse hex body into regex pattern
  let pattern = "";
  hexBody = hexBody?.toUpperCase().replace(/[^0-9A-F?~|()[\-\]]/g, "") || ""; // Trim invalid chars
  const parts = hexBody.match(/\[\d*(-\d*)?\]|\(.*\)|~?[0-9A-F?]{2}/g) || [];
  const isPrivate = /\bprivate\b/.test(mods);

  if (parts.length === 0) {
    // Empty pattern matches nothing
    const matcher = (data) => [];
    return { matcher, type: "hex", private: isPrivate };
  }

  for (const token of parts) {
    if (token.startsWith("[")) {
      // Jump: [N] or [N-M] or [N-] or [-M] or [-]
      const dashIndex = token.indexOf("-");
      if (dashIndex === -1) {
        // [N] - exact count
        const count = parseInt(token.slice(1, -1));
        pattern += `(?:[0-9A-F]{2}){${count}}`;
      } else {
        // [N-M] or [N-] or [-M] or [-] - range
        const match = /\[(\d*)-(\d*)\]/.exec(token);
        const min = parseInt(match[1]) || 0;
        const max = parseInt(match[2]) || MAX_HEX_JUMP;
        pattern += `(?:[0-9A-F]{2}){${min},${max}}`;
      }
    } else if (token.startsWith("(")) {
      // Group: (XX | ?X | ?? | ~XX | ~?X)
      pattern += convertNegationToRegex(token).replace(/\?/g, "[0-9A-F]");
    } else if (token.startsWith("~")) {
      // Negated byte: ~XX
      pattern += convertNegationToRegex(token);
    } else {
      // Wildcard: ?? or ?X or X?
      // Literals: XX
      pattern += token.replace(/\?/g, "[0-9A-F]");
    }
  }

  const regex = new RegExp(pattern, "g");

  const matcher = (data) => {
    // Convert UInt8Array to hex string; if string passed, assumes it is cached hex string
    const hexString = (typeof data === "string") ? data : Array.from(data)
      .map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
      .join("");

    const matches = [];
    let m;
    // Same shared-instance hazard as the regex matcher: `regex` lives as long as the matcher, so
    // reset before each run (the MAX_MATCHES cap can leave `lastIndex` mid-string).
    regex.lastIndex = 0;
    while ((m = regex.exec(hexString)) !== null && matches.length < limits.maxMatches) {
      // Convert hex string offset to byte offset
      if (m.index % 2 !== 0) { 
        // Skip to next aligned position to check
        regex.lastIndex = m.index + 1; 
        continue; 
      }
      // Ignoring as better to overmatch than undermatch
      // if (m[0].length % 2 !== 0) { 
      //   // Skip non-aligned length matches
      //   continue; 
      // }
      matches.push({ offset: m.index / 2, length: Math.ceil(m[0].length / 2) });
      regex.lastIndex = m.index + 2; // Move forward to find overlapping matches
    }
    return matches;
  };

  return { matcher, type: "hex", private: isPrivate };
}

// function addAllOverlappingMatches(regex, text, textIndex = 0, matches = [], indexStep = 1) {
//   if (!regex || !text || !matches) return;
//   const newRegex = new RegExp(regex.source, regex.flags.replace("g", ""));
//   text = text.slice(indexStep); // Start from next indexStep to check overlaps
//   let additionalOffset = indexStep;
//   let m;
//   while (text?.length > 0 && (m = newRegex.exec(text)) !== null) {
//     if (indexStep > 1 && (m.index % indexStep !== 0 || m[0].length % indexStep !== 0  )) { 
//       // Jump to next aligned position
//       const nextAlignedIndex = indexStep * Math.ceil(m.index / indexStep);
//       text = text.slice(nextAlignedIndex);
//       additionalOffset += nextAlignedIndex;
//       continue; 
//     } // Skip non-aligned matches
//     matches.push({ offset: (textIndex + m.index + additionalOffset) / indexStep, length: m[0].length / indexStep });
//     text = text.slice(m.index + indexStep);
//     additionalOffset += m.index + indexStep;
//   }
//   return matches;
// }

function convertNegationToRegex(token) {
  if (!token || !token.includes("~")) return token;
  const matches = token.split("~");
  let pattern = matches[0];
  for (let i = 1; i < matches.length; i++) {
    const nibbles = matches[i].slice(0, 2).split("");
    nibbles[0] = nibbles[0] === "?" ? "[0-9A-F]" : `${nibbles[0]}`;
    nibbles[1] = nibbles[1] === "?" ? "[0-9A-F]" : `${nibbles[1]}`;
    pattern += `(?!${nibbles[0]}${nibbles[1]})[0-9A-F]{2}${matches[i].slice(2)}`;
  }
  return pattern;
}

// ╭─────────────────────────────╮
// │ YARA BASE64 / BASE64WIDE    │
// ╰─────────────────────────────╯
function yaraBase64Variants(input, wide = false) {
  // Accept either string or Uint8Array (for when 'wide' modifier is applied first)
  const encoder = new TextEncoder();
  let bytes;
  if (typeof input === "string") {
    bytes = encoder.encode(input);
  } else {
    bytes = input; // Already Uint8Array from toWideBytes()
  }

  const variants = [];
  const dropCharsMap = [0, 2, 3];
  for (let offset = 0; offset < 3; offset++) {
    const padded = new Uint8Array(offset + bytes.length);
    padded.set(bytes, offset);
    let b64 = btoa(String.fromCharCode(...padded));
    const dropChars = dropCharsMap[offset];
    const trailing = (/=*$/.exec(b64 ?? [0]))[0].length;
    const b64string = b64.slice(dropChars, b64.length - (trailing ? trailing + 1 : 0));
    variants.push(wide ? toWideBytes(b64string) : encoder.encode(b64string));
  }

  return variants.filter((v) => v.length >= 1);
}
