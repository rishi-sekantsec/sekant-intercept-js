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


// Search window for a single-run matcher call (literal-prefixed regexes), mirroring libyara's
// YR_RE_SCAN_LIMIT (4096). Full-buffer scans are unbounded, and text verification compares bytes
// at the candidate offset directly, so it needs no window.
const MAX_RE_SCAN_LIMIT = 4096;
export const MAX_MATCHES = 100;
const DEFAULT_MATCH_LIMITS = { maxMatches: MAX_MATCHES };

/**
 * Extract Intercept-only `reject(name, ...)` and `rejectRECapture(name, ...)` modifiers from a
 * definition's modifier text.
 *
 * Both forms are matched in one pass so each name stays bound to the buffer its modifier selects:
 * `reject` passes the full match, `rejectRECapture` passes capture group 1 (falling back to the
 * full match when the pattern has no participating group). The optional group is required rather
 * than a `reject|rejectRECapture` alternation, which would match `reject` first and then fail to
 * match the `(`.
 *
 * Names are captured verbatim: YARA identifiers are case-sensitive, so lowercasing the modifier
 * text before extraction would break `reject(MyFilter)`.
 */
function extractRejectRules(modifiers) {
  const reject = [];
  const rejectCapture = [];

  if (!modifiers) return { reject, rejectCapture, modifiers: modifiers ?? "" };

  const pattern = /\breject(RECapture)?\s*\(([^)]*)\)/gi;
  let match;
  while ((match = pattern.exec(modifiers)) !== null) {
    const target = match[1] ? rejectCapture : reject;
    for (const candidate of match[2].split(",")) {
      const name = candidate.trim();
      if (name && !target.includes(name)) target.push(name);
    }
  }

  return {
    reject,
    rejectCapture,
    modifiers: modifiers.replace(/\breject(RECapture)?\s*\([^)]*\)/gi, " "),
  };
}

// `d` (hasIndices) supplies capture positions. It is never user-controlled: rule flags are
// filtered down to `s`/`i`, and this flag is added only when capture output is requested. If an
// engine lacks it, values are still reported and positions fall back to null.
const SUPPORTS_INDICES = (() => {
  try {
    new RegExp("", "d");
    return true;
  } catch {
    return false;
  }
})();

/** Byte offset of every UTF-16 index in `text`; lets positions stay O(1) once built. */
function buildByteOffsets(text) {
  const byteOf = new Uint32Array(text.length + 1);
  let bytes = 0;

  for (let i = 0; i < text.length; i++) {
    byteOf[i] = bytes;
    const codePoint = text.codePointAt(i);
    bytes += codePoint < 0x80 ? 1 : codePoint < 0x800 ? 2 : codePoint < 0x10000 ? 3 : 4;
    if (codePoint > 0xffff) {
      byteOf[i + 1] = bytes;
      i += 1;
    }
  }

  byteOf[text.length] = bytes;
  return byteOf;
}

/**
 * Name of the first capture group, so the numbered entry can carry the name JS exposes only through
 * `match.groups`. Scans the pattern once, skipping escapes, character classes, and non-capturing
 * groups (`(?:`, lookarounds).
 */
function firstCaptureGroupName(pattern) {
  let inClass = false;

  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];

    if (char === "\\") {
      i += 1;
      continue;
    }
    if (inClass) {
      if (char === "]") inClass = false;
      continue;
    }
    if (char === "[") {
      inClass = true;
      continue;
    }
    if (char !== "(") continue;

    if (pattern[i + 1] !== "?") return undefined;

    const isNamed = pattern[i + 2] === "<" && pattern[i + 3] !== "=" && pattern[i + 3] !== "!";
    if (!isNamed) continue; // (?:, (?=, (?!, (?<=, (?<!

    const end = pattern.indexOf(">", i + 3);
    return end === -1 ? undefined : pattern.slice(i + 3, end);
  }

  return undefined;
}

/**
 * Compile a YARA-like string definition into a matcher function.
 * Supports: text, wide, ascii, xor, base64/base64wide, regex, hex, fullword, nocase
 * @param {Object} [limits] - Shared `{ maxMatches }` object; read live on every match run
 * @param {Object} [options] - `{ includeCaptures }`; capture offsets are regex-only
 */
export function compileYaraLike(definition, limits = DEFAULT_MATCH_LIMITS, options = {}) {
  definition = definition.trim();

  const isRegex = definition.startsWith("/");
  const isHex = definition.startsWith("{");
  const quoteMatch = definition.match(/^"(.*)"(.*)$/);

  if (isRegex) {
    return makeRegexMatcher(definition, limits, options);
  } else if (isHex) {
    const mods = definition.slice(definition.lastIndexOf("}") + 1);
    return makeHexMatcher(definition.slice(1, definition.lastIndexOf("}")).trim(), mods, limits);
  } else if (quoteMatch) {
    const [, text, modsRaw] = quoteMatch;
    const { reject, rejectCapture, modifiers: modsWithoutReject } = extractRejectRules(modsRaw);
    const mods = modsWithoutReject.toLowerCase();

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
      reject,
      rejectCapture,
    };

    return makeTextMatcher(text, opts);
  }

  throw new Error("Unsupported definition: " + definition);
}

function addOptionsToMatcher(matcher, verifyAt) {
  // Public contract: `offset < 0` scans the whole buffer, otherwise the search starts at `offset`
  // and a single run returns at most one match per pattern.
  const scan = (data, offset = -1) => matcher(data, offset, -1);

  // Aho-Corasick candidates ask "is there a match starting exactly here?", which a forward scan
  // cannot answer without also returning a neighbouring occurrence. Types with a direct
  // implementation pass `verifyAt`; `hint` carries the candidate's XOR key so no key search is
  // needed.
  scan.verifyAt = verifyAt ?? ((data, offset) => matcher(data, offset, offset));
  return scan;
}

// ╭─────────────────────────────╮
// │ REGEX MATCHER               │
// ╰─────────────────────────────╯
const textDecoder = new TextDecoder();

// Decoded views of scanned buffers, so a scan with many Aho-Corasick candidates decodes the
// buffer once instead of once per candidate.
const decodedBuffers = new WeakMap();
const asciiBuffers = new WeakMap();

/**
 * True when every byte is ASCII, which guarantees that byte offsets and decoded character indices
 * coincide. Purely binary buffers fail this on the first high byte, so they never pay for a
 * whole-buffer decode they cannot use.
 */
function isAsciiBuffer(data) {
  let ascii = asciiBuffers.get(data);
  if (ascii === undefined) {
    ascii = true;
    for (let i = 0; i < data.length; i++) {
      if (data[i] >= 0x80) {
        ascii = false;
        break;
      }
    }
    asciiBuffers.set(data, ascii);
  }
  return ascii;
}

function makeDecoded(text, byteLength) {
  return {
    text,
    // One code unit per byte means byte offsets and character indices are interchangeable.
    identity: text.length === byteLength,
    byteOf: null,
  };
}

function getDecodedBuffer(data) {
  let decoded = decodedBuffers.get(data);
  if (decoded === undefined) {
    decoded = makeDecoded(textDecoder.decode(data), data.length);
    decodedBuffers.set(data, decoded);
  }
  return decoded;
}

/**
 * Decodes the bytes from `offset` onward. Candidates are byte offsets, so verifying inside a
 * window that starts at the candidate keeps the match anchored to those bytes even when the
 * buffer is not valid UTF-8 (where a decoded offset would not line up with a byte offset).
 */
function decodeWindow(data, offset) {
  const end = Math.min(data.length, offset + MAX_RE_SCAN_LIMIT);
  return makeDecoded(textDecoder.decode(data.subarray(offset, end)), end - offset);
}

/** Lazily builds the char-index -> byte-offset table for buffers that are not one-to-one. */
function byteOffsetsOf(decoded) {
  if (!decoded.identity && decoded.byteOf === null) {
    decoded.byteOf = buildByteOffsets(decoded.text);
  }
  return decoded;
}

function byteAt(decoded, charIndex) {
  return decoded.identity ? charIndex : byteOffsetsOf(decoded).byteOf[charIndex];
}

function makeRegexMatcher(definition, limits, options = {}) {
  const lastSlash = definition.lastIndexOf("/");
  const suffix = definition.slice(lastSlash + 1);
  const { reject, rejectCapture, modifiers } = extractRejectRules(suffix);
  const wantsCapture = rejectCapture.length > 0;
  // `includeCaptures` is the only switch for capture output. It needs no regex flag: `exec` already
  // materializes every group, so reading group 1 back is free.
  const wantsCaptureOutput = options.includeCaptures === true;
  const wantsIndices = wantsCaptureOutput && SUPPORTS_INDICES;
  const mods = modifiers.toLowerCase();
  // Flags are only valid immediately after the closing slash; space-separated words after that are
  // modifiers. YARA treats `/foo/i` and `/foo/ nocase` as equivalent.
  const regexFlags = mods.match(/^([a-z]*)/)?.[1] ?? "";
  const isPrivate = /\bprivate\b/.test(mods);
  const pattern = definition.slice(1, lastSlash);
  const nocase = regexFlags.includes("i") || /\bnocase\b/.test(mods);
  const commonFlags =
    (regexFlags.includes("s") ? "s" : "") + (nocase ? "i" : "") + (wantsIndices ? "d" : "");
  const literalPrefix = getRegexPrefix(pattern, nocase);
  const firstGroupName = wantsCaptureOutput ? firstCaptureGroupName(pattern) : undefined;
  const re = new RegExp(pattern, "g" + commonFlags);
  // Sticky twin answers "does a match start exactly at this character?".
  const reAt = new RegExp(pattern, "y" + commonFlags);

  /** Builds a match record; `base` is the byte offset the decoded text starts at. */
  const buildEntry = (m, decoded, base = 0) => {
    const startByte = base + byteAt(decoded, m.index);
    const entry = {
      offset: startByte,
      length: base + byteAt(decoded, m.index + m[0].length) - startByte,
    };
    // The reject gate needs only the capture *value*, so no indices flag is involved. Absent,
    // non-participating, and empty groups all fall back to the full match.
    if (wantsCapture && typeof m[1] === "string" && m[1] !== "") {
      Object.defineProperty(entry, "capture", { value: m[1], enumerable: false });
    }
    // Capture output carries only group 1 — the group rejectRECapture uses — so the other
    // groups' substrings become collectable as soon as the iteration ends.
    if (wantsCaptureOutput) {
      if (m.length > 1) {
        const capture =
          firstGroupName === undefined
            ? { index: 1, value: typeof m[1] === "string" ? m[1] : null }
            : { index: 1, name: firstGroupName, value: typeof m[1] === "string" ? m[1] : null };

        const span = wantsIndices ? m.indices?.[1] : null;
        if (span) {
          const startByte = base + byteAt(decoded, span[0]);
          capture.offset = startByte;
          capture.length = base + byteAt(decoded, span[1]) - startByte;
        } else {
          capture.offset = null;
          capture.length = null;
        }

        entry.captures = [capture];
      } else {
        entry.captures = [];
      }
    }
    return entry;
  };

  // `re`/`reAt` outlive a call: they run once per Aho-Corasick candidate plus once per full scan,
  // and an early `break` (or the MAX_MATCHES cap) leaves `lastIndex` mid-text. Position them
  // explicitly on entry instead of inheriting the previous run's position.

  /** Candidates ask "is there a match starting exactly at this byte offset?". */
  const verifyAt = (data, offset) => {
    if (isAsciiBuffer(data)) {
      const decoded = getDecodedBuffer(data);
      reAt.lastIndex = offset;
      const m = reAt.exec(decoded.text);
      return m === null ? [] : [buildEntry(m, decoded)];
    }

    // Non-ASCII: a decoded index is not the candidate's byte offset, so verify inside the
    // candidate's own bytes.
    const window = decodeWindow(data, offset);
    reAt.lastIndex = 0;
    const m = reAt.exec(window.text);
    return m === null ? [] : [buildEntry(m, window, offset)];
  };

  /** Single run from `offset`: at most one match, bounded by the verification window. */
  const firstMatchFrom = (data, offset) => {
    if (isAsciiBuffer(data)) {
      const decoded = getDecodedBuffer(data);
      const limit = offset + MAX_RE_SCAN_LIMIT;
      re.lastIndex = offset;
      const m = re.exec(decoded.text);
      return m === null || m.index > limit ? [] : [buildEntry(m, decoded)];
    }

    const window = decodeWindow(data, offset);
    re.lastIndex = 0;
    const m = re.exec(window.text);
    return m === null ? [] : [buildEntry(m, window, offset)];
  };

  /** Full-buffer scan: overlapping matches, capped by the shared match limit. */
  const scanAll = (data) => {
    const decoded = getDecodedBuffer(data);
    const results = [];
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(decoded.text)) !== null && results.length < limits.maxMatches) {
      results.push(buildEntry(m, decoded));
      re.lastIndex = m.index + 1; // Move forward to find overlapping matches
    }
    return results;
  };

  const matcher = (data, offset = -1, exactIndex = -1) => {
    if (exactIndex >= 0) return verifyAt(data, exactIndex);
    return offset < 0 ? scanAll(data) : firstMatchFrom(data, offset);
  };

  return { matcher: addOptionsToMatcher(matcher, verifyAt), literalPrefix, type: "regex", nocase, private: isPrivate, reject, rejectCapture };
}

function getRegexPrefix(pattern, nocase = false) {
  // `^`/`$` anchor to the buffer, so a buffer-wide scan is the only sound way to honour them.
  if (pattern.startsWith("^")) return "";

  const haystack = nocase ? pattern.toLowerCase() : pattern;

  // Match literal prefix: either escaped chars (\. \? etc) or non-special chars
  const match = haystack.match(/^((?:\\[^bBdDwWsSAZzGnrtfv0u]|[^\\[\]()|*+?{}.^$])+)/);
  if (!match || match.length < 2) return "";

  let literal = match[1];
  const following = haystack.slice(literal.length);

  // An anchor right after the literal is buffer-relative, or unreachable mid-pattern.
  if (following.startsWith("$") || following.startsWith("^")) return "";

  // A trailing alternation means the literal is one branch among several: it is not a prefix of
  // every match, so the whole buffer has to be scanned.
  if (following.startsWith("|")) return "";

  // `https?`, `abc*` and `abc{0,2}` make the last literal character optional.
  if (/^[?*]/.test(following) || /^\{0[,}]/.test(following)) {
    literal = literal.slice(0, -1);
  }

  // Unescape hex sequences like \x41 → A
  let prefix = literal.replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));

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
    const singleRun = offset >= 0;
    const start = offset < 0 ? 0 : offset;
    const end = offset < 0 ? data.length : Math.min(data.length, offset + MAX_RE_SCAN_LIMIT);
    let matches = [];

    for (const { bytes, isWide } of patterns) {
      const found = opts.xor
        ? findXorMatches(data, bytes, opts.xor, opts.allowKey0, start, end, singleRun, exactIndex)
        : findPlainMatches(data, bytes, opts.nocase, start, end, singleRun, exactIndex);
      matches.push(...found.map((m) => ({ ...m, length: bytes.length, isWide })));
    }

    if (opts.fullword) {
      matches = matches.filter((m) => isFullWordMatch(data, m.offset, m.length));
    }

    return matches;
  };

  /**
   * Exact-position verification. Aho-Corasick already located the literal, so this only has to
   * compare the pattern's bytes at that offset: no window slice and no forward rescan.
   */
  const verifyAt = (data, offset, hint) => {
    const xorKey = hint === undefined ? undefined : hint.xorKey;
    // An XOR candidate without its key needs the key search after all.
    if (opts.xor && xorKey === undefined) return matcher(data, offset, offset);

    const matches = [];
    for (const { bytes, isWide } of patterns) {
      if (bytes.length === 0 || offset + bytes.length > data.length) continue;
      if (opts.xor) {
        if (!matchXorAt(data, offset, bytes, xorKey)) continue;
        matches.push({ offset, key: xorKey, length: bytes.length, isWide });
      } else if (matchPlainAt(data, offset, bytes, opts.nocase)) {
        matches.push({ offset, length: bytes.length, isWide });
      }
    }

    return opts.fullword
      ? matches.filter((m) => isFullWordMatch(data, m.offset, m.length))
      : matches;
  };

  return { matcher: addOptionsToMatcher(matcher, verifyAt), patterns, type: "text", xor: opts.xor, nocase: opts.nocase, private: opts.private, reject: opts.reject ?? [], rejectCapture: opts.rejectCapture ?? [] };
}

// ╭─────────────────────────────╮
// │ XOR-AWARE MATCHING          │
// ╰─────────────────────────────╯
function findXorMatches(data, pattern, keyRange, allowKey0 = true, start = 0, end = data.length, singleRun = false, exactIndex = -1) {
  const [minKey, maxKey] = keyRange;
  const matches = [];
  const pLen = pattern.length;
  if (pLen === 0 || pLen > data.length) return matches;

  // An exact run only accepts the requested offset, which is a single comparison per key.
  if (exactIndex >= 0) {
    for (let candidateKey = minKey; candidateKey <= maxKey; candidateKey++) {
      if (matchXorAt(data, exactIndex, pattern, candidateKey)) matches.push({ offset: exactIndex, key: candidateKey });
    }
    return matches;
  }

  for (let candidateKey = minKey; candidateKey <= maxKey; candidateKey++) {
    for (let i = start; i + pLen <= end; i++) {
      if (matchXorAt(data, i, pattern, candidateKey)) {
        matches.push({ offset: i, key: candidateKey });
        if (singleRun) break;
      }
    }
  }
  return matches;
}

// ╭─────────────────────────────╮
// │ PLAIN MATCHING              │
// ╰─────────────────────────────╯
function findPlainMatches(data, pattern, nocase = false, start = 0, end = data.length, singleRun = false, exactIndex = -1) {
  const matches = [];
  const pLen = pattern.length;
  if (pLen > data.length) return matches;

  // An exact run only accepts the requested offset, which is a single comparison.
  if (exactIndex >= 0) {
    if (matchPlainAt(data, exactIndex, pattern, nocase)) matches.push({ offset: exactIndex });
    return matches;
  }

  for (let i = start; i + pLen <= end; i++) {
    if (matchPlainAt(data, i, pattern, nocase)) {
      matches.push({ offset: i });
      if (singleRun) break;
    }
  }
  return matches;
}

/** Compares a literal pattern against `data` starting exactly at `offset`. */
function matchPlainAt(data, offset, pattern, nocase) {
  const pLen = pattern.length;
  if (offset + pLen > data.length) return false;

  for (let j = 0; j < pLen; j++) {
    const byte = data[offset + j];
    if ((nocase ? lowercaseByte(byte) : byte) !== pattern[j]) return false;
  }
  return true;
}

/** Compares a literal pattern against `data` after applying a single-byte XOR key. */
function matchXorAt(data, offset, pattern, key) {
  const pLen = pattern.length;
  if (offset + pLen > data.length) return false;

  for (let j = 0; j < pLen; j++) {
    if ((data[offset + j] ^ key) !== pattern[j]) return false;
  }
  return true;
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
  const { reject, rejectCapture, modifiers } = extractRejectRules(mods);
  const isPrivate = /\bprivate\b/.test(modifiers);

  if (parts.length === 0) {
    // Empty pattern matches nothing
    const matcher = (data) => [];
    return { matcher, type: "hex", private: isPrivate, reject, rejectCapture };
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

  return { matcher, type: "hex", private: isPrivate, reject, rejectCapture };
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
