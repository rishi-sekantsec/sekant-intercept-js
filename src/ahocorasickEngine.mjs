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

// Atoms are the fixed-size fragments stored in the automaton. Three bytes keeps the trie small
// while still producing specific enough candidates to avoid a verification flood.
const DEFAULT_ATOM_LENGTH = 3;

class Node {
  constructor() {
    this.children = new Map(); // byte (or char code) -> Node; numeric keys avoid per-byte strings
    this.fail = null; // failure link
    this.outputs = null; // matched atoms, allocated on demand
  }
}

const isAsciiLetter = (code) =>
  (code >= 0x61 && code <= 0x7a) || (code >= 0x41 && code <= 0x5a);

function generateCaseVariants(atom) {
  const variants = [atom];

  for (let i = 0; i < atom.length; i++) {
    const code = atom[i];
    if (!isAsciiLetter(code)) continue;

    const alternateCode = code >= 0x61 ? code - 0x20 : code + 0x20;
    const existingCount = variants.length;
    for (let j = 0; j < existingCount; j++) {
      const variant = variants[j].slice();
      variant[i] = alternateCode;
      variants.push(variant);
    }
  }

  return variants;
}

/**
 * Pick the atom window deterministically. More distinct bytes means a more selective atom (fewer
 * false candidates); zero bytes are common in binaries, and every ASCII letter doubles the case
 * variants a `nocase` atom needs, so both are penalized. Ties keep the earliest window.
 */
function chooseAtomOffset(bytes, atomLength, nocase) {
  const maxOffset = bytes.length - atomLength;
  const seen = new Int32Array(256);
  let stamp = 0;
  let bestOffset = 0;
  let bestScore = -Infinity;

  for (let offset = 0; offset <= maxOffset; offset++) {
    stamp += 1;
    let distinct = 0;
    let zeroes = 0;
    let letters = 0;

    for (let i = offset; i < offset + atomLength; i++) {
      const code = bytes[i];
      if (seen[code] !== stamp) {
        seen[code] = stamp;
        distinct += 1;
      }
      if (code === 0) zeroes += 1;
      else if (nocase && isAsciiLetter(code)) letters += 1;
    }

    const score = distinct * 8 - zeroes * 4 - letters * 2;
    if (score > bestScore) {
      bestScore = score;
      bestOffset = offset;
    }
  }

  return bestOffset;
}

const atomEncoder = new TextEncoder();

// Rule structure example:
// {
//   name: ruleName,
//   id: ruleId,
//   tags,
//   metadata,
//   strings,
//   condition,
// }

// Strings structure example:
// strings[varName] = {
//   definition: definition.trim(),
//   type,
//   matcher,
//   literalPrefix,      // for regex
//   patterns           // for text
// };

// Format for a trie output (one atom variant of one pattern):
// {
//   group,       // shared by every variant of one pattern, used to collapse duplicate hits
//   id,          // rule id
//   varName,     // string identifier
//   matcher,     // exact-position verifier for the pattern
//   atom,        // Uint8Array atom stored in the trie
//   atomOffset,  // atom position within the full pattern
//   atomLength,
//   length,      // full pattern length in bytes
//   xorKey,      // present for XOR variants
// }

export class AhoCorasick {
  constructor(rules) {
    this.root = new Node();
    this.groupCount = 0;
    this.lastOffsets = new Float64Array(0);
    this.addRules(rules);
  }

  addRules(rules) {
    // Collect one entry per underlying pattern; every atom variant derived from it shares a group,
    // so duplicate hits from case/XOR variants collapse into a single candidate.
    const entries = [];

    for (const rule of rules) {
      const { id, strings } = rule;
      for (const varName of Object.keys(strings)) {
        const strDef = strings[varName];

        if (strDef.type === "text") {
          for (const patternObj of strDef.patterns ?? []) {
            const bytes = patternObj.bytes;
            if (!bytes || bytes.length === 0) continue; // empty strings never match
            entries.push({
              group: this.groupCount++,
              id,
              varName,
              bytes,
              matcher: strDef.matcher,
              xor: strDef.xor ?? null,
              nocase: strDef.nocase === true,
            });
          }
        } else if (strDef.type === "regex" && strDef.literalPrefix) {
          const bytes = atomEncoder.encode(strDef.literalPrefix);
          if (bytes.length === 0) continue;
          entries.push({
            group: this.groupCount++,
            id,
            varName,
            bytes,
            matcher: strDef.matcher,
            xor: null,
            nocase: strDef.nocase === true,
          });
        }
      }
    }

    this.buildTrie(this.buildAtoms(entries));
    this.buildFailures();
  }

  buildAtoms(entries, atomLength = DEFAULT_ATOM_LENGTH) {
    const atoms = [];

    for (const entry of entries) {
      const bytes = entry.bytes;
      const length = bytes.length;
      const useWholePattern = length <= atomLength;
      const atomOffset = useWholePattern ? 0 : chooseAtomOffset(bytes, atomLength, entry.nocase);
      const usedAtomLength = useWholePattern ? length : atomLength;
      const atom = bytes.subarray(atomOffset, atomOffset + usedAtomLength);
      const base = {
        group: entry.group,
        id: entry.id,
        varName: entry.varName,
        matcher: entry.matcher,
        atomOffset,
        atomLength: usedAtomLength,
        length,
      };

      if (entry.nocase && !entry.xor) {
        for (const variant of generateCaseVariants(atom)) {
          atoms.push({ ...base, atom: variant });
        }
      } else if (entry.xor) {
        const [minKey, maxKey] = entry.xor;
        for (let key = minKey; key <= maxKey; key++) {
          const xoredAtom = new Uint8Array(usedAtomLength);
          for (let i = 0; i < usedAtomLength; i++) xoredAtom[i] = atom[i] ^ key;
          atoms.push({ ...base, atom: xoredAtom, xorKey: key });
        }
      } else {
        atoms.push({ ...base, atom });
      }
    }

    return atoms;
  }

  buildTrie(atoms) {
    for (const atomEntry of atoms) {
      let node = this.root;
      const atom = atomEntry.atom;
      for (let i = 0; i < atom.length; i++) {
        const code = atom[i];
        let child = node.children.get(code);
        if (child === undefined) {
          child = new Node();
          node.children.set(code, child);
        }
        node = child;
      }
      if (node.outputs === null) node.outputs = [atomEntry];
      else node.outputs.push(atomEntry);
    }
  }

  printTrie() {
    const traverse = (node, prefix) => {
      for (const [code, child] of node.children) {
        const childCodes = [...child.children.keys()].map((c) => String.fromCharCode(c));
        const count = child.outputs === null ? 0 : child.outputs.length;
        console.log(`${prefix}${String.fromCharCode(code)} (children: [${childCodes}]) (outputs: ${count})`);
        traverse(child, prefix + "  ");
      }
    };
    traverse(this.root, "");
  }

  buildFailures() {
    const queue = [];

    // Level 1 fail links = root
    for (const child of this.root.children.values()) {
      child.fail = this.root;
      queue.push(child);
    }

    for (let qi = 0; qi < queue.length; qi++) {
      const current = queue[qi];
      for (const [code, nextNode] of current.children) {
        queue.push(nextNode);

        let fail = current.fail;
        while (fail && !fail.children.has(code)) {
          fail = fail.fail;
        }
        nextNode.fail = fail ? fail.children.get(code) : this.root;

        // Merge output patterns from failure link
        const failOutputs = nextNode.fail.outputs;
        if (failOutputs !== null) {
          nextNode.outputs = nextNode.outputs === null
            ? failOutputs.slice()
            : nextNode.outputs.concat(failOutputs);
        }
      }
    }
  }

  resetGroupState() {
    if (this.lastOffsets.length < this.groupCount) {
      this.lastOffsets = new Float64Array(this.groupCount);
    }
    this.lastOffsets.fill(-1, 0, this.groupCount);
  }

  search(text) {
    // Atoms are byte sequences, so text handed in as a string is matched as its UTF-8 bytes.
    if (typeof text === "string") text = atomEncoder.encode(text);

    const results = [];
    const root = this.root;
    const lastOffsets = this.lastOffsets;
    const length = text.length;
    let node = root;

    this.resetGroupState();

    for (let i = 0; i < length; i++) {
      const code = text[i];

      // Follow failure links until we find a valid transition
      let next = node.children.get(code);
      while (next === undefined && node !== root) {
        node = node.fail;
        next = node.children.get(code);
      }

      node = next === undefined ? root : next;
      if (node === root) continue;

      // If this node outputs atoms, record candidate matches
      const outputs = node.outputs;
      if (outputs === null) continue;

      for (let k = 0; k < outputs.length; k++) {
        const output = outputs[k];
        const index = i - output.atomLength + 1;
        const offset = index - output.atomOffset;
        // Ignore matches that would start before or run past the end of the text
        if (offset < 0 || offset + output.length > length) continue;
        // Every atom variant of one pattern reaches a given offset at the same position, so a
        // non-increasing offset is always a duplicate of what this pattern already reported.
        if (offset <= lastOffsets[output.group]) continue;
        lastOffsets[output.group] = offset;

        results.push({
          id: output.id,
          varName: output.varName,
          offset,
          index,
          xorKey: output.xorKey,
          matcher: output.matcher,
        });
      }
    }

    return results;
  }
}
