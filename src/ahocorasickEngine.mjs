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

class Node {
  constructor() {
    this.children = {}; // edges
    this.fail = null; // failure link
    this.outputs = []; // matched patterns
    this.nocase = false;
  }
}

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

// Format for outputs node
// { id, varName }

export class AhoCorasick {
  constructor(rules) {
    this.root = new Node();
    this.addRules(rules);
  }

  addRules(rules) {
    // Add multiple rules to the AC automaton
    const patterns = [];

    const decoder = new TextDecoder();

    // console.log(JSON.stringify(rules));

    // Extract all the relevant patterns from the rules
    for (const rule of rules) {
      const { id, strings } = rule;
      for (const varName of Object.keys(strings)) {
        const strDef = strings[varName];
        if (strDef.type === "text") {
          for (const patternObj of strDef.patterns) {
            // patterns is an array of { bytes: Uint8Array }
            const bytes = patternObj.bytes;
            const patternStr = decoder.decode(bytes);
            patterns.push({ id, varName, pattern: patternStr, matcher: strDef.matcher, xor: strDef.xor, nocase: strDef.nocase });
          }
        } else if (strDef.type === "regex" && strDef.literalPrefix && strDef.literalPrefix.length > 0) {
          patterns.push({ id, varName, pattern: strDef.literalPrefix, matcher: strDef.matcher, nocase: strDef.nocase });
        }
      }
    }

    // Generate atoms per pattern for optimization ; modifies the patterns array
    this.generateAtoms(patterns);

    // console.log(`Aho-Corasick: Adding ${patterns.length} patterns to trie`);
    // console.log(patterns);

    this.buildTrie(patterns);
    this.buildFailures();
  }

  generateAtoms(patterns, atomLength = 3) {
    const xorPatterns = [];

    for (const p of patterns) {
      if (p.pattern.length <= atomLength) {
        p.atom = p.pattern;
        p.atomOffset = 0;
      } else {
        // Pick random offset to avoid bias
        const randomOffset = Math.floor(Math.random() * (p.pattern.length - atomLength));
        p.atom = p.pattern.slice(randomOffset, randomOffset + atomLength);
        p.atomOffset = randomOffset;
      }
      p.atomLength = p.atom.length;
      p.length = p.pattern.length;

      if (p.xor) {
        const [minKey, maxKey] = p.xor;

        const originalAtomChars = Array.from(p.atom);
        for (let key = minKey; key <= maxKey; key++) {
          const xorredAtom = originalAtomChars.map((c) => String.fromCharCode(c.charCodeAt(0) ^ key)).join("");
          if (key === minKey) {
            // Overwrite original pattern's atom with first XOR variant
            p.atom = xorredAtom;
            p.xorKey = key;
          } else {
            // Add additional patterns for other XOR variants
            xorPatterns.push({ ...p, atom: xorredAtom, xorKey: key });
          }
        }
      }
      // Memory optimization
      // delete p.pattern;
    }

    patterns.push(...xorPatterns);
  }

  buildTrie(patterns) {
    for (const p of patterns) {
      let node = this.root;
      // Iterate over code units (not code points) to handle surrogate pairs correctly
      for (let i = 0; i < p.atom.length; i++) {
        const ch = p.atom[i];
        if (!node.children[ch]) node.children[ch] = new Node();
        node = node.children[ch];
        node.nocase = p.nocase ?? false;
      }
      node.outputs.push(p);
    }
    // this.printTrie();
  }

  printTrie() {
    const traverse = (node, prefix) => {
      for (const [ch, child] of Object.entries(node.children)) {
        console.log(`${prefix}${ch} (nocase: ${child.nocase}) (children: [${Object.keys(child.children)}]) (outputs: ${child.outputs.length})`);
        traverse(child, prefix + "  ");
      }
    };
    traverse(this.root, "");
  }

  buildFailures() {
    const queue = [];
    // Level 1 fail links = root
    for (const ch in this.root.children) {
      const child = this.root.children[ch];
      child.fail = this.root;
      queue.push(child);
    }

    while (queue.length > 0) {
      const current = queue.shift();
      for (const [ch, nextNode] of Object.entries(current.children)) {
        queue.push(nextNode);

        // Compute failure link
        let fail = current.fail;
        while (fail && !fail.children[ch]) {
          fail = fail.fail;
        }
        nextNode.fail = fail ? fail.children[ch] : this.root;

        // Merge output patterns from failure link
        nextNode.outputs = nextNode.outputs.concat(nextNode.fail.outputs);
      }
    }
  }

  search(text) {
    const results = [];
    let node = this.root;

    for (let i = 0; i < text.length; i++) {
      const ch = text[i];

      // For Uint8Array, ch is a number (byte value); convert to character
      // For string, ch is already a character
      const charValue = typeof ch === "number" ? String.fromCharCode(ch) : ch;
      const lowerCharValue = charValue.toLowerCase();

      // console.log(`i=${i}, ch=${ch}, charValue='${charValue}', lower='${lowerCharValue}'`);

      // Follow failure links until we find a valid transition
      while (node && !(node.children[charValue] || (node.children[lowerCharValue] && node.children[lowerCharValue].nocase))) {
        node = node.fail;
      }

      if (!node) node = this.root;
      else {
        if (node.children[charValue]) node = node.children[charValue];
        else if (node.children[lowerCharValue]?.nocase) node = node.children[lowerCharValue];
        else node = this.root; // Should never happen due to the while loop above
      }

      // Do not report matches for root node (zero-length patterns)
      if (node === this.root) continue;

      // If this node outputs patterns, record matches
      for (const output of node.outputs) {
        const index = i - (output.atomLength || 0) + 1;
        if (index - output.atomOffset < 0) continue; // Ignore matches that would start before text begins
        if (index - output.atomOffset + output.length > text.length) continue; // Ignore matches that would exceed text length
        results.push({
          id: output.id,
          varName: output.varName,
          offset: index - output.atomOffset, // byte offset of the start of the full pattern
          index,
          xorKey: output.xorKey,
          matcher: output.matcher,
        });
      }
    }

    //  console.log(results.filter(r => r.varName === 'a9').length, " $a9 candidate matches");
    //  console.log(results.filter(r => r.varName === 'a9'));
    return results;
  }
}
