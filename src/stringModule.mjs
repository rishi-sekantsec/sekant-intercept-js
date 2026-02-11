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

export const string = {
  to_int: (s, base = 10) => {
    if (typeof s !== "string" && !(s instanceof String)) {
      throw new Error("to_int() first argument must be a string");
      // return 0; // Match YARA behavior
    }
    if (s.startsWith("0x") || s.startsWith("0X")) {
      base = 16;
      s = s.slice(2);
    } else if (s.startsWith("O") || s.startsWith("o")) {
      base = 8;
      s = s.slice(1);
    }
    const result = parseInt(s, base);
    if (isNaN(result)) {
      throw new Error(`to_int() could not convert string '${s}' to integer`);
      // return 0; // Match YARA behavior
    }
    return result;
  },
  length: (s) => {
    if (typeof s === "string" || s instanceof String) {
      return s.length;
    }
    return 0;
  },
};
