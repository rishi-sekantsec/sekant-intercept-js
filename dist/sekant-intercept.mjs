var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// node_modules/spark-md5/spark-md5.js
var require_spark_md5 = __commonJS({
  "node_modules/spark-md5/spark-md5.js"(exports, module) {
    (function(factory) {
      if (typeof exports === "object") {
        module.exports = factory();
      } else if (typeof define === "function" && define.amd) {
        define(factory);
      } else {
        var glob;
        try {
          glob = window;
        } catch (e) {
          glob = self;
        }
        glob.SparkMD5 = factory();
      }
    })(function(undefined2) {
      "use strict";
      var add32 = function(a, b) {
        return a + b & 4294967295;
      }, hex_chr = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"];
      function cmn(q, a, b, x, s, t) {
        a = add32(add32(a, q), add32(x, t));
        return add32(a << s | a >>> 32 - s, b);
      }
      function md5cycle(x, k) {
        var a = x[0], b = x[1], c = x[2], d = x[3];
        a += (b & c | ~b & d) + k[0] - 680876936 | 0;
        a = (a << 7 | a >>> 25) + b | 0;
        d += (a & b | ~a & c) + k[1] - 389564586 | 0;
        d = (d << 12 | d >>> 20) + a | 0;
        c += (d & a | ~d & b) + k[2] + 606105819 | 0;
        c = (c << 17 | c >>> 15) + d | 0;
        b += (c & d | ~c & a) + k[3] - 1044525330 | 0;
        b = (b << 22 | b >>> 10) + c | 0;
        a += (b & c | ~b & d) + k[4] - 176418897 | 0;
        a = (a << 7 | a >>> 25) + b | 0;
        d += (a & b | ~a & c) + k[5] + 1200080426 | 0;
        d = (d << 12 | d >>> 20) + a | 0;
        c += (d & a | ~d & b) + k[6] - 1473231341 | 0;
        c = (c << 17 | c >>> 15) + d | 0;
        b += (c & d | ~c & a) + k[7] - 45705983 | 0;
        b = (b << 22 | b >>> 10) + c | 0;
        a += (b & c | ~b & d) + k[8] + 1770035416 | 0;
        a = (a << 7 | a >>> 25) + b | 0;
        d += (a & b | ~a & c) + k[9] - 1958414417 | 0;
        d = (d << 12 | d >>> 20) + a | 0;
        c += (d & a | ~d & b) + k[10] - 42063 | 0;
        c = (c << 17 | c >>> 15) + d | 0;
        b += (c & d | ~c & a) + k[11] - 1990404162 | 0;
        b = (b << 22 | b >>> 10) + c | 0;
        a += (b & c | ~b & d) + k[12] + 1804603682 | 0;
        a = (a << 7 | a >>> 25) + b | 0;
        d += (a & b | ~a & c) + k[13] - 40341101 | 0;
        d = (d << 12 | d >>> 20) + a | 0;
        c += (d & a | ~d & b) + k[14] - 1502002290 | 0;
        c = (c << 17 | c >>> 15) + d | 0;
        b += (c & d | ~c & a) + k[15] + 1236535329 | 0;
        b = (b << 22 | b >>> 10) + c | 0;
        a += (b & d | c & ~d) + k[1] - 165796510 | 0;
        a = (a << 5 | a >>> 27) + b | 0;
        d += (a & c | b & ~c) + k[6] - 1069501632 | 0;
        d = (d << 9 | d >>> 23) + a | 0;
        c += (d & b | a & ~b) + k[11] + 643717713 | 0;
        c = (c << 14 | c >>> 18) + d | 0;
        b += (c & a | d & ~a) + k[0] - 373897302 | 0;
        b = (b << 20 | b >>> 12) + c | 0;
        a += (b & d | c & ~d) + k[5] - 701558691 | 0;
        a = (a << 5 | a >>> 27) + b | 0;
        d += (a & c | b & ~c) + k[10] + 38016083 | 0;
        d = (d << 9 | d >>> 23) + a | 0;
        c += (d & b | a & ~b) + k[15] - 660478335 | 0;
        c = (c << 14 | c >>> 18) + d | 0;
        b += (c & a | d & ~a) + k[4] - 405537848 | 0;
        b = (b << 20 | b >>> 12) + c | 0;
        a += (b & d | c & ~d) + k[9] + 568446438 | 0;
        a = (a << 5 | a >>> 27) + b | 0;
        d += (a & c | b & ~c) + k[14] - 1019803690 | 0;
        d = (d << 9 | d >>> 23) + a | 0;
        c += (d & b | a & ~b) + k[3] - 187363961 | 0;
        c = (c << 14 | c >>> 18) + d | 0;
        b += (c & a | d & ~a) + k[8] + 1163531501 | 0;
        b = (b << 20 | b >>> 12) + c | 0;
        a += (b & d | c & ~d) + k[13] - 1444681467 | 0;
        a = (a << 5 | a >>> 27) + b | 0;
        d += (a & c | b & ~c) + k[2] - 51403784 | 0;
        d = (d << 9 | d >>> 23) + a | 0;
        c += (d & b | a & ~b) + k[7] + 1735328473 | 0;
        c = (c << 14 | c >>> 18) + d | 0;
        b += (c & a | d & ~a) + k[12] - 1926607734 | 0;
        b = (b << 20 | b >>> 12) + c | 0;
        a += (b ^ c ^ d) + k[5] - 378558 | 0;
        a = (a << 4 | a >>> 28) + b | 0;
        d += (a ^ b ^ c) + k[8] - 2022574463 | 0;
        d = (d << 11 | d >>> 21) + a | 0;
        c += (d ^ a ^ b) + k[11] + 1839030562 | 0;
        c = (c << 16 | c >>> 16) + d | 0;
        b += (c ^ d ^ a) + k[14] - 35309556 | 0;
        b = (b << 23 | b >>> 9) + c | 0;
        a += (b ^ c ^ d) + k[1] - 1530992060 | 0;
        a = (a << 4 | a >>> 28) + b | 0;
        d += (a ^ b ^ c) + k[4] + 1272893353 | 0;
        d = (d << 11 | d >>> 21) + a | 0;
        c += (d ^ a ^ b) + k[7] - 155497632 | 0;
        c = (c << 16 | c >>> 16) + d | 0;
        b += (c ^ d ^ a) + k[10] - 1094730640 | 0;
        b = (b << 23 | b >>> 9) + c | 0;
        a += (b ^ c ^ d) + k[13] + 681279174 | 0;
        a = (a << 4 | a >>> 28) + b | 0;
        d += (a ^ b ^ c) + k[0] - 358537222 | 0;
        d = (d << 11 | d >>> 21) + a | 0;
        c += (d ^ a ^ b) + k[3] - 722521979 | 0;
        c = (c << 16 | c >>> 16) + d | 0;
        b += (c ^ d ^ a) + k[6] + 76029189 | 0;
        b = (b << 23 | b >>> 9) + c | 0;
        a += (b ^ c ^ d) + k[9] - 640364487 | 0;
        a = (a << 4 | a >>> 28) + b | 0;
        d += (a ^ b ^ c) + k[12] - 421815835 | 0;
        d = (d << 11 | d >>> 21) + a | 0;
        c += (d ^ a ^ b) + k[15] + 530742520 | 0;
        c = (c << 16 | c >>> 16) + d | 0;
        b += (c ^ d ^ a) + k[2] - 995338651 | 0;
        b = (b << 23 | b >>> 9) + c | 0;
        a += (c ^ (b | ~d)) + k[0] - 198630844 | 0;
        a = (a << 6 | a >>> 26) + b | 0;
        d += (b ^ (a | ~c)) + k[7] + 1126891415 | 0;
        d = (d << 10 | d >>> 22) + a | 0;
        c += (a ^ (d | ~b)) + k[14] - 1416354905 | 0;
        c = (c << 15 | c >>> 17) + d | 0;
        b += (d ^ (c | ~a)) + k[5] - 57434055 | 0;
        b = (b << 21 | b >>> 11) + c | 0;
        a += (c ^ (b | ~d)) + k[12] + 1700485571 | 0;
        a = (a << 6 | a >>> 26) + b | 0;
        d += (b ^ (a | ~c)) + k[3] - 1894986606 | 0;
        d = (d << 10 | d >>> 22) + a | 0;
        c += (a ^ (d | ~b)) + k[10] - 1051523 | 0;
        c = (c << 15 | c >>> 17) + d | 0;
        b += (d ^ (c | ~a)) + k[1] - 2054922799 | 0;
        b = (b << 21 | b >>> 11) + c | 0;
        a += (c ^ (b | ~d)) + k[8] + 1873313359 | 0;
        a = (a << 6 | a >>> 26) + b | 0;
        d += (b ^ (a | ~c)) + k[15] - 30611744 | 0;
        d = (d << 10 | d >>> 22) + a | 0;
        c += (a ^ (d | ~b)) + k[6] - 1560198380 | 0;
        c = (c << 15 | c >>> 17) + d | 0;
        b += (d ^ (c | ~a)) + k[13] + 1309151649 | 0;
        b = (b << 21 | b >>> 11) + c | 0;
        a += (c ^ (b | ~d)) + k[4] - 145523070 | 0;
        a = (a << 6 | a >>> 26) + b | 0;
        d += (b ^ (a | ~c)) + k[11] - 1120210379 | 0;
        d = (d << 10 | d >>> 22) + a | 0;
        c += (a ^ (d | ~b)) + k[2] + 718787259 | 0;
        c = (c << 15 | c >>> 17) + d | 0;
        b += (d ^ (c | ~a)) + k[9] - 343485551 | 0;
        b = (b << 21 | b >>> 11) + c | 0;
        x[0] = a + x[0] | 0;
        x[1] = b + x[1] | 0;
        x[2] = c + x[2] | 0;
        x[3] = d + x[3] | 0;
      }
      function md5blk(s) {
        var md5blks = [], i;
        for (i = 0; i < 64; i += 4) {
          md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24);
        }
        return md5blks;
      }
      function md5blk_array(a) {
        var md5blks = [], i;
        for (i = 0; i < 64; i += 4) {
          md5blks[i >> 2] = a[i] + (a[i + 1] << 8) + (a[i + 2] << 16) + (a[i + 3] << 24);
        }
        return md5blks;
      }
      function md51(s) {
        var n = s.length, state = [1732584193, -271733879, -1732584194, 271733878], i, length, tail, tmp, lo, hi;
        for (i = 64; i <= n; i += 64) {
          md5cycle(state, md5blk(s.substring(i - 64, i)));
        }
        s = s.substring(i - 64);
        length = s.length;
        tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < length; i += 1) {
          tail[i >> 2] |= s.charCodeAt(i) << (i % 4 << 3);
        }
        tail[i >> 2] |= 128 << (i % 4 << 3);
        if (i > 55) {
          md5cycle(state, tail);
          for (i = 0; i < 16; i += 1) {
            tail[i] = 0;
          }
        }
        tmp = n * 8;
        tmp = tmp.toString(16).match(/(.*?)(.{0,8})$/);
        lo = parseInt(tmp[2], 16);
        hi = parseInt(tmp[1], 16) || 0;
        tail[14] = lo;
        tail[15] = hi;
        md5cycle(state, tail);
        return state;
      }
      function md51_array(a) {
        var n = a.length, state = [1732584193, -271733879, -1732584194, 271733878], i, length, tail, tmp, lo, hi;
        for (i = 64; i <= n; i += 64) {
          md5cycle(state, md5blk_array(a.subarray(i - 64, i)));
        }
        a = i - 64 < n ? a.subarray(i - 64) : new Uint8Array(0);
        length = a.length;
        tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < length; i += 1) {
          tail[i >> 2] |= a[i] << (i % 4 << 3);
        }
        tail[i >> 2] |= 128 << (i % 4 << 3);
        if (i > 55) {
          md5cycle(state, tail);
          for (i = 0; i < 16; i += 1) {
            tail[i] = 0;
          }
        }
        tmp = n * 8;
        tmp = tmp.toString(16).match(/(.*?)(.{0,8})$/);
        lo = parseInt(tmp[2], 16);
        hi = parseInt(tmp[1], 16) || 0;
        tail[14] = lo;
        tail[15] = hi;
        md5cycle(state, tail);
        return state;
      }
      function rhex(n) {
        var s = "", j;
        for (j = 0; j < 4; j += 1) {
          s += hex_chr[n >> j * 8 + 4 & 15] + hex_chr[n >> j * 8 & 15];
        }
        return s;
      }
      function hex(x) {
        var i;
        for (i = 0; i < x.length; i += 1) {
          x[i] = rhex(x[i]);
        }
        return x.join("");
      }
      if (hex(md51("hello")) !== "5d41402abc4b2a76b9719d911017c592") {
        add32 = function(x, y) {
          var lsw = (x & 65535) + (y & 65535), msw = (x >> 16) + (y >> 16) + (lsw >> 16);
          return msw << 16 | lsw & 65535;
        };
      }
      if (typeof ArrayBuffer !== "undefined" && !ArrayBuffer.prototype.slice) {
        (function() {
          function clamp(val, length) {
            val = val | 0 || 0;
            if (val < 0) {
              return Math.max(val + length, 0);
            }
            return Math.min(val, length);
          }
          ArrayBuffer.prototype.slice = function(from, to) {
            var length = this.byteLength, begin = clamp(from, length), end = length, num, target, targetArray, sourceArray;
            if (to !== undefined2) {
              end = clamp(to, length);
            }
            if (begin > end) {
              return new ArrayBuffer(0);
            }
            num = end - begin;
            target = new ArrayBuffer(num);
            targetArray = new Uint8Array(target);
            sourceArray = new Uint8Array(this, begin, num);
            targetArray.set(sourceArray);
            return target;
          };
        })();
      }
      function toUtf8(str) {
        if (/[\u0080-\uFFFF]/.test(str)) {
          str = unescape(encodeURIComponent(str));
        }
        return str;
      }
      function utf8Str2ArrayBuffer(str, returnUInt8Array) {
        var length = str.length, buff = new ArrayBuffer(length), arr = new Uint8Array(buff), i;
        for (i = 0; i < length; i += 1) {
          arr[i] = str.charCodeAt(i);
        }
        return returnUInt8Array ? arr : buff;
      }
      function arrayBuffer2Utf8Str(buff) {
        return String.fromCharCode.apply(null, new Uint8Array(buff));
      }
      function concatenateArrayBuffers(first, second, returnUInt8Array) {
        var result = new Uint8Array(first.byteLength + second.byteLength);
        result.set(new Uint8Array(first));
        result.set(new Uint8Array(second), first.byteLength);
        return returnUInt8Array ? result : result.buffer;
      }
      function hexToBinaryString(hex2) {
        var bytes = [], length = hex2.length, x;
        for (x = 0; x < length - 1; x += 2) {
          bytes.push(parseInt(hex2.substr(x, 2), 16));
        }
        return String.fromCharCode.apply(String, bytes);
      }
      function SparkMD52() {
        this.reset();
      }
      SparkMD52.prototype.append = function(str) {
        this.appendBinary(toUtf8(str));
        return this;
      };
      SparkMD52.prototype.appendBinary = function(contents) {
        this._buff += contents;
        this._length += contents.length;
        var length = this._buff.length, i;
        for (i = 64; i <= length; i += 64) {
          md5cycle(this._hash, md5blk(this._buff.substring(i - 64, i)));
        }
        this._buff = this._buff.substring(i - 64);
        return this;
      };
      SparkMD52.prototype.end = function(raw) {
        var buff = this._buff, length = buff.length, i, tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], ret;
        for (i = 0; i < length; i += 1) {
          tail[i >> 2] |= buff.charCodeAt(i) << (i % 4 << 3);
        }
        this._finish(tail, length);
        ret = hex(this._hash);
        if (raw) {
          ret = hexToBinaryString(ret);
        }
        this.reset();
        return ret;
      };
      SparkMD52.prototype.reset = function() {
        this._buff = "";
        this._length = 0;
        this._hash = [1732584193, -271733879, -1732584194, 271733878];
        return this;
      };
      SparkMD52.prototype.getState = function() {
        return {
          buff: this._buff,
          length: this._length,
          hash: this._hash.slice()
        };
      };
      SparkMD52.prototype.setState = function(state) {
        this._buff = state.buff;
        this._length = state.length;
        this._hash = state.hash;
        return this;
      };
      SparkMD52.prototype.destroy = function() {
        delete this._hash;
        delete this._buff;
        delete this._length;
      };
      SparkMD52.prototype._finish = function(tail, length) {
        var i = length, tmp, lo, hi;
        tail[i >> 2] |= 128 << (i % 4 << 3);
        if (i > 55) {
          md5cycle(this._hash, tail);
          for (i = 0; i < 16; i += 1) {
            tail[i] = 0;
          }
        }
        tmp = this._length * 8;
        tmp = tmp.toString(16).match(/(.*?)(.{0,8})$/);
        lo = parseInt(tmp[2], 16);
        hi = parseInt(tmp[1], 16) || 0;
        tail[14] = lo;
        tail[15] = hi;
        md5cycle(this._hash, tail);
      };
      SparkMD52.hash = function(str, raw) {
        return SparkMD52.hashBinary(toUtf8(str), raw);
      };
      SparkMD52.hashBinary = function(content, raw) {
        var hash2 = md51(content), ret = hex(hash2);
        return raw ? hexToBinaryString(ret) : ret;
      };
      SparkMD52.ArrayBuffer = function() {
        this.reset();
      };
      SparkMD52.ArrayBuffer.prototype.append = function(arr) {
        var buff = concatenateArrayBuffers(this._buff.buffer, arr, true), length = buff.length, i;
        this._length += arr.byteLength;
        for (i = 64; i <= length; i += 64) {
          md5cycle(this._hash, md5blk_array(buff.subarray(i - 64, i)));
        }
        this._buff = i - 64 < length ? new Uint8Array(buff.buffer.slice(i - 64)) : new Uint8Array(0);
        return this;
      };
      SparkMD52.ArrayBuffer.prototype.end = function(raw) {
        var buff = this._buff, length = buff.length, tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], i, ret;
        for (i = 0; i < length; i += 1) {
          tail[i >> 2] |= buff[i] << (i % 4 << 3);
        }
        this._finish(tail, length);
        ret = hex(this._hash);
        if (raw) {
          ret = hexToBinaryString(ret);
        }
        this.reset();
        return ret;
      };
      SparkMD52.ArrayBuffer.prototype.reset = function() {
        this._buff = new Uint8Array(0);
        this._length = 0;
        this._hash = [1732584193, -271733879, -1732584194, 271733878];
        return this;
      };
      SparkMD52.ArrayBuffer.prototype.getState = function() {
        var state = SparkMD52.prototype.getState.call(this);
        state.buff = arrayBuffer2Utf8Str(state.buff);
        return state;
      };
      SparkMD52.ArrayBuffer.prototype.setState = function(state) {
        state.buff = utf8Str2ArrayBuffer(state.buff, true);
        return SparkMD52.prototype.setState.call(this, state);
      };
      SparkMD52.ArrayBuffer.prototype.destroy = SparkMD52.prototype.destroy;
      SparkMD52.ArrayBuffer.prototype._finish = SparkMD52.prototype._finish;
      SparkMD52.ArrayBuffer.hash = function(arr, raw) {
        var hash2 = md51_array(new Uint8Array(arr)), ret = hex(hash2);
        return raw ? hexToBinaryString(ret) : ret;
      };
      return SparkMD52;
    });
  }
});

// src/ahocorasickEngine.mjs
var Node = class {
  constructor() {
    this.children = {};
    this.fail = null;
    this.outputs = [];
    this.nocase = false;
  }
};
var AhoCorasick = class {
  constructor(rules) {
    this.root = new Node();
    this.addRules(rules);
  }
  addRules(rules) {
    const patterns = [];
    const decoder = new TextDecoder();
    for (const rule of rules) {
      const { id, strings } = rule;
      for (const varName of Object.keys(strings)) {
        const strDef = strings[varName];
        if (strDef.type === "text") {
          for (const patternObj of strDef.patterns) {
            const bytes = patternObj.bytes;
            const patternStr = decoder.decode(bytes);
            patterns.push({ id, varName, pattern: patternStr, matcher: strDef.matcher, xor: strDef.xor, nocase: strDef.nocase });
          }
        } else if (strDef.type === "regex" && strDef.literalPrefix && strDef.literalPrefix.length > 0) {
          patterns.push({ id, varName, pattern: strDef.literalPrefix, matcher: strDef.matcher, nocase: strDef.nocase });
        }
      }
    }
    this.generateAtoms(patterns);
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
            p.atom = xorredAtom;
            p.xorKey = key;
          } else {
            xorPatterns.push({ ...p, atom: xorredAtom, xorKey: key });
          }
        }
      }
    }
    patterns.push(...xorPatterns);
  }
  buildTrie(patterns) {
    for (const p of patterns) {
      let node = this.root;
      for (let i = 0; i < p.atom.length; i++) {
        const ch = p.atom[i];
        if (!node.children[ch]) node.children[ch] = new Node();
        node = node.children[ch];
        node.nocase = p.nocase ?? false;
      }
      node.outputs.push(p);
    }
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
    for (const ch in this.root.children) {
      const child = this.root.children[ch];
      child.fail = this.root;
      queue.push(child);
    }
    while (queue.length > 0) {
      const current = queue.shift();
      for (const [ch, nextNode] of Object.entries(current.children)) {
        queue.push(nextNode);
        let fail = current.fail;
        while (fail && !fail.children[ch]) {
          fail = fail.fail;
        }
        nextNode.fail = fail ? fail.children[ch] : this.root;
        nextNode.outputs = nextNode.outputs.concat(nextNode.fail.outputs);
      }
    }
  }
  search(text) {
    const results = [];
    let node = this.root;
    for (let i = 0; i < text.length; i++) {
      const ch = text[i];
      const charValue = typeof ch === "number" ? String.fromCharCode(ch) : ch;
      const lowerCharValue = charValue.toLowerCase();
      while (node && !(node.children[charValue] || node.children[lowerCharValue] && node.children[lowerCharValue].nocase)) {
        node = node.fail;
      }
      if (!node) node = this.root;
      else {
        if (node.children[charValue]) node = node.children[charValue];
        else if (node.children[lowerCharValue]?.nocase) node = node.children[lowerCharValue];
        else node = this.root;
      }
      if (node === this.root) continue;
      for (const output of node.outputs) {
        const index = i - (output.atomLength || 0) + 1;
        if (index - output.atomOffset < 0) continue;
        if (index - output.atomOffset + output.length > text.length) continue;
        results.push({
          id: output.id,
          varName: output.varName,
          index,
          xorKey: output.xorKey,
          matcher: output.matcher
        });
      }
    }
    return results;
  }
};

// src/yaraStringMatch.mjs
var MAX_STRING_MATCH_LENGTH = 2048;
var MAX_MATCHES = 100;
function compileYaraLike(definition) {
  definition = definition.trim();
  const isRegex = definition.startsWith("/");
  const isHex = definition.startsWith("{");
  const quoteMatch = definition.match(/^"(.*)"(.*)$/);
  if (isRegex) {
    return makeRegexMatcher(definition);
  } else if (isHex) {
    const mods = definition.slice(definition.lastIndexOf("}") + 1);
    return makeHexMatcher(definition.slice(1, definition.lastIndexOf("}")).trim(), mods);
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
      private: /\bprivate\b/.test(mods)
    };
    return makeTextMatcher(text, opts);
  }
  throw new Error("Unsupported definition: " + definition);
}
function addOptionsToMatcher(matcher) {
  return (data, offset = -1, maxLength = MAX_STRING_MATCH_LENGTH) => {
    const singleRun = offset >= 0;
    offset = Math.max(0, offset - 1);
    data = singleRun ? data.slice(offset, offset + maxLength) : data;
    return matcher(data, singleRun ? offset : -1);
  };
}
function makeRegexMatcher(definition) {
  const mods = definition.split("/").pop().toLowerCase() ?? "";
  const regexFlags = mods.split(" ")[0];
  const isPrivate = /\bprivate\b/.test(mods);
  const pattern = definition.slice(1, definition.lastIndexOf("/"));
  const nocase = regexFlags.includes("i");
  const flags = "g" + (regexFlags.includes("s") ? "s" : "") + (nocase ? "i" : "");
  const literalPrefix = getRegexPrefix(pattern, nocase);
  const re = new RegExp(pattern, flags);
  const matcher = (data, offset = -1) => {
    const encoder = new TextEncoder();
    const text = new TextDecoder().decode(data);
    const results = [];
    const singleRun = offset >= 0;
    offset = offset < 0 ? 0 : offset;
    let m;
    while ((m = re.exec(text)) !== null && results.length < MAX_MATCHES) {
      const byteIndex = encoder.encode(text.slice(0, m.index)).length;
      results.push({ offset: byteIndex + offset, length: encoder.encode(m[0]).length });
      re.lastIndex = m.index + 1;
      if (singleRun) break;
    }
    return results;
  };
  return { matcher: addOptionsToMatcher(matcher), literalPrefix, type: "regex", nocase, private: isPrivate };
}
function getRegexPrefix(pattern, nocase = false) {
  pattern = pattern.replace(/^\^/, "");
  pattern = nocase ? pattern.toLowerCase() : pattern;
  const match = pattern.match(/^((?:\\[^bBdDwWsSAZzGnrtfv0u]|[^\\[\]()|*+?{}.])+)/);
  if (!match || match.length < 2) return "";
  let prefix = match[1].replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  return prefix.replace(/\\(.)/g, "$1");
}
function makeTextMatcher(text, opts) {
  const encoder = new TextEncoder();
  const patterns = [];
  if (!opts.wide) opts.ascii = true;
  if (opts.base64 || opts.base64wide) {
    opts.nocase = false;
    opts.fullword = false;
    opts.xor = null;
  }
  const unescapedText = text.replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "	").replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16))).replace(/\\\\/g, "\\").replace(/\\"/g, '"').replace(/\\'/g, "'");
  const textVariants = opts.nocase ? [unescapedText.toLowerCase()] : [unescapedText];
  for (const variant of textVariants) {
    if (opts.base64 || opts.base64wide) {
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
          patterns.push(...yaraBase64Variants(variant, true).map((bytes) => ({ bytes, isWide: true })));
        }
        if (opts.wide) {
          patterns.push(...yaraBase64Variants(toWideBytes(variant), true).map((bytes) => ({ bytes, isWide: true })));
        }
      }
    } else {
      if (opts.ascii) {
        patterns.push({ bytes: encoder.encode(variant), isWide: false });
      }
      if (opts.wide) {
        patterns.push({ bytes: toWideBytes(variant), isWide: true });
      }
    }
  }
  const matcher = (data, offset = -1) => {
    let matches = [];
    const singleRun = offset >= 0;
    offset = offset < 0 ? 0 : offset;
    for (const { bytes, isWide } of patterns) {
      if (opts.xor) {
        const xorMatches = findXorMatches(data, bytes, opts.xor, opts.allowKey0, singleRun);
        matches.push(...xorMatches.map((m) => ({ ...m, length: bytes.length, isWide })));
      } else {
        const plainMatches = findPlainMatches(data, bytes, opts.nocase, singleRun);
        matches.push(...plainMatches.map((m) => ({ ...m, length: bytes.length, isWide })));
      }
    }
    if (opts.fullword) {
      matches = matches.filter((m) => isFullWordMatch(data, m.offset, m.length));
    }
    matches.forEach((m) => {
      m.offset += offset;
    });
    return matches;
  };
  return { matcher: addOptionsToMatcher(matcher), patterns, type: "text", xor: opts.xor, nocase: opts.nocase, private: opts.private };
}
function findXorMatches(data, pattern, keyRange, allowKey0 = true, singleRun = false) {
  const [minKey, maxKey] = keyRange;
  const matches = [];
  const pLen = pattern.length;
  const dLen = data.length;
  if (pLen === 0 || pLen > dLen) return matches;
  for (let candidateKey = minKey; candidateKey <= maxKey; candidateKey++) {
    for (let i = 0; i <= dLen - pLen; i++) {
      let ok = true;
      for (let j = 0; j < pLen; j++) {
        if ((data[i + j] ^ candidateKey) !== pattern[j]) {
          ok = false;
          break;
        }
      }
      if (ok) {
        matches.push({ offset: i, key: candidateKey });
        if (singleRun) break;
      }
    }
  }
  return matches;
}
function findPlainMatches(data, pattern, nocase = false, singleRun = false) {
  const matches = [];
  const pLen = pattern.length;
  const dLen = data.length;
  outer: for (let i = 0; i <= dLen - pLen; i++) {
    for (let j = 0; j < pLen; j++) {
      if ((nocase ? lowercaseByte(data[i + j]) : data[i + j]) !== pattern[j]) continue outer;
    }
    matches.push({ offset: i });
    if (singleRun) break;
  }
  return matches;
}
function lowercaseByte(b) {
  if (b >= 65 && b <= 90) {
    return b + 32;
  }
  return b;
}
function isFullWordMatch(data, offset, length) {
  const isWordChar = (b) => b >= 48 && b <= 57 || // 0-9
  b >= 65 && b <= 90 || // A-Z
  b >= 97 && b <= 122;
  const before = offset === 0 || !isWordChar(data[offset - 1]);
  const after = offset + length >= data.length || !isWordChar(data[offset + length]);
  return before && after;
}
function toWideBytes(text) {
  const buf = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    buf[i * 2] = code & 255;
    buf[i * 2 + 1] = code >> 8;
  }
  return buf;
}
function parseXorRange(mods) {
  const m = mods.match(/xor(?:\((0x[0-9a-f]+|\d+)(?:-(0x[0-9a-f]+|\d+))?\))?/i);
  if (!m) return null;
  const [, start, end] = m;
  if (!start && !end) return [0, 255];
  let startVal = start ? parseInt(start, start.startsWith("0x") ? 16 : 10) : null;
  let endVal = end ? parseInt(end, end.startsWith("0x") ? 16 : 10) : null;
  if (startVal !== null && endVal === null) return [startVal, startVal];
  if (endVal !== null && startVal === null) return [endVal, endVal];
  return [startVal, endVal];
}
var MAX_HEX_JUMP = 1e4;
function makeHexMatcher(hexBody, mods) {
  let pattern = "";
  hexBody = hexBody?.toUpperCase().replace(/[^0-9A-F?~|()[\-\]]/g, "") || "";
  const parts = hexBody.match(/\[\d*(-\d*)?\]|\(.*\)|~?[0-9A-F?]{2}/g) || [];
  const isPrivate = /\bprivate\b/.test(mods);
  if (parts.length === 0) {
    const matcher2 = (data) => [];
    return { matcher: matcher2, type: "hex", private: isPrivate };
  }
  for (const token of parts) {
    if (token.startsWith("[")) {
      const dashIndex = token.indexOf("-");
      if (dashIndex === -1) {
        const count = parseInt(token.slice(1, -1));
        pattern += `(?:[0-9A-F]{2}){${count}}`;
      } else {
        const match = /\[(\d*)-(\d*)\]/.exec(token);
        const min = parseInt(match[1]) || 0;
        const max = parseInt(match[2]) || MAX_HEX_JUMP;
        pattern += `(?:[0-9A-F]{2}){${min},${max}}`;
      }
    } else if (token.startsWith("(")) {
      pattern += convertNegationToRegex(token).replace(/\?/g, "[0-9A-F]");
    } else if (token.startsWith("~")) {
      pattern += convertNegationToRegex(token);
    } else {
      pattern += token.replace(/\?/g, "[0-9A-F]");
    }
  }
  const regex = new RegExp(pattern, "g");
  const matcher = (data) => {
    const hexString = typeof data === "string" ? data : Array.from(data).map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join("");
    const matches = [];
    let m;
    while ((m = regex.exec(hexString)) !== null && matches.length < MAX_MATCHES) {
      if (m.index % 2 !== 0) {
        regex.lastIndex = m.index + 1;
        continue;
      }
      matches.push({ offset: m.index / 2 });
      regex.lastIndex = m.index + 2;
    }
    return matches;
  };
  return { matcher, type: "hex", private: isPrivate };
}
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
function yaraBase64Variants(input, wide = false) {
  const encoder = new TextEncoder();
  let bytes;
  if (typeof input === "string") {
    bytes = encoder.encode(input);
  } else {
    bytes = input;
  }
  const variants = [];
  const dropCharsMap = [0, 2, 3];
  for (let offset = 0; offset < 3; offset++) {
    const padded = new Uint8Array(offset + bytes.length);
    padded.set(bytes, offset);
    let b64 = btoa(String.fromCharCode(...padded));
    const dropChars = dropCharsMap[offset];
    const trailing = /=*$/.exec(b64 ?? [0])[0].length;
    const b64string = b64.slice(dropChars, b64.length - (trailing ? trailing + 1 : 0));
    variants.push(wide ? toWideBytes(b64string) : encoder.encode(b64string));
  }
  return variants.filter((v) => v.length >= 1);
}

// src/yaraRuleCompiler.mjs
var SUPPORTED_MODULES = [
  "pe",
  // Windows PE file format module
  "elf",
  // Linux/Unix ELF file format module
  "math",
  // Mathematical and statistical functions
  "hash",
  // Cryptographic hash functions (MD5, SHA1, SHA256, CRC32)
  "time",
  // Time-related functions
  "string"
  // String manipulation functions
];
function parseImports(text) {
  const imports = [];
  const importRegex = /^\s*import\s+"(\w+)"\s*$/gm;
  let match;
  while ((match = importRegex.exec(text)) !== null) {
    const moduleName = match[1];
    if (!SUPPORTED_MODULES.includes(moduleName)) {
      throw new Error(
        `Unsupported module import: "${moduleName}". Supported modules are: ${SUPPORTED_MODULES.join(", ")}. Note: All supported modules are automatically available; the import statement is only for validation.`
      );
    }
    imports.push(moduleName);
  }
  return imports;
}
function stripComments(text) {
  let result = "";
  let i = 0;
  const len = text.length;
  while (i < len) {
    if (text[i] === '"' || text[i] === "'") {
      const quote = text[i];
      result += text[i++];
      while (i < len) {
        if (text[i] === "\\" && i + 1 < len) {
          result += text[i++];
          result += text[i++];
        } else if (text[i] === quote) {
          result += text[i++];
          break;
        } else {
          result += text[i++];
        }
      }
    } else if (text[i] === "/" && i + 1 < len && text[i + 1] === "/") {
      i += 2;
      while (i < len && text[i] !== "\n") {
        i++;
      }
      if (i < len && text[i] === "\n") {
        result += text[i++];
      }
    } else if (text[i] === "/" && i + 1 < len && text[i + 1] === "*") {
      i += 2;
      while (i < len - 1) {
        if (text[i] === "*" && text[i + 1] === "/") {
          i += 2;
          break;
        }
        if (text[i] === "\n") {
          result += "\n";
        }
        i++;
      }
    } else {
      result += text[i++];
    }
  }
  return result;
}
function countBracesOutsideStrings(line) {
  let openCount = 0;
  let closeCount = 0;
  let inString = false;
  let stringChar = null;
  let i = 0;
  while (i < line.length) {
    const char = line[i];
    if (inString && char === "\\" && i + 1 < line.length) {
      i += 2;
      continue;
    }
    if ((char === '"' || char === "'") && !inString) {
      inString = true;
      stringChar = char;
    } else if (char === stringChar && inString) {
      inString = false;
      stringChar = null;
    } else if (!inString) {
      if (char === "{") {
        openCount++;
      } else if (char === "}") {
        closeCount++;
      }
    }
    i++;
  }
  return { openCount, closeCount };
}
function parseYaraRuleGroup(multiRuleText, existingRules = []) {
  parseImports(multiRuleText);
  multiRuleText = multiRuleText.replace(/^\s*import\s+"[^"]+"\s*$/gm, "");
  const rules = existingRules ?? [];
  let currentRuleText = "";
  let braceDepth = 0;
  let inRule = false;
  const lines = multiRuleText.split("\n");
  for (let line of lines) {
    if (!inRule && line.match(/^\s*(?:\s*(?:private|global)\s+)*rule\b/i)) {
      inRule = true;
      currentRuleText = line + "\n";
      const braceCounts = countBracesOutsideStrings(line);
      braceDepth = braceCounts.openCount - braceCounts.closeCount;
      const atleastOneBrace = braceCounts.openCount > 0;
      if (braceDepth === 0 && atleastOneBrace) {
        rules.push(parseYaraRule(currentRuleText));
        inRule = false;
        currentRuleText = "";
      }
    } else if (inRule) {
      currentRuleText += line + "\n";
      const braceCounts = countBracesOutsideStrings(line);
      braceDepth += braceCounts.openCount - braceCounts.closeCount;
      if (braceDepth === 0) {
        rules.push(parseYaraRule(currentRuleText));
        inRule = false;
        currentRuleText = "";
      }
    } else {
    }
  }
  rules.forEach((rule, index) => {
    rule.id = index + 1;
  });
  return rules;
}
function parseYaraRule(ruleText) {
  ruleText = stripComments(ruleText).trim();
  const isPrivate = /^.*\bprivate\b.*rule\s+/i.test(ruleText);
  const isGlobal = /^.*\bglobal\b.*rule\s+/i.test(ruleText);
  const ruleMatch = ruleText.match(/^(?:.*)?rule\s+(\w+)(?:\s*:\s*([\w\s]+))?\s*\{/);
  if (!ruleMatch) {
    throw new Error("Invalid YARA rule: missing rule declaration");
  }
  const ruleName = ruleMatch[1];
  const tags = ruleMatch[2] ? ruleMatch[2].trim().split(/\s+/) : [];
  const bodyMatch = ruleText.match(/\{([\s\S]*)\}/);
  if (!bodyMatch) {
    throw new Error("Invalid YARA rule: missing rule body");
  }
  const ruleBody = bodyMatch[1];
  const metadata = parseMetadata(ruleBody);
  const strings = parseStrings(ruleBody);
  const condition = parseCondition(ruleBody);
  return {
    name: ruleName,
    tags,
    metadata,
    strings,
    condition,
    private: isPrivate,
    global: isGlobal
  };
}
function parseMetadata(ruleBody) {
  const metaMatch = ruleBody.match(/meta:\s*([\s\S]*?)(?=strings:|condition:|$)/);
  if (!metaMatch) return {};
  const metaText = metaMatch[1];
  const metadata = {};
  const metaLines = metaText.match(/(\w+)\s*=\s*("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|(-)?\d+(\.\d+)?|true|false)/g);
  if (metaLines) {
    for (const line of metaLines) {
      const [, key, value] = line.match(/(\w+)\s*=\s*(.+)/);
      if (value.startsWith('"') || value.startsWith("'")) {
        metadata[key] = value.slice(1, -1);
      } else if (value === "true" || value === "false") {
        metadata[key] = value === "true";
      } else if (!isNaN(value)) {
        metadata[key] = Number(value);
      } else {
        metadata[key] = value;
      }
    }
  }
  return metadata;
}
function parseStrings(ruleBody) {
  const stringsMatch = ruleBody.match(/strings:\s*([\s\S]*?)(?=condition:|$)/);
  if (!stringsMatch) return {};
  const stringsText = stringsMatch[1];
  const strings = {};
  const stringLines = stringsText.match(/\$\w*\s*=\s*(.*)?/g);
  if (stringLines) {
    let anonCounter = 0;
    for (const line of stringLines) {
      const match = line.match(/\$(\w*)\s*=\s*(.+)/);
      if (!match) continue;
      let [, varName, definition] = match;
      if (!varName || varName === "") {
        varName = `.anon_${anonCounter++}`;
      }
      try {
        const compiledRule = compileYaraLike(definition.trim());
        strings[varName] = {
          definition: definition.trim(),
          ...compiledRule
        };
      } catch (error) {
        console.warn(`Warning: Failed to compile string $${varName}: ${error.message}`);
        console.warn(`Definition: ${definition.trim()}`);
        console.warn(line);
        console.warn(stringsMatch);
        console.warn(ruleBody);
        strings[varName] = {
          definition: definition.trim(),
          type: null,
          matcher: null,
          error: error.message
        };
      }
    }
  }
  return strings;
}
function parseCondition(ruleBody) {
  const conditionMatch = ruleBody.match(/condition:\s*([\s\S]*?)$/);
  if (!conditionMatch) {
    throw new Error("Invalid YARA rule: missing condition");
  }
  return conditionMatch[1].trim().replace(/\}\s*$/, "").trim();
}

// src/yaraConditionsMatch.mjs
function createScanFacts(data, stringMatches = {}, modules = {}, options = {}) {
  const normalizedStrings = {};
  for (const [identifier, result] of Object.entries(stringMatches)) {
    if (Array.isArray(result)) {
      normalizedStrings[identifier] = {
        identifier,
        matched: result.length > 0,
        count: result.length,
        matches: result,
        offsets: result.map((m) => m.offset)
        // length: result.length > 0 ? result[0].length : null
      };
    } else if (typeof result === "object" && result !== null) {
      normalizedStrings[identifier] = {
        identifier,
        matched: result.matched ?? result.count > 0,
        count: result.count ?? 0,
        matches: result.matches ?? [],
        offsets: result.offsets ?? (result.matches || []).map((m) => m.offset),
        // length: result.length ?? result.matches?.length,
        ...result
      };
    }
  }
  return {
    data,
    filesize: data.length,
    entrypoint: options.entrypoint ?? 0,
    isFileSizeCapped: options.isFileSizeCapped ?? false,
    maxFileSize: options.maxFileSize ?? 1024 * 1024,
    // Default 1MB
    strings: normalizedStrings,
    modules: modules || {},
    matchedRules: options.matchedRules || {},
    // Map of rule names to match status
    metadata: options.metadata || {}
  };
}
var ConditionEvaluator = class {
  constructor(scanFacts) {
    this.facts = scanFacts;
    this.data = scanFacts.data;
    this.filesize = scanFacts.filesize;
    this.entrypoint = scanFacts.entrypoint;
    this.isFileSizeCapped = scanFacts.isFileSizeCapped ?? false;
    this.maxFileSize = scanFacts.maxFileSize ?? 1024 * 1024;
    this.strings = scanFacts.strings;
    this.modules = scanFacts.modules;
    this.matchedRules = scanFacts.matchedRules || {};
  }
  /**
   * Check if any operand is undefined (YARA semantics)
   * According to YARA docs: "All remaining operators, including the not operator, 
   * return undefined if any of their operands is undefined"
   * @param {...*} operands - One or more operands to check
   * @returns {boolean} True if any operand is undefined
   */
  isAnyUndefined(...operands) {
    return operands.some((operand) => operand === void 0);
  }
  /**
   * Evaluate a YARA condition expression
   * @param {string|Object} condition - Condition string or AST
   * @returns {Promise<boolean>} Result of condition evaluation
   */
  async evaluate(condition) {
    if (typeof condition === "string") {
      condition = this.parseCondition(condition);
    }
    return await this.evaluateNode(condition);
  }
  /**
   * Parse a condition string into an AST
   * This is a simplified parser - in production, use a proper parser
   * @param {string} condition 
   * @returns {Object} AST node
   */
  parseCondition(condition) {
    throw new Error("String parsing not implemented - pass AST directly");
  }
  /**
   * Evaluate an AST node
   * @param {Object} node 
   * @returns {Promise<*>} Evaluation result
   */
  async evaluateNode(node) {
    if (node === null || node === void 0) {
      return false;
    }
    const type = node.type;
    switch (type) {
      // Literals
      case "boolean":
        return node.value;
      case "number":
        return node.value;
      case "string":
        return node.value;
      case "identifier":
        return this.resolveIdentifier(node.name);
      // Rule identifiers (dependent rules)
      case "ruleIdentifier":
        return this.evaluateRuleIdentifier(node);
      // String identifiers
      case "stringIdentifier":
        return this.evaluateStringIdentifier(node);
      case "stringCount":
        return this.getStringCount(node.identifier);
      case "stringOffset": {
        let index = node.index;
        if (typeof index === "object") {
          index = await this.evaluateNode(index);
        }
        return this.getStringOffset(node.identifier, index);
      }
      case "stringLength": {
        let index = node.index;
        if (typeof index === "object") {
          index = await this.evaluateNode(index);
        }
        return this.getStringLength(node.identifier, index);
      }
      // Logical operators
      case "and": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (left === void 0 || left === false) return false;
        if (right === void 0 || right === false) return false;
        return true;
      }
      case "or": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        const leftBool = left === void 0 ? false : left;
        const rightBool = right === void 0 ? false : right;
        return leftBool || rightBool;
      }
      case "not": {
        const operand = await this.evaluateNode(node.operand);
        if (this.isAnyUndefined(operand)) return void 0;
        return !operand;
      }
      case "defined":
        return await this.evaluateDefined(node.operand);
      // Comparison operators
      case "equal":
        return await this.evaluateEqual(node);
      case "notEqual":
        return await this.evaluateNotEqual(node);
      case "lessThan":
        return await this.evaluateLessThan(node);
      case "greaterThan":
        return await this.evaluateGreaterThan(node);
      case "lessThanOrEqual":
        return await this.evaluateLessThanOrEqual(node);
      case "greaterThanOrEqual":
        return await this.evaluateGreaterThanOrEqual(node);
      // Arithmetic operators
      case "add": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return left + right;
      }
      case "subtract": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return left - right;
      }
      case "multiply": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return left * right;
      }
      case "divide": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return Math.floor(left / right);
      }
      case "modulo": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return left % right;
      }
      // Bitwise operators (convert results to unsigned 32-bit to match YARA behavior)
      case "bitwiseAnd": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return (left & right) >>> 0;
      }
      case "bitwiseOr": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return (left | right) >>> 0;
      }
      case "bitwiseXor": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return (left ^ right) >>> 0;
      }
      case "bitwiseNot": {
        const operand = await this.evaluateNode(node.operand);
        if (this.isAnyUndefined(operand)) return void 0;
        return ~operand >>> 0;
      }
      case "shiftLeft": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return left << right;
      }
      case "shiftRight": {
        const left = await this.evaluateNode(node.left);
        const right = await this.evaluateNode(node.right);
        if (this.isAnyUndefined(left, right)) return void 0;
        return left >> right;
      }
      // String operators
      case "contains":
        return await this.stringContains(node.left, node.right, false);
      case "icontains":
        return await this.stringContains(node.left, node.right, true);
      case "startswith":
        return await this.stringStartsWith(node.left, node.right, false);
      case "istartswith":
        return await this.stringStartsWith(node.left, node.right, true);
      case "endswith":
        return await this.stringEndsWith(node.left, node.right, false);
      case "iendswith":
        return await this.stringEndsWith(node.left, node.right, true);
      case "iequals":
        return await this.stringEquals(node.left, node.right, true);
      case "matches":
        return await this.stringMatches(node.left, node.right);
      // Set membership
      case "in":
        return await this.evaluateInOperator(node);
      // Range
      case "range":
        return { start: await this.evaluateNode(node.start), end: await this.evaluateNode(node.end) };
      // Quantifiers
      case "all":
        return await this.evaluateAll(node.items);
      case "any":
        return await this.evaluateAny(node.items);
      case "none":
        return await this.evaluateNone(node.items);
      case "quantified":
        return await this.evaluateQuantified(node);
      // For expressions
      case "for":
        return await this.evaluateFor(node);
      // Member access (e.g., pe.entry_point)
      case "memberAccess":
        return await this.evaluateMemberAccess(node);
      // Array access (e.g., pe.sections[0])
      case "arrayAccess":
        return await this.evaluateArrayAccess(node);
      // Function call
      case "functionCall":
        return await this.evaluateFunctionCall(node);
      // Data access (uint8, uint16, etc.)
      case "dataAccess":
        return this.evaluateDataAccess(node);
      // At expression ($a at 0x100)
      case "at":
        return await this.evaluateAt(node);
      // In range expression ($a in (0..100))
      case "inRange":
        return await this.evaluateInRange(node);
      // Within expression ($a within N of $b)
      case "within":
        return await this.evaluateWithin(node);
      // Module function call (e.g., string.to_int(), time.now())
      case "moduleFunction":
        return await this.evaluateModuleFunction(node);
      default:
        throw new Error(`Unknown node type: ${type}`);
    }
  }
  /**
   * Resolve a simple identifier (filesize, entrypoint, modules, etc.)
   */
  resolveIdentifier(name) {
    if (this.forContext && name in this.forContext) {
      return this.forContext[name];
    }
    switch (name) {
      case "filesize":
        return this.filesize;
      case "entrypoint":
        if (typeof this.entrypoint !== "number") {
          throw new Error("Entrypoint is not defined");
        }
        return this.entrypoint;
      default:
        if (this.modules && name in this.modules) {
          return this.modules[name];
        }
        if (["pe", "elf", "hash", "math", "string", "time"].includes(name)) {
          return void 0;
        }
        throw new Error(`Unknown identifier: ${name}`);
    }
  }
  /**
   * Check if left side is filesize identifier
   */
  isFilesizeNode(node) {
    return node && node.type === "identifier" && node.name === "filesize";
  }
  /**
   * Evaluate equal comparison with filesize special handling
   */
  async evaluateEqual(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);
    if (this.isAnyUndefined(left, right)) return void 0;
    if (this.isFilesizeNode(node.left) && this.isFileSizeCapped && right >= this.maxFileSize) {
      return true;
    }
    if (this.isFilesizeNode(node.right) && this.isFileSizeCapped && left >= this.maxFileSize) {
      return true;
    }
    return left === right;
  }
  /**
   * Evaluate not equal comparison with filesize special handling
   */
  async evaluateNotEqual(node) {
    const result = await this.evaluateEqual(node);
    if (this.isAnyUndefined(result)) return void 0;
    return !result;
  }
  /**
   * Evaluate less than comparison with filesize special handling
   */
  async evaluateLessThan(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);
    if (this.isAnyUndefined(left, right)) return void 0;
    return left < right;
  }
  /**
   * Evaluate greater than comparison with filesize special handling
   */
  async evaluateGreaterThan(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);
    if (this.isAnyUndefined(left, right)) return void 0;
    if (this.isFilesizeNode(node.left) && this.isFileSizeCapped && right >= this.maxFileSize) {
      return true;
    }
    return left > right;
  }
  /**
   * Evaluate less than or equal comparison with filesize special handling
   */
  async evaluateLessThanOrEqual(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);
    if (this.isAnyUndefined(left, right)) return void 0;
    return left <= right;
  }
  /**
   * Evaluate greater than or equal comparison with filesize special handling
   */
  async evaluateGreaterThanOrEqual(node) {
    const left = await this.evaluateNode(node.left);
    const right = await this.evaluateNode(node.right);
    if (this.isAnyUndefined(left, right)) return void 0;
    if (this.isFilesizeNode(node.left) && this.isFileSizeCapped && right >= this.maxFileSize) {
      return true;
    }
    return left >= right;
  }
  /**
   * Evaluate string identifier ($a)
   * In for loops, if identifier is '$', use the current loop variable
   */
  evaluateStringIdentifier(node) {
    let identifier = node.identifier;
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }
    const stringInfo = this.strings[identifier];
    if (!stringInfo) {
      return false;
    }
    return stringInfo.matched && stringInfo.count > 0;
  }
  /**
   * Evaluate rule identifier (dependent rule reference)
   * Returns true if the referenced rule matched, false otherwise
   */
  evaluateRuleIdentifier(node) {
    const ruleName = node.name;
    if (!(ruleName in this.matchedRules)) {
      return false;
    }
    return this.matchedRules[ruleName] === true;
  }
  /**
   * Get string match count (#a)
   * In for loops, if identifier is '$', use the current loop variable
   */
  getStringCount(identifier) {
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }
    const stringInfo = this.strings[identifier];
    return stringInfo ? stringInfo.count : 0;
  }
  /**
   * Get string match offset (@a or @a[1])
   * In for loops, supports @a[i] where i is the iterator variable
   * YARA uses 1-indexed: @a[1] = first match, @a[2] = second match, etc.
   */
  getStringOffset(identifier, index = 0) {
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }
    if (typeof index === "string" && this.forContext && index in this.forContext) {
      index = this.forContext[index];
    }
    const stringInfo = this.strings[identifier];
    if (!stringInfo || !stringInfo.offsets || stringInfo.offsets.length === 0) {
      return void 0;
    }
    const arrayIndex = index === 0 ? 0 : index - 1;
    return stringInfo.offsets[arrayIndex];
  }
  /**
   * Get string match length (!a or !a[1])
   * In for loops, supports !a[i] where i is the iterator variable
   * YARA uses 1-indexed: !a[1] = first match length, !a[2] = second match length, etc.
   */
  getStringLength(identifier, index = 0) {
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }
    if (typeof index === "string" && this.forContext && index in this.forContext) {
      index = this.forContext[index];
    }
    const stringInfo = this.strings[identifier];
    if (!stringInfo || !stringInfo.matches || stringInfo.matches.length === 0) {
      return void 0;
    }
    const arrayIndex = index === 0 ? 0 : index - 1;
    const match = stringInfo.matches[arrayIndex];
    return match ? match.length : void 0;
  }
  /**
   * Evaluate 'all of them' or 'all of ($a*, $b*)'
   */
  evaluateAll(items) {
    const identifiers = this.resolveStringSet(items);
    if (identifiers.length === 0) return false;
    return identifiers.every((id) => {
      const stringInfo = this.strings[id];
      return stringInfo && stringInfo.matched && stringInfo.count > 0;
    });
  }
  /**
   * Evaluate 'any of them' or 'any of ($a*, $b*)'
   */
  evaluateAny(items) {
    const identifiers = this.resolveStringSet(items);
    if (identifiers.length === 0) return false;
    return identifiers.some((id) => {
      const stringInfo = this.strings[id];
      return stringInfo && stringInfo.matched && stringInfo.count > 0;
    });
  }
  /**
   * Evaluate 'none of them'
   */
  evaluateNone(items) {
    const identifiers = this.resolveStringSet(items);
    if (identifiers.length === 0) return true;
    return identifiers.every((id) => {
      const stringInfo = this.strings[id];
      return !stringInfo || !stringInfo.matched || stringInfo.count === 0;
    });
  }
  /**
   * Evaluate quantified expression (e.g., '2 of them', '50% of them')
   */
  evaluateQuantified(node) {
    const identifiers = this.resolveStringSet(node.items);
    if (identifiers.length === 0) return false;
    const matchCount = identifiers.filter((id) => {
      const stringInfo = this.strings[id];
      return stringInfo && stringInfo.matched && stringInfo.count > 0;
    }).length;
    const quantifier = node.quantifier;
    if (quantifier.type === "number") {
      return matchCount >= quantifier.value;
    } else if (quantifier.type === "percentage") {
      const required = Math.ceil(identifiers.length * quantifier.value / 100);
      return matchCount >= required;
    } else if (quantifier.type === "range") {
      const min = quantifier.min;
      const max = quantifier.max;
      return matchCount >= min && matchCount <= max;
    }
    return false;
  }
  /**
   * Resolve string set (e.g., 'them', '$a*', '($a, $b, $c)')
   */
  resolveStringSet(items) {
    if (items === "them") {
      return Object.keys(this.strings);
    }
    if (Array.isArray(items)) {
      const resolved = [];
      for (const item of items) {
        if (item.includes("*")) {
          const pattern = item.replace(/\*/g, ".*").replace(/\$/g, "\\$");
          const regex = new RegExp("^" + pattern + "$");
          const matches = Object.keys(this.strings).filter((id) => regex.test(id));
          resolved.push(...matches);
        } else {
          resolved.push(item);
        }
      }
      return resolved;
    }
    if (typeof items === "string") {
      if (items.includes("*")) {
        const pattern = items.replace(/\*/g, ".*").replace(/\$/g, "\\$");
        const regex = new RegExp("^" + pattern + "$");
        return Object.keys(this.strings).filter((id) => regex.test(id));
      }
      return [items];
    }
    return [];
  }
  /**
   * Evaluate 'for' expression
   * e.g., 'for any of them : ($ at entrypoint)'
   * e.g., 'for all i in (1..5) : (@a[i] < @a[i+1])'
   * e.g., 'for 50% of them : ($ in (0..100))'
   * e.g., 'for all of ($api*) : ($ at entrypoint)'
   */
  async evaluateFor(node) {
    const quantifier = node.quantifier;
    const variable = node.variable;
    const set = node.set;
    const condition = node.condition;
    let items = [];
    if (set.type === "stringSet") {
      items = this.resolveStringSet(set.items);
      if (items.length === 0) {
        if (quantifier === "all") return true;
        return false;
      }
    } else if (set.type === "range") {
      const startVal = await this.evaluateNode(set.start);
      const endVal = await this.evaluateNode(set.end);
      if (typeof startVal !== "number" || typeof endVal !== "number") {
        throw new Error(`Invalid range values: ${startVal} to ${endVal}`);
      }
      for (let i = startVal; i <= endVal; i++) {
        items.push(i);
      }
      if (items.length === 0) {
        if (quantifier === "all") return true;
        return false;
      }
    } else {
      const evaluated = await this.evaluateNode(set);
      if (Array.isArray(evaluated)) {
        items = evaluated;
      } else {
        items = [evaluated];
      }
    }
    if (items.length === 0) {
      if (quantifier === "all") return true;
      return false;
    }
    const originalContext = this.forContext || {};
    const results = [];
    for (const item of items) {
      this.forContext = { ...originalContext, [variable]: item };
      try {
        const result = await this.evaluateNode(condition);
        results.push(!!result);
      } catch (error) {
        console.warn(`For loop condition evaluation failed for item ${item}:`, error.message);
        results.push(false);
      }
    }
    this.forContext = originalContext;
    const trueCount = results.filter((r) => r).length;
    if (quantifier === "any") {
      return trueCount > 0;
    } else if (quantifier === "all") {
      return trueCount === items.length;
    } else if (quantifier === "none") {
      return trueCount === 0;
    } else if (typeof quantifier === "number") {
      return trueCount >= quantifier;
    } else if (quantifier && quantifier.type === "percentage") {
      const required = Math.ceil(items.length * quantifier.value / 100);
      return trueCount >= required;
    } else if (quantifier && quantifier.type === "number") {
      return trueCount >= quantifier.value;
    }
    return false;
  }
  /**
   * Evaluate member access (e.g., pe.entry_point, math.entropy(0, 100))
   */
  async evaluateMemberAccess(node) {
    const obj = await this.evaluateNode(node.object);
    const property = node.property;
    if (obj === void 0 || obj === null) {
      return void 0;
    }
    if (typeof property === "string") {
      return obj[property];
    } else {
      const prop = await this.evaluateNode(property);
      return obj[prop];
    }
  }
  /**
   * Evaluate array access (e.g., pe.sections[0], elf.sections[1])
   */
  async evaluateArrayAccess(node) {
    const obj = await this.evaluateNode(node.object);
    const index = await this.evaluateNode(node.index);
    if (obj === void 0 || obj === null) {
      return void 0;
    }
    if (!Array.isArray(obj)) {
      return void 0;
    }
    const actualIndex = index < 0 ? obj.length + index : index;
    if (actualIndex < 0 || actualIndex >= obj.length) {
      return void 0;
    }
    return obj[actualIndex];
  }
  /**
   * Evaluate function call
   */
  async evaluateFunctionCall(node) {
    const func = await this.evaluateNode(node.function);
    const args = await Promise.all(node.arguments.map((arg) => this.evaluateNode(arg)));
    if (typeof func !== "function") {
      throw new Error(`Not a function: ${node.function}`);
    }
    const result = func(...args);
    return result instanceof Promise ? await result : result;
  }
  /**
   * Evaluate data access (uint8, uint16, uint32, int8, int16, int32)
   */
  async evaluateDataAccess(node) {
    const offset = await this.evaluateNode(node.offset);
    const dataType = node.dataType;
    const endian = node.endian || "little";
    if (offset < 0 || offset >= this.data.length) {
      return void 0;
    }
    const view = new DataView(this.data.buffer, this.data.byteOffset, this.data.byteLength);
    const littleEndian = endian === "little";
    try {
      switch (dataType) {
        case "uint8":
          return view.getUint8(offset);
        case "uint16":
          return view.getUint16(offset, littleEndian);
        case "uint32":
          return view.getUint32(offset, littleEndian);
        case "int8":
          return view.getInt8(offset);
        case "int16":
          return view.getInt16(offset, littleEndian);
        case "int32":
          return view.getInt32(offset, littleEndian);
        default:
          throw new Error(`Unknown data type: ${dataType}`);
      }
    } catch (e) {
      return void 0;
    }
  }
  /**
   * Evaluate 'defined' operator
   * Checks if an expression is defined (not undefined, not null)
   */
  async evaluateDefined(operand) {
    try {
      const value = await this.evaluateNode(operand);
      return value !== void 0 && value !== null;
    } catch {
      return false;
    }
  }
  /**
   * Evaluate 'at' expression ($a at 0x100 or "string" at 0)
   * In for loops, if identifier is '$', use the current loop variable
   */
  async evaluateAt(node) {
    let identifier = node.identifier;
    if (typeof identifier === "object" && identifier.type === "string") {
      const offset2 = await this.evaluateNode(node.offset);
      const stringValue = identifier.value;
      const stringBytes = new TextEncoder().encode(stringValue);
      if (offset2 < 0 || offset2 + stringBytes.length > this.data.length) {
        return false;
      }
      for (let i = 0; i < stringBytes.length; i++) {
        if (this.data[offset2 + i] !== stringBytes[i]) {
          return false;
        }
      }
      return true;
    }
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }
    const offset = await this.evaluateNode(node.offset);
    const stringInfo = this.strings[identifier];
    if (!stringInfo || !stringInfo.offsets) {
      return false;
    }
    return stringInfo.offsets.includes(offset);
  }
  /**
   * Evaluate 'in range' expression ($a in (0..100))
   * In for loops, if identifier is '$', use the current loop variable
   */
  async evaluateInRange(node) {
    let identifier = node.identifier;
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }
    const range = await this.evaluateNode(node.range);
    const stringInfo = this.strings[identifier];
    if (!stringInfo || !stringInfo.offsets) {
      return false;
    }
    return stringInfo.offsets.some(
      (offset) => offset >= range.start && offset <= range.end
    );
  }
  /**
   * Evaluate 'within' expression ($a within N of $b)
   * Checks if any occurrence of $a is within N bytes of any occurrence of $b
   * 
   * Distance is measured from start offset to start offset (YARA standard behavior).
   * Returns true if the absolute distance between any pair of matches is <= N.
   * 
   * @param {Object} node - AST node with identifier, distance, reference
   * @returns {Promise<boolean>} True if any match is within distance
   * 
   * TODO: Performance optimization needed for large match sets
   * - Current O(n*m) complexity could be slow with many matches
   * - Consider: early termination, sorted offset arrays with binary search,
   *   or distance caching for repeated evaluations
   */
  async evaluateWithin(node) {
    let identifier = node.identifier;
    let reference = node.reference;
    if (identifier === "$" && this.forContext && this.forContext["$"]) {
      identifier = this.forContext["$"];
    }
    if (reference === "$" && this.forContext && this.forContext["$"]) {
      reference = this.forContext["$"];
    }
    const distance = await this.evaluateNode(node.distance);
    const stringInfo = this.strings[identifier];
    const refInfo = this.strings[reference];
    if (!stringInfo || !stringInfo.offsets || stringInfo.offsets.length === 0) {
      return false;
    }
    if (!refInfo || !refInfo.offsets || refInfo.offsets.length === 0) {
      return false;
    }
    for (const offset of stringInfo.offsets) {
      for (const refOffset of refInfo.offsets) {
        const dist = Math.abs(offset - refOffset);
        if (dist <= distance) {
          return true;
        }
      }
    }
    return false;
  }
  /**
   * Evaluate module function call (e.g., string.to_int($version), time.now())
   */
  async evaluateModuleFunction(node) {
    const { module, function: functionName, args } = node;
    const moduleObj = this.modules[module];
    if (!moduleObj) {
      return void 0;
    }
    const func = moduleObj[functionName];
    if (typeof func !== "function") {
      return void 0;
    }
    const evaluatedArgs = await Promise.all(args.map(async (arg) => {
      const result = await this.evaluateNode(arg);
      if (arg.type === "stringIdentifier") {
        const stringInfo = this.strings[arg.identifier];
        if (stringInfo && stringInfo.matches && stringInfo.matches.length > 0) {
          const match = stringInfo.matches[0];
          if (match.value) {
            return match.value;
          }
          if (this.data && match.offset !== void 0 && match.length !== void 0) {
            const bytes = this.data.slice(match.offset, match.offset + match.length);
            return new TextDecoder().decode(bytes);
          }
        }
        return "";
      }
      return result;
    }));
    try {
      const result = func.apply(moduleObj, evaluatedArgs);
      return result instanceof Promise ? await result : result;
    } catch (error) {
      throw new Error(`Error calling ${module}.${functionName}: ${error.message}`);
    }
  }
  /**
   * Evaluate 'in' operator (value in (set))
   */
  async evaluateInOperator(node) {
    const value = await this.evaluateNode(node.value);
    const set = await this.evaluateNode(node.set);
    if (this.isAnyUndefined(value, set)) return void 0;
    if (Array.isArray(set)) {
      return set.includes(value);
    } else if (set && typeof set === "object" && set.start !== void 0 && set.end !== void 0) {
      return value >= set.start && value <= set.end;
    }
    return false;
  }
  /**
   * String contains (case-sensitive or insensitive)
   */
  async stringContains(leftNode, rightNode, ignoreCase = false) {
    let left = await this.evaluateNode(leftNode);
    let right = await this.evaluateNode(rightNode);
    if (this.isAnyUndefined(left, right)) return void 0;
    if (typeof left !== "string" || typeof right !== "string") {
      return false;
    }
    if (ignoreCase) {
      left = left.toLowerCase();
      right = right.toLowerCase();
    }
    return left.includes(right);
  }
  /**
   * String starts with
   */
  async stringStartsWith(leftNode, rightNode, ignoreCase = false) {
    let left = await this.evaluateNode(leftNode);
    let right = await this.evaluateNode(rightNode);
    if (this.isAnyUndefined(left, right)) return void 0;
    if (typeof left !== "string" || typeof right !== "string") {
      return false;
    }
    if (ignoreCase) {
      left = left.toLowerCase();
      right = right.toLowerCase();
    }
    return left.startsWith(right);
  }
  /**
   * String ends with
   */
  async stringEndsWith(leftNode, rightNode, ignoreCase = false) {
    let left = await this.evaluateNode(leftNode);
    let right = await this.evaluateNode(rightNode);
    if (this.isAnyUndefined(left, right)) return void 0;
    if (typeof left !== "string" || typeof right !== "string") {
      return false;
    }
    if (ignoreCase) {
      left = left.toLowerCase();
      right = right.toLowerCase();
    }
    return left.endsWith(right);
  }
  /**
   * String equals (case-insensitive)
   */
  async stringEquals(leftNode, rightNode, ignoreCase = false) {
    let left = await this.evaluateNode(leftNode);
    let right = await this.evaluateNode(rightNode);
    if (this.isAnyUndefined(left, right)) return void 0;
    if (typeof left !== "string" || typeof right !== "string") {
      return false;
    }
    if (ignoreCase) {
      left = left.toLowerCase();
      right = right.toLowerCase();
    }
    return left === right;
  }
  /**
   * String matches regex
   */
  async stringMatches(leftNode, rightNode) {
    const left = await this.evaluateNode(leftNode);
    const right = await this.evaluateNode(rightNode);
    if (this.isAnyUndefined(left, right)) return void 0;
    if (typeof left !== "string") {
      return false;
    }
    let regex;
    if (right instanceof RegExp) {
      regex = right;
    } else if (typeof right === "string") {
      regex = new RegExp(right);
    } else {
      return false;
    }
    return regex.test(left);
  }
};
async function evaluateCondition(condition, scanFacts) {
  const evaluator = new ConditionEvaluator(scanFacts);
  return evaluator.evaluate(condition);
}

// src/yaraConditionParser.mjs
var PLACEHOLDER_PREFIX = "__LITERAL_";
var PLACEHOLDER_SUFFIX = "__";
var DATA_ACCESS_TYPES = [
  { name: "uint8", bits: 8, signed: false, endian: "little" },
  { name: "uint16", bits: 16, signed: false, endian: "little" },
  { name: "uint32", bits: 32, signed: false, endian: "little" },
  { name: "int8", bits: 8, signed: true, endian: "little" },
  { name: "int16", bits: 16, signed: true, endian: "little" },
  { name: "int32", bits: 32, signed: true, endian: "little" },
  { name: "uint16be", bits: 16, signed: false, endian: "big" },
  { name: "uint32be", bits: 32, signed: false, endian: "big" },
  { name: "int16be", bits: 16, signed: true, endian: "big" },
  { name: "int32be", bits: 32, signed: true, endian: "big" }
];
function skipWhitespace(str, startIndex) {
  let index = startIndex;
  while (index < str.length && /\s/.test(str[index])) index++;
  return index;
}
function wrapsEntireExpression(expr) {
  if (!expr.startsWith("(") || !expr.endsWith(")")) return false;
  let depth = 0;
  for (let i = 0; i < expr.length; i++) {
    if (expr[i] === "(") depth++;
    if (expr[i] === ")") depth--;
    if (depth === 0 && i < expr.length - 1) return false;
  }
  return true;
}
function hasUnescapedQuotesInMiddle(str, quoteChar) {
  let escaped = false;
  for (let i = 1; i < str.length - 1; i++) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (str[i] === "\\") {
      escaped = true;
      continue;
    }
    if (str[i] === quoteChar) {
      return true;
    }
  }
  return false;
}
function isValidStringLiteral(str, quoteChar) {
  if (str.length === 2) {
    return true;
  }
  return !hasUnescapedQuotesInMiddle(str, quoteChar);
}
function extractStringLiterals(condition) {
  const literals = [];
  let processed = condition;
  let counter = 0;
  const extractQuoted = (text, quoteChar) => {
    const regex = new RegExp(`${quoteChar}(?:[^${quoteChar}\\\\]|\\\\.)*${quoteChar}`, "g");
    return text.replace(regex, (match) => {
      if (isValidStringLiteral(match, quoteChar)) {
        const placeholder = `${PLACEHOLDER_PREFIX}${counter}${PLACEHOLDER_SUFFIX}`;
        literals.push({
          id: placeholder,
          type: "string",
          value: match.slice(1, -1)
          // Remove quotes
        });
        counter++;
        return placeholder;
      }
      return match;
    });
  };
  processed = extractQuoted(processed, '"');
  processed = extractQuoted(processed, "'");
  return { processed, literals };
}
function restoreStringLiterals(ast, literals) {
  if (!ast || typeof ast !== "object") {
    return ast;
  }
  if (ast.type === "identifier" && ast.name && ast.name.startsWith(PLACEHOLDER_PREFIX)) {
    const literal = literals.find((lit) => lit.id === ast.name);
    if (literal) {
      return { type: "string", value: literal.value };
    }
  }
  const result = { ...ast };
  for (const key in result) {
    if (Object.prototype.hasOwnProperty.call(result, key)) {
      if (Array.isArray(result[key])) {
        result[key] = result[key].map((item) => {
          if (typeof item === "string" && item.startsWith(PLACEHOLDER_PREFIX)) {
            const literal = literals.find((lit) => lit.id === item);
            return literal ? literal.value : item;
          }
          return typeof item === "object" ? restoreStringLiterals(item, literals) : item;
        });
      } else if (typeof result[key] === "object") {
        result[key] = restoreStringLiterals(result[key], literals);
      }
    }
  }
  return result;
}
function parseConditionToAST(condition, strings = {}) {
  condition = condition.trim();
  const { processed, literals } = extractStringLiterals(condition);
  const ast = parseStructure(processed, strings);
  return restoreStringLiterals(ast, literals);
}
function parseQuantifier(condition) {
  const quantifierPattern = /^(any|all|none|\d+|\d+%|\d+\.\.\d+)\s+of\s+(them|\([^)]+\))$/;
  const match = condition.match(quantifierPattern);
  if (!match) return null;
  const [, quantPart, itemsPart] = match;
  let quantifier;
  let type;
  if (quantPart === "any") {
    type = "any";
  } else if (quantPart === "all") {
    type = "all";
  } else if (quantPart === "none") {
    type = "none";
  } else if (quantPart.includes("..")) {
    const [min, max] = quantPart.split("..").map((n) => parseInt(n));
    type = "quantified";
    quantifier = { type: "range", min, max };
  } else if (quantPart.endsWith("%")) {
    type = "quantified";
    quantifier = { type: "percentage", value: parseInt(quantPart) };
  } else {
    type = "quantified";
    quantifier = { type: "number", value: parseInt(quantPart) };
  }
  let items;
  if (itemsPart === "them") {
    items = "them";
  } else {
    const itemsStr = itemsPart.slice(1, -1);
    items = itemsStr.split(",").map((s) => s.trim());
  }
  return { type, ...quantifier && { quantifier }, items };
}
function parseStructure(condition, strings = {}) {
  condition = condition.trim();
  while (wrapsEntireExpression(condition)) {
    condition = condition.slice(1, -1).trim();
  }
  const quantifierNode = parseQuantifier(condition);
  if (quantifierNode) {
    return quantifierNode;
  }
  const parseBinaryOperator = (operator, operatorLength) => {
    const opIndex = findOperatorOutsideParens(condition, ` ${operator} `);
    if (opIndex === -1) return null;
    let endIndex = skipWhitespace(condition, opIndex);
    endIndex += operatorLength;
    endIndex = skipWhitespace(condition, endIndex);
    return {
      type: operator,
      left: parseStructure(condition.substring(0, opIndex), strings),
      right: parseStructure(condition.substring(endIndex), strings)
    };
  };
  const orNode = parseBinaryOperator("or", 2);
  if (orNode) return orNode;
  const andNode = parseBinaryOperator("and", 3);
  if (andNode) return andNode;
  if (condition.trim().startsWith("for ")) {
    const colonIndex = condition.indexOf(":");
    if (colonIndex !== -1) {
      let openParenIndex = colonIndex + 1;
      while (openParenIndex < condition.length && condition[openParenIndex] !== "(") {
        openParenIndex++;
      }
      if (openParenIndex < condition.length) {
        let depth = 1;
        let closeParenIndex = openParenIndex + 1;
        while (closeParenIndex < condition.length && depth > 0) {
          if (condition[closeParenIndex] === "(") depth++;
          if (condition[closeParenIndex] === ")") depth--;
          closeParenIndex++;
        }
        if (depth === 0) {
          const forHeader = condition.substring(0, colonIndex).trim();
          const bodyCondition = condition.substring(openParenIndex + 1, closeParenIndex - 1).trim();
          const parseForQuantifier = (quantifierStr) => {
            if (["all", "any", "none"].includes(quantifierStr)) return quantifierStr;
            if (quantifierStr.endsWith("%")) {
              return { type: "percentage", value: parseInt(quantifierStr) };
            }
            return { type: "number", value: parseInt(quantifierStr) };
          };
          const parseForIterator = (iteratorPart) => {
            const iteratorInRangeMatch = iteratorPart.match(/^(\w+)\s+in\s+\((.+?)\.\.(.+?)\)$/);
            if (iteratorInRangeMatch) {
              return {
                variable: iteratorInRangeMatch[1],
                set: {
                  type: "range",
                  start: parseExpression(iteratorInRangeMatch[2].trim()),
                  end: parseExpression(iteratorInRangeMatch[3].trim())
                }
              };
            }
            const ofMatch = iteratorPart.match(/^of\s+(.+)$/);
            if (ofMatch) {
              const setStr = ofMatch[1].trim();
              let items;
              if (setStr === "them") {
                items = "them";
              } else if (setStr.startsWith("(") && setStr.endsWith(")")) {
                items = setStr.slice(1, -1).split(",").map((s) => s.trim());
              } else {
                items = setStr;
              }
              return {
                variable: "$",
                // implicit variable for strings
                set: { type: "stringSet", items }
              };
            }
            return { variable: null, set: null };
          };
          const forMatch = forHeader.match(/^for\s+(all|any|none|\d+|(\d+)%)\s+(.+)$/);
          if (forMatch) {
            const quantifier = parseForQuantifier(forMatch[1]);
            const { variable, set } = parseForIterator(forMatch[3]);
            return {
              type: "for",
              quantifier,
              variable,
              set,
              condition: parseStructure(bodyCondition, strings)
            };
          }
        }
      }
    }
  }
  if (condition.startsWith("not ")) {
    return {
      type: "not",
      operand: parseStructure(condition.substring(4), strings)
    };
  }
  if (condition.startsWith("defined ")) {
    return {
      type: "defined",
      operand: parseStructure(condition.substring(8), strings)
    };
  }
  const atMatch = condition.match(/^(\$\w*|\w+)\s+at\s+(.+)$/);
  if (atMatch) {
    const firstPart = atMatch[1];
    if (firstPart.startsWith("$")) {
      return {
        type: "at",
        identifier: firstPart,
        offset: parseExpression(atMatch[2])
      };
    } else if (firstPart.startsWith(PLACEHOLDER_PREFIX)) {
      return {
        type: "at",
        identifier: parseExpression(firstPart),
        offset: parseExpression(atMatch[2])
      };
    }
  }
  const inRangeMatch = condition.match(/^(\$\w*)\s+in\s+\((.+)\.\.(.+)\)$/);
  if (inRangeMatch) {
    return {
      type: "inRange",
      identifier: inRangeMatch[1],
      range: {
        type: "range",
        start: parseExpression(inRangeMatch[2]),
        end: parseExpression(inRangeMatch[3])
      }
    };
  }
  const withinMatch = condition.match(/^(\$\w*)\s+within\s+(.+?)(?:\s+bytes)?\s+of\s+(\$\w*)$/);
  if (withinMatch) {
    return {
      type: "within",
      identifier: withinMatch[1],
      distance: parseExpression(withinMatch[2]),
      reference: withinMatch[3]
    };
  }
  const stringOps = [
    { pattern: "icontains", type: "icontains" },
    { pattern: "contains", type: "contains" },
    { pattern: "istartswith", type: "istartswith" },
    { pattern: "startswith", type: "startswith" },
    { pattern: "iendswith", type: "iendswith" },
    { pattern: "endswith", type: "endswith" }
  ];
  for (const op of stringOps) {
    const opIndex = findOperatorOutsideParens(condition, ` ${op.pattern} `);
    if (opIndex !== -1) {
      let endIndex = opIndex;
      while (endIndex < condition.length && /\s/.test(condition[endIndex])) endIndex++;
      endIndex += op.pattern.length;
      while (endIndex < condition.length && /\s/.test(condition[endIndex])) endIndex++;
      return {
        type: op.type,
        left: parseExpression(condition.substring(0, opIndex)),
        right: parseExpression(condition.substring(endIndex))
      };
    }
  }
  const comparisonOps = [
    { pattern: "==", type: "equal" },
    { pattern: "!=", type: "notEqual" },
    { pattern: "<=", type: "lessThanOrEqual" },
    { pattern: ">=", type: "greaterThanOrEqual" },
    { pattern: "<", type: "lessThan" },
    { pattern: ">", type: "greaterThan" }
  ];
  for (const op of comparisonOps) {
    const opIndex = findOperatorOutsideParens(condition, op.pattern);
    if (opIndex !== -1) {
      return {
        type: op.type,
        left: parseExpression(condition.substring(0, opIndex)),
        right: parseExpression(condition.substring(opIndex + op.pattern.length))
      };
    }
  }
  return parseExpression(condition);
}
function parseExpression(expr) {
  expr = expr.trim();
  if (expr === "true") {
    return { type: "boolean", value: true };
  }
  if (expr === "false") {
    return { type: "boolean", value: false };
  }
  const sizeUnitMatch = expr.match(/^(\d+)(KB|MB|GB)$/i);
  if (sizeUnitMatch) {
    const value = parseInt(sizeUnitMatch[1]);
    const unit = sizeUnitMatch[2].toUpperCase();
    const multipliers = { KB: 1024, MB: 1024 * 1024, GB: 1024 * 1024 * 1024 };
    return { type: "number", value: value * multipliers[unit] };
  }
  if (/^-?\d+\.\d+$/.test(expr)) {
    return { type: "number", value: parseFloat(expr) };
  }
  if (/^-?\d+$/.test(expr)) {
    return { type: "number", value: parseInt(expr) };
  }
  if (/^0x[0-9a-fA-F]+$/.test(expr)) {
    return { type: "number", value: parseInt(expr, 16) };
  }
  if (/^\$\w*$/.test(expr)) {
    return { type: "stringIdentifier", identifier: expr };
  }
  if (/^#\w*$/.test(expr)) {
    return { type: "stringCount", identifier: expr.replace("#", "$") };
  }
  if (/^@\w*$/.test(expr)) {
    return { type: "stringOffset", identifier: expr.replace("@", "$"), index: 0 };
  }
  const parseIndexedStringOp = (expr2, prefix, type) => {
    const pattern = new RegExp(`^\\${prefix}([\\w$]+)\\[([^\\]]+)\\]$`);
    const match = expr2.match(pattern);
    if (!match) return null;
    const identifierPart = match[1];
    const indexExpr = match[2].trim();
    const identifier = identifierPart.startsWith("$") ? identifierPart : `$${identifierPart}`;
    const index = /^\d+$/.test(indexExpr) ? parseInt(indexExpr) : parseExpression(indexExpr);
    return { type, identifier, index };
  };
  const offsetIndexed = parseIndexedStringOp(expr, "@", "stringOffset");
  if (offsetIndexed) return offsetIndexed;
  if (/^![\w$]+$/.test(expr)) {
    const id = expr.slice(1);
    return { type: "stringLength", identifier: id.startsWith("$") ? id : `$${id}`, index: 0 };
  }
  const lengthIndexed = parseIndexedStringOp(expr, "!", "stringLength");
  if (lengthIndexed) return lengthIndexed;
  if (expr === "filesize") {
    return { type: "identifier", name: "filesize" };
  }
  if (expr === "entrypoint") {
    return { type: "identifier", name: "entrypoint" };
  }
  for (const dataAccessType of DATA_ACCESS_TYPES) {
    const pattern = new RegExp(`^${dataAccessType.name}\\((.+)\\)$`);
    const match = expr.match(pattern);
    if (match) {
      return {
        type: "dataAccess",
        dataType: dataAccessType.name.replace("be", ""),
        // Remove 'be' suffix for storage
        offset: parseExpression(match[1]),
        endian: dataAccessType.endian
      };
    }
  }
  const moduleFuncMatch = expr.match(/^(\w+)\.(\w+)\((.*)\)$/);
  if (moduleFuncMatch) {
    const [, moduleName, functionName, argsStr] = moduleFuncMatch;
    let args = [];
    if (argsStr.trim()) {
      let depth = 0;
      let currentArg = "";
      for (let i = 0; i < argsStr.length; i++) {
        const ch = argsStr[i];
        if (ch === "(") depth++;
        if (ch === ")") depth--;
        if (ch === "," && depth === 0) {
          args.push(parseExpression(currentArg.trim()));
          currentArg = "";
        } else {
          currentArg += ch;
        }
      }
      if (currentArg.trim()) {
        args.push(parseExpression(currentArg.trim()));
      }
    }
    return {
      type: "moduleFunction",
      module: moduleName,
      function: functionName,
      args
    };
  }
  const moduleArrayChainMatch = expr.match(/^(\w+)\.(\w+)\[([^\]]+)\]\.?(\w*)$/);
  if (moduleArrayChainMatch) {
    const [, moduleName, propertyName, indexExpr, rest] = moduleArrayChainMatch;
    let node = {
      type: "arrayAccess",
      object: {
        type: "memberAccess",
        object: { type: "identifier", name: moduleName },
        property: propertyName
      },
      index: parseExpression(indexExpr.trim())
    };
    if (rest) {
      const chainedProperties = rest.split(".");
      for (const prop of chainedProperties) {
        if (prop) {
          node = {
            type: "memberAccess",
            object: node,
            property: prop
          };
        }
      }
    }
    return node;
  }
  const modulePropMatch = expr.match(/^(\w+)\.(\w+)$/);
  if (modulePropMatch) {
    const [, moduleName, propertyName] = modulePropMatch;
    return {
      type: "memberAccess",
      object: { type: "identifier", name: moduleName },
      property: propertyName
    };
  }
  if (expr.startsWith("~")) {
    const rest = expr.substring(1).trim();
    let operandEnd = 0;
    if (rest.startsWith("(")) {
      let depth = 1;
      operandEnd = 1;
      while (operandEnd < rest.length && depth > 0) {
        if (rest[operandEnd] === "(") depth++;
        if (rest[operandEnd] === ")") depth--;
        operandEnd++;
      }
    } else if (rest.startsWith("~")) {
      let idx = 0;
      while (idx < rest.length && rest[idx] === "~") {
        idx++;
      }
      const afterTildes = rest.substring(idx).trim();
      let primaryEnd = 0;
      if (afterTildes.startsWith("(")) {
        let depth = 1;
        primaryEnd = 1;
        while (primaryEnd < afterTildes.length && depth > 0) {
          if (afterTildes[primaryEnd] === "(") depth++;
          if (afterTildes[primaryEnd] === ")") depth--;
          primaryEnd++;
        }
      } else {
        const funcMatch = afterTildes.match(/^([a-zA-Z_$]\w*)\s*\(/);
        if (funcMatch) {
          let depth = 1;
          primaryEnd = funcMatch[0].length;
          while (primaryEnd < afterTildes.length && depth > 0) {
            if (afterTildes[primaryEnd] === "(") depth++;
            if (afterTildes[primaryEnd] === ")") depth--;
            primaryEnd++;
          }
        } else {
          const match = afterTildes.match(/^(0x[0-9a-fA-F]+|\d+|[a-zA-Z_$]\w*)/);
          if (match) {
            primaryEnd = match[0].length;
          }
        }
      }
      operandEnd = idx + primaryEnd;
    } else {
      const funcMatch = rest.match(/^([a-zA-Z_$]\w*)\s*\(/);
      if (funcMatch) {
        let depth = 1;
        operandEnd = funcMatch[0].length;
        while (operandEnd < rest.length && depth > 0) {
          if (rest[operandEnd] === "(") depth++;
          if (rest[operandEnd] === ")") depth--;
          operandEnd++;
        }
      } else {
        const match = rest.match(/^(0x[0-9a-fA-F]+|\d+|[a-zA-Z_$]\w*)/);
        if (match) {
          operandEnd = match[0].length;
        } else {
          return {
            type: "bitwiseNot",
            operand: parseExpression(rest)
          };
        }
      }
    }
    const operand = parseExpression(rest.substring(0, operandEnd));
    const remaining = rest.substring(operandEnd).trim();
    if (remaining) {
      const fullExpr = "(" + expr.substring(0, operandEnd + 1) + ")" + remaining;
      return parseExpression(fullExpr);
    }
    return {
      type: "bitwiseNot",
      operand
    };
  }
  const bitwiseOrIndex = findOperatorOutsideParens(expr, "|");
  if (bitwiseOrIndex !== -1) {
    return {
      type: "bitwiseOr",
      left: parseExpression(expr.substring(0, bitwiseOrIndex)),
      right: parseExpression(expr.substring(bitwiseOrIndex + 1))
    };
  }
  const bitwiseXorIndex = findOperatorOutsideParens(expr, "^");
  if (bitwiseXorIndex !== -1) {
    return {
      type: "bitwiseXor",
      left: parseExpression(expr.substring(0, bitwiseXorIndex)),
      right: parseExpression(expr.substring(bitwiseXorIndex + 1))
    };
  }
  const bitwiseAndIndex = findOperatorOutsideParens(expr, "&");
  if (bitwiseAndIndex !== -1) {
    return {
      type: "bitwiseAnd",
      left: parseExpression(expr.substring(0, bitwiseAndIndex)),
      right: parseExpression(expr.substring(bitwiseAndIndex + 1))
    };
  }
  const shiftLeftIndex = findOperatorOutsideParens(expr, "<<");
  if (shiftLeftIndex !== -1) {
    return {
      type: "shiftLeft",
      left: parseExpression(expr.substring(0, shiftLeftIndex)),
      right: parseExpression(expr.substring(shiftLeftIndex + 2))
    };
  }
  const shiftRightIndex = findOperatorOutsideParens(expr, ">>");
  if (shiftRightIndex !== -1) {
    return {
      type: "shiftRight",
      left: parseExpression(expr.substring(0, shiftRightIndex)),
      right: parseExpression(expr.substring(shiftRightIndex + 2))
    };
  }
  const arithmeticOps = [
    { pattern: "+", type: "add" },
    { pattern: "-", type: "subtract" },
    { pattern: "*", type: "multiply" },
    { pattern: "\\", type: "divide" },
    { pattern: "%", type: "modulo" }
  ];
  for (const op of arithmeticOps) {
    const opIndex = findOperatorOutsideParens(expr, op.pattern);
    if (opIndex !== -1) {
      return {
        type: op.type,
        left: parseExpression(expr.substring(0, opIndex)),
        right: parseExpression(expr.substring(opIndex + op.pattern.length))
      };
    }
  }
  if (expr.startsWith("(") && expr.endsWith(")")) {
    let depth = 0;
    let wrapsEntireExpression2 = true;
    for (let i = 0; i < expr.length; i++) {
      if (expr[i] === "(") depth++;
      if (expr[i] === ")") depth--;
      if (depth === 0 && i < expr.length - 1) {
        wrapsEntireExpression2 = false;
        break;
      }
    }
    if (wrapsEntireExpression2) {
      return parseExpression(expr.slice(1, -1));
    }
  }
  if (/^[A-Z][a-zA-Z0-9_]*$/.test(expr)) {
    return { type: "ruleIdentifier", name: expr };
  }
  return { type: "identifier", name: expr };
}
function findOperatorOutsideParens(str, op) {
  const opTrimmed = op.trim();
  const isWordOp = /^(and|or|not)$/.test(opTrimmed);
  let parenDepth = 0;
  let bracketDepth = 0;
  for (let i = 0; i < str.length; i++) {
    if (str[i] === "(") parenDepth++;
    if (str[i] === ")") parenDepth--;
    if (str[i] === "[") bracketDepth++;
    if (str[i] === "]") bracketDepth--;
    if (parenDepth === 0 && bracketDepth === 0) {
      if (isWordOp) {
        const hasWhitespaceBefore = i === 0 || /\s/.test(str[i - 1]);
        if (!hasWhitespaceBefore) continue;
        let j = i;
        while (j < str.length && /\s/.test(str[j])) j++;
        if (str.substring(j, j + opTrimmed.length) === opTrimmed) {
          const afterOp = j + opTrimmed.length;
          const hasWhitespaceAfter = afterOp >= str.length || /\s/.test(str[afterOp]);
          if (hasWhitespaceAfter) {
            return i;
          }
        }
      } else {
        if (str.substring(i, i + op.length) === op) {
          return i;
        }
      }
    }
  }
  return -1;
}

// node_modules/pe-library/dist/format/index.js
var format_exports = {};
__export(format_exports, {
  ArrayFormatBase: () => ArrayFormatBase_default,
  FormatBase: () => FormatBase_default,
  ImageDataDirectoryArray: () => ImageDataDirectoryArray_default,
  ImageDirectoryEntry: () => ImageDirectoryEntry_default,
  ImageDosHeader: () => ImageDosHeader_default,
  ImageFileHeader: () => ImageFileHeader_default,
  ImageNtHeaders: () => ImageNtHeaders_default,
  ImageOptionalHeader: () => ImageOptionalHeader_default,
  ImageOptionalHeader64: () => ImageOptionalHeader64_default,
  ImageSectionHeaderArray: () => ImageSectionHeaderArray_default,
  findImageSectionBlockByDirectoryEntry: () => findImageSectionBlockByDirectoryEntry,
  getImageDosHeader: () => getImageDosHeader,
  getImageNtHeadersByDosHeader: () => getImageNtHeadersByDosHeader,
  getImageSectionHeadersByNtHeaders: () => getImageSectionHeadersByNtHeaders
});

// node_modules/pe-library/dist/format/FormatBase.js
var FormatBase = (
  /** @class */
  (function() {
    function FormatBase2(view) {
      this.view = view;
    }
    FormatBase2.prototype.copyTo = function(bin, offset) {
      new Uint8Array(bin, offset, this.view.byteLength).set(new Uint8Array(this.view.buffer, this.view.byteOffset, this.view.byteLength));
    };
    Object.defineProperty(FormatBase2.prototype, "byteLength", {
      get: function() {
        return this.view.byteLength;
      },
      enumerable: false,
      configurable: true
    });
    return FormatBase2;
  })()
);
var FormatBase_default = FormatBase;

// node_modules/pe-library/dist/format/ArrayFormatBase.js
var __extends = /* @__PURE__ */ (function() {
  var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d2, b2) {
      d2.__proto__ = b2;
    } || function(d2, b2) {
      for (var p in b2) if (Object.prototype.hasOwnProperty.call(b2, p)) d2[p] = b2[p];
    };
    return extendStatics(d, b);
  };
  return function(d, b) {
    if (typeof b !== "function" && b !== null)
      throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
    extendStatics(d, b);
    function __() {
      this.constructor = d;
    }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
  };
})();
var ArrayFormatBase = (
  /** @class */
  (function(_super) {
    __extends(ArrayFormatBase2, _super);
    function ArrayFormatBase2(view) {
      return _super.call(this, view) || this;
    }
    ArrayFormatBase2.prototype.forEach = function(callback) {
      var len = this.length;
      var a = [];
      a.length = len;
      for (var i = 0; i < len; ++i) {
        a[i] = this.get(i);
      }
      for (var i = 0; i < len; ++i) {
        callback(a[i], i, this);
      }
    };
    ArrayFormatBase2.prototype._iterator = function() {
      return new /** @class */
      ((function() {
        function class_1(base) {
          this.base = base;
          this.i = 0;
        }
        class_1.prototype.next = function() {
          if (this.i === this.base.length) {
            return {
              value: void 0,
              done: true
            };
          } else {
            return {
              value: this.base.get(this.i++),
              done: false
            };
          }
        };
        return class_1;
      })())(this);
    };
    return ArrayFormatBase2;
  })(FormatBase_default)
);
if (typeof Symbol !== "undefined") {
  ArrayFormatBase.prototype[Symbol.iterator] = // eslint-disable-next-line @typescript-eslint/unbound-method
  ArrayFormatBase.prototype._iterator;
}
var ArrayFormatBase_default = ArrayFormatBase;

// node_modules/pe-library/dist/format/ImageDataDirectoryArray.js
var __extends2 = /* @__PURE__ */ (function() {
  var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d2, b2) {
      d2.__proto__ = b2;
    } || function(d2, b2) {
      for (var p in b2) if (Object.prototype.hasOwnProperty.call(b2, p)) d2[p] = b2[p];
    };
    return extendStatics(d, b);
  };
  return function(d, b) {
    if (typeof b !== "function" && b !== null)
      throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
    extendStatics(d, b);
    function __() {
      this.constructor = d;
    }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
  };
})();
var ImageDataDirectoryArray = (
  /** @class */
  (function(_super) {
    __extends2(ImageDataDirectoryArray2, _super);
    function ImageDataDirectoryArray2(view) {
      var _this = _super.call(this, view) || this;
      _this.length = 16;
      return _this;
    }
    ImageDataDirectoryArray2.from = function(bin, offset) {
      if (offset === void 0) {
        offset = 0;
      }
      return new ImageDataDirectoryArray2(new DataView(bin, offset, 128));
    };
    ImageDataDirectoryArray2.prototype.get = function(index) {
      return {
        virtualAddress: this.view.getUint32(index * 8, true),
        size: this.view.getUint32(4 + index * 8, true)
      };
    };
    ImageDataDirectoryArray2.prototype.set = function(index, data) {
      this.view.setUint32(index * 8, data.virtualAddress, true);
      this.view.setUint32(4 + index * 8, data.size, true);
    };
    ImageDataDirectoryArray2.prototype.findIndexByVirtualAddress = function(virtualAddress) {
      for (var i = 0; i < 16; ++i) {
        var va = this.view.getUint32(i * 8, true);
        var vs = this.view.getUint32(4 + i * 8, true);
        if (virtualAddress >= va && virtualAddress < va + vs) {
          return i;
        }
      }
      return null;
    };
    ImageDataDirectoryArray2.size = 128;
    ImageDataDirectoryArray2.itemSize = 8;
    return ImageDataDirectoryArray2;
  })(ArrayFormatBase_default)
);
var ImageDataDirectoryArray_default = ImageDataDirectoryArray;

// node_modules/pe-library/dist/format/ImageDirectoryEntry.js
var ImageDirectoryEntry = {
  Export: 0,
  Import: 1,
  Resource: 2,
  Exception: 3,
  Certificate: 4,
  Security: 4,
  BaseRelocation: 5,
  Debug: 6,
  Architecture: 7,
  GlobalPointer: 8,
  Tls: 9,
  TLS: 9,
  LoadConfig: 10,
  BoundImport: 11,
  Iat: 12,
  IAT: 12,
  DelayImport: 13,
  ComDescriptor: 14,
  COMDescriptor: 14
  // alias
};
var ImageDirectoryEntry_default = ImageDirectoryEntry;

// node_modules/pe-library/dist/util/functions.js
function cloneObject(object) {
  var r = {};
  Object.keys(object).forEach(function(key) {
    r[key] = object[key];
  });
  return r;
}
function createDataView(bin, byteOffset, byteLength) {
  if ("buffer" in bin) {
    var newOffset = bin.byteOffset;
    var newLength = bin.byteLength;
    if (typeof byteOffset !== "undefined") {
      newOffset += byteOffset;
      newLength -= byteOffset;
    }
    if (typeof byteLength !== "undefined") {
      newLength = byteLength;
    }
    return new DataView(bin.buffer, newOffset, newLength);
  } else {
    return new DataView(bin, byteOffset, byteLength);
  }
}
function calculateCheckSumForPE(bin, storeToBinary) {
  var dosHeader = ImageDosHeader_default.from(bin);
  var view = new DataView(bin);
  var checkSumOffset = dosHeader.newHeaderAddress + 88;
  var result = 0;
  var limit = 4294967296;
  var update = function(dword) {
    result += dword;
    if (result >= limit) {
      result = result % limit + (result / limit | 0);
    }
  };
  var len = view.byteLength;
  var lenExtra = len % 4;
  var lenAlign = len - lenExtra;
  for (var i = 0; i < lenAlign; i += 4) {
    if (i !== checkSumOffset) {
      update(view.getUint32(i, true));
    }
  }
  if (lenExtra !== 0) {
    var extra = 0;
    for (var i = 0; i < lenExtra; i++) {
      extra |= view.getUint8(lenAlign + i) << (3 - i) * 8;
    }
    update(extra);
  }
  result = (result & 65535) + (result >>> 16);
  result += result >>> 16;
  result = (result & 65535) + len;
  if (storeToBinary) {
    view.setUint32(checkSumOffset, result, true);
  }
  return result;
}
function roundUp(val, align) {
  return Math.floor((val + align - 1) / align) * align;
}
function copyBuffer(dest, destOffset, src, srcOffset, length) {
  var ua8Dest = "buffer" in dest ? new Uint8Array(dest.buffer, dest.byteOffset + (destOffset || 0), length) : new Uint8Array(dest, destOffset, length);
  var ua8Src = "buffer" in src ? new Uint8Array(src.buffer, src.byteOffset + (srcOffset || 0), length) : new Uint8Array(src, srcOffset, length);
  ua8Dest.set(ua8Src);
}
function allocatePartialBinary(binBase, offset, length) {
  var b = new ArrayBuffer(length);
  copyBuffer(b, 0, binBase, offset, length);
  return b;
}
function cloneToArrayBuffer(binBase) {
  if ("buffer" in binBase) {
    var b = new ArrayBuffer(binBase.byteLength);
    new Uint8Array(b).set(new Uint8Array(binBase.buffer, binBase.byteOffset, binBase.byteLength));
    return b;
  } else {
    var b = new ArrayBuffer(binBase.byteLength);
    new Uint8Array(b).set(new Uint8Array(binBase));
    return b;
  }
}
function getFixedString(view, offset, length) {
  var actualLen = 0;
  for (var i = 0; i < length; ++i) {
    if (view.getUint8(offset + i) === 0) {
      break;
    }
    ++actualLen;
  }
  if (typeof Buffer !== "undefined") {
    return Buffer.from(view.buffer, view.byteOffset + offset, actualLen).toString("utf8");
  } else if (typeof decodeURIComponent !== "undefined") {
    var s = "";
    for (var i = 0; i < actualLen; ++i) {
      var c = view.getUint8(offset + i);
      if (c < 16) {
        s += "%0" + c.toString(16);
      } else {
        s += "%" + c.toString(16);
      }
    }
    return decodeURIComponent(s);
  } else {
    var s = "";
    for (var i = 0; i < actualLen; ++i) {
      var c = view.getUint8(offset + i);
      s += String.fromCharCode(c);
    }
    return s;
  }
}
function setFixedString(view, offset, length, text) {
  if (typeof Buffer !== "undefined") {
    var u = new Uint8Array(view.buffer, view.byteOffset + offset, length);
    u.set(new Uint8Array(length));
    u.set(Buffer.from(text, "utf8").subarray(0, length));
  } else if (typeof encodeURIComponent !== "undefined") {
    var s = encodeURIComponent(text);
    for (var i = 0, j = 0; i < length; ++i) {
      if (j >= s.length) {
        view.setUint8(i + offset, 0);
      } else {
        var c = s.charCodeAt(j);
        if (c === 37) {
          var n = parseInt(s.substr(j + 1, 2), 16);
          if (typeof n === "number" && !isNaN(n)) {
            view.setUint8(i + offset, n);
          } else {
            view.setUint8(i + offset, 0);
          }
          j += 3;
        } else {
          view.setUint8(i + offset, c);
        }
      }
    }
  } else {
    for (var i = 0, j = 0; i < length; ++i) {
      if (j >= text.length) {
        view.setUint8(i + offset, 0);
      } else {
        var c = text.charCodeAt(j);
        view.setUint8(i + offset, c & 255);
      }
    }
  }
}
function binaryToString(bin) {
  if (typeof TextDecoder !== "undefined") {
    var dec = new TextDecoder();
    return dec.decode(bin);
  } else if (typeof Buffer !== "undefined") {
    var b = void 0;
    if ("buffer" in bin) {
      b = Buffer.from(bin.buffer, bin.byteOffset, bin.byteLength);
    } else {
      b = Buffer.from(bin);
    }
    return b.toString("utf8");
  } else {
    var view = void 0;
    if ("buffer" in bin) {
      view = new Uint8Array(bin.buffer, bin.byteOffset, bin.byteLength);
    } else {
      view = new Uint8Array(bin);
    }
    if (typeof decodeURIComponent !== "undefined") {
      var s = "";
      for (var i = 0; i < view.length; ++i) {
        var c = view[i];
        if (c < 16) {
          s += "%0" + c.toString(16);
        } else {
          s += "%" + c.toString(16);
        }
      }
      return decodeURIComponent(s);
    } else {
      var s = "";
      for (var i = 0; i < view.length; ++i) {
        var c = view[i];
        s += String.fromCharCode(c);
      }
      return s;
    }
  }
}
function stringToBinary(string2) {
  if (typeof TextEncoder !== "undefined") {
    var enc = new TextEncoder();
    return cloneToArrayBuffer(enc.encode(string2));
  } else if (typeof Buffer !== "undefined") {
    return cloneToArrayBuffer(Buffer.from(string2, "utf8"));
  } else if (typeof encodeURIComponent !== "undefined") {
    var data = encodeURIComponent(string2);
    var len = 0;
    for (var i = 0; i < data.length; ++len) {
      var c = data.charCodeAt(i);
      if (c === 37) {
        i += 3;
      } else {
        ++i;
      }
    }
    var bin = new ArrayBuffer(len);
    var view = new Uint8Array(bin);
    for (var i = 0, j = 0; i < data.length; ++j) {
      var c = data.charCodeAt(i);
      if (c === 37) {
        var n = parseInt(data.substring(i + 1, i + 3), 16);
        view[j] = n;
        i += 3;
      } else {
        view[j] = c;
        ++i;
      }
    }
    return bin;
  } else {
    var bin = new ArrayBuffer(string2.length);
    new Uint8Array(bin).set([].map.call(string2, function(c2) {
      return c2.charCodeAt(0);
    }));
    return bin;
  }
}

// node_modules/pe-library/dist/format/ImageDosHeader.js
var __extends3 = /* @__PURE__ */ (function() {
  var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d2, b2) {
      d2.__proto__ = b2;
    } || function(d2, b2) {
      for (var p in b2) if (Object.prototype.hasOwnProperty.call(b2, p)) d2[p] = b2[p];
    };
    return extendStatics(d, b);
  };
  return function(d, b) {
    if (typeof b !== "function" && b !== null)
      throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
    extendStatics(d, b);
    function __() {
      this.constructor = d;
    }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
  };
})();
var ImageDosHeader = (
  /** @class */
  (function(_super) {
    __extends3(ImageDosHeader2, _super);
    function ImageDosHeader2(view) {
      return _super.call(this, view) || this;
    }
    ImageDosHeader2.from = function(bin, offset) {
      if (offset === void 0) {
        offset = 0;
      }
      return new ImageDosHeader2(createDataView(bin, offset, 64));
    };
    ImageDosHeader2.prototype.isValid = function() {
      return this.magic === ImageDosHeader2.DEFAULT_MAGIC;
    };
    Object.defineProperty(ImageDosHeader2.prototype, "magic", {
      get: function() {
        return this.view.getUint16(0, true);
      },
      set: function(val) {
        this.view.setUint16(0, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "lastPageSize", {
      get: function() {
        return this.view.getUint16(2, true);
      },
      set: function(val) {
        this.view.setUint16(2, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "pages", {
      get: function() {
        return this.view.getUint16(4, true);
      },
      set: function(val) {
        this.view.setUint16(4, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "relocations", {
      get: function() {
        return this.view.getUint16(6, true);
      },
      set: function(val) {
        this.view.setUint16(6, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "headerSizeInParagraph", {
      get: function() {
        return this.view.getUint16(8, true);
      },
      set: function(val) {
        this.view.setUint16(8, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "minAllocParagraphs", {
      get: function() {
        return this.view.getUint16(10, true);
      },
      set: function(val) {
        this.view.setUint16(10, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "maxAllocParagraphs", {
      get: function() {
        return this.view.getUint16(12, true);
      },
      set: function(val) {
        this.view.setUint16(12, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "initialSS", {
      get: function() {
        return this.view.getUint16(14, true);
      },
      set: function(val) {
        this.view.setUint16(14, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "initialSP", {
      get: function() {
        return this.view.getUint16(16, true);
      },
      set: function(val) {
        this.view.setUint16(16, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "checkSum", {
      get: function() {
        return this.view.getUint16(18, true);
      },
      set: function(val) {
        this.view.setUint16(18, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "initialIP", {
      get: function() {
        return this.view.getUint16(20, true);
      },
      set: function(val) {
        this.view.setUint16(20, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "initialCS", {
      get: function() {
        return this.view.getUint16(22, true);
      },
      set: function(val) {
        this.view.setUint16(22, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "relocationTableAddress", {
      get: function() {
        return this.view.getUint16(24, true);
      },
      set: function(val) {
        this.view.setUint16(24, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "overlayNum", {
      get: function() {
        return this.view.getUint16(26, true);
      },
      set: function(val) {
        this.view.setUint16(26, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "oemId", {
      // WORD e_res[4] (28,30,32,34)
      get: function() {
        return this.view.getUint16(36, true);
      },
      set: function(val) {
        this.view.setUint16(36, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "oemInfo", {
      get: function() {
        return this.view.getUint16(38, true);
      },
      set: function(val) {
        this.view.setUint16(38, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageDosHeader2.prototype, "newHeaderAddress", {
      // WORD e_res2[10] (40,42,44,46,48,50,52,54,56,58)
      get: function() {
        return this.view.getUint32(60, true);
      },
      set: function(val) {
        this.view.setUint32(60, val, true);
      },
      enumerable: false,
      configurable: true
    });
    ImageDosHeader2.size = 64;
    ImageDosHeader2.DEFAULT_MAGIC = 23117;
    return ImageDosHeader2;
  })(FormatBase_default)
);
var ImageDosHeader_default = ImageDosHeader;

// node_modules/pe-library/dist/format/ImageFileHeader.js
var __extends4 = /* @__PURE__ */ (function() {
  var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d2, b2) {
      d2.__proto__ = b2;
    } || function(d2, b2) {
      for (var p in b2) if (Object.prototype.hasOwnProperty.call(b2, p)) d2[p] = b2[p];
    };
    return extendStatics(d, b);
  };
  return function(d, b) {
    if (typeof b !== "function" && b !== null)
      throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
    extendStatics(d, b);
    function __() {
      this.constructor = d;
    }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
  };
})();
var ImageFileHeader = (
  /** @class */
  (function(_super) {
    __extends4(ImageFileHeader2, _super);
    function ImageFileHeader2(view) {
      return _super.call(this, view) || this;
    }
    ImageFileHeader2.from = function(bin, offset) {
      if (offset === void 0) {
        offset = 0;
      }
      return new ImageFileHeader2(new DataView(bin, offset, 20));
    };
    Object.defineProperty(ImageFileHeader2.prototype, "machine", {
      get: function() {
        return this.view.getUint16(0, true);
      },
      set: function(val) {
        this.view.setUint16(0, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageFileHeader2.prototype, "numberOfSections", {
      get: function() {
        return this.view.getUint16(2, true);
      },
      set: function(val) {
        this.view.setUint16(2, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageFileHeader2.prototype, "timeDateStamp", {
      get: function() {
        return this.view.getUint32(4, true);
      },
      set: function(val) {
        this.view.setUint32(4, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageFileHeader2.prototype, "pointerToSymbolTable", {
      get: function() {
        return this.view.getUint32(8, true);
      },
      set: function(val) {
        this.view.setUint32(8, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageFileHeader2.prototype, "numberOfSymbols", {
      get: function() {
        return this.view.getUint32(12, true);
      },
      set: function(val) {
        this.view.setUint32(12, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageFileHeader2.prototype, "sizeOfOptionalHeader", {
      get: function() {
        return this.view.getUint16(16, true);
      },
      set: function(val) {
        this.view.setUint16(16, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageFileHeader2.prototype, "characteristics", {
      get: function() {
        return this.view.getUint16(18, true);
      },
      set: function(val) {
        this.view.setUint16(18, val, true);
      },
      enumerable: false,
      configurable: true
    });
    ImageFileHeader2.size = 20;
    return ImageFileHeader2;
  })(FormatBase_default)
);
var ImageFileHeader_default = ImageFileHeader;

// node_modules/pe-library/dist/format/ImageOptionalHeader.js
var __extends5 = /* @__PURE__ */ (function() {
  var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d2, b2) {
      d2.__proto__ = b2;
    } || function(d2, b2) {
      for (var p in b2) if (Object.prototype.hasOwnProperty.call(b2, p)) d2[p] = b2[p];
    };
    return extendStatics(d, b);
  };
  return function(d, b) {
    if (typeof b !== "function" && b !== null)
      throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
    extendStatics(d, b);
    function __() {
      this.constructor = d;
    }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
  };
})();
var ImageOptionalHeader = (
  /** @class */
  (function(_super) {
    __extends5(ImageOptionalHeader2, _super);
    function ImageOptionalHeader2(view) {
      return _super.call(this, view) || this;
    }
    ImageOptionalHeader2.from = function(bin, offset) {
      if (offset === void 0) {
        offset = 0;
      }
      return new ImageOptionalHeader2(new DataView(bin, offset, 96));
    };
    Object.defineProperty(ImageOptionalHeader2.prototype, "magic", {
      get: function() {
        return this.view.getUint16(0, true);
      },
      set: function(val) {
        this.view.setUint16(0, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "majorLinkerVersion", {
      get: function() {
        return this.view.getUint8(2);
      },
      set: function(val) {
        this.view.setUint8(2, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "minorLinkerVersion", {
      get: function() {
        return this.view.getUint8(3);
      },
      set: function(val) {
        this.view.setUint8(3, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sizeOfCode", {
      get: function() {
        return this.view.getUint32(4, true);
      },
      set: function(val) {
        this.view.setUint32(4, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sizeOfInitializedData", {
      get: function() {
        return this.view.getUint32(8, true);
      },
      set: function(val) {
        this.view.setUint32(8, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sizeOfUninitializedData", {
      get: function() {
        return this.view.getUint32(12, true);
      },
      set: function(val) {
        this.view.setUint32(12, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "addressOfEntryPoint", {
      get: function() {
        return this.view.getUint32(16, true);
      },
      set: function(val) {
        this.view.setUint32(16, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "baseOfCode", {
      get: function() {
        return this.view.getUint32(20, true);
      },
      set: function(val) {
        this.view.setUint32(20, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "baseOfData", {
      get: function() {
        return this.view.getUint32(24, true);
      },
      set: function(val) {
        this.view.setUint32(24, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "imageBase", {
      get: function() {
        return this.view.getUint32(28, true);
      },
      set: function(val) {
        this.view.setUint32(28, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sectionAlignment", {
      get: function() {
        return this.view.getUint32(32, true);
      },
      set: function(val) {
        this.view.setUint32(32, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "fileAlignment", {
      get: function() {
        return this.view.getUint32(36, true);
      },
      set: function(val) {
        this.view.setUint32(36, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "majorOperatingSystemVersion", {
      get: function() {
        return this.view.getUint16(40, true);
      },
      set: function(val) {
        this.view.setUint16(40, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "minorOperatingSystemVersion", {
      get: function() {
        return this.view.getUint16(42, true);
      },
      set: function(val) {
        this.view.setUint16(42, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "majorImageVersion", {
      get: function() {
        return this.view.getUint16(44, true);
      },
      set: function(val) {
        this.view.setUint16(44, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "minorImageVersion", {
      get: function() {
        return this.view.getUint16(46, true);
      },
      set: function(val) {
        this.view.setUint16(46, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "majorSubsystemVersion", {
      get: function() {
        return this.view.getUint16(48, true);
      },
      set: function(val) {
        this.view.setUint16(48, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "minorSubsystemVersion", {
      get: function() {
        return this.view.getUint16(50, true);
      },
      set: function(val) {
        this.view.setUint16(50, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "win32VersionValue", {
      get: function() {
        return this.view.getUint32(52, true);
      },
      set: function(val) {
        this.view.setUint32(52, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sizeOfImage", {
      get: function() {
        return this.view.getUint32(56, true);
      },
      set: function(val) {
        this.view.setUint32(56, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sizeOfHeaders", {
      get: function() {
        return this.view.getUint32(60, true);
      },
      set: function(val) {
        this.view.setUint32(60, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "checkSum", {
      get: function() {
        return this.view.getUint32(64, true);
      },
      set: function(val) {
        this.view.setUint32(64, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "subsystem", {
      get: function() {
        return this.view.getUint16(68, true);
      },
      set: function(val) {
        this.view.setUint16(68, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "dllCharacteristics", {
      get: function() {
        return this.view.getUint16(70, true);
      },
      set: function(val) {
        this.view.setUint16(70, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sizeOfStackReserve", {
      get: function() {
        return this.view.getUint32(72, true);
      },
      set: function(val) {
        this.view.setUint32(72, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sizeOfStackCommit", {
      get: function() {
        return this.view.getUint32(76, true);
      },
      set: function(val) {
        this.view.setUint32(76, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sizeOfHeapReserve", {
      get: function() {
        return this.view.getUint32(80, true);
      },
      set: function(val) {
        this.view.setUint32(80, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "sizeOfHeapCommit", {
      get: function() {
        return this.view.getUint32(84, true);
      },
      set: function(val) {
        this.view.setUint32(84, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "loaderFlags", {
      get: function() {
        return this.view.getUint32(88, true);
      },
      set: function(val) {
        this.view.setUint32(88, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader2.prototype, "numberOfRvaAndSizes", {
      get: function() {
        return this.view.getUint32(92, true);
      },
      set: function(val) {
        this.view.setUint32(92, val, true);
      },
      enumerable: false,
      configurable: true
    });
    ImageOptionalHeader2.size = 96;
    ImageOptionalHeader2.DEFAULT_MAGIC = 267;
    return ImageOptionalHeader2;
  })(FormatBase_default)
);
var ImageOptionalHeader_default = ImageOptionalHeader;

// node_modules/pe-library/dist/format/ImageOptionalHeader64.js
var __extends6 = /* @__PURE__ */ (function() {
  var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d2, b2) {
      d2.__proto__ = b2;
    } || function(d2, b2) {
      for (var p in b2) if (Object.prototype.hasOwnProperty.call(b2, p)) d2[p] = b2[p];
    };
    return extendStatics(d, b);
  };
  return function(d, b) {
    if (typeof b !== "function" && b !== null)
      throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
    extendStatics(d, b);
    function __() {
      this.constructor = d;
    }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
  };
})();
function getUint64LE(view, offset) {
  return view.getUint32(offset + 4, true) * 4294967296 + view.getUint32(offset, true);
}
function setUint64LE(view, offset, val) {
  view.setUint32(offset, val & 4294967295, true);
  view.setUint32(offset + 4, Math.floor(val / 4294967296), true);
}
function getUint64LEBigInt(view, offset) {
  if (typeof BigInt === "undefined") {
    throw new Error("BigInt not supported");
  }
  return BigInt(4294967296) * BigInt(view.getUint32(offset + 4, true)) + BigInt(view.getUint32(offset, true));
}
function setUint64LEBigInt(view, offset, val) {
  if (typeof BigInt === "undefined") {
    throw new Error("BigInt not supported");
  }
  view.setUint32(offset, Number(val & BigInt(4294967295)), true);
  view.setUint32(offset + 4, Math.floor(Number(val / BigInt(4294967296) & BigInt(4294967295))), true);
}
var ImageOptionalHeader64 = (
  /** @class */
  (function(_super) {
    __extends6(ImageOptionalHeader642, _super);
    function ImageOptionalHeader642(view) {
      return _super.call(this, view) || this;
    }
    ImageOptionalHeader642.from = function(bin, offset) {
      if (offset === void 0) {
        offset = 0;
      }
      return new ImageOptionalHeader642(new DataView(bin, offset, 112));
    };
    Object.defineProperty(ImageOptionalHeader642.prototype, "magic", {
      get: function() {
        return this.view.getUint16(0, true);
      },
      set: function(val) {
        this.view.setUint16(0, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "majorLinkerVersion", {
      get: function() {
        return this.view.getUint8(2);
      },
      set: function(val) {
        this.view.setUint8(2, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "minorLinkerVersion", {
      get: function() {
        return this.view.getUint8(3);
      },
      set: function(val) {
        this.view.setUint8(3, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfCode", {
      get: function() {
        return this.view.getUint32(4, true);
      },
      set: function(val) {
        this.view.setUint32(4, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfInitializedData", {
      get: function() {
        return this.view.getUint32(8, true);
      },
      set: function(val) {
        this.view.setUint32(8, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfUninitializedData", {
      get: function() {
        return this.view.getUint32(12, true);
      },
      set: function(val) {
        this.view.setUint32(12, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "addressOfEntryPoint", {
      get: function() {
        return this.view.getUint32(16, true);
      },
      set: function(val) {
        this.view.setUint32(16, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "baseOfCode", {
      get: function() {
        return this.view.getUint32(20, true);
      },
      set: function(val) {
        this.view.setUint32(20, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "imageBase", {
      get: function() {
        return getUint64LE(this.view, 24);
      },
      set: function(val) {
        setUint64LE(this.view, 24, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "imageBaseBigInt", {
      get: function() {
        return getUint64LEBigInt(this.view, 24);
      },
      set: function(val) {
        setUint64LEBigInt(this.view, 24, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sectionAlignment", {
      get: function() {
        return this.view.getUint32(32, true);
      },
      set: function(val) {
        this.view.setUint32(32, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "fileAlignment", {
      get: function() {
        return this.view.getUint32(36, true);
      },
      set: function(val) {
        this.view.setUint32(36, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "majorOperatingSystemVersion", {
      get: function() {
        return this.view.getUint16(40, true);
      },
      set: function(val) {
        this.view.setUint16(40, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "minorOperatingSystemVersion", {
      get: function() {
        return this.view.getUint16(42, true);
      },
      set: function(val) {
        this.view.setUint16(42, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "majorImageVersion", {
      get: function() {
        return this.view.getUint16(44, true);
      },
      set: function(val) {
        this.view.setUint16(44, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "minorImageVersion", {
      get: function() {
        return this.view.getUint16(46, true);
      },
      set: function(val) {
        this.view.setUint16(46, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "majorSubsystemVersion", {
      get: function() {
        return this.view.getUint16(48, true);
      },
      set: function(val) {
        this.view.setUint16(48, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "minorSubsystemVersion", {
      get: function() {
        return this.view.getUint16(50, true);
      },
      set: function(val) {
        this.view.setUint16(50, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "win32VersionValue", {
      get: function() {
        return this.view.getUint32(52, true);
      },
      set: function(val) {
        this.view.setUint32(52, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfImage", {
      get: function() {
        return this.view.getUint32(56, true);
      },
      set: function(val) {
        this.view.setUint32(56, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfHeaders", {
      get: function() {
        return this.view.getUint32(60, true);
      },
      set: function(val) {
        this.view.setUint32(60, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "checkSum", {
      get: function() {
        return this.view.getUint32(64, true);
      },
      set: function(val) {
        this.view.setUint32(64, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "subsystem", {
      get: function() {
        return this.view.getUint16(68, true);
      },
      set: function(val) {
        this.view.setUint16(68, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "dllCharacteristics", {
      get: function() {
        return this.view.getUint16(70, true);
      },
      set: function(val) {
        this.view.setUint16(70, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfStackReserve", {
      get: function() {
        return getUint64LE(this.view, 72);
      },
      set: function(val) {
        setUint64LE(this.view, 72, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfStackReserveBigInt", {
      get: function() {
        return getUint64LEBigInt(this.view, 72);
      },
      set: function(val) {
        setUint64LEBigInt(this.view, 72, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfStackCommit", {
      get: function() {
        return getUint64LE(this.view, 80);
      },
      set: function(val) {
        setUint64LE(this.view, 80, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfStackCommitBigInt", {
      get: function() {
        return getUint64LEBigInt(this.view, 80);
      },
      set: function(val) {
        setUint64LEBigInt(this.view, 80, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfHeapReserve", {
      get: function() {
        return getUint64LE(this.view, 88);
      },
      set: function(val) {
        setUint64LE(this.view, 88, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfHeapReserveBigInt", {
      get: function() {
        return getUint64LEBigInt(this.view, 88);
      },
      set: function(val) {
        setUint64LEBigInt(this.view, 88, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfHeapCommit", {
      get: function() {
        return getUint64LE(this.view, 96);
      },
      set: function(val) {
        setUint64LE(this.view, 96, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "sizeOfHeapCommitBigInt", {
      get: function() {
        return getUint64LEBigInt(this.view, 96);
      },
      set: function(val) {
        setUint64LEBigInt(this.view, 96, val);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "loaderFlags", {
      get: function() {
        return this.view.getUint32(104, true);
      },
      set: function(val) {
        this.view.setUint32(104, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageOptionalHeader642.prototype, "numberOfRvaAndSizes", {
      get: function() {
        return this.view.getUint32(108, true);
      },
      set: function(val) {
        this.view.setUint32(108, val, true);
      },
      enumerable: false,
      configurable: true
    });
    ImageOptionalHeader642.size = 112;
    ImageOptionalHeader642.DEFAULT_MAGIC = 523;
    return ImageOptionalHeader642;
  })(FormatBase_default)
);
var ImageOptionalHeader64_default = ImageOptionalHeader64;

// node_modules/pe-library/dist/format/ImageNtHeaders.js
var __extends7 = /* @__PURE__ */ (function() {
  var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d2, b2) {
      d2.__proto__ = b2;
    } || function(d2, b2) {
      for (var p in b2) if (Object.prototype.hasOwnProperty.call(b2, p)) d2[p] = b2[p];
    };
    return extendStatics(d, b);
  };
  return function(d, b) {
    if (typeof b !== "function" && b !== null)
      throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
    extendStatics(d, b);
    function __() {
      this.constructor = d;
    }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
  };
})();
var ImageNtHeaders = (
  /** @class */
  (function(_super) {
    __extends7(ImageNtHeaders2, _super);
    function ImageNtHeaders2(view) {
      return _super.call(this, view) || this;
    }
    ImageNtHeaders2.from = function(bin, offset) {
      if (offset === void 0) {
        offset = 0;
      }
      var magic = createDataView(bin, offset + ImageFileHeader_default.size, 6).getUint16(4, true);
      var len = 4 + ImageFileHeader_default.size + ImageDataDirectoryArray_default.size;
      if (magic === ImageOptionalHeader64_default.DEFAULT_MAGIC) {
        len += ImageOptionalHeader64_default.size;
      } else {
        len += ImageOptionalHeader_default.size;
      }
      return new ImageNtHeaders2(createDataView(bin, offset, len));
    };
    ImageNtHeaders2.prototype.isValid = function() {
      return this.signature === ImageNtHeaders2.DEFAULT_SIGNATURE;
    };
    ImageNtHeaders2.prototype.is32bit = function() {
      return this.view.getUint16(ImageFileHeader_default.size + 4, true) === ImageOptionalHeader_default.DEFAULT_MAGIC;
    };
    Object.defineProperty(ImageNtHeaders2.prototype, "signature", {
      get: function() {
        return this.view.getUint32(0, true);
      },
      set: function(val) {
        this.view.setUint32(0, val, true);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageNtHeaders2.prototype, "fileHeader", {
      get: function() {
        return ImageFileHeader_default.from(this.view.buffer, this.view.byteOffset + 4);
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageNtHeaders2.prototype, "optionalHeader", {
      get: function() {
        var off = ImageFileHeader_default.size + 4;
        var magic = this.view.getUint16(off, true);
        if (magic === ImageOptionalHeader64_default.DEFAULT_MAGIC) {
          return ImageOptionalHeader64_default.from(this.view.buffer, this.view.byteOffset + off);
        } else {
          return ImageOptionalHeader_default.from(this.view.buffer, this.view.byteOffset + off);
        }
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(ImageNtHeaders2.prototype, "optionalHeaderDataDirectory", {
      get: function() {
        return ImageDataDirectoryArray_default.from(this.view.buffer, this.view.byteOffset + this.getDataDirectoryOffset());
      },
      enumerable: false,
      configurable: true
    });
    ImageNtHeaders2.prototype.getDataDirectoryOffset = function() {
      var off = ImageFileHeader_default.size + 4;
      var magic = this.view.getUint16(off, true);
      if (magic === ImageOptionalHeader64_default.DEFAULT_MAGIC) {
        off += ImageOptionalHeader64_default.size;
      } else {
        off += ImageOptionalHeader_default.size;
      }
      return off;
    };
    ImageNtHeaders2.prototype.getSectionHeaderOffset = function() {
      return this.getDataDirectoryOffset() + ImageDataDirectoryArray_default.size;
    };
    ImageNtHeaders2.DEFAULT_SIGNATURE = 17744;
    return ImageNtHeaders2;
  })(FormatBase_default)
);
var ImageNtHeaders_default = ImageNtHeaders;

// node_modules/pe-library/dist/format/ImageSectionHeaderArray.js
var __extends8 = /* @__PURE__ */ (function() {
  var extendStatics = function(d, b) {
    extendStatics = Object.setPrototypeOf || { __proto__: [] } instanceof Array && function(d2, b2) {
      d2.__proto__ = b2;
    } || function(d2, b2) {
      for (var p in b2) if (Object.prototype.hasOwnProperty.call(b2, p)) d2[p] = b2[p];
    };
    return extendStatics(d, b);
  };
  return function(d, b) {
    if (typeof b !== "function" && b !== null)
      throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
    extendStatics(d, b);
    function __() {
      this.constructor = d;
    }
    d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
  };
})();
var ImageSectionHeaderArray = (
  /** @class */
  (function(_super) {
    __extends8(ImageSectionHeaderArray2, _super);
    function ImageSectionHeaderArray2(view, length) {
      var _this = _super.call(this, view) || this;
      _this.length = length;
      return _this;
    }
    ImageSectionHeaderArray2.from = function(bin, length, offset) {
      if (offset === void 0) {
        offset = 0;
      }
      var size = length * 40;
      return new ImageSectionHeaderArray2(new DataView(bin, offset, size), length);
    };
    ImageSectionHeaderArray2.prototype.get = function(index) {
      return {
        name: getFixedString(this.view, index * 40, 8),
        virtualSize: this.view.getUint32(8 + index * 40, true),
        virtualAddress: this.view.getUint32(12 + index * 40, true),
        sizeOfRawData: this.view.getUint32(16 + index * 40, true),
        pointerToRawData: this.view.getUint32(20 + index * 40, true),
        pointerToRelocations: this.view.getUint32(24 + index * 40, true),
        pointerToLineNumbers: this.view.getUint32(28 + index * 40, true),
        numberOfRelocations: this.view.getUint16(32 + index * 40, true),
        numberOfLineNumbers: this.view.getUint16(34 + index * 40, true),
        characteristics: this.view.getUint32(36 + index * 40, true)
      };
    };
    ImageSectionHeaderArray2.prototype.set = function(index, data) {
      setFixedString(this.view, index * 40, 8, data.name);
      this.view.setUint32(8 + index * 40, data.virtualSize, true);
      this.view.setUint32(12 + index * 40, data.virtualAddress, true);
      this.view.setUint32(16 + index * 40, data.sizeOfRawData, true);
      this.view.setUint32(20 + index * 40, data.pointerToRawData, true);
      this.view.setUint32(24 + index * 40, data.pointerToRelocations, true);
      this.view.setUint32(28 + index * 40, data.pointerToLineNumbers, true);
      this.view.setUint16(32 + index * 40, data.numberOfRelocations, true);
      this.view.setUint16(34 + index * 40, data.numberOfLineNumbers, true);
      this.view.setUint32(36 + index * 40, data.characteristics, true);
    };
    ImageSectionHeaderArray2.itemSize = 40;
    return ImageSectionHeaderArray2;
  })(ArrayFormatBase_default)
);
var ImageSectionHeaderArray_default = ImageSectionHeaderArray;

// node_modules/pe-library/dist/format/index.js
function getImageDosHeader(bin) {
  return ImageDosHeader_default.from(bin);
}
function getImageNtHeadersByDosHeader(bin, dosHeader) {
  return ImageNtHeaders_default.from(bin, dosHeader.newHeaderAddress);
}
function getImageSectionHeadersByNtHeaders(bin, dosHeader, ntHeaders) {
  return ImageSectionHeaderArray_default.from(bin, ntHeaders.fileHeader.numberOfSections, dosHeader.newHeaderAddress + ntHeaders.byteLength);
}
function findImageSectionBlockByDirectoryEntry(bin, dosHeader, ntHeaders, entryType) {
  var arr = ImageSectionHeaderArray_default.from(bin, ntHeaders.fileHeader.numberOfSections, dosHeader.newHeaderAddress + ntHeaders.byteLength);
  var len = arr.length;
  var rva = ntHeaders.optionalHeaderDataDirectory.get(entryType).virtualAddress;
  for (var i = 0; i < len; ++i) {
    var sec = arr.get(i);
    var vaEnd = sec.virtualAddress + sec.virtualSize;
    if (rva >= sec.virtualAddress && rva < vaEnd) {
      var ptr = sec.pointerToRawData;
      if (!ptr) {
        return null;
      }
      return bin.slice(ptr, ptr + sec.sizeOfRawData);
    }
    if (rva < sec.virtualAddress) {
      return null;
    }
  }
  return null;
}

// node_modules/pe-library/dist/util/generate.js
var DOS_STUB_PROGRAM = new Uint8Array([
  14,
  31,
  186,
  14,
  0,
  180,
  9,
  205,
  33,
  184,
  1,
  76,
  205,
  33,
  68,
  79,
  83,
  32,
  109,
  111,
  100,
  101,
  32,
  110,
  111,
  116,
  32,
  115,
  117,
  112,
  112,
  111,
  114,
  116,
  101,
  100,
  46,
  13,
  13,
  10,
  36,
  0,
  0,
  0,
  0,
  0,
  0,
  0
]);
var DOS_STUB_SIZE = roundUp(ImageDosHeader_default.size + DOS_STUB_PROGRAM.length, 128);
var DEFAULT_FILE_ALIGNMENT = 512;
function fillDosStubData(bin) {
  var dos = ImageDosHeader_default.from(bin);
  dos.magic = ImageDosHeader_default.DEFAULT_MAGIC;
  dos.lastPageSize = DOS_STUB_SIZE % 512;
  dos.pages = Math.ceil(DOS_STUB_SIZE / 512);
  dos.relocations = 0;
  dos.headerSizeInParagraph = Math.ceil(ImageDosHeader_default.size / 16);
  dos.minAllocParagraphs = 0;
  dos.maxAllocParagraphs = 65535;
  dos.initialSS = 0;
  dos.initialSP = 128;
  dos.relocationTableAddress = ImageDosHeader_default.size;
  dos.newHeaderAddress = DOS_STUB_SIZE;
  copyBuffer(bin, ImageDosHeader_default.size, DOS_STUB_PROGRAM, 0, DOS_STUB_PROGRAM.length);
}
function estimateNewHeaderSize(is32Bit) {
  return (
    // magic
    4 + ImageFileHeader_default.size + (is32Bit ? ImageOptionalHeader_default.size : ImageOptionalHeader64_default.size) + ImageDataDirectoryArray_default.size
  );
}
function fillPeHeaderEmptyData(bin, offset, totalBinSize, is32Bit, isDLL) {
  var _bin;
  var _offset;
  if ("buffer" in bin) {
    _bin = bin.buffer;
    _offset = bin.byteOffset + offset;
  } else {
    _bin = bin;
    _offset = offset;
  }
  new DataView(_bin, _offset).setUint32(0, ImageNtHeaders_default.DEFAULT_SIGNATURE, true);
  var fh = ImageFileHeader_default.from(_bin, _offset + 4);
  fh.machine = is32Bit ? 332 : 34404;
  fh.numberOfSections = 0;
  fh.timeDateStamp = 0;
  fh.pointerToSymbolTable = 0;
  fh.numberOfSymbols = 0;
  fh.sizeOfOptionalHeader = (is32Bit ? ImageOptionalHeader_default.size : ImageOptionalHeader64_default.size) + ImageDataDirectoryArray_default.size;
  fh.characteristics = isDLL ? 8450 : 258;
  var oh = (is32Bit ? ImageOptionalHeader_default : ImageOptionalHeader64_default).from(_bin, _offset + 4 + ImageFileHeader_default.size);
  oh.magic = is32Bit ? ImageOptionalHeader_default.DEFAULT_MAGIC : ImageOptionalHeader64_default.DEFAULT_MAGIC;
  oh.sizeOfCode = 0;
  oh.sizeOfInitializedData = 0;
  oh.sizeOfUninitializedData = 0;
  oh.addressOfEntryPoint = 0;
  oh.baseOfCode = 4096;
  oh.imageBase = is32Bit ? 16777216 : 6442450944;
  oh.sectionAlignment = 4096;
  oh.fileAlignment = DEFAULT_FILE_ALIGNMENT;
  oh.majorOperatingSystemVersion = 6;
  oh.minorOperatingSystemVersion = 0;
  oh.majorSubsystemVersion = 6;
  oh.minorSubsystemVersion = 0;
  oh.sizeOfHeaders = roundUp(totalBinSize, oh.fileAlignment);
  oh.subsystem = 2;
  oh.dllCharacteristics = (is32Bit ? 0 : 32) + // IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA
  64 + // IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
  256;
  oh.sizeOfStackReserve = 1048576;
  oh.sizeOfStackCommit = 4096;
  oh.sizeOfHeapReserve = 1048576;
  oh.sizeOfHeapCommit = 4096;
  oh.numberOfRvaAndSizes = ImageDataDirectoryArray_default.size / ImageDataDirectoryArray_default.itemSize;
}
function makeEmptyNtExecutableBinary(is32Bit, isDLL) {
  var bufferSize = roundUp(DOS_STUB_SIZE + estimateNewHeaderSize(is32Bit), DEFAULT_FILE_ALIGNMENT);
  var bin = new ArrayBuffer(bufferSize);
  fillDosStubData(bin);
  fillPeHeaderEmptyData(bin, DOS_STUB_SIZE, bufferSize, is32Bit, isDLL);
  return bin;
}

// node_modules/pe-library/dist/NtExecutable.js
var NtExecutable = (
  /** @class */
  (function() {
    function NtExecutable2(_headers, _sections, _ex) {
      this._headers = _headers;
      this._sections = _sections;
      this._ex = _ex;
      var dh = ImageDosHeader_default.from(_headers);
      var nh = ImageNtHeaders_default.from(_headers, dh.newHeaderAddress);
      this._dh = dh;
      this._nh = nh;
      this._dda = nh.optionalHeaderDataDirectory;
      _sections.sort(function(a, b) {
        var ra = a.info.pointerToRawData;
        var rb = a.info.pointerToRawData;
        if (ra !== rb) {
          return ra - rb;
        }
        var va = a.info.virtualAddress;
        var vb = b.info.virtualAddress;
        if (va === vb) {
          return a.info.virtualSize - b.info.virtualSize;
        }
        return va - vb;
      });
    }
    NtExecutable2.createEmpty = function(is32Bit, isDLL) {
      if (is32Bit === void 0) {
        is32Bit = false;
      }
      if (isDLL === void 0) {
        isDLL = true;
      }
      return this.from(makeEmptyNtExecutableBinary(is32Bit, isDLL));
    };
    NtExecutable2.from = function(bin, options) {
      var dh = ImageDosHeader_default.from(bin);
      var nh = ImageNtHeaders_default.from(bin, dh.newHeaderAddress);
      if (!dh.isValid() || !nh.isValid()) {
        throw new TypeError("Invalid binary format");
      }
      if (nh.fileHeader.numberOfSymbols > 0) {
        throw new Error("Binary with symbols is not supported now");
      }
      var fileAlignment = nh.optionalHeader.fileAlignment;
      var securityEntry = nh.optionalHeaderDataDirectory.get(ImageDirectoryEntry_default.Certificate);
      if (securityEntry.size > 0) {
        if (!(options === null || options === void 0 ? void 0 : options.ignoreCert)) {
          throw new Error("Parsing signed executable binary is not allowed by default.");
        }
      }
      var secOff = dh.newHeaderAddress + nh.getSectionHeaderOffset();
      var secCount = nh.fileHeader.numberOfSections;
      var sections = [];
      var tempSectionHeaderBinary = allocatePartialBinary(bin, secOff, secCount * ImageSectionHeaderArray_default.itemSize);
      var secArray = ImageSectionHeaderArray_default.from(tempSectionHeaderBinary, secCount, 0);
      var lastOffset = roundUp(secOff + secCount * ImageSectionHeaderArray_default.itemSize, fileAlignment);
      secArray.forEach(function(info) {
        if (!info.pointerToRawData || !info.sizeOfRawData) {
          info.pointerToRawData = 0;
          info.sizeOfRawData = 0;
          sections.push({
            info,
            data: null
          });
        } else {
          var secBin = allocatePartialBinary(bin, info.pointerToRawData, info.sizeOfRawData);
          sections.push({
            info,
            data: secBin
          });
          var secEndOffset = roundUp(info.pointerToRawData + info.sizeOfRawData, fileAlignment);
          if (secEndOffset > lastOffset) {
            lastOffset = secEndOffset;
          }
        }
      });
      var headers = allocatePartialBinary(bin, 0, secOff);
      var exData = null;
      var lastExDataOffset = bin.byteLength;
      if (securityEntry.size > 0) {
        lastExDataOffset = securityEntry.virtualAddress;
      }
      if (lastOffset < lastExDataOffset) {
        exData = allocatePartialBinary(bin, lastOffset, lastExDataOffset - lastOffset);
      }
      return new NtExecutable2(headers, sections, exData);
    };
    NtExecutable2.prototype.is32bit = function() {
      return this._nh.is32bit();
    };
    NtExecutable2.prototype.getTotalHeaderSize = function() {
      return this._headers.byteLength;
    };
    Object.defineProperty(NtExecutable2.prototype, "dosHeader", {
      get: function() {
        return this._dh;
      },
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(NtExecutable2.prototype, "newHeader", {
      get: function() {
        return this._nh;
      },
      enumerable: false,
      configurable: true
    });
    NtExecutable2.prototype.getRawHeader = function() {
      return this._headers;
    };
    NtExecutable2.prototype.getImageBase = function() {
      return this._nh.optionalHeader.imageBase;
    };
    NtExecutable2.prototype.getFileAlignment = function() {
      return this._nh.optionalHeader.fileAlignment;
    };
    NtExecutable2.prototype.getSectionAlignment = function() {
      return this._nh.optionalHeader.sectionAlignment;
    };
    NtExecutable2.prototype.getAllSections = function() {
      return this._sections;
    };
    NtExecutable2.prototype.getSectionByEntry = function(entry) {
      var dd = this._dda.get(entry);
      var r = this._sections.filter(function(sec) {
        var vaEnd = sec.info.virtualAddress + sec.info.virtualSize;
        return dd.virtualAddress >= sec.info.virtualAddress && dd.virtualAddress < vaEnd;
      }).shift();
      return r !== void 0 ? r : null;
    };
    NtExecutable2.prototype.setSectionByEntry = function(entry, section) {
      var sec = section ? { data: section.data, info: section.info } : null;
      var dd = this._dda.get(entry);
      var hasEntry = dd.size > 0;
      if (!sec) {
        if (!hasEntry) {
        } else {
          this._dda.set(entry, { size: 0, virtualAddress: 0 });
          var len = this._sections.length;
          for (var i = 0; i < len; ++i) {
            var sec_1 = this._sections[i];
            var vaStart = sec_1.info.virtualAddress;
            var vaLast = vaStart + sec_1.info.virtualSize;
            if (dd.virtualAddress >= vaStart && dd.virtualAddress < vaLast) {
              this._sections.splice(i, 1);
              this._nh.fileHeader.numberOfSections = this._sections.length;
              break;
            }
          }
        }
      } else {
        var rawSize = !sec.data ? 0 : sec.data.byteLength;
        var fileAlign = this._nh.optionalHeader.fileAlignment;
        var secAlign = this._nh.optionalHeader.sectionAlignment;
        var alignedFileSize = !sec.data ? 0 : roundUp(rawSize, fileAlign);
        var alignedSecSize = !sec.data ? 0 : roundUp(sec.info.virtualSize, secAlign);
        if (sec.info.sizeOfRawData < alignedFileSize) {
          sec.info.sizeOfRawData = alignedFileSize;
        } else {
          alignedFileSize = sec.info.sizeOfRawData;
        }
        if (!hasEntry) {
          var virtAddr_1 = 0;
          var rawAddr_1 = roundUp(this._headers.byteLength, fileAlign);
          this._sections.forEach(function(secExist) {
            if (secExist.info.pointerToRawData) {
              if (rawAddr_1 <= secExist.info.pointerToRawData) {
                rawAddr_1 = secExist.info.pointerToRawData + secExist.info.sizeOfRawData;
              }
            }
            if (virtAddr_1 <= secExist.info.virtualAddress) {
              virtAddr_1 = secExist.info.virtualAddress + secExist.info.virtualSize;
            }
          });
          if (!alignedFileSize) {
            rawAddr_1 = 0;
          }
          if (!virtAddr_1) {
            virtAddr_1 = this.newHeader.optionalHeader.baseOfCode;
          }
          virtAddr_1 = roundUp(virtAddr_1, secAlign);
          sec.info.pointerToRawData = rawAddr_1;
          sec.info.virtualAddress = virtAddr_1;
          this._dda.set(entry, {
            size: rawSize,
            virtualAddress: virtAddr_1
          });
          this._sections.push(sec);
          this._nh.fileHeader.numberOfSections = this._sections.length;
          this._nh.optionalHeader.sizeOfImage = roundUp(virtAddr_1 + alignedSecSize, this._nh.optionalHeader.sectionAlignment);
        } else {
          this.replaceSectionImpl(dd.virtualAddress, sec.info, sec.data);
        }
      }
    };
    NtExecutable2.prototype.getExtraData = function() {
      return this._ex;
    };
    NtExecutable2.prototype.setExtraData = function(bin) {
      if (bin === null) {
        this._ex = null;
      } else {
        this._ex = cloneToArrayBuffer(bin);
      }
    };
    NtExecutable2.prototype.generate = function(paddingSize) {
      var dh = this._dh;
      var nh = this._nh;
      var secOff = dh.newHeaderAddress + nh.getSectionHeaderOffset();
      var size = secOff;
      size += this._sections.length * ImageSectionHeaderArray_default.itemSize;
      var align = nh.optionalHeader.fileAlignment;
      size = roundUp(size, align);
      this._sections.forEach(function(sec) {
        if (!sec.info.pointerToRawData) {
          return;
        }
        var lastOff = sec.info.pointerToRawData + sec.info.sizeOfRawData;
        if (size < lastOff) {
          size = lastOff;
          size = roundUp(size, align);
        }
      });
      var lastPosition = size;
      if (this._ex !== null) {
        size += this._ex.byteLength;
      }
      if (typeof paddingSize === "number") {
        size += paddingSize;
      }
      var bin = new ArrayBuffer(size);
      var u8bin = new Uint8Array(bin);
      u8bin.set(new Uint8Array(this._headers, 0, secOff));
      ImageDataDirectoryArray_default.from(bin, dh.newHeaderAddress + nh.getDataDirectoryOffset()).set(ImageDirectoryEntry_default.Certificate, {
        size: 0,
        virtualAddress: 0
      });
      var secArray = ImageSectionHeaderArray_default.from(bin, this._sections.length, secOff);
      this._sections.forEach(function(sec, i) {
        if (!sec.data) {
          sec.info.pointerToRawData = 0;
          sec.info.sizeOfRawData = 0;
        }
        secArray.set(i, sec.info);
        if (!sec.data || !sec.info.pointerToRawData) {
          return;
        }
        u8bin.set(new Uint8Array(sec.data), sec.info.pointerToRawData);
      });
      if (this._ex !== null) {
        u8bin.set(new Uint8Array(this._ex), lastPosition);
      }
      if (nh.optionalHeader.checkSum !== 0) {
        calculateCheckSumForPE(bin, true);
      }
      return bin;
    };
    NtExecutable2.prototype.rearrangeSections = function(rawAddressStart, rawDiff, virtualAddressStart, virtualDiff) {
      if (!rawDiff && !virtualDiff) {
        return;
      }
      var nh = this._nh;
      var secAlign = nh.optionalHeader.sectionAlignment;
      var dirs = this._dda;
      var len = this._sections.length;
      var lastVirtAddress = 0;
      for (var i = 0; i < len; ++i) {
        var sec = this._sections[i];
        var virtAddr = sec.info.virtualAddress;
        if (virtualDiff && virtAddr >= virtualAddressStart) {
          var iDir = dirs.findIndexByVirtualAddress(virtAddr);
          virtAddr += virtualDiff;
          if (iDir !== null) {
            dirs.set(iDir, {
              virtualAddress: virtAddr,
              size: sec.info.virtualSize
            });
          }
          sec.info.virtualAddress = virtAddr;
        }
        var fileAddr = sec.info.pointerToRawData;
        if (rawDiff && fileAddr >= rawAddressStart) {
          sec.info.pointerToRawData = fileAddr + rawDiff;
        }
        lastVirtAddress = roundUp(sec.info.virtualAddress + sec.info.virtualSize, secAlign);
      }
      nh.optionalHeader.sizeOfImage = lastVirtAddress;
    };
    NtExecutable2.prototype.replaceSectionImpl = function(virtualAddress, info, data) {
      var len = this._sections.length;
      for (var i = 0; i < len; ++i) {
        var s = this._sections[i];
        if (s.info.virtualAddress === virtualAddress) {
          var secAlign = this._nh.optionalHeader.sectionAlignment;
          var fileAddr = s.info.pointerToRawData;
          var oldFileAddr = fileAddr + s.info.sizeOfRawData;
          var oldVirtAddr = virtualAddress + roundUp(s.info.virtualSize, secAlign);
          s.info = cloneObject(info);
          s.info.virtualAddress = virtualAddress;
          s.info.pointerToRawData = fileAddr;
          s.data = data;
          var newFileAddr = fileAddr + info.sizeOfRawData;
          var newVirtAddr = virtualAddress + roundUp(info.virtualSize, secAlign);
          this.rearrangeSections(oldFileAddr, newFileAddr - oldFileAddr, oldVirtAddr, newVirtAddr - oldVirtAddr);
          {
            var dirs = this._dda;
            var iDir = dirs.findIndexByVirtualAddress(virtualAddress);
            if (iDir !== null) {
              dirs.set(iDir, {
                virtualAddress,
                size: info.virtualSize
              });
            }
          }
          break;
        }
      }
    };
    return NtExecutable2;
  })()
);
var NtExecutable_default = NtExecutable;

// node_modules/pe-library/dist/NtExecutableResource.js
function removeDuplicates(a) {
  return a.reduce(function(p, c) {
    return p.indexOf(c) >= 0 ? p : p.concat(c);
  }, []);
}
function readString(view, offset) {
  var length = view.getUint16(offset, true);
  var r = "";
  offset += 2;
  for (var i = 0; i < length; ++i) {
    r += String.fromCharCode(view.getUint16(offset, true));
    offset += 2;
  }
  return r;
}
function readLanguageTable(view, typeEntry, name, languageTable, cb) {
  var off = languageTable;
  var nameEntry = {
    name,
    languageTable,
    characteristics: view.getUint32(off, true),
    dateTime: view.getUint32(off + 4, true),
    majorVersion: view.getUint16(off + 8, true),
    minorVersion: view.getUint16(off + 10, true)
  };
  var nameCount = view.getUint16(off + 12, true);
  var idCount = view.getUint16(off + 14, true);
  off += 16;
  for (var i = 0; i < nameCount; ++i) {
    var nameOffset = view.getUint32(off, true) & 2147483647;
    var dataOffset = view.getUint32(off + 4, true);
    if ((dataOffset & 2147483648) !== 0) {
      off += 8;
      continue;
    }
    var name_1 = readString(view, nameOffset);
    cb(typeEntry, nameEntry, { lang: name_1, dataOffset });
    off += 8;
  }
  for (var i = 0; i < idCount; ++i) {
    var id = view.getUint32(off, true) & 2147483647;
    var dataOffset = view.getUint32(off + 4, true);
    if ((dataOffset & 2147483648) !== 0) {
      off += 8;
      continue;
    }
    cb(typeEntry, nameEntry, { lang: id, dataOffset });
    off += 8;
  }
}
function readNameTable(view, type, nameTable, cb) {
  var off = nameTable;
  var typeEntry = {
    type,
    nameTable,
    characteristics: view.getUint32(off, true),
    dateTime: view.getUint32(off + 4, true),
    majorVersion: view.getUint16(off + 8, true),
    minorVersion: view.getUint16(off + 10, true)
  };
  var nameCount = view.getUint16(off + 12, true);
  var idCount = view.getUint16(off + 14, true);
  off += 16;
  for (var i = 0; i < nameCount; ++i) {
    var nameOffset = view.getUint32(off, true) & 2147483647;
    var nextTable = view.getUint32(off + 4, true);
    if (!(nextTable & 2147483648)) {
      off += 8;
      continue;
    }
    nextTable &= 2147483647;
    var name_2 = readString(view, nameOffset);
    readLanguageTable(view, typeEntry, name_2, nextTable, cb);
    off += 8;
  }
  for (var i = 0; i < idCount; ++i) {
    var id = view.getUint32(off, true) & 2147483647;
    var nextTable = view.getUint32(off + 4, true);
    if (!(nextTable & 2147483648)) {
      off += 8;
      continue;
    }
    nextTable &= 2147483647;
    readLanguageTable(view, typeEntry, id, nextTable, cb);
    off += 8;
  }
}
function divideEntriesImplByID(r, names, entries) {
  var entriesByString = {};
  var entriesByNumber = {};
  entries.forEach(function(e) {
    if (typeof e.lang === "string") {
      entriesByString[e.lang] = e;
      names.push(e.lang);
    } else {
      entriesByNumber[e.lang] = e;
    }
  });
  var strKeys = Object.keys(entriesByString);
  strKeys.sort().forEach(function(type) {
    r.s.push(entriesByString[type]);
  });
  var numKeys = Object.keys(entriesByNumber);
  numKeys.map(function(k) {
    return Number(k);
  }).sort(function(a, b) {
    return a - b;
  }).forEach(function(type) {
    r.n.push(entriesByNumber[type]);
  });
  return 16 + 8 * (strKeys.length + numKeys.length);
}
function divideEntriesImplByName(r, names, entries) {
  var entriesByString = {};
  var entriesByNumber = {};
  entries.forEach(function(e) {
    var _a, _b;
    if (typeof e.id === "string") {
      var a = (_a = entriesByString[e.id]) !== null && _a !== void 0 ? _a : entriesByString[e.id] = [];
      names.push(e.id);
      a.push(e);
    } else {
      var a = (_b = entriesByNumber[e.id]) !== null && _b !== void 0 ? _b : entriesByNumber[e.id] = [];
      a.push(e);
    }
  });
  var sSum = Object.keys(entriesByString).sort().map(function(id) {
    var o = {
      id,
      s: [],
      n: []
    };
    r.s.push(o);
    return divideEntriesImplByID(o, names, entriesByString[id]);
  }).reduce(function(p, c) {
    return p + 8 + c;
  }, 0);
  var nSum = Object.keys(entriesByNumber).map(function(k) {
    return Number(k);
  }).sort(function(a, b) {
    return a - b;
  }).map(function(id) {
    var o = {
      id,
      s: [],
      n: []
    };
    r.n.push(o);
    return divideEntriesImplByID(o, names, entriesByNumber[id]);
  }).reduce(function(p, c) {
    return p + 8 + c;
  }, 0);
  return 16 + sSum + nSum;
}
function divideEntriesImplByType(r, names, entries) {
  var entriesByString = {};
  var entriesByNumber = {};
  entries.forEach(function(e) {
    var _a, _b;
    if (typeof e.type === "string") {
      var a = (_a = entriesByString[e.type]) !== null && _a !== void 0 ? _a : entriesByString[e.type] = [];
      names.push(e.type);
      a.push(e);
    } else {
      var a = (_b = entriesByNumber[e.type]) !== null && _b !== void 0 ? _b : entriesByNumber[e.type] = [];
      a.push(e);
    }
  });
  var sSum = Object.keys(entriesByString).sort().map(function(type) {
    var o = { type, s: [], n: [] };
    r.s.push(o);
    return divideEntriesImplByName(o, names, entriesByString[type]);
  }).reduce(function(p, c) {
    return p + 8 + c;
  }, 0);
  var nSum = Object.keys(entriesByNumber).map(function(k) {
    return Number(k);
  }).sort(function(a, b) {
    return a - b;
  }).map(function(type) {
    var o = { type, s: [], n: [] };
    r.n.push(o);
    return divideEntriesImplByName(o, names, entriesByNumber[type]);
  }).reduce(function(p, c) {
    return p + 8 + c;
  }, 0);
  return 16 + sSum + nSum;
}
function calculateStringLengthForWrite(text) {
  var length = text.length;
  return length > 65535 ? 65535 : length;
}
function getStringOffset(target, strings) {
  var l = strings.length;
  for (var i = 0; i < l; ++i) {
    var s = strings[i];
    if (s.text === target) {
      return s.offset;
    }
  }
  throw new Error("Unexpected");
}
function writeString(view, offset, text) {
  var length = calculateStringLengthForWrite(text);
  view.setUint16(offset, length, true);
  offset += 2;
  for (var i = 0; i < length; ++i) {
    view.setUint16(offset, text.charCodeAt(i), true);
    offset += 2;
  }
  return offset;
}
function writeLanguageTable(view, offset, strings, data) {
  view.setUint32(offset, 0, true);
  view.setUint32(offset + 4, 0, true);
  view.setUint32(offset + 8, 0, true);
  view.setUint16(offset + 12, data.s.length, true);
  view.setUint16(offset + 14, data.n.length, true);
  offset += 16;
  data.s.forEach(function(e) {
    var strOff = getStringOffset(e.lang, strings);
    view.setUint32(offset, strOff, true);
    view.setUint32(offset + 4, e.offset, true);
    offset += 8;
  });
  data.n.forEach(function(e) {
    view.setUint32(offset, e.lang, true);
    view.setUint32(offset + 4, e.offset, true);
    offset += 8;
  });
  return offset;
}
function writeNameTable(view, offset, leafOffset, strings, data) {
  view.setUint32(offset, 0, true);
  view.setUint32(offset + 4, 0, true);
  view.setUint32(offset + 8, 0, true);
  view.setUint16(offset + 12, data.s.length, true);
  view.setUint16(offset + 14, data.n.length, true);
  offset += 16;
  data.s.forEach(function(e) {
    e.offset = leafOffset;
    leafOffset = writeLanguageTable(view, leafOffset, strings, e);
  });
  data.n.forEach(function(e) {
    e.offset = leafOffset;
    leafOffset = writeLanguageTable(view, leafOffset, strings, e);
  });
  data.s.forEach(function(e) {
    var strOff = getStringOffset(e.id, strings);
    view.setUint32(offset, strOff + 2147483648, true);
    view.setUint32(offset + 4, e.offset + 2147483648, true);
    offset += 8;
  });
  data.n.forEach(function(e) {
    view.setUint32(offset, e.id, true);
    view.setUint32(offset + 4, e.offset + 2147483648, true);
    offset += 8;
  });
  return leafOffset;
}
function writeTypeTable(view, offset, strings, data) {
  view.setUint32(offset, 0, true);
  view.setUint32(offset + 4, 0, true);
  view.setUint32(offset + 8, 0, true);
  view.setUint16(offset + 12, data.s.length, true);
  view.setUint16(offset + 14, data.n.length, true);
  offset += 16;
  var nextTableOffset = offset + 8 * (data.s.length + data.n.length);
  data.s.forEach(function(e) {
    e.offset = nextTableOffset;
    nextTableOffset += 16 + 8 * (e.s.length + e.n.length);
  });
  data.n.forEach(function(e) {
    e.offset = nextTableOffset;
    nextTableOffset += 16 + 8 * (e.s.length + e.n.length);
  });
  data.s.forEach(function(e) {
    var strOff = getStringOffset(e.type, strings);
    view.setUint32(offset, strOff + 2147483648, true);
    view.setUint32(offset + 4, e.offset + 2147483648, true);
    offset += 8;
    nextTableOffset = writeNameTable(view, e.offset, nextTableOffset, strings, e);
  });
  data.n.forEach(function(e) {
    view.setUint32(offset, e.type, true);
    view.setUint32(offset + 4, e.offset + 2147483648, true);
    offset += 8;
    nextTableOffset = writeNameTable(view, e.offset, nextTableOffset, strings, e);
  });
  return nextTableOffset;
}
var NtExecutableResource = (
  /** @class */
  (function() {
    function NtExecutableResource2() {
      this.dateTime = 0;
      this.majorVersion = 0;
      this.minorVersion = 0;
      this.entries = [];
      this.sectionDataHeader = null;
      this.originalSize = 0;
    }
    NtExecutableResource2.prototype.parse = function(section, ignoreUnparsableData) {
      if (!section.data) {
        return;
      }
      var view = new DataView(section.data);
      this.dateTime = view.getUint32(4, true);
      this.majorVersion = view.getUint16(8, true);
      this.minorVersion = view.getUint16(10, true);
      var nameCount = view.getUint16(12, true);
      var idCount = view.getUint16(14, true);
      var off = 16;
      var res = [];
      var cb = function(t, n, l) {
        var off2 = view.getUint32(l.dataOffset, true) - section.info.virtualAddress;
        var size = view.getUint32(l.dataOffset + 4, true);
        var cp = view.getUint32(l.dataOffset + 8, true);
        if (off2 >= 0) {
          var bin = new Uint8Array(size);
          bin.set(new Uint8Array(section.data, off2, size));
          res.push({
            type: t.type,
            id: n.name,
            lang: l.lang,
            codepage: cp,
            bin: bin.buffer
          });
        } else {
          if (!ignoreUnparsableData) {
            throw new Error("Cannot parse resource directory entry; RVA seems to be invalid.");
          }
          res.push({
            type: t.type,
            id: n.name,
            lang: l.lang,
            codepage: cp,
            bin: new ArrayBuffer(0),
            rva: l.dataOffset
          });
        }
      };
      for (var i = 0; i < nameCount; ++i) {
        var nameOffset = view.getUint32(off, true) & 2147483647;
        var nextTable = view.getUint32(off + 4, true);
        if (!(nextTable & 2147483648)) {
          off += 8;
          continue;
        }
        nextTable &= 2147483647;
        var name_3 = readString(view, nameOffset);
        readNameTable(view, name_3, nextTable, cb);
        off += 8;
      }
      for (var i = 0; i < idCount; ++i) {
        var typeId = view.getUint32(off, true) & 2147483647;
        var nextTable = view.getUint32(off + 4, true);
        if (!(nextTable & 2147483648)) {
          off += 8;
          continue;
        }
        nextTable &= 2147483647;
        readNameTable(view, typeId, nextTable, cb);
        off += 8;
      }
      this.entries = res;
      this.originalSize = section.data.byteLength;
    };
    NtExecutableResource2.from = function(exe, ignoreUnparsableData) {
      if (ignoreUnparsableData === void 0) {
        ignoreUnparsableData = false;
      }
      var secs = [].concat(exe.getAllSections()).sort(function(a, b) {
        return a.info.virtualAddress - b.info.virtualAddress;
      });
      var entry = exe.getSectionByEntry(ImageDirectoryEntry_default.Resource);
      if (entry) {
        var reloc = exe.getSectionByEntry(ImageDirectoryEntry_default.BaseRelocation);
        for (var i = 0; i < secs.length; ++i) {
          var s = secs[i];
          if (s === entry) {
            for (var j = i + 1; j < secs.length; ++j) {
              if (!reloc || secs[j] !== reloc) {
                throw new Error("After Resource section, sections except for relocation are not supported");
              }
            }
            break;
          }
        }
      }
      var r = new NtExecutableResource2();
      r.sectionDataHeader = entry ? cloneObject(entry.info) : null;
      if (entry) {
        r.parse(entry, ignoreUnparsableData);
      }
      return r;
    };
    NtExecutableResource2.prototype.replaceResourceEntry = function(entry) {
      for (var len = this.entries.length, i = 0; i < len; ++i) {
        var e = this.entries[i];
        if (e.type === entry.type && e.id === entry.id && e.lang === entry.lang) {
          this.entries[i] = entry;
          return;
        }
      }
      this.entries.push(entry);
    };
    NtExecutableResource2.prototype.getResourceEntriesAsString = function(type, id) {
      return this.entries.filter(function(entry) {
        return entry.type === type && entry.id === id;
      }).map(function(entry) {
        return [entry.lang, binaryToString(entry.bin)];
      });
    };
    NtExecutableResource2.prototype.replaceResourceEntryFromString = function(type, id, lang, value) {
      var entry = {
        type,
        id,
        lang,
        codepage: 1200,
        bin: stringToBinary(value)
      };
      this.replaceResourceEntry(entry);
    };
    NtExecutableResource2.prototype.removeResourceEntry = function(type, id, lang) {
      this.entries = this.entries.filter(function(entry) {
        return !(entry.type === type && entry.id === id && (typeof lang === "undefined" || entry.lang === lang));
      });
    };
    NtExecutableResource2.prototype.generateResourceData = function(virtualAddress, alignment, noGrow, allowShrink) {
      if (noGrow === void 0) {
        noGrow = false;
      }
      if (allowShrink === void 0) {
        allowShrink = false;
      }
      var r = {
        s: [],
        n: []
      };
      var strings = [];
      var size = divideEntriesImplByType(r, strings, this.entries);
      strings = removeDuplicates(strings);
      var stringsOffset = size;
      size += strings.reduce(function(prev, cur) {
        return prev + 2 + calculateStringLengthForWrite(cur) * 2;
      }, 0);
      size = roundUp(size, 8);
      var descOffset = size;
      size = this.entries.reduce(function(p, e) {
        e.offset = p;
        return p + 16;
      }, descOffset);
      var dataOffset = size;
      size = this.entries.reduce(function(p, e) {
        return roundUp(p, 8) + e.bin.byteLength;
      }, dataOffset);
      var alignedSize = roundUp(size, alignment);
      var originalAlignedSize = roundUp(this.originalSize, alignment);
      if (noGrow) {
        if (alignedSize > originalAlignedSize) {
          throw new Error("New resource data is larger than original");
        }
      }
      if (!allowShrink) {
        if (alignedSize < originalAlignedSize) {
          alignedSize = originalAlignedSize;
        }
      }
      var bin = new ArrayBuffer(alignedSize);
      var view = new DataView(bin);
      var o = descOffset;
      var va = virtualAddress + dataOffset;
      this.entries.forEach(function(e) {
        var len = e.bin.byteLength;
        if (typeof e.rva !== "undefined") {
          view.setUint32(o, e.rva, true);
        } else {
          va = roundUp(va, 8);
          view.setUint32(o, va, true);
          va += len;
        }
        view.setUint32(o + 4, len, true);
        view.setUint32(o + 8, e.codepage, true);
        view.setUint32(o + 12, 0, true);
        o += 16;
      });
      o = dataOffset;
      this.entries.forEach(function(e) {
        var len = e.bin.byteLength;
        copyBuffer(bin, o, e.bin, 0, len);
        o += roundUp(len, 8);
      });
      var stringsData = [];
      o = stringsOffset;
      strings.forEach(function(s) {
        stringsData.push({
          offset: o,
          text: s
        });
        o = writeString(view, o, s);
      });
      writeTypeTable(view, 0, stringsData, r);
      if (alignedSize > size) {
        var pad = "PADDINGX";
        for (var i = size, j = 0; i < alignedSize; ++i, ++j) {
          if (j === 8) {
            j = 0;
          }
          view.setUint8(i, pad.charCodeAt(j));
        }
      }
      return {
        bin,
        rawSize: size,
        dataOffset,
        descEntryOffset: descOffset,
        descEntryCount: this.entries.length
      };
    };
    NtExecutableResource2.prototype.outputResource = function(exeDest, noGrow, allowShrink) {
      if (noGrow === void 0) {
        noGrow = false;
      }
      if (allowShrink === void 0) {
        allowShrink = false;
      }
      var fileAlign = exeDest.getFileAlignment();
      var sectionData;
      if (this.sectionDataHeader) {
        sectionData = {
          data: null,
          info: cloneObject(this.sectionDataHeader)
        };
      } else {
        sectionData = {
          data: null,
          info: {
            name: ".rsrc",
            virtualSize: 0,
            virtualAddress: 0,
            sizeOfRawData: 0,
            pointerToRawData: 0,
            pointerToRelocations: 0,
            pointerToLineNumbers: 0,
            numberOfRelocations: 0,
            numberOfLineNumbers: 0,
            characteristics: 1073741888
            // read access and initialized data
          }
        };
      }
      var data = this.generateResourceData(0, fileAlign, noGrow, allowShrink);
      sectionData.data = data.bin;
      sectionData.info.sizeOfRawData = data.bin.byteLength;
      sectionData.info.virtualSize = data.rawSize;
      exeDest.setSectionByEntry(ImageDirectoryEntry_default.Resource, sectionData);
      var generatedSection = exeDest.getSectionByEntry(ImageDirectoryEntry_default.Resource);
      var view = new DataView(generatedSection.data);
      var o = data.descEntryOffset;
      var va = generatedSection.info.virtualAddress + data.dataOffset;
      for (var i = 0; i < data.descEntryCount; ++i) {
        var len = view.getUint32(o + 4, true);
        va = roundUp(va, 8);
        view.setUint32(o, va, true);
        va += len;
        o += 16;
      }
    };
    return NtExecutableResource2;
  })()
);

// src/sharedUtils.mjs
var import_spark_md5 = __toESM(require_spark_md5(), 1);
var isBrowser = typeof crypto !== "undefined";
var isNode = typeof globalThis.process !== "undefined" && globalThis.process.versions && globalThis.process.versions.node;
function getCrypto() {
  if (isBrowser) {
    return crypto;
  } else if (isNode) {
    return globalThis.crypto;
  }
  throw new Error("Crypto API not available in this environment");
}
function computeEntropy(u8) {
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
function toHex(u8) {
  return Array.from(u8).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function digestHex(algo, buf) {
  const crypto2 = getCrypto();
  const hash2 = await crypto2.subtle.digest(algo, buf);
  return toHex(new Uint8Array(hash2));
}
function calculateMD5(data) {
  const spark = new import_spark_md5.default.ArrayBuffer();
  spark.append(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
  return spark.end();
}
function readUint16(view, offset, littleEndian) {
  return view.getUint16(offset, littleEndian);
}
function readUint32(view, offset, littleEndian) {
  return view.getUint32(offset, littleEndian);
}
function readUint64(view, offset, littleEndian) {
  const lo = view.getUint32(offset + (littleEndian ? 0 : 4), littleEndian);
  const hi = view.getUint32(offset + (littleEndian ? 4 : 0), littleEndian);
  return hi * 2 ** 32 + lo;
}
function readString2(buf, offset, maxLength = 1024) {
  const end = Math.min(buf.length, offset + maxLength);
  let str = "";
  for (let i = offset; i < end; i++) {
    if (buf[i] === 0) break;
    str += String.fromCharCode(buf[i]);
  }
  return str;
}
function findPattern(buf, pattern) {
  const len = buf.length, plen = pattern.length;
  for (let i = 0; i <= len - plen; i++) {
    let ok = true;
    for (let j = 0; j < plen; j++) if (buf[i + j] !== pattern[j]) {
      ok = false;
      break;
    }
    if (ok) return i;
  }
  return -1;
}

// src/peModule.mjs
async function parsePESections(exe, inputBytes) {
  const sections = [];
  const exeSections = exe.getAllSections?.() || exe.sections || [];
  for (const s of exeSections) {
    const sectionInfo = s.info || s;
    const data = s.data ? new Uint8Array(s.data) : s.data ?? new Uint8Array();
    const md5Hash = calculateMD5(data);
    const sha1Hash = await digestHex("SHA-1", data);
    const sha256Hash = await digestHex("SHA-256", data);
    const sectionHashes = {
      md5: md5Hash,
      sha1: sha1Hash,
      sha256: sha256Hash
    };
    sections.push({
      name: (sectionInfo.name || s.name || "")?.replace(/\0.*$/, ""),
      raw_data: data,
      entropy: computeEntropy(data),
      virtual_address: sectionInfo.virtualAddress ?? sectionInfo.VirtualAddress ?? s.VirtualAddress ?? 0,
      virtual_size: sectionInfo.virtualSize ?? sectionInfo.VirtualSize ?? s.VirtualSize ?? 0,
      raw_data_offset: sectionInfo.pointerToRawData ?? sectionInfo.PointerToRawData ?? s.PointerToRawData ?? 0,
      raw_data_size: sectionInfo.sizeOfRawData ?? sectionInfo.SizeOfRawData ?? s.SizeOfRawData ?? 0,
      characteristics: (sectionInfo.characteristics ?? sectionInfo.Characteristics ?? s.Characteristics ?? 0) >>> 0,
      // Convert to unsigned 32-bit
      ...sectionHashes
    });
  }
  return sections;
}
function parseImports2(exe) {
  return (exe.imports || []).map((imp) => ({
    dll: imp.name || "",
    functions: (imp.functions || []).map((f) => ({ name: f.name || null, ordinal: f.ordinal || null }))
  }));
}
function parseExports(exe) {
  return (exe.exports || []).map((e) => e.name || e).filter(Boolean);
}
function computeImpHash(importsArray) {
  const parts = [];
  for (const imp of importsArray) {
    const dll = (imp.dll || "").toLowerCase();
    if (Array.isArray(imp.functions)) {
      for (const fn of imp.functions) {
        const name = (fn.name || `ordinal${fn.ordinal || ""}`).toLowerCase();
        parts.push(`${dll}.${name}`);
      }
    }
  }
  const encoder = new TextEncoder();
  return calculateMD5(encoder.encode(parts.join(",")));
}
function detectAuthenticode(exe) {
  const dirEntry = exe.optionalHeader?.dataDirectory?.[format_exports.ImageDirectoryEntry.Security];
  if (!dirEntry || !dirEntry.virtualAddress || !dirEntry.size) return { has_signature: false };
  return { has_signature: true, certificate_table: { offset: dirEntry.virtualAddress, size: dirEntry.size } };
}
function detectRichHeader(buf) {
  const pattern = new Uint8Array([82, 105, 99, 104]);
  const offset = findPattern(buf, pattern);
  return offset !== -1 ? { offset } : null;
}
function parseOptionalHeaderFlat(exe) {
  const opt = exe.newHeader?.optionalHeader || exe.optionalHeader;
  if (!opt) return {};
  return {
    size_of_code: opt.sizeOfCode ?? 0,
    size_of_initialized_data: opt.sizeOfInitializedData ?? 0,
    size_of_uninitialized_data: opt.sizeOfUninitializedData ?? 0,
    address_of_entry_point: opt.addressOfEntryPoint ?? 0,
    base_of_code: opt.baseOfCode ?? 0,
    base_of_data: opt.baseOfData ?? 0,
    image_base: opt.imageBase ?? 0,
    section_alignment: opt.sectionAlignment ?? 0,
    file_alignment: opt.fileAlignment ?? 0,
    subsystem: opt.subsystem ?? 0,
    dll_characteristics: opt.dllCharacteristics ?? 0,
    size_of_stack_reserve: opt.sizeOfStackReserve ?? 0,
    size_of_stack_commit: opt.sizeOfStackCommit ?? 0,
    size_of_heap_reserve: opt.sizeOfHeapReserve ?? 0,
    size_of_heap_commit: opt.sizeOfHeapCommit ?? 0
  };
}
async function parsePEYara(inputBytes) {
  if (inputBytes instanceof ArrayBuffer) inputBytes = new Uint8Array(inputBytes);
  let exe;
  try {
    exe = NtExecutable_default.from(inputBytes);
  } catch (e) {
    return { error: "Failed to parse PE", message: e.message };
  }
  const sections = await parsePESections(exe, inputBytes);
  const imports = parseImports2(exe);
  const exportsArr = parseExports(exe);
  const imphash = computeImpHash(imports);
  const digital_signature = detectAuthenticode(exe);
  const rich_header = detectRichHeader(inputBytes);
  const optional_header = parseOptionalHeaderFlat(exe);
  const optHeader = exe.newHeader?.optionalHeader || exe.optionalHeader;
  const coffHeader = exe.newHeader?.fileHeader || exe.coffHeader;
  const entryPointRVA = optHeader?.addressOfEntryPoint ?? 0;
  let entryPointOffset = entryPointRVA;
  if (entryPointRVA > 0 && sections.length > 0) {
    for (const section of sections) {
      const sectionStart = section.virtual_address;
      const sectionEnd = sectionStart + section.virtual_size;
      if (entryPointRVA >= sectionStart && entryPointRVA < sectionEnd) {
        entryPointOffset = entryPointRVA - section.virtual_address + section.raw_data_offset;
        break;
      }
    }
  }
  const peObj = {
    machine: coffHeader?.machine ?? 0,
    entry_point: entryPointOffset,
    image_base: optHeader?.imageBase ?? 0,
    number_of_sections: sections.length,
    sections,
    imports,
    exports: exportsArr,
    imphash,
    digital_signature,
    rich_signature: rich_header,
    // matches YARA field name
    // Flatten optional header fields at top-level for YARA
    ...optional_header,
    file_size: inputBytes.length
  };
  peObj.is_dll = () => {
    const characteristics = coffHeader?.characteristics ?? 0;
    return (characteristics & 8192) !== 0;
  };
  peObj.is_32bit = () => {
    const magic = optHeader?.magic ?? 0;
    return magic === 267;
  };
  peObj.is_64bit = () => {
    const magic = optHeader?.magic ?? 0;
    return magic === 523;
  };
  return peObj;
}
function createPEModule(parsedPE) {
  if (!parsedPE || parsedPE.error) {
    return null;
  }
  return {
    // Direct properties
    machine: parsedPE.machine,
    entry_point: parsedPE.entry_point,
    image_base: parsedPE.image_base,
    number_of_sections: parsedPE.number_of_sections,
    sections: parsedPE.sections,
    imports: parsedPE.imports,
    exports: parsedPE.exports,
    imphash: parsedPE.imphash,
    rich_signature: parsedPE.rich_signature,
    digital_signature: parsedPE.digital_signature,
    // Optional header fields
    size_of_code: parsedPE.size_of_code,
    size_of_initialized_data: parsedPE.size_of_initialized_data,
    size_of_uninitialized_data: parsedPE.size_of_uninitialized_data,
    address_of_entry_point: parsedPE.address_of_entry_point,
    base_of_code: parsedPE.base_of_code,
    base_of_data: parsedPE.base_of_data,
    section_alignment: parsedPE.section_alignment,
    file_alignment: parsedPE.file_alignment,
    subsystem: parsedPE.subsystem,
    dll_characteristics: parsedPE.dll_characteristics,
    // YARA-compatible methods
    is_dll: parsedPE.is_dll,
    is_32bit: parsedPE.is_32bit,
    is_64bit: parsedPE.is_64bit,
    // Helper to check if a DLL is imported
    imports_dll: (dllName) => {
      const lower = dllName.toLowerCase();
      return parsedPE.imports.some((imp) => imp.dll.toLowerCase() === lower);
    },
    // Helper to check if a specific function is imported from a DLL
    // Usage: pe.imports("kernel32.dll", "CreateProcess") or pe.imports("kernel32.dll")
    importsFunction: (dllName, functionName) => {
      const lower = dllName.toLowerCase();
      const imp = parsedPE.imports.find((imp2) => imp2.dll.toLowerCase() === lower);
      if (!imp) return false;
      if (!functionName) return true;
      const lowerFunc = functionName.toLowerCase();
      return imp.functions.some(
        (fn) => fn.name && fn.name.toLowerCase() === lowerFunc
      );
    },
    // Helper to check if a function is exported
    exports_function: (functionName) => {
      const lower = functionName.toLowerCase();
      return parsedPE.exports.some((exp) => exp.toLowerCase() === lower);
    },
    // PE constants (common values used in YARA rules)
    MACHINE_I386: 332,
    MACHINE_AMD64: 34404,
    MACHINE_ARM: 448,
    MACHINE_ARM64: 43620,
    SUBSYSTEM_NATIVE: 1,
    SUBSYSTEM_WINDOWS_GUI: 2,
    SUBSYSTEM_WINDOWS_CUI: 3,
    SECTION_CNT_CODE: 32,
    SECTION_CNT_INITIALIZED_DATA: 64,
    SECTION_CNT_UNINITIALIZED_DATA: 128,
    SECTION_MEM_EXECUTE: 536870912,
    SECTION_MEM_READ: 1073741824,
    SECTION_MEM_WRITE: 2147483648
  };
}

// src/elfModule.mjs
var ELF_MAGIC = [127, 69, 76, 70];
var DT_NEEDED = 1;
var DT_SONAME = 14;
var DT_RPATH = 15;
var DT_RUNPATH = 29;
function parseElfHeader(buf) {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  for (let i = 0; i < 4; i++) if (buf[i] !== ELF_MAGIC[i]) throw new Error("Not ELF");
  const elfClass = buf[4];
  const littleEndian = buf[5] === 1;
  const header = { is64bit: elfClass === 2, littleEndian };
  header.type = readUint16(view, 16, littleEndian);
  header.machine = readUint16(view, 18, littleEndian);
  header.entry_point = header.is64bit ? readUint64(view, 24, littleEndian) : readUint32(view, 24, littleEndian);
  header.phoff = header.is64bit ? readUint64(view, 32, littleEndian) : readUint32(view, 28, littleEndian);
  header.shoff = header.is64bit ? readUint64(view, 40, littleEndian) : readUint32(view, 32, littleEndian);
  header.phentsize = header.is64bit ? readUint16(view, 54, littleEndian) : readUint16(view, 42, littleEndian);
  header.phnum = header.is64bit ? readUint16(view, 56, littleEndian) : readUint16(view, 44, littleEndian);
  header.shentsize = header.is64bit ? readUint16(view, 58, littleEndian) : readUint16(view, 46, littleEndian);
  header.shnum = header.is64bit ? readUint16(view, 60, littleEndian) : readUint16(view, 48, littleEndian);
  header.shstrndx = header.is64bit ? readUint16(view, 62, littleEndian) : readUint16(view, 50, littleEndian);
  return header;
}
function parseProgramHeaders(buf, header) {
  const phs = [];
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = header.phoff;
  for (let i = 0; i < header.phnum; i++) {
    let p_type, p_offset, p_vaddr, p_filesz, p_memsz, p_flags, p_align;
    if (header.is64bit) {
      p_type = readUint32(view, offset, header.littleEndian);
      p_flags = readUint32(view, offset + 4, header.littleEndian);
      p_offset = readUint64(view, offset + 8, header.littleEndian);
      p_vaddr = readUint64(view, offset + 16, header.littleEndian);
      p_filesz = readUint64(view, offset + 32, header.littleEndian);
      p_memsz = readUint64(view, offset + 40, header.littleEndian);
      p_align = readUint64(view, offset + 48, header.littleEndian);
      offset += 56;
    } else {
      p_type = readUint32(view, offset, header.littleEndian);
      p_offset = readUint32(view, offset + 4, header.littleEndian);
      p_vaddr = readUint32(view, offset + 8, header.littleEndian);
      p_filesz = readUint32(view, offset + 16, header.littleEndian);
      p_memsz = readUint32(view, offset + 20, header.littleEndian);
      p_flags = readUint32(view, offset + 24, header.littleEndian);
      p_align = readUint32(view, offset + 28, header.littleEndian);
      offset += 32;
    }
    phs.push({ type: p_type, offset: p_offset, vaddr: p_vaddr, filesz: p_filesz, memsz: p_memsz, flags: p_flags, align: p_align });
  }
  return phs;
}
async function parseSections(buf, header) {
  const shs = [];
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let offset = header.shoff;
  for (let i = 0; i < header.shnum; i++) {
    const sh_offset = header.is64bit ? readUint64(view, offset + 24, header.littleEndian) : readUint32(view, offset + 16, header.littleEndian);
    const sh_size = header.is64bit ? readUint64(view, offset + 32, header.littleEndian) : readUint32(view, offset + 20, header.littleEndian);
    const sectionData = sh_offset + sh_size <= buf.length ? buf.slice(sh_offset, sh_offset + sh_size) : new Uint8Array();
    const md5Hash = calculateMD5(sectionData);
    const sha1Hash = await digestHex("SHA-1", sectionData);
    const sha256Hash = await digestHex("SHA-256", sectionData);
    shs.push({
      offset: sh_offset,
      size: sh_size,
      entropy: computeEntropy(sectionData),
      raw_data: sectionData,
      md5: md5Hash,
      sha1: sha1Hash,
      sha256: sha256Hash
    });
    offset += header.is64bit ? 64 : 40;
  }
  return shs;
}
function parseDynamicDependencies(buf, sections, header) {
  const dynSection = sections.find((s) => s.raw_data && s.raw_data.length > 0 && s.name === ".dynamic");
  const dynstrSection = sections.find((s) => s.raw_data && s.raw_data.length > 0 && s.name === ".dynstr");
  if (!dynSection || !dynstrSection) return { needed_libraries: [], soname: null, rpath: null, runpath: null };
  const dynBuf = dynSection.raw_data;
  const strBuf = dynstrSection.raw_data;
  const view = new DataView(dynBuf.buffer, dynBuf.byteOffset, dynBuf.byteLength);
  const entrySize = header.is64bit ? 16 : 8;
  const needed_libraries = [];
  let soname = null;
  let rpath = null;
  let runpath = null;
  for (let offset = 0; offset + entrySize <= dynBuf.length; offset += entrySize) {
    const tag = header.is64bit ? readUint64(view, offset, header.littleEndian) : readUint32(view, offset, header.littleEndian);
    const val = header.is64bit ? readUint64(view, offset + 8, header.littleEndian) : readUint32(view, offset + 4, header.littleEndian);
    if (tag === DT_NEEDED) needed_libraries.push(readString2(strBuf, val));
    else if (tag === DT_SONAME) soname = readString2(strBuf, val);
    else if (tag === DT_RPATH) rpath = readString2(strBuf, val);
    else if (tag === DT_RUNPATH) runpath = readString2(strBuf, val);
  }
  return { needed_libraries, soname, rpath, runpath };
}
function parseExports2(buf, sections, header) {
  const exportsArr = [];
  const dynsym = sections.find((s) => s.name === ".dynsym");
  const dynstr = sections.find((s) => s.name === ".dynstr");
  if (!dynsym || !dynstr) return exportsArr;
  const symBuf = dynsym.raw_data;
  const strBuf = dynstr.raw_data;
  const view = new DataView(symBuf.buffer, symBuf.byteOffset, symBuf.byteLength);
  const entrySize = header.is64bit ? 24 : 16;
  for (let offset = 0; offset + entrySize <= symBuf.length; offset += entrySize) {
    const nameOffset = readUint32(view, offset, header.littleEndian);
    if (nameOffset >= strBuf.length) continue;
    const name = readString2(strBuf, nameOffset);
    if (name) exportsArr.push(name);
  }
  return exportsArr;
}
async function parseELFYaraFull(inputBytes) {
  if (inputBytes instanceof ArrayBuffer) inputBytes = new Uint8Array(inputBytes);
  const file_size = inputBytes.length;
  let header;
  try {
    header = parseElfHeader(inputBytes);
  } catch (e) {
    return { error: "Invalid ELF file", message: e.message };
  }
  const program_headers = parseProgramHeaders(inputBytes, header);
  const sections = await parseSections(inputBytes, header);
  const { needed_libraries, soname, rpath, runpath } = parseDynamicDependencies(inputBytes, sections, header);
  const exportsArr = parseExports2(inputBytes, sections, header);
  const vaddr = (program_headers?.map((ph) => ph.vaddr) || [0])[0];
  const offset = (program_headers?.map((ph) => ph.offset) || [0])[0];
  return {
    type: header.type,
    machine: header.machine,
    entry_point: header.entry_point - vaddr + offset,
    is_64bit: header.is64bit,
    endianness: header.littleEndian ? "little" : "big",
    file_size,
    program_headers,
    sections,
    imports: needed_libraries.map((lib) => ({ dll: lib, functions: [] })),
    exports: exportsArr,
    needed_libraries,
    soname,
    rpath,
    runpath,
    hashes: {}
    // optional whole-file hashes
  };
}
function createELFModule(parsedELF) {
  if (!parsedELF || parsedELF.error) {
    return null;
  }
  const elfModule = {
    // Basic properties
    type: parsedELF.type || 0,
    machine: parsedELF.machine || 0,
    entry_point: parsedELF.entry_point || 0,
    file_size: parsedELF.file_size || 0,
    is_64bit: parsedELF.is_64bit || false,
    endianness: parsedELF.endianness || "little",
    // Sections
    sections: parsedELF.sections || [],
    number_of_sections: (parsedELF.sections || []).length,
    // Program headers (also exposed as "segments" for Python YARA compatibility)
    program_headers: parsedELF.program_headers || [],
    segments: parsedELF.program_headers || [],
    // Alias for Python YARA compatibility
    number_of_segments: (parsedELF.program_headers || []).length,
    // Imports/Exports
    imports: parsedELF.needed_libraries || [],
    exports: parsedELF.exports || [],
    needed_libraries: parsedELF.needed_libraries || [],
    // Dynamic linking info
    soname: parsedELF.soname || null,
    rpath: parsedELF.rpath || null,
    runpath: parsedELF.runpath || null,
    // Helper methods
    is_32bit() {
      return !this.is_64bit;
    },
    is_little_endian() {
      return this.endianness === "little";
    },
    is_big_endian() {
      return this.endianness === "big";
    },
    // Check if imports a specific library
    imports_library(libName) {
      return this.needed_libraries.some(
        (lib) => lib.toLowerCase().includes(libName.toLowerCase())
      );
    },
    // Check if exports a specific function
    exports_function(funcName) {
      return this.exports.some((exp) => exp === funcName);
    },
    // Get section by name
    get_section_by_name(name) {
      return this.sections.find((s) => s.name === name);
    },
    // ELF constants (matching YARA standard)
    // ELF types (e_type)
    ET_NONE: 0,
    ET_REL: 1,
    ET_EXEC: 2,
    ET_DYN: 3,
    ET_CORE: 4,
    // ELF machine types (e_machine)
    EM_NONE: 0,
    EM_386: 3,
    // Intel 80386
    EM_X86_64: 62,
    // AMD x86-64
    EM_ARM: 40,
    // ARM
    EM_AARCH64: 183,
    // ARM 64-bit
    // Legacy names for compatibility
    ARCH_X86: 3,
    ARCH_X86_64: 62,
    ARCH_ARM: 40,
    ARCH_AARCH64: 183,
    TYPE_EXEC: 2,
    TYPE_DYN: 3,
    TYPE_CORE: 4
  };
  return elfModule;
}

// src/mathModule.mjs
function stringToBytes(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}
function calculateEntropy(data) {
  if (data.length === 0) return 0;
  const frequency = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) {
    frequency[data[i]]++;
  }
  let entropy = 0;
  const length = data.length;
  for (let i = 0; i < 256; i++) {
    if (frequency[i] > 0) {
      const probability = frequency[i] / length;
      entropy -= probability * Math.log2(probability);
    }
  }
  return entropy;
}
function calculateMean(data) {
  if (data.length === 0) return 0;
  let sum = 0;
  for (let i = 0; i < data.length; i++) {
    sum += data[i];
  }
  return sum / data.length;
}
function calculateDeviation(data, mean) {
  if (data.length === 0) return 0;
  let sumSquaredDiff = 0;
  for (let i = 0; i < data.length; i++) {
    const diff = data[i] - mean;
    sumSquaredDiff += diff * diff;
  }
  return Math.sqrt(sumSquaredDiff / data.length);
}
function calculateMonteCarloPI(data) {
  if (data.length < 2) return 0;
  let insideCircle = 0;
  let totalPoints = 0;
  for (let i = 0; i < data.length - 1; i += 2) {
    const x = data[i] / 255 * 2 - 1;
    const y = data[i + 1] / 255 * 2 - 1;
    if (x * x + y * y <= 1) {
      insideCircle++;
    }
    totalPoints++;
  }
  if (totalPoints === 0) return 0;
  return 4 * insideCircle / totalPoints;
}
function calculateSerialCorrelation(data) {
  if (data.length < 2) return 0;
  const mean = calculateMean(data);
  let numerator = 0;
  let denominator = 0;
  for (let i = 0; i < data.length - 1; i++) {
    numerator += (data[i] - mean) * (data[i + 1] - mean);
  }
  for (let i = 0; i < data.length; i++) {
    const diff = data[i] - mean;
    denominator += diff * diff;
  }
  if (denominator === 0) return 0;
  return numerator / denominator;
}
function findMin(...data) {
  if (data.length === 0) throw new Error("No data provided");
  return Math.min(...data);
}
function findMax(...data) {
  if (data.length === 0) throw new Error("No data provided");
  return Math.max(...data);
}
function countByte(byte, data) {
  let count = 0;
  for (let i = 0; i < data.length; i++) {
    if (data[i] === byte) {
      count++;
    }
  }
  return count;
}
function findMode(data) {
  if (data.length === 0) return 0;
  const frequency = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) {
    frequency[data[i]]++;
  }
  let maxFreq = 0;
  let mode = 0;
  for (let i = 0; i < 256; i++) {
    if (frequency[i] > maxFreq) {
      maxFreq = frequency[i];
      mode = i;
    }
  }
  return mode;
}
function createMathModule(data) {
  if (!data || !(data instanceof Uint8Array)) {
    throw new Error("Math module requires a Uint8Array data buffer");
  }
  return {
    /**
     * Calculate Shannon entropy
     * Can be called with (offset, size) or (string)
     */
    entropy: function(...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        const bytes = stringToBytes(args[0]);
        return calculateEntropy(bytes);
      } else if (args.length === 2) {
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        if (offset >= data.length || offset + size > data.length) return 0;
        const slice = data.slice(offset, offset + size);
        if (slice.length === 0) return 0;
        return calculateEntropy(slice);
      } else {
        throw new Error("entropy() requires either (offset, size) or (string)");
      }
    },
    /**
     * Monte Carlo estimation of Pi
     * Called with (offset, size) or (string)
     */
    monte_carlo_pi: function(...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        const bytes = stringToBytes(args[0]);
        return calculateMonteCarloPI(bytes);
      } else if (args.length === 2) {
        const [offset, size] = args;
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        if (offset >= data.length || offset + size > data.length) return 0;
        const slice = data.slice(offset, offset + size);
        if (slice.length === 0) return 0;
        return calculateMonteCarloPI(slice);
      } else {
        throw new Error("monte_carlo_pi() requires (offset, size)");
      }
    },
    /**
     * Serial correlation coefficient
     * Called with (offset, size) or (string)
     */
    serial_correlation: function(...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        const bytes = stringToBytes(args[0]);
        return calculateSerialCorrelation(bytes);
      } else if (args.length === 2) {
        const [offset, size] = args;
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        if (offset >= data.length || offset + size > data.length) return 0;
        const slice = data.slice(offset, offset + size);
        if (slice.length === 0) return 0;
        return calculateSerialCorrelation(slice);
      } else {
        throw new Error("serial_correlation() requires (offset, size)");
      }
    },
    /**
     * Arithmetic mean of bytes
     * Called with (offset, size) or (string)
     */
    mean: function(...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        const bytes = stringToBytes(args[0]);
        return calculateMean(bytes);
      } else if (args.length === 2) {
        const [offset, size] = args;
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        if (offset >= data.length || offset + size > data.length) return 0;
        const slice = data.slice(offset, offset + size);
        if (slice.length === 0) return 0;
        return calculateMean(slice);
      } else {
        throw new Error("mean() requires (offset, size)");
      }
    },
    /**
     * Standard deviation of bytes
     * Called with (offset, size, mean) or (string)
     */
    deviation: function(...args) {
      if (args.length === 2 && typeof args[0] === "string") {
        const [str, mean] = args;
        const bytes = stringToBytes(str);
        return calculateDeviation(bytes, mean);
      } else if (args.length === 3) {
        const [offset, size, mean] = args;
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        if (offset >= data.length || offset + size > data.length) return 0;
        const slice = data.slice(offset, offset + size);
        if (slice.length === 0) return 0;
        return calculateDeviation(slice, mean);
      } else {
        throw new Error("deviation() requires (offset, size, mean)");
      }
    },
    /**
     * Minimum byte value
     * Called with (offset, size)
     */
    min: function(a, b) {
      return findMin(a, b);
    },
    /**
     * Maximum byte value
     * Called with (offset, size)
     */
    max: function(a, b) {
      return findMax(a, b);
    },
    /**
     * Count occurrences of a byte
     * Called with (byte, offset, size)
     */
    count: function(byte, offset, size) {
      if (byte < 0 || byte > 255) {
        throw new Error(`Invalid byte value: ${byte} (must be 0-255)`);
      }
      if (offset < 0 || size < 0) {
        throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
      }
      const slice = data.slice(offset, offset + size);
      if (slice.length === 0) return 0;
      return countByte(byte, slice);
    },
    /**
     * Percentage of a byte value
     * Called with (byte, offset, size)
     */
    percentage: function(byte, offset, size) {
      return this.count(byte, offset, size) / size;
    },
    /**
     * Most common byte value (mode)
     * Called with (offset, size)
     */
    mode: function(offset, size) {
      if (offset < 0 || size < 0) {
        throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
      }
      const slice = data.slice(offset, offset + size);
      if (slice.length === 0) return 0;
      return findMode(slice);
    },
    /**
     * Absolute value
     * Called with (value)
     */
    abs: function(value) {
      return Math.abs(value);
    },
    /**
     * Convert boolean to number
     * Called with (bool)
     */
    to_number: function(bool) {
      return bool ? 1 : 0;
    },
    /**
     * Check if value is in range
     * Called with (value, lower, upper)
     */
    in_range: function(value, lower, upper) {
      return value >= lower && value <= upper;
    }
  };
}
var math = {
  /**
   * Calculate entropy of a string
   * @param {string} str
   * @returns {number} Entropy value
   */
  entropy: function(str) {
    const bytes = stringToBytes(str);
    return calculateEntropy(bytes);
  },
  /**
   * Absolute value
   * @param {number} value
   * @returns {number}
   */
  abs: function(value) {
    return Math.abs(value);
  },
  /**
   * Convert boolean to number
   * @param {boolean} bool
   * @returns {number} 1 for true, 0 for false
   */
  to_number: function(bool) {
    return bool ? 1 : 0;
  },
  /**
   * Check if value is in range [lower, upper]
   * @param {number} value
   * @param {number} lower
   * @param {number} upper
   * @returns {boolean}
   */
  in_range: function(value, lower, upper) {
    return value >= lower && value <= upper;
  }
};

// src/hashModule.mjs
function stringToBytes2(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}
function calculateChecksum32(data) {
  let sum = 0;
  for (let i = 0; i < data.length; i++) {
    sum = sum + data[i] >>> 0;
  }
  return sum & 4294967295;
}
var CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let crc = i;
    for (let j = 0; j < 8; j++) {
      crc = crc & 1 ? 3988292384 ^ crc >>> 1 : crc >>> 1;
    }
    table[i] = crc;
  }
  return table;
})();
function calculateCRC32(data) {
  let crc = 4294967295;
  for (let i = 0; i < data.length; i++) {
    crc = crc >>> 8 ^ CRC32_TABLE[(crc ^ data[i]) & 255];
  }
  crc = (crc ^ 4294967295) >>> 0;
  return crc;
}
function createHashModule(data) {
  if (!data || !(data instanceof Uint8Array)) {
    throw new Error("Hash module requires a Uint8Array data buffer");
  }
  return {
    /**
     * Calculate MD5 hash
     * Can be called with (offset, size) or (string)
     */
    md5: async function(...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        const bytes = stringToBytes2(args[0]);
        return calculateMD5(bytes);
      } else if (args.length === 2) {
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        return calculateMD5(slice);
      } else {
        throw new Error("md5() requires either (offset, size) or (string)");
      }
    },
    /**
     * Calculate SHA1 hash
     * Can be called with (offset, size) or (string)
     */
    sha1: async function(...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        const bytes = stringToBytes2(args[0]);
        return await digestHex("SHA-1", bytes);
      } else if (args.length === 2) {
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0 || offset + size > data.length) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        return await digestHex("SHA-1", slice);
      } else {
        throw new Error("sha1() requires either (offset, size) or (string)");
      }
    },
    /**
     * Calculate SHA256 hash
     * Can be called with (offset, size) or (string)
     */
    sha256: async function(...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        const bytes = stringToBytes2(args[0]);
        return await digestHex("SHA-256", bytes);
      } else if (args.length === 2) {
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0 || offset + size > data.length) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        return await digestHex("SHA-256", slice);
      } else {
        throw new Error("sha256() requires either (offset, size) or (string)");
      }
    },
    /**
     * Calculate 32-bit checksum
     * Can be called with (offset, size) or (string)
     */
    checksum32: function(...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        const bytes = stringToBytes2(args[0]);
        return calculateChecksum32(bytes);
      } else if (args.length === 2) {
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        if (slice.length === 0) return 0;
        return calculateChecksum32(slice);
      } else {
        throw new Error("checksum32() requires either (offset, size) or (string)");
      }
    },
    /**
     * Calculate CRC32 checksum
     * Can be called with (offset, size) or (string)
     */
    crc32: function(...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        const bytes = stringToBytes2(args[0]);
        return calculateCRC32(bytes);
      } else if (args.length === 2) {
        const offset = args[0];
        const size = args[1];
        if (offset < 0 || size < 0) {
          throw new Error(`Invalid range: offset=${offset}, size=${size}, data.length=${data.length}`);
        }
        const slice = data.slice(offset, offset + size);
        if (slice.length === 0) return 0;
        return calculateCRC32(slice);
      } else {
        throw new Error("crc32() requires either (offset, size) or (string)");
      }
    }
  };
}
var hash = {
  /**
   * Calculate MD5 hash of a string
   * @param {string} str 
   * @returns {Promise<string>} Hex string
   */
  md5: async function(str) {
    const bytes = stringToBytes2(str);
    return calculateMD5(bytes);
  },
  /**
   * Calculate SHA1 hash of a string
   * @param {string} str 
   * @returns {Promise<string>} Hex string
   */
  sha1: async function(str) {
    const bytes = stringToBytes2(str);
    return await digestHex("SHA-1", bytes);
  },
  /**
   * Calculate SHA256 hash of a string
   * @param {string} str 
   * @returns {Promise<string>} Hex string
   */
  sha256: async function(str) {
    const bytes = stringToBytes2(str);
    return await digestHex("SHA-256", bytes);
  },
  /**
   * Calculate 32-bit checksum of a string
   * @param {string} str 
   * @returns {string} Hex string
   */
  checksum32: function(str) {
    const bytes = stringToBytes2(str);
    return calculateChecksum32(bytes);
  },
  /**
   * Calculate CRC32 of a string
   * @param {string} str 
   * @returns {string} Hex string
   */
  crc32: function(str) {
    const bytes = stringToBytes2(str);
    return calculateCRC32(bytes);
  }
};

// src/timeModule.mjs
var time = {
  now: () => Date.now()
};

// src/stringModule.mjs
var string = {
  to_int: (s, base = 10) => {
    if (typeof s !== "string" && !(s instanceof String)) {
      throw new Error("to_int() first argument must be a string");
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
    }
    return result;
  },
  length: (s) => {
    if (typeof s === "string" || s instanceof String) {
      return s.length;
    }
    return 0;
  }
};

// src/performanceInstrumentation.mjs
var defaultLogger = typeof console !== "undefined" && typeof console.log === "function" ? (...args) => console.log(...args) : () => {
};
var hasPerformance = typeof globalThis !== "undefined" && globalThis.performance && typeof globalThis.performance.now === "function";
function now() {
  return hasPerformance ? globalThis.performance.now() : Date.now();
}
function cloneDeep(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}
var PerformanceTracker = class {
  constructor(options = {}) {
    const enabled = options.enabled ?? options.enableTiming ?? false;
    const logger = options.logger ?? defaultLogger;
    const autoPrint = options.autoPrint ?? false;
    this.options = {
      enabled: Boolean(enabled),
      logger,
      autoPrint: Boolean(autoPrint)
    };
    this.lastTiming = {
      compile: null,
      scan: null
    };
  }
  isEnabled() {
    return Boolean(this.options.enabled);
  }
  now() {
    return now();
  }
  updateOptions(options = {}) {
    if (Object.prototype.hasOwnProperty.call(options, "enabled") || Object.prototype.hasOwnProperty.call(options, "enableTiming")) {
      this.options.enabled = Boolean(options.enabled ?? options.enableTiming);
    }
    if (Object.prototype.hasOwnProperty.call(options, "logger")) {
      this.options.logger = options.logger ?? defaultLogger;
    }
    if (Object.prototype.hasOwnProperty.call(options, "autoPrint")) {
      this.options.autoPrint = Boolean(options.autoPrint);
    }
  }
  enable(enable = true, logger) {
    this.updateOptions({ enabled: enable, logger });
  }
  clearCompile() {
    this.lastTiming.compile = null;
  }
  clearScan() {
    this.lastTiming.scan = null;
  }
  recordCompile(duration) {
    const entry = { total: duration };
    this.lastTiming.compile = entry;
    this.printTiming("compile", entry);
  }
  createScanTiming() {
    return {
      total: 0,
      steps: {
        buildAutomaton: 0,
        acSearch: 0,
        deduplicate: 0,
        verifyCandidates: 0,
        buildMatches: 0,
        evaluateConditions: 0,
        filterStrings: 0
      },
      modules: {
        total: 0,
        pe: 0,
        elf: 0,
        math: 0,
        hash: 0
      },
      conditionParsing: {
        total: 0,
        byRule: {}
      },
      matchCount: 0
    };
  }
  finalizeScan(scanTiming) {
    this.lastTiming.scan = scanTiming;
    this.printTiming("scan", scanTiming);
  }
  accumulateStep(steps, key, duration) {
    if (!steps || !Number.isFinite(duration)) return;
    steps[key] = (steps[key] || 0) + duration;
  }
  accumulateModule(modules, key, duration) {
    if (!modules || !Number.isFinite(duration)) return;
    modules.total = (modules.total || 0) + duration;
    modules[key] = (modules[key] || 0) + duration;
  }
  accumulateCondition(conditionTiming, ruleName, duration) {
    if (!conditionTiming || !Number.isFinite(duration)) return;
    conditionTiming.total = (conditionTiming.total || 0) + duration;
    if (!conditionTiming.byRule) {
      conditionTiming.byRule = {};
    }
    conditionTiming.byRule[ruleName] = (conditionTiming.byRule[ruleName] || 0) + duration;
  }
  getSnapshot() {
    return cloneDeep(this.lastTiming);
  }
  printTiming(phase, data) {
    if (!this.options.enabled || !this.options.autoPrint || !this.options.logger || !data) {
      return;
    }
    const logger = this.options.logger;
    if (phase === "compile") {
      logger(`[InterceptScanner] Compile completed in ${data.total.toFixed(3)}ms`);
      return;
    }
    if (phase === "scan") {
      const matchCount = data.matchCount ?? "n/a";
      logger(`[InterceptScanner] Scan completed in ${data.total.toFixed(3)}ms (matches: ${matchCount})`);
      if (data.steps) {
        Object.entries(data.steps).forEach(([step, value]) => {
          if (value == null) return;
          logger(`  \u2022 ${step}: ${value.toFixed(3)}ms`);
        });
      }
      if (data.modules && data.modules.total) {
        logger(`  \u2022 moduleCreation.total: ${data.modules.total.toFixed(3)}ms`);
      }
      if (data.conditionParsing && data.conditionParsing.total) {
        logger(`  \u2022 conditionParsing.total: ${data.conditionParsing.total.toFixed(3)}ms`);
      }
    }
  }
};
function createPerformanceTracker(options = {}) {
  return new PerformanceTracker(options);
}

// src/interceptCustomModules.mjs
var BaseCustomModule = class {
  constructor(name) {
    this._isLoaded = false;
    this._name = name;
    if (!isValidModuleName(name)) {
      throw new Error(`Invalid module name: "${name}". It is either reserved or malformed.`);
    }
  }
  /**
   * Returns the module keyword for YARA conditions
   * @returns {string} Module name (must be unique and not reserved)
   */
  getName() {
    return this._name;
  }
  /**
   * Returns whether the module loaded successfully
   * @returns {boolean} Load status
   */
  isLoaded() {
    return this._isLoaded;
  }
  /**
   * One-time initialization
   * Should catch errors internally and set loaded flag
   * @returns {Promise<boolean>} Load success status
   */
  async load() {
    this._isLoaded = true;
    return this._isLoaded;
  }
  /**
   * Process file data per scan
   * @param {Uint8Array} data - File data being scanned
   * @param {Object} metadata - Scan metadata (filesize, hasPE, hasELF, timestamp)
   * @returns {Promise<Object>} Interim results (any structure)
   */
  async initialize(data, metadata) {
    throw new Error("CustomModule.initialize() must be implemented");
  }
  /**
   * Create final module object for condition evaluation
   * @param {Object} interimResults - Results from initialize()
   * @returns {Object} Module object with properties and/or functions
   */
  createModule(interimResults) {
    throw new Error("CustomModule.createModule() must be implemented");
  }
};
var RESERVED_MODULE_NAMES = [
  "pe",
  "elf",
  "math",
  "hash",
  "string",
  "time",
  "filesize",
  "entrypoint"
];
function isValidModuleName(name) {
  if (!name || typeof name !== "string") {
    return false;
  }
  const nameLower = name.toLowerCase();
  return !RESERVED_MODULE_NAMES.includes(nameLower);
}

// src/interceptScanner.mjs
var InterceptScanner = class {
  constructor(options = {}) {
    this.compiledRules = [];
    this.ac = null;
    this.autoParsePE = true;
    this.autoParseELF = true;
    this.maxFileSize = 1024 * 1024;
    this.setModules(options.modules);
    this.customModules = options.modules || {};
    const timingOptions = {
      enabled: options.timing?.enabled ?? options.timing?.enableTiming ?? options.enableTiming ?? false,
      autoPrint: options.timing?.autoPrint ?? options.autoPrint ?? false,
      logger: options.timing?.logger ?? options.timingLogger ?? options.logger
    };
    this.timingTracker = createPerformanceTracker(timingOptions);
  }
  /**
   * Add YARA rules from text (Same as addRules, but named compile for clarity)
   * @param {string} rulesText - YARA rules in text format
   */
  compile(rulesText) {
    const tracker = this.timingTracker;
    const timingEnabled = tracker?.isEnabled();
    const start = timingEnabled ? tracker.now() : 0;
    this.compiledRules = parseYaraRuleGroup(rulesText, this.compiledRules || []);
    this.ac = null;
    if (timingEnabled) {
      tracker.recordCompile(tracker.now() - start);
    } else if (tracker) {
      tracker.clearCompile();
    }
  }
  /**
   * Add YARA rules from text
   * @param {string} rulesText - YARA rules in text format
   */
  addRules(rulesText) {
    this.compile(rulesText);
  }
  /**
   * Remove all YARA rules
   */
  clearRules() {
    this.compiledRules = [];
    this.ac = null;
  }
  /**
   * Set modules for condition evaluation
   * @param {Object} modules - Module instances (pe, elf, math, hash, etc.)
   */
  setModules(modules) {
    this.modules = { string, time, ...modules || {} };
  }
  setTiming(timingOptions = {}) {
    this.timingTracker.updateOptions(timingOptions);
  }
  enableTiming(enable = true, logger) {
    this.timingTracker.enable(enable, logger);
  }
  getTiming() {
    return this.timingTracker.getSnapshot();
  }
  /**
   * Deduplicate candidate matches
   * @param {Array} candidates - Array of candidate matches from AC
   * @returns {Array} Deduplicated candidates
   */
  deduplicateCandidates(candidates) {
    const unique = /* @__PURE__ */ new Map();
    for (const candidate of candidates) {
      const key = `${candidate.id}:${candidate.varName}:${candidate.offset}`;
      if (!unique.has(key)) {
        unique.set(key, candidate);
      }
    }
    return Array.from(unique.values());
  }
  /**
   * Verify candidates with full string matchers
   * @param {Array} candidates - Candidate matches
   * @param {Uint8Array} data - File data
   * @param {Array} rules - Compiled rules
   * @returns {Array} Verified matches
   */
  verifyCandidates(candidates, data, rules) {
    const verified = [];
    for (const candidate of candidates) {
      const rule = rules.find((r) => r.id === candidate.id);
      if (!rule) continue;
      const strDef = rule.strings[candidate.varName];
      if (!strDef || !strDef.matcher) continue;
      if (strDef.type === "text" || strDef.type === "regex" && strDef.literalPrefix) {
        const matches = strDef.matcher(data, candidate.offset);
        if (matches && matches.length > 0) {
          verified.push({
            ...candidate,
            matches
          });
        }
      } else {
        verified.push(candidate);
      }
    }
    return verified;
  }
  /**
   * Build string match results per rule
   * @param {Array} verifiedCandidates - Verified matches
   * @param {Array} rules - Compiled rules
   * @param {Uint8Array} data - File data
   * @returns {Object} String matches organized by rule
   */
  buildStringMatches(verifiedCandidates, rules, data) {
    const ruleMatches = {};
    for (const rule of rules) {
      ruleMatches[rule.id] = {};
      for (const varName of Object.keys(rule.strings)) {
        ruleMatches[rule.id][`$${varName}`] = {
          identifier: `$${varName}`,
          matched: false,
          count: 0,
          matches: [],
          offsets: [],
          // length: null,
          private: rule.strings[varName].private
        };
      }
    }
    for (const candidate of verifiedCandidates) {
      const matchInfo = ruleMatches[candidate.id][`$${candidate.varName}`];
      if (candidate.matches && candidate.matches.length > 0) {
        const prunedList = candidate.matches.length > MAX_MATCHES ? candidate.matches.slice(0, MAX_MATCHES) : candidate.matches;
        matchInfo.matched = true;
        matchInfo.count += prunedList.length;
        matchInfo.matches.push(...prunedList);
        matchInfo.offsets.push(...candidate.matches.map((m) => m.offset));
      } else {
        matchInfo.matched = true;
        matchInfo.count += 1;
        matchInfo.matches.push({
          offset: candidate.offset,
          length: candidate.length || 0
        });
        matchInfo.offsets.push(candidate.offset);
      }
    }
    let dataAsHexString = null;
    for (const rule of rules) {
      for (const [varName, strDef] of Object.entries(rule.strings)) {
        if (strDef.type === "text" || strDef.type === "regex" && strDef.literalPrefix?.length > 0) continue;
        const matchInfo = ruleMatches[rule.id][`$${varName}`];
        if (strDef.type === "hex" && dataAsHexString === null) {
          dataAsHexString = Array.from(data).map((b) => b.toString(16).toUpperCase().padStart(2, "0")).join("");
        }
        let matches = strDef.type === "hex" && dataAsHexString !== null ? strDef.matcher(dataAsHexString, -1) : strDef.matcher(data, -1);
        if (matches && matches.length > 0) {
          const prunedList = matches.length > MAX_MATCHES ? matches.slice(0, MAX_MATCHES) : matches;
          matchInfo.matched = true;
          matchInfo.count += prunedList.length;
          if (matchInfo.matches.length === 0) {
            matchInfo.matches = prunedList;
          } else {
            matchInfo.matches.push(...prunedList);
          }
          matchInfo.offsets.push(...matches.map((m) => m.offset));
        }
      }
    }
    return ruleMatches;
  }
  /**
   * Evaluate rule conditions
   * @param {Object} ruleMatches - String matches per rule
   * @param {Array} rules - Compiled rules
   * @param {Uint8Array} data - File data
   * @param {Object} metadata - Scan metadata to pass to custom modules
   * @param {Object} timingContext - Timing context for performance tracking
   * @returns {Array} Rules that matched
   */
  async evaluateConditions(ruleMatches, rules, data, metadata = {}, timingContext = null) {
    const matchedRules = [];
    const ruleMatchStatus = {};
    const tracker = timingContext?.tracker;
    const modulesTiming = timingContext?.modules;
    let peModule = this.modules.pe;
    if (this.autoParsePE && !peModule) {
      const start = tracker ? tracker.now() : 0;
      try {
        if (data.length > 2 && data[0] === 77 && data[1] === 90) {
          const parsedPE = await parsePEYara(data);
          if (parsedPE && !parsedPE.error) {
            peModule = createPEModule(parsedPE);
          }
        } else {
        }
      } catch {
      } finally {
        if (tracker && modulesTiming) {
          tracker.accumulateModule(modulesTiming, "pe", tracker.now() - start);
        }
      }
    }
    let elfModule = this.modules.elf;
    if (this.autoParseELF && !elfModule) {
      const start = tracker ? tracker.now() : 0;
      try {
        if (data.length > 4 && data[0] === 127 && data[1] === 69 && data[2] === 76 && data[3] === 70) {
          const parsedELF = await parseELFYaraFull(data);
          if (parsedELF && !parsedELF.error) {
            elfModule = createELFModule(parsedELF);
          }
        }
      } catch {
      } finally {
        if (tracker && modulesTiming) {
          tracker.accumulateModule(modulesTiming, "elf", tracker.now() - start);
        }
      }
    }
    const modulesWithBinary = {
      ...this.modules,
      ...peModule && { pe: peModule },
      ...elfModule && { elf: elfModule }
    };
    const mathStart = tracker ? tracker.now() : 0;
    modulesWithBinary.math = createMathModule(data);
    if (tracker && modulesTiming) {
      tracker.accumulateModule(modulesTiming, "math", tracker.now() - mathStart);
    }
    const hashStart = tracker ? tracker.now() : 0;
    modulesWithBinary.hash = createHashModule(data);
    if (tracker && modulesTiming) {
      tracker.accumulateModule(modulesTiming, "hash", tracker.now() - hashStart);
    }
    for (const [key, moduleValue] of Object.entries(this.modules)) {
      try {
        if (typeof moduleValue?.getName === "function") {
          const moduleName = moduleValue.getName();
          if (!isValidModuleName(moduleName)) {
            console.warn(`InterceptScanner: Custom module "${moduleName}" has reserved name - skipping initialization`);
            continue;
          }
          if (typeof moduleValue.isLoaded === "function" && !moduleValue.isLoaded()) {
            const loadStart = tracker ? tracker.now() : 0;
            if (typeof moduleValue.load === "function") {
              await moduleValue.load();
            }
            if (tracker && modulesTiming) {
              tracker.accumulateModule(modulesTiming, `${moduleName}_load`, tracker.now() - loadStart);
            }
          }
          const moduleStart = tracker ? tracker.now() : 0;
          const scanMetadata = {
            ...metadata,
            filesize: data.length,
            hasPE: !!peModule,
            hasELF: !!elfModule,
            timestamp: Date.now()
          };
          let moduleObject = moduleValue;
          if (typeof moduleValue.initialize === "function" && typeof moduleValue.createModule === "function") {
            const interimResults = await moduleValue.initialize(data, scanMetadata);
            moduleObject = moduleValue.createModule(interimResults);
          }
          if (tracker && modulesTiming) {
            tracker.accumulateModule(modulesTiming, moduleName, tracker.now() - moduleStart);
          }
          modulesWithBinary[moduleName] = moduleObject;
        }
      } catch (error) {
        console.warn(`InterceptScanner: Error initializing custom module "${key}": ${error.message}`);
      }
    }
    const globalRules = rules.filter((rule) => rule.global);
    for (const rule of globalRules) {
      const result = await this.evaluateRuleCondition(
        ruleMatches,
        rule,
        data,
        ruleMatchStatus,
        { peModule, elfModule, modulesWithBinary },
        timingContext
      );
      if (result) {
        if (!rule.private) {
          matchedRules.push(result);
        }
      } else {
        return matchedRules;
      }
    }
    const nonGlobalRules = rules.filter((rule) => !rule.global);
    for (const rule of nonGlobalRules) {
      const result = await this.evaluateRuleCondition(
        ruleMatches,
        rule,
        data,
        ruleMatchStatus,
        { peModule, elfModule, modulesWithBinary },
        timingContext
      );
      if (result && !rule.private) {
        matchedRules.push(result);
      }
    }
    for (const [moduleName, moduleInstance] of Object.entries(modulesWithBinary)) {
      if (["string", "time", "hash", "math"].includes(moduleName)) {
        continue;
      }
      matchedRules[moduleName] = {};
      for (const [key, value] of Object.entries(moduleInstance)) {
        if (!key.startsWith("_") && typeof value !== "function" && !/[A-Z0-9]+/.test(key)) {
          matchedRules[moduleName][key] = typeof value === "object" ? removeKeyDeep({ ...value }, ["raw_data", "data"]) : value;
        }
      }
    }
    return matchedRules;
  }
  async evaluateRuleCondition(ruleMatches, rule, data, ruleMatchStatus, modules = {}, timingContext = null) {
    const { peModule, elfModule, modulesWithBinary } = modules;
    const tracker = timingContext?.tracker;
    const conditionTiming = timingContext?.condition;
    try {
      const entrypoint = peModule ? peModule.entry_point : elfModule ? elfModule.entry_point : -1e6;
      const actualFileSize = data.length;
      const isFileSizeCapped = actualFileSize >= this.maxFileSize;
      const scanFacts = createScanFacts(data, ruleMatches[rule.id], modulesWithBinary, {
        entrypoint,
        filesize: actualFileSize,
        isFileSizeCapped,
        maxFileSize: this.maxFileSize,
        matchedRules: ruleMatchStatus,
        // Pass matched rules for dependent rule evaluation
        metadata: {
          ruleName: rule.name
        }
      });
      let conditionAST;
      const parseStart = tracker ? tracker.now() : 0;
      try {
        conditionAST = parseConditionToAST(rule.condition, scanFacts.strings);
      } catch {
        conditionAST = this.parseSimpleCondition(rule.condition, scanFacts.strings);
      } finally {
        if (tracker && conditionTiming) {
          tracker.accumulateCondition(conditionTiming, rule.name, tracker.now() - parseStart);
        }
      }
      const matched = await evaluateCondition(conditionAST, scanFacts);
      ruleMatchStatus[rule.name] = matched;
      if (matched) {
        const filteredStrings = {};
        for (const [key, value] of Object.entries(ruleMatches[rule.id])) {
          if (!key.startsWith("$.") && !value.private) {
            filteredStrings[key] = value;
          }
        }
        return {
          rule: rule.name,
          namespace: rule.namespace || "default",
          tags: rule.tags || [],
          metadata: rule.metadata || {},
          strings: filteredStrings
        };
      }
    } catch (error) {
      console.log("Failing rule: ", rule);
      console.trace(error);
    }
    return false;
  }
  /**
   * Parse simple conditions (fallback parser)
   * Handles common patterns: $a, any of them, all of them, N of them
   * @param {string} condition - Condition string
   * @param {Object} strings - String match information
   * @returns {Object} AST node
   */
  parseSimpleCondition(condition, strings) {
    condition = condition.trim();
    if (condition === "any of them") {
      return { type: "any", items: "them" };
    }
    if (condition === "all of them") {
      return { type: "all", items: "them" };
    }
    if (condition === "none of them") {
      return { type: "none", items: "them" };
    }
    const nOfThemMatch = condition.match(/^(\d+)\s+of\s+them$/);
    if (nOfThemMatch) {
      return {
        type: "quantified",
        quantifier: { type: "number", value: parseInt(nOfThemMatch[1]) },
        items: "them"
      };
    }
    const singleStringMatch = condition.match(/^\$(\w+)$/);
    if (singleStringMatch) {
      return {
        type: "stringIdentifier",
        identifier: `$${singleStringMatch[1]}`
      };
    }
    const andMatch = condition.match(/^\(?(\$\w+)\s+and\s+(\$\w+)\)?$/);
    if (andMatch) {
      return {
        type: "and",
        left: { type: "stringIdentifier", identifier: andMatch[1] },
        right: { type: "stringIdentifier", identifier: andMatch[2] }
      };
    }
    const orMatch = condition.match(/^\(?(\$\w+)\s+or\s+(\$\w+)\)?$/);
    if (orMatch) {
      return {
        type: "or",
        left: { type: "stringIdentifier", identifier: orMatch[1] },
        right: { type: "stringIdentifier", identifier: orMatch[2] }
      };
    }
    const stringIds = Object.keys(strings);
    for (const id of stringIds) {
      if (condition.includes(id) && strings[id].matched) {
        return { type: "boolean", value: true };
      }
    }
    return { type: "boolean", value: false };
  }
  filterStringResults(ruleMatches) {
    if (!Array.isArray(ruleMatches)) return;
    ruleMatches.forEach((ruleMatch) => {
      if (Object.keys(ruleMatch.strings).length > 0) {
        for (const [strId, strInfo] of Object.entries(ruleMatch.strings)) {
          if (!strInfo.matched) {
            delete ruleMatch.strings[strId];
          }
        }
      }
    });
  }
  /**
   * Scan binary data with all loaded rules
   * @param {Uint8Array|string} data - Data to scan
   * @returns {Promise<Array>} Matched rules with details
   */
  async scan(data, metadata = {}) {
    const tracker = this.timingTracker;
    const timingEnabled = tracker?.isEnabled();
    const totalStart = timingEnabled ? tracker.now() : 0;
    const scanTiming = timingEnabled ? tracker.createScanTiming() : null;
    if (typeof data === "string") {
      const encoder = new TextEncoder();
      data = encoder.encode(data);
    }
    if (!this.compiledRules || this.compiledRules.length === 0) {
      if (timingEnabled && scanTiming) {
        scanTiming.total = tracker.now() - totalStart;
        scanTiming.matchCount = 0;
        tracker.finalizeScan(scanTiming);
      } else if (tracker) {
        tracker.clearScan();
      }
      return [];
    }
    if (!this.ac) {
      if (timingEnabled && scanTiming) {
        const start = tracker.now();
        this.ac = new AhoCorasick(this.compiledRules);
        tracker.accumulateStep(scanTiming.steps, "buildAutomaton", tracker.now() - start);
      } else {
        this.ac = new AhoCorasick(this.compiledRules);
      }
    }
    const acSearchStart = timingEnabled ? tracker.now() : 0;
    const candidates = this.ac.search(data);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "acSearch", tracker.now() - acSearchStart);
    }
    const dedupeStart = timingEnabled ? tracker.now() : 0;
    const unique = this.deduplicateCandidates(candidates);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "deduplicate", tracker.now() - dedupeStart);
    }
    const verifyStart = timingEnabled ? tracker.now() : 0;
    const verified = this.verifyCandidates(unique, data, this.compiledRules);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "verifyCandidates", tracker.now() - verifyStart);
    }
    const buildStart = timingEnabled ? tracker.now() : 0;
    const ruleMatches = this.buildStringMatches(verified, this.compiledRules, data);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "buildMatches", tracker.now() - buildStart);
    }
    let evaluationContext = null;
    let evaluateStart = 0;
    if (timingEnabled && scanTiming) {
      evaluationContext = {
        tracker,
        modules: scanTiming.modules,
        condition: scanTiming.conditionParsing
      };
      evaluateStart = tracker.now();
    }
    const results = await this.evaluateConditions(ruleMatches, this.compiledRules, data, metadata, evaluationContext);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "evaluateConditions", tracker.now() - evaluateStart);
    }
    const filterStart = timingEnabled ? tracker.now() : 0;
    this.filterStringResults(results);
    if (timingEnabled && scanTiming) {
      tracker.accumulateStep(scanTiming.steps, "filterStrings", tracker.now() - filterStart);
      scanTiming.total = tracker.now() - totalStart;
      scanTiming.matchCount = results.length;
      tracker.finalizeScan(scanTiming);
    } else if (tracker) {
      tracker.clearScan();
    }
    return results;
  }
  /**
   * Set maximum file size limit for filesize operator
   * @param {number} size - Maximum file size in bytes
   */
  setMaxFileSize(size) {
    this.maxFileSize = size;
  }
  /**
   * Get statistics about loaded rules
   * @returns {Object} Rule statistics
   */
  getStats() {
    return {
      totalRules: this.compiledRules.length,
      ruleNames: this.compiledRules.map((r) => r.name),
      rulesWithStrings: this.compiledRules.filter((r) => Object.keys(r.strings).length > 0).length,
      totalStrings: this.compiledRules.reduce((sum, r) => sum + Object.keys(r.strings).length, 0),
      totalPatterns: this.compiledRules.reduce((sum, r) => {
        return sum + Object.values(r.strings).reduce((s, str) => {
          return s + (str.patterns ? str.patterns.length : 0);
        }, 0);
      }, 0),
      acBuilt: this.ac !== null,
      maxFileSize: this.maxFileSize
    };
  }
  /**
   * Clear all loaded rules
   */
  clear() {
    this.compiledRules = [];
    this.ac = null;
    this.setModules(this.customModules);
  }
};
function removeKeyDeep(value, keysToRemove) {
  if (typeof value === "string" || typeof value === "number" || typeof value === "boolean" || value === null) {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((v) => removeKeyDeep(v, keysToRemove));
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).filter(([k]) => !keysToRemove.includes(k)).map(([k, v]) => [k, removeKeyDeep(v, keysToRemove)])
    );
  }
  return value;
}
export {
  BaseCustomModule,
  InterceptScanner,
  InterceptScanner as YaraScanner,
  createELFModule,
  createHashModule,
  createMathModule,
  createPEModule,
  hash,
  math,
  parseELFYaraFull,
  parsePEYara,
  string,
  time
};
