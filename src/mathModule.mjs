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
 * YARA Math Module Implementation
 *
 * Provides mathematical and statistical functions for YARA rules.
 * This implementation matches the official YARA math module API.
 *
 * Supported functions:
 * - entropy(offset, size)        : Calculate Shannon entropy
 * - entropy(string)              : Calculate Shannon entropy of string
 * - monte_carlo_pi(offset, size) : Monte Carlo estimation of Pi
 * - serial_correlation(offset, size) : Serial correlation coefficient
 * - mean(offset, size)           : Arithmetic mean of bytes
 * - deviation(offset, size)      : Standard deviation of bytes
 * - min(offset, size)            : Minimum byte value
 * - max(offset, size)            : Maximum byte value
 * - abs(value)                   : Absolute value
 * - count(byte, offset, size)    : Count occurrences of byte
 * - percentage(byte, offset, size) : Percentage of byte occurrences
 * - mode(offset, size)           : Most common byte value
 * - to_number(bool)              : Convert boolean to number
 * - in_range(value, lower, upper): Check if value is in range
 *
 * All statistical functions operate on byte values (0-255).
 *
 * @see https://yara.readthedocs.io/en/stable/modules/math.html
 */

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
 * Calculate Shannon entropy of data
 * Entropy measures the randomness/unpredictability of data
 * @param {Uint8Array} data
 * @returns {number} Entropy value (0 to 8 bits per byte)
 */
function calculateEntropy(data) {
  if (data.length === 0) return 0.0;

  // Count frequency of each byte value (0-255)
  const frequency = new Uint32Array(256);
  for (let i = 0; i < data.length; i++) {
    frequency[data[i]]++;
  }

  // Calculate entropy
  let entropy = 0.0;
  const length = data.length;

  for (let i = 0; i < 256; i++) {
    if (frequency[i] > 0) {
      const probability = frequency[i] / length;
      entropy -= probability * Math.log2(probability);
    }
  }

  return entropy;
}

/**
 * Calculate arithmetic mean of byte values
 * @param {Uint8Array} data
 * @returns {number} Mean value (0 to 255)
 */
function calculateMean(data) {
  if (data.length === 0) return 0.0;

  let sum = 0;
  for (let i = 0; i < data.length; i++) {
    sum += data[i];
  }

  return sum / data.length;
}

/**
 * Calculate standard deviation of byte values
 * @param {Uint8Array} data
 * @returns {number} Standard deviation
 */
function calculateDeviation(data, mean) {
  if (data.length === 0) return 0.0;

  let sumSquaredDiff = 0;

  for (let i = 0; i < data.length; i++) {
    const diff = data[i] - mean;
    sumSquaredDiff += diff * diff;
  }

  return Math.sqrt(sumSquaredDiff / data.length);
}

/**
 * Monte Carlo estimation of Pi using byte pairs as coordinates
 * @param {Uint8Array} data
 * @returns {number} Estimated value of Pi (typically close to 3.14159...)
 */
function calculateMonteCarloPI(data) {
  if (data.length < 2) return 0.0;

  let insideCircle = 0;
  let totalPoints = 0;

  // Use consecutive byte pairs as (x, y) coordinates
  for (let i = 0; i < data.length - 1; i += 2) {
    // Normalize coordinates to [-1, 1] range
    const x = (data[i] / 255.0) * 2.0 - 1.0;
    const y = (data[i + 1] / 255.0) * 2.0 - 1.0;

    // Check if point is inside unit circle
    if (x * x + y * y <= 1.0) {
      insideCircle++;
    }
    totalPoints++;
  }

  if (totalPoints === 0) return 0.0;

  // Pi ≈ 4 * (points inside circle / total points)
  return (4.0 * insideCircle) / totalPoints;
}

/**
 * Calculate serial correlation coefficient
 * Measures correlation between consecutive bytes
 * @param {Uint8Array} data
 * @returns {number} Correlation coefficient (-1 to 1)
 */
function calculateSerialCorrelation(data) {
  if (data.length < 2) return 0.0;

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

  if (denominator === 0) return 0.0;

  return numerator / denominator;
}

/**
 * Find minimum byte value
 * @param {Array<number>} data
 * @returns {number} Minimum value
 */
function findMin(...data) {
  if (data.length === 0) throw new Error("No data provided");

  return Math.min(...data);
}

/**
 * Find maximum byte value
 * @param {Array<number>} data
 * @returns {number} Maximum value
 */
function findMax(...data) {
  if (data.length === 0) throw new Error("No data provided");

  return Math.max(...data);
}

/**
 * Count occurrences of a specific byte value
 * @param {number} byte - Byte value to count (0-255)
 * @param {Uint8Array} data
 * @returns {number} Count of occurrences
 */
function countByte(byte, data) {
  let count = 0;
  for (let i = 0; i < data.length; i++) {
    if (data[i] === byte) {
      count++;
    }
  }
  return count;
}

/**
 * Calculate percentage of a specific byte value
 * @param {number} byte - Byte value (0-255)
 * @param {Uint8Array} data
 * @returns {number} Percentage (0.0 to 1.0)
 */
function percentageByte(byte, data) {
  if (data.length === 0) return 0.0;
  return countByte(byte, data) / data.length;
}

/**
 * Find the mode (most common byte value)
 * @param {Uint8Array} data
 * @returns {number} Most common byte value (0-255)
 */
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

/**
 * Create a math module instance for a specific data buffer
 * @param {Uint8Array} data - The data to perform mathematical operations on
 * @returns {Object} Math module with all YARA math functions
 */
export function createMathModule(data) {
  if (!data || !(data instanceof Uint8Array)) {
    throw new Error("Math module requires a Uint8Array data buffer");
  }

  return {
    /**
     * Calculate Shannon entropy
     * Can be called with (offset, size) or (string)
     */
    entropy: function (...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        // entropy(string)
        const bytes = stringToBytes(args[0]);
        return calculateEntropy(bytes);
      } else if (args.length === 2) {
        // entropy(offset, size)
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
    monte_carlo_pi: function (...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        // monte_carlo_pi(string)
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
    serial_correlation: function (...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        // monte_carlo_pi(string)
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
    mean: function (...args) {
      if (args.length === 1 && typeof args[0] === "string") {
        // monte_carlo_pi(string)
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
    deviation: function (...args) {
      if (args.length === 2 && typeof args[0] === "string") {
        // deviation(string)
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
    min: function (a, b) {
      return findMin(a, b);
    },

    /**
     * Maximum byte value
     * Called with (offset, size)
     */
    max: function (a, b) {
      return findMax(a, b);
    },

    /**
     * Count occurrences of a byte
     * Called with (byte, offset, size)
     */
    count: function (byte, offset, size) {
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
    percentage: function (byte, offset, size) {
      return this.count(byte, offset, size) / size;
    },

    /**
     * Most common byte value (mode)
     * Called with (offset, size)
     */
    mode: function (offset, size) {
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
    abs: function (value) {
      return Math.abs(value);
    },

    /**
     * Convert boolean to number
     * Called with (bool)
     */
    to_number: function (bool) {
      return bool ? 1 : 0;
    },

    /**
     * Check if value is in range
     * Called with (value, lower, upper)
     */
    in_range: function (value, lower, upper) {
      return value >= lower && value <= upper;
    },
  };
}

/**
 * Standalone math functions that don't require a data buffer
 */
export const math = {
  /**
   * Calculate entropy of a string
   * @param {string} str
   * @returns {number} Entropy value
   */
  entropy: function (str) {
    const bytes = stringToBytes(str);
    return calculateEntropy(bytes);
  },

  /**
   * Absolute value
   * @param {number} value
   * @returns {number}
   */
  abs: function (value) {
    return Math.abs(value);
  },

  /**
   * Convert boolean to number
   * @param {boolean} bool
   * @returns {number} 1 for true, 0 for false
   */
  to_number: function (bool) {
    return bool ? 1 : 0;
  },

  /**
   * Check if value is in range [lower, upper]
   * @param {number} value
   * @param {number} lower
   * @param {number} upper
   * @returns {boolean}
   */
  in_range: function (value, lower, upper) {
    return value >= lower && value <= upper;
  },
};

// Export for convenience
export default {
  createMathModule,
  math,
};
