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

const defaultLogger = typeof console !== "undefined" && typeof console.log === "function" ? (...args) => console.log(...args) : () => {};

const hasPerformance = typeof globalThis !== "undefined" && globalThis.performance && typeof globalThis.performance.now === "function";

function now() {
  return hasPerformance ? globalThis.performance.now() : Date.now();
}

function cloneDeep(value) {
  return value == null ? value : JSON.parse(JSON.stringify(value));
}

export class PerformanceTracker {
  constructor(options = {}) {
    const enabled = options.enabled ?? options.enableTiming ?? false;
    const logger = options.logger ?? defaultLogger;
    const autoPrint = options.autoPrint ?? false;

    this.options = {
      enabled: Boolean(enabled),
      logger,
      autoPrint: Boolean(autoPrint),
    };

    this.lastTiming = {
      compile: null,
      scan: null,
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
        filterStrings: 0,
      },
      modules: {
        total: 0,
        pe: 0,
        elf: 0,
        math: 0,
        hash: 0,
      },
      conditionParsing: {
        total: 0,
        byRule: {},
      },
      matchCount: 0,
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
          logger(`  • ${step}: ${value.toFixed(3)}ms`);
        });
      }
      if (data.modules && data.modules.total) {
        logger(`  • moduleCreation.total: ${data.modules.total.toFixed(3)}ms`);
      }
      if (data.conditionParsing && data.conditionParsing.total) {
        logger(`  • conditionParsing.total: ${data.conditionParsing.total.toFixed(3)}ms`);
      }
    }
  }
}

export function createPerformanceTracker(options = {}) {
  return new PerformanceTracker(options);
}
