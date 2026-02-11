import * as esbuild from 'esbuild';

const licenseHeader = 
`/*
 * Sekant Intercept.js
 * Copyright 2026 Rishi Kant (Sekant Security Inc.)
 * Licensed under Apache 2.0
 * Includes third-party code from pe-library and spark-md5 (MIT)
 */`;

const sharedConfig = {
  entryPoints: ['src/index.js'],
  bundle: true,
  minify: true,
  banner: { js: licenseHeader },
  legalComments: 'inline',
  format: 'esm',
};

// 1. Browser Build (IIFE for global window usage)
const browserBuild = esbuild.build({
  ...sharedConfig,
  outfile: 'dist/sekant-intercept.browser.mjs',
  platform: 'browser',
  target: ['chrome120', 'firefox120', 'safari17'],
});

// 2. Node.js Build (ESM for modern Node/Serverless)
const nodeBuild = esbuild.build({
  ...sharedConfig,
  outfile: 'dist/sekant-intercept.node.mjs',
  platform: 'node',
  target: ['node20'],
});

await Promise.all([browserBuild, nodeBuild]);
console.log('Builds complete: Browser (ESM) and Node (ESM)');