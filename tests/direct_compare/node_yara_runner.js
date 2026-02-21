#!/usr/bin/env node
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { argv, exit } from "process";
import { InterceptScanner } from "../../src/interceptScanner.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function parseArgs() {
  const args = {};
  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    if (arg.startsWith("--")) {
      const key = arg.slice(2);
      args[key] = argv[i + 1] && !argv[i + 1].startsWith("--") ? argv[i + 1] : true;
      if (argv[i + 1] && !argv[i + 1].startsWith("--")) i++;
    }
  }

  if (!args.rule && !args.rulefile) {
    console.error("Error: must specify --rule '<text>' or --rulefile <path>");
    exit(1);
  }
  if (!args.file) {
    console.error("Error: must specify --file <path>");
    exit(1);
  }
  return args;
}

async function main() {
  const args = parseArgs();
  const ruleText = args.rulefile ? fs.readFileSync(args.rulefile, "utf8") : args.rule;
  const data = fs.readFileSync(args.file);

  // console.log(data.slice(6067, 6074).toString('utf8'));

  const scanner = new InterceptScanner();
  scanner.compile(ruleText);

  try {
    const result = await scanner.scan(data);
    const anyMatch = Array.isArray(result)
      // ? result.some(r => Object.values(r.strings || {}).some(s => s.matched))
      ? result.length > 0
      : false;

    if (args.json) {
      // To exact match python output, unescape backslashes in strings
      console.log(JSON.stringify({ matches: result }, null, 2).replaceAll(/\\(\\|"|'|')/g, "$1"));
    } else {
      console.log(anyMatch ? "MATCH" : "NO MATCH");
    }
  } catch (err) {
    console.error(JSON.stringify({ error: err.message }));
    exit(1);
  }
}

main();
