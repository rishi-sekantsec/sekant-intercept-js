import { compileYaraLike } from "../yaraStringMatch.mjs";

const encoder = new TextEncoder();

function testYara1() {
  const data = encoder.encode("Hello world! This program cannot fail");

  // 1️⃣ Simple ASCII match
  console.log(compileYaraLike('"Hello"').matcher(data));
  // → [{ offset: 0 }]

  // 2️⃣ Wide match
  const wideData = new Uint8Array([0x48, 0, 0x65, 0, 0x6c, 0, 0x6c, 0, 0x6f, 0]);
  console.log(compileYaraLike('"Hello" wide').matcher(wideData));
  // → [{ offset: 0 }]

  // 3️⃣ XOR match
  const xorData = new Uint8Array(encoder.encode("Hello").map((b) => b ^ 0x10));
  console.log(compileYaraLike('"Hello" xor(1-32)').matcher(xorData));
  // → [{ offset: 0, key: 16 }]

  // 4️⃣ Base64 match
  console.log(compileYaraLike('"This program cannot" base64').matcher(data));
  // → Matches 3 permutations

  // 5️⃣ Base64wide match
  console.log(compileYaraLike('"This program cannot" base64wide').matcher(wideData));
  // → Matches 3 wide-base64 permutations

  // 6️⃣ Fullword match
  console.log(compileYaraLike('"Hello" fullword').matcher(data));
  // → Only matches "Hello" if surrounded by word boundaries
}

function testYara2() {
  const data = encoder.encode("Visit PayPal for account info.");

  // 1️⃣ ASCII nocase
  console.log(compileYaraLike('"paypal" nocase').matcher(data));
  // → [{ offset: 6 }]

  // 2️⃣ Fullword + nocase
  console.log(compileYaraLike('"paypal" fullword nocase').matcher(data));
  // → [{ offset: 6 }]

  // 3️⃣ Base64 + nocase
  console.log(compileYaraLike('"This program cannot" base64 nocase').matcher(data));
  // → Matches all 3 Base64 permutations, case-insensitive

  // 4️⃣ XOR + nocase (handles both A/a patterns)
  const xorData = new Uint8Array(encoder.encode("HELLO").map((b) => b ^ 0x10));
  console.log(compileYaraLike('"hello" xor(1-32) nocase').matcher(xorData));
  // → [{ offset: 0, key: 16 }]
}

testYara1();
testYara2();