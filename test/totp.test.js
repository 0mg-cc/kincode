/**
 * TOTP test with RFC 6238 test vectors
 * Run: node test/totp.test.js
 */

import TOTP from '../public/js/totp.js';

const tests = [];
let passed = 0;
let failed = 0;

function test(name, fn) {
  tests.push({ name, fn });
}

async function run() {
  for (const { name, fn } of tests) {
    try {
      await fn();
      passed++;
      console.log(`✓ ${name}`);
    } catch (e) {
      failed++;
      console.log(`✗ ${name}`);
      console.log(`  ${e.message}`);
    }
  }
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed > 0 ? 1 : 0);
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(msg || `Expected "${expected}", got "${actual}"`);
  }
}

// RFC 6238 test secret (ASCII "12345678901234567890" = base32 encoded)
const RFC_SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

// RFC 6238 test vectors for SHA1
// Time (sec) | TOTP
// 59         | 287082
// 1111111109 | 081804
// 1234567890 | 005924
// 2000000000 | 279037

test('base32 encode/decode roundtrip', () => {
  const original = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
  const encoded = TOTP.bytesToBase32(original);
  const decoded = TOTP.base32ToBytes(encoded);
  assertEqual(decoded.length, original.length, 'Length mismatch');
  for (let i = 0; i < original.length; i++) {
    assertEqual(decoded[i], original[i], `Byte ${i} mismatch`);
  }
});

test('base32 encode known value', () => {
  // "12345678901234567890" should encode to GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
  const bytes = new TextEncoder().encode('12345678901234567890');
  const encoded = TOTP.bytesToBase32(bytes);
  assertEqual(encoded, RFC_SECRET);
});

test('TOTP RFC 6238 vector: t=59', async () => {
  const code = await TOTP.generateCode(RFC_SECRET, 59 * 1000);
  assertEqual(code, '287082');
});

test('TOTP RFC 6238 vector: t=1111111109', async () => {
  const code = await TOTP.generateCode(RFC_SECRET, 1111111109 * 1000);
  assertEqual(code, '081804');
});

test('TOTP RFC 6238 vector: t=1234567890', async () => {
  const code = await TOTP.generateCode(RFC_SECRET, 1234567890 * 1000);
  assertEqual(code, '005924');
});

test('TOTP RFC 6238 vector: t=2000000000', async () => {
  const code = await TOTP.generateCode(RFC_SECRET, 2000000000 * 1000);
  assertEqual(code, '279037');
});

test('generateSecret returns 32-char base32', () => {
  const secret = TOTP.generateSecret();
  assertEqual(secret.length, 32, 'Secret should be 32 chars (160 bits)');
  assert(/^[A-Z2-7]+$/.test(secret), 'Secret should be valid base32');
});

test('buildURI format', () => {
  const uri = TOTP.buildURI({
    secret: 'JBSWY3DPEHPK3PXP',
    issuer: 'KinCode',
    account: 'Alice'
  });
  assert(uri.startsWith('otpauth://totp/'), 'Should start with otpauth://totp/');
  assert(uri.includes('secret=JBSWY3DPEHPK3PXP'), 'Should contain secret');
  assert(uri.includes('issuer=KinCode'), 'Should contain issuer');
});

run();
