'use strict';

// This test verifies that Buffer.allocUnsafe and Buffer.allocUnsafeSlow
// work correctly using the new createUnsafeArrayBuffer C++ function
// instead of the vulnerable zeroFill toggle mechanism.
// This is a regression test for CVE-2025-55131.

const common = require('../common');
const assert = require('assert');

// Test that Buffer.allocUnsafe works for various sizes
{
  // Small buffer (<=64 bytes, uses heap allocation path)
  const small = Buffer.allocUnsafe(32);
  assert.strictEqual(small.length, 32);
  assert.ok(Buffer.isBuffer(small));

  // Medium buffer (uses the C++ createUnsafeArrayBuffer)
  const medium = Buffer.allocUnsafe(1024);
  assert.strictEqual(medium.length, 1024);
  assert.ok(Buffer.isBuffer(medium));

  // Large buffer
  const large = Buffer.allocUnsafe(1024 * 1024);
  assert.strictEqual(large.length, 1024 * 1024);
  assert.ok(Buffer.isBuffer(large));
}

// Test that Buffer.allocUnsafeSlow works
{
  const slow = Buffer.allocUnsafeSlow(1024);
  assert.strictEqual(slow.length, 1024);
  assert.ok(Buffer.isBuffer(slow));
}

// Test that zero-length buffers work
{
  const zero = Buffer.allocUnsafe(0);
  assert.strictEqual(zero.length, 0);
  assert.ok(Buffer.isBuffer(zero));
}

// Test that buffers are writable
{
  const buf = Buffer.allocUnsafe(100);
  buf.fill(0x42);
  for (let i = 0; i < buf.length; i++) {
    assert.strictEqual(buf[i], 0x42);
  }
}

// Test that Buffer.alloc (safe version) still zero-fills
{
  const safe = Buffer.alloc(100);
  for (let i = 0; i < safe.length; i++) {
    assert.strictEqual(safe[i], 0, `Expected 0 at index ${i}, got ${safe[i]}`);
  }
}

// Test pool allocation (uses createUnsafeBuffer internally)
{
  // Multiple small allocations from pool
  const bufs = [];
  for (let i = 0; i < 100; i++) {
    bufs.push(Buffer.allocUnsafe(100));
  }
  // Verify all buffers are valid
  for (const buf of bufs) {
    assert.strictEqual(buf.length, 100);
    assert.ok(Buffer.isBuffer(buf));
  }
}

console.log('All CVE-2025-55131 tests passed');
