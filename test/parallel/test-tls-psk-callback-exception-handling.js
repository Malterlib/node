'use strict';

// This test verifies that exceptions in pskCallback are properly routed
// through tlsClientError instead of becoming uncaught exceptions.
// This is a regression test for CVE-2026-21637.
//
// Note: ALPNCallback tests are not included because ALPNCallback option
// was added in Node.js v20+.

const common = require('../common');

if (!common.hasCrypto)
  common.skip('missing crypto');

const assert = require('assert');
const tls = require('tls');

const CIPHERS = 'PSK+HIGH';

// Run tests sequentially
const tests = [];
let testNumber = 0;

function runNextTest() {
  const test = tests.shift();
  if (test) {
    testNumber++;
    console.log(`Running test ${testNumber}...`);
    test(runNextTest);
  } else {
    console.log('All tests passed!');
  }
}

// Test 1: PSK server callback returning invalid type should emit tlsClientError
tests.push((done) => {
  console.log('  - Server pskCallback returns invalid type -> tlsClientError');
  const server = tls.createServer({
    ciphers: CIPHERS,
    pskCallback: common.mustCall(() => {
      console.log('    pskCallback called, returning invalid string');
      // Return invalid type (string instead of object/Buffer)
      return 'invalid-should-be-object-or-buffer';
    }),
    pskIdentityHint: 'test-hint',
  });

  server.on('tlsClientError', common.mustCall((err, socket) => {
    console.log('    tlsClientError received:', err.code);
    assert.ok(err instanceof Error);
    assert.strictEqual(err.code, 'ERR_INVALID_ARG_TYPE');
    socket.destroy();
    console.log('    Test 1 PASSED');
    server.close(done);
  }));

  server.on('secureConnection', common.mustNotCall());

  server.listen(0, common.mustCall(() => {
    const client = tls.connect({
      port: server.address().port,
      host: '127.0.0.1',
      ciphers: CIPHERS,
      checkServerIdentity: () => {},
      pskCallback: () => ({
        psk: Buffer.alloc(32),
        identity: 'test-identity',
      }),
    });

    client.on('error', () => {});
  }));
});

// Test 2: PSK server callback throwing should emit tlsClientError
tests.push((done) => {
  console.log('  - Server pskCallback throws -> tlsClientError');
  const server = tls.createServer({
    ciphers: CIPHERS,
    pskCallback: common.mustCall(() => {
      console.log('    pskCallback called, throwing error');
      throw new Error('Intentional callback error');
    }),
    pskIdentityHint: 'test-hint',
  });

  server.on('tlsClientError', common.mustCall((err, socket) => {
    console.log('    tlsClientError received:', err.message);
    assert.ok(err instanceof Error);
    assert.strictEqual(err.message, 'Intentional callback error');
    socket.destroy();
    console.log('    Test 2 PASSED');
    server.close(done);
  }));

  server.on('secureConnection', common.mustNotCall());

  server.listen(0, common.mustCall(() => {
    const client = tls.connect({
      port: server.address().port,
      host: '127.0.0.1',
      ciphers: CIPHERS,
      checkServerIdentity: () => {},
      pskCallback: () => ({
        psk: Buffer.alloc(32),
        identity: 'test-identity',
      }),
    });

    client.on('error', () => {});
  }));
});

// Test 3: PSK client callback returning invalid type should emit error event
tests.push((done) => {
  console.log('  - Client pskCallback returns invalid type -> client error');
  const PSK = Buffer.alloc(32);

  const server = tls.createServer({
    ciphers: CIPHERS,
    pskCallback: () => PSK,
    pskIdentityHint: 'test-hint',
  });

  server.on('secureConnection', common.mustNotCall());

  server.listen(0, common.mustCall(() => {
    const client = tls.connect({
      port: server.address().port,
      host: '127.0.0.1',
      ciphers: CIPHERS,
      checkServerIdentity: () => {},
      pskCallback: common.mustCall(() => {
        console.log('    client pskCallback called, returning invalid string');
        // Return invalid type - should cause validation error
        return 'invalid-should-be-object';
      }),
    });

    client.on('error', common.mustCall((err) => {
      console.log('    client error received:', err.code);
      assert.ok(err instanceof Error);
      assert.strictEqual(err.code, 'ERR_INVALID_ARG_TYPE');
      console.log('    Test 3 PASSED');
      server.close(done);
    }));
  }));
});

// Test 4: PSK client callback throwing should emit error event
tests.push((done) => {
  console.log('  - Client pskCallback throws -> client error');
  const PSK = Buffer.alloc(32);

  const server = tls.createServer({
    ciphers: CIPHERS,
    pskCallback: () => PSK,
    pskIdentityHint: 'test-hint',
  });

  server.on('secureConnection', common.mustNotCall());

  server.listen(0, common.mustCall(() => {
    const client = tls.connect({
      port: server.address().port,
      host: '127.0.0.1',
      ciphers: CIPHERS,
      checkServerIdentity: () => {},
      pskCallback: common.mustCall(() => {
        console.log('    client pskCallback called, throwing error');
        throw new Error('Intentional client PSK callback error');
      }),
    });

    client.on('error', common.mustCall((err) => {
      console.log('    client error received:', err.message);
      assert.ok(err instanceof Error);
      assert.strictEqual(err.message, 'Intentional client PSK callback error');
      console.log('    Test 4 PASSED');
      server.close(done);
    }));
  }));
});

// Start running tests
runNextTest();
