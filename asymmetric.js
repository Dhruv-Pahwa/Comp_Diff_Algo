const crypto = require("crypto");
const { performance } = require("perf_hooks");

function x25519KeyExchange() {
  const t0 = performance.now();
  const alice = crypto.generateKeyPairSync("x25519");
  const bob = crypto.generateKeyPairSync("x25519");
  const keyGen = performance.now() - t0;

  const t1 = performance.now();
  const secret = crypto.diffieHellman({
    privateKey: alice.privateKey,
    publicKey: bob.publicKey
  });
  const exch = performance.now() - t1;

  return { keyGen, exch, sessionKey: secret.slice(0, 32) };
}

module.exports = { x25519KeyExchange };
