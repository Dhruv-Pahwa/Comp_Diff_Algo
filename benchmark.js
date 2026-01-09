//Main file for benchmarking cryptographic operations
const agcData = require("./agcData");
const crypto = require("crypto");
const process = require("process");
const { performance } = require("perf_hooks");

const ITERATIONS = 100;

const payload = Buffer.from(JSON.stringify(agcData));
const payloadKB = (payload.length / 1024).toFixed(2);

function measureCPUAndMemory(fn) {
  const cpuStart = process.cpuUsage();
  fn();
  const cpu = process.cpuUsage(cpuStart);
  const cpuMs = (cpu.user + cpu.system) / 1000;
  const memMB = (process.memoryUsage().rss / 1024 / 1024).toFixed(2);
  return { cpuMs, memMB };
}

function rsa2048Benchmark() {
  const sessionKey = crypto.randomBytes(32);

  const cpuMem = measureCPUAndMemory(() => {
    crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
  });

  const t0 = performance.now();
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048
  });
  const keyGen = performance.now() - t0;

  const t1 = performance.now();
  const encKey = crypto.publicEncrypt(publicKey, sessionKey);
  const encTime = performance.now() - t1;

  const t2 = performance.now();
  crypto.privateDecrypt(privateKey, encKey);
  const decTime = performance.now() - t2;

  return { keyGen, encTime, decTime, ...cpuMem };
}

function ecdhP256Benchmark() {
  const cpuMem = measureCPUAndMemory(() => {
    const a = crypto.createECDH("prime256v1");
    a.generateKeys();
  });

  const t0 = performance.now();
  const alice = crypto.createECDH("prime256v1");
  alice.generateKeys();
  const bob = crypto.createECDH("prime256v1");
  bob.generateKeys();
  const keyGen = performance.now() - t0;

  const t1 = performance.now();
  alice.computeSecret(bob.getPublicKey());
  const exch = performance.now() - t1;

  return { keyGen, encTime: exch, decTime: "N/A", ...cpuMem };
}

function x25519Benchmark() {
  const cpuMem = measureCPUAndMemory(() => {
    crypto.generateKeyPairSync("x25519");
  });

  const t0 = performance.now();
  const alice = crypto.generateKeyPairSync("x25519");
  const bob = crypto.generateKeyPairSync("x25519");
  const keyGen = performance.now() - t0;

  const t1 = performance.now();
  crypto.diffieHellman({
    privateKey: alice.privateKey,
    publicKey: bob.publicKey
  });
  const exch = performance.now() - t1;

  return { keyGen, encTime: exch, decTime: "N/A", ...cpuMem, sessionKey: Buffer.alloc(32) };
}

function aes256gcmBenchmark(key) {
  let enc = 0, dec = 0;

  const cpuStart = process.cpuUsage();
  const t0 = Date.now();

  for (let i = 0; i < ITERATIONS; i++) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv("aes-256-gcm", key, iv);
    const encrypted = Buffer.concat([c.update(payload), c.final()]);
    const tag = c.getAuthTag();

    const d = crypto.createDecipheriv("aes-256-gcm", key, iv);
    d.setAuthTag(tag);
    d.update(encrypted);
    d.final();

    enc += 0;
    dec += 0;
  }

  const wall = Date.now() - t0;
  const cpu = process.cpuUsage(cpuStart);
  const cpuMs = (cpu.user + cpu.system) / 1000;

  return {
    keyGen: 0,
    encTime: (wall / ITERATIONS).toFixed(3),
    decTime: (wall / ITERATIONS).toFixed(3),
    cpuMs,
    memMB: (process.memoryUsage().rss / 1024 / 1024).toFixed(2)
  };
}

function chacha20Benchmark(key) {
  let enc = 0, dec = 0;

  const cpuStart = process.cpuUsage();
  const t0 = Date.now();

  for (let i = 0; i < ITERATIONS; i++) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv("chacha20-poly1305", key, iv, { authTagLength: 16 });
    const encrypted = Buffer.concat([c.update(payload), c.final()]);
    const tag = c.getAuthTag();

    const d = crypto.createDecipheriv("chacha20-poly1305", key, iv, { authTagLength: 16 });
    d.setAuthTag(tag);
    d.update(encrypted);
    d.final();
  }

  const wall = Date.now() - t0;
  const cpu = process.cpuUsage(cpuStart);
  const cpuMs = (cpu.user + cpu.system) / 1000;

  return {
    keyGen: 0,
    encTime: (wall / ITERATIONS).toFixed(3),
    decTime: (wall / ITERATIONS).toFixed(3),
    cpuMs,
    memMB: (process.memoryUsage().rss / 1024 / 1024).toFixed(2)
  };
}

function printResult(name, r) {
  console.log(`
========================================
Algorithm       : ${name}
Payload Size    : ${payloadKB} KB
Iterations      : ${ITERATIONS}
----------------------------------------
Key Gen Time    : ${r.keyGen} ms
Encrypt / Exchg : ${r.encTime} ms
Decrypt Time    : ${r.decTime} ms
CPU Usage (ms)  : ${r.cpuMs}
Memory Usage    : ${r.memMB} MB
========================================
`);
}

console.log("\nOPGW AGC CRYPTOGRAPHY BENCHMARK\n");

const rsa = rsa2048Benchmark();
printResult("RSA-2048", rsa);

const ecdh = ecdhP256Benchmark();
printResult("ECDH P-256", ecdh);

const x25519 = x25519Benchmark();
printResult("X25519", x25519);

const aes = aes256gcmBenchmark(x25519.sessionKey || crypto.randomBytes(32));
printResult("AES-256-GCM", aes);

const cha = chacha20Benchmark(x25519.sessionKey || crypto.randomBytes(32));
printResult("ChaCha20-Poly1305", cha);
