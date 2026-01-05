import crypto from "crypto";
import { performance } from "perf_hooks";

export function aes256gcm(data, key) {
  const iv = crypto.randomBytes(12);

  const t1 = performance.now();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  const encTime = performance.now() - t1;

  const t2 = performance.now();
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  decipher.update(enc);
  decipher.final();
  const decTime = performance.now() - t2;

  return { encTime, decTime };
}

export function chacha20(data, key) {
  const iv = crypto.randomBytes(12);

  const t1 = performance.now();
  const cipher = crypto.createCipheriv("chacha20-poly1305", key, iv, {
    authTagLength: 16
  });
  const enc = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  const encTime = performance.now() - t1;

  const t2 = performance.now();
  const decipher = crypto.createDecipheriv("chacha20-poly1305", key, iv, {
    authTagLength: 16
  });
  decipher.setAuthTag(tag);
  decipher.update(enc);
  decipher.final();
  const decTime = performance.now() - t2;

  return { encTime, decTime };
}
