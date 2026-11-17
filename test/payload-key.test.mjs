import test from "node:test";
import assert from "node:assert/strict";

import { deriveX25519PublicKey, generatePayloadKeyPair } from "../src/index.js";

const fromBase64 = (value) => Buffer.from(value, "base64");
const paddedStandardBase64 = /^[A-Za-z0-9+/]{43}=$/;

test("payload key exports are bare 32-byte padded standard base64", async () => {
  const pair = await generatePayloadKeyPair();
  assert.match(pair.publicKey, paddedStandardBase64);
  assert.match(pair.privateKey, paddedStandardBase64);
  assert.equal(fromBase64(pair.publicKey).byteLength, 32);
  assert.equal(fromBase64(pair.privateKey).byteLength, 32);
});

test("payload key generation produces unique key pairs", async () => {
  const first = await generatePayloadKeyPair();
  const second = await generatePayloadKeyPair();
  assert.notEqual(first.privateKey, second.privateKey);
  assert.notEqual(first.publicKey, second.publicKey);
});

test("X25519 derivation matches RFC 7748 vector", async () => {
  const privateKey = Buffer.from("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "hex");
  const expectedPublic = Buffer.from("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a", "hex");
  assert.deepEqual(Buffer.from(await deriveX25519PublicKey(privateKey)), expectedPublic);
});

test("Cloudflare matched-data-cli documented key derives its documented public key", async () => {
  const privateKey = fromBase64("uBS5eBttHrqkdY41kbZPdvYnNz8Vj0TvKIUpjB1y/GA=");
  const expectedPublic = fromBase64("Ycig/Zr/pZmklmFUN99nr+taURlYItL91g+NcHGYpB8=");
  assert.deepEqual(Buffer.from(await deriveX25519PublicKey(privateKey)), expectedPublic);
});
