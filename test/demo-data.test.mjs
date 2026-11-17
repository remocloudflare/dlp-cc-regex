import test from "node:test";
import assert from "node:assert/strict";

import { generateDemoData } from "../src/index.js";

const zeroRandom = (length) => new Uint8Array(length);
const digits = (value) => value.replace(/\D/g, "");
const luhnValid = (value) => {
  let sum = 0;
  let double = false;
  for (let index = value.length - 1; index >= 0; index -= 1) {
    let digit = Number(value[index]);
    if (double) digit = digit * 2 > 9 ? digit * 2 - 9 : digit * 2;
    sum += digit;
    double = !double;
  }
  return sum % 10 === 0;
};

test("demo quantities are bounded to integers from 1 through 100", () => {
  for (const quantity of [0, 101, 1.5, NaN, "10"]) {
    assert.throws(() => generateDemoData({ type: "card", quantity, randomBytes: zeroRandom }), /integer from 1 through 100/);
  }
  assert.equal(generateDemoData({ type: "card", quantity: 1, randomBytes: zeroRandom }).length, 1);
  assert.equal(generateDemoData({ type: "ssn", quantity: 100, randomBytes: zeroRandom }).length, 100);
});

test("card demos are synthetic PAN-shaped fixtures using test BINs and are Luhn-valid", () => {
  const values = generateDemoData({ type: "card", quantity: 8, format: "plain", randomBytes: zeroRandom });
  const testBins = ["424242", "400005", "555555", "378282"];
  assert.ok(values.every((value) => testBins.some((bin) => value.startsWith(bin))));
  assert.ok(values.every((value) => luhnValid(digits(value))));
});

test("card demos support plain, spaces, dashes, and mixed separators", () => {
  const formats = {
    plain: /^\d+$/,
    spaces: /^\d{4}(?: \d{4}){3}$/,
    dashes: /^\d{4}(?:-\d{4}){3}$/,
    mixed: /^\d{4} \d{4}-\d{4} \d{4}$/,
  };
  for (const [format, pattern] of Object.entries(formats)) {
    const [value] = generateDemoData({ type: "card", quantity: 1, format, randomBytes: zeroRandom });
    assert.match(value, pattern);
    assert.ok(luhnValid(digits(value)));
  }
});

test("SSN demos are deterministic reserved non-issued 000-area values", () => {
  const first = generateDemoData({ type: "ssn", quantity: 3, randomBytes: zeroRandom });
  const second = generateDemoData({ type: "ssn", quantity: 3, randomBytes: zeroRandom });
  assert.deepEqual(first, second);
  assert.ok(first.every((value) => /^000-\d{2}-\d{4}$/.test(value)));
});
