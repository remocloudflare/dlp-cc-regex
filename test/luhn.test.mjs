// Standalone logic test — mirrors src/index.js so we can verify without a running Worker.
const CC_REGEX_SOURCE = String.raw`\b\d(?:[ -]?\d){12,18}\b`;

function luhnValid(d) {
  let sum = 0, alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return d.length >= 13 && d.length <= 19 && sum % 10 === 0;
}
function scan(text) {
  const re = new RegExp(CC_REGEX_SOURCE, "g");
  const out = []; let m;
  while ((m = re.exec(text)) !== null) {
    const digits = m[0].replace(/[^0-9]/g, "");
    out.push({ match: m[0], digits, luhn: luhnValid(digits) });
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return out;
}

const cases = [
  { text: "1 344-4343 12345", wantMatch: true,  note: "loose 13-digit — the whole point" },
  { text: "4242 4242 4242 4242", wantMatch: true, wantLuhn: true, note: "Visa test card" },
  { text: "4111-1111-1111-1111", wantMatch: true, wantLuhn: true, note: "Visa dashes" },
  { text: "5555 5555 5555 4444", wantMatch: true, wantLuhn: true, note: "Mastercard test" },
  { text: "378282246310005",     wantMatch: true, wantLuhn: true, note: "Amex 15-digit no sep" },
  { text: "order#12345678 ref 999", wantMatch: false, note: "short runs, should NOT match" },
];

let fail = 0;
for (const c of cases) {
  const r = scan(c.text);
  const matched = r.length > 0;
  const luhn = r.some(x => x.luhn);
  let ok = matched === c.wantMatch;
  if (c.wantLuhn !== undefined) ok = ok && (luhn === c.wantLuhn);
  if (!ok) fail++;
  console.log(
    (ok ? "PASS" : "FAIL"),
    JSON.stringify(c.text).padEnd(28),
    "matched=" + matched,
    "luhn=" + luhn,
    "→", c.note
  );
  for (const x of r) console.log("        match:", JSON.stringify(x.match), "digits=" + x.digits.length, "luhn=" + x.luhn);
}
console.log(fail === 0 ? "\nALL PASS" : `\n${fail} FAILED`);
process.exit(fail === 0 ? 0 : 1);
