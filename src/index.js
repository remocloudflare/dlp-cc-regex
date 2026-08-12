/**
 * DLP Regex Builder — Cloudflare Worker
 *
 * A self-serve frontend where a customer authors and TESTS a regex for a
 * Cloudflare DLP custom entry, then copies out:
 *   - the raw RE2 regex to paste into the DLP dashboard, AND
 *   - a ready-to-paste Terraform `dlp_custom_entries` object.
 *
 * Flagship preset: a loosely-formatted credit-card pattern that catches numbers
 * like `1 344-4343 12345` which Cloudflare's default PCI detector misses.
 *
 * DLP custom entries run on the RE2 engine (no lookahead/lookbehind/backrefs,
 * no checksum). This tool previews matches with the browser's JS regex engine
 * (close to RE2) and runs an OPTIONAL Luhn check in JS — because RE2 can't.
 * In production, Luhn is expressed as the entry's `validation` option.
 */

// ---- presets -------------------------------------------------------------
const PRESETS = [
  {
    id: "cc-loose",
    label: "Credit card (loose separators) ★",
    regex: String.raw`\b\d(?:[ -]?\d){12,18}\b`,
    validation: "luhn",
    sample:
      "1 344-4343 12345\n4242 4242 4242 4242\norder#12345678 ref 999\nMy card is 5555 5555 5555 4444",
    note: "13-19 digits, any pair may be split by a single space or dash.",
  },
  {
    id: "cc-strict",
    label: "Credit card (canonical 4-4-4-4)",
    regex: String.raw`\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b`,
    validation: "luhn",
    sample: "4242 4242 4242 4242\n4111-1111-1111-1111",
    note: "16 digits in standard grouping (what the default detector expects).",
  },
  {
    id: "custom",
    label: "Custom (write your own)",
    regex: "",
    validation: "none",
    sample: "",
    note: "Type any RE2-safe pattern.",
  },
];

// RE2 does NOT support these — flag them so the customer isn't surprised when
// the same pattern that "worked" in this preview is rejected by DLP.
function re2Warnings(src) {
  const w = [];
  if (/\(\?=|\(\?!/.test(src)) w.push("lookahead (?= / ?!) — not supported by RE2");
  if (/\(\?<=|\(\?<!/.test(src)) w.push("lookbehind (?<= / ?<!) — not supported by RE2");
  if (/\\[1-9]/.test(src)) w.push("backreference (\\1) — not supported by RE2");
  if (/\(\?>/.test(src)) w.push("atomic group (?>) — not supported by RE2");
  return w;
}

function luhnValid(digits) {
  if (!/^\d{13,19}$/.test(digits)) return false;
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

function scan(text, regexSrc, flags, validation) {
  let re;
  try {
    re = new RegExp(regexSrc, (flags || "g").includes("g") ? flags : (flags || "") + "g");
  } catch (e) {
    return { error: "Invalid regex: " + e.message };
  }
  const out = [];
  let m, guard = 0;
  while ((m = re.exec(text)) !== null && guard++ < 5000) {
    const raw = m[0];
    const digits = raw.replace(/\D/g, "");
    const row = { match: raw, index: m.index, length: raw.length };
    if (validation === "luhn") {
      row.digits = digits.length;
      row.valid = luhnValid(digits);
    }
    out.push(row);
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return { matches: out, re2Warnings: re2Warnings(regexSrc) };
}

function tfEntry(name, regexSrc, validation) {
  const safeName = (name || "Custom entry").replace(/"/g, "'");
  const lines = [
    "  {",
    `    name       = ${JSON.stringify(safeName)}`,
    `    regex      = ${JSON.stringify(regexSrc)}`,
  ];
  if (validation && validation !== "none") {
    lines.push(`    validation = ${JSON.stringify(validation)}`);
  }
  lines.push("  },");
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
function html() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>DLP Regex Builder</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3;
          --muted:#8b949e; --accent:#f0883e; --ok:#3fb950; --warn:#d29922; --dim:#484f58; }
  * { box-sizing:border-box; }
  body { margin:0; font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
         background:var(--bg); color:var(--fg); }
  header { padding:22px 28px; border-bottom:1px solid var(--border); }
  h1 { margin:0 0 4px; font-size:20px; color:var(--accent); }
  header p { margin:0; color:var(--muted); font-size:13px; max-width:820px; }
  main { display:grid; grid-template-columns:1fr 1fr; gap:20px; padding:24px 28px; align-items:start; }
  @media (max-width:920px){ main{ grid-template-columns:1fr; } }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px; }
  .card h2 { margin:0 0 12px; font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }
  label { display:block; font-size:12px; color:var(--muted); margin:12px 0 4px; }
  input[type=text], textarea, select {
    width:100%; background:var(--bg); color:var(--fg); border:1px solid var(--border);
    border-radius:8px; padding:10px 12px; font-family:ui-monospace,Menlo,monospace; font-size:13px; }
  textarea { min-height:130px; resize:vertical; }
  .row { display:flex; gap:12px; } .row > * { flex:1; }
  code.regex { display:block; background:var(--bg); border:1px solid var(--border); border-radius:8px;
    padding:12px; color:var(--accent); font-family:ui-monospace,monospace; font-size:13px; word-break:break-all; margin-bottom:8px; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--border); font-family:ui-monospace,monospace; }
  th { color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; }
  .pill { padding:1px 8px; border-radius:999px; font-size:11px; font-weight:600; }
  .pass { background:rgba(63,185,80,.15); color:var(--ok); }
  .fail { background:rgba(139,148,158,.15); color:var(--muted); }
  .empty { color:var(--dim); font-style:italic; }
  .warn { color:var(--warn); font-size:12px; margin:8px 0 0; }
  pre { background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:12px;
        overflow:auto; font-size:12px; color:var(--fg); white-space:pre; }
  .count { color:var(--muted); font-size:12px; margin:0 0 10px; }
  button.copy { background:#21262d; color:var(--fg); border:1px solid var(--border); border-radius:6px;
    padding:5px 11px; font-size:12px; cursor:pointer; margin-top:8px; }
  button.copy:hover { border-color:var(--accent); }
</style>
</head>
<body>
<header>
  <h1>DLP Regex Builder</h1>
  <p>Author and test a regex for a Cloudflare DLP <em>custom entry</em>, then copy the RE2 pattern for the dashboard or a ready-made Terraform block. Ships with a loose credit-card preset that catches numbers like <code>1 344-4343 12345</code> the default PCI detector misses.</p>
</header>
<main>
  <section class="card">
    <h2>1 · Build your pattern</h2>
    <label>Preset</label>
    <select id="preset"></select>

    <label>Entry name (shown in DLP)</label>
    <input type="text" id="name" value="CC 13-19 digits, loose separators"/>

    <label>Regex (RE2 syntax)</label>
    <input type="text" id="regex" spellcheck="false"/>
    <div id="re2warn"></div>

    <div class="row">
      <div>
        <label>Validation</label>
        <select id="validation">
          <option value="none">none (structural match only)</option>
          <option value="luhn">luhn (credit-card checksum)</option>
        </select>
      </div>
      <div>
        <label>Flags</label>
        <input type="text" id="flags" value="g"/>
      </div>
    </div>

    <label>Sample text to test against</label>
    <textarea id="in" spellcheck="false"></textarea>
  </section>

  <section class="card">
    <h2>2 · Matches</h2>
    <p class="count" id="count"></p>
    <table>
      <thead><tr><th>Match</th><th>Len</th><th id="th-v">Valid</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </section>

  <section class="card">
    <h2>3 · Paste into DLP (dashboard)</h2>
    <code class="regex" id="rx"></code>
    <p class="count">Zero Trust → DLP → DLP profiles → Custom profile → add entry → Regex. Engine is RE2. Set the entry's Validation to match the dropdown above.</p>
    <button class="copy" data-target="rx">Copy regex</button>
  </section>

  <section class="card">
    <h2>4 · Or add to Terraform (tfvars)</h2>
    <pre id="tf"></pre>
    <button class="copy" data-target="tf">Copy tfvars entry</button>
    <p class="count">Append this object to <code>dlp_custom_entries</code> in <code>terraform.tfvars</code>, then <code>terraform apply</code>.</p>
  </section>
</main>

<script>
const PRESETS = ${JSON.stringify(PRESETS)};
const presetEl = document.getElementById('preset');
PRESETS.forEach(p => { const o=document.createElement('option'); o.value=p.id; o.textContent=p.label; presetEl.appendChild(o); });

function applyPreset(id){
  const p = PRESETS.find(x=>x.id===id) || PRESETS[0];
  document.getElementById('regex').value = p.regex;
  document.getElementById('validation').value = p.validation;
  document.getElementById('in').value = p.sample;
  if (p.id !== 'custom') document.getElementById('name').value = p.label.replace(/ ★$/,'');
  run();
}
presetEl.onchange = () => applyPreset(presetEl.value);
['regex','validation','flags','in','name'].forEach(id => document.getElementById(id).addEventListener('input', run));

async function run(){
  const body = {
    text: document.getElementById('in').value,
    regex: document.getElementById('regex').value,
    flags: document.getElementById('flags').value,
    validation: document.getElementById('validation').value,
    name: document.getElementById('name').value,
  };
  document.getElementById('th-v').style.display = body.validation==='none' ? 'none' : '';
  const r = await fetch('/scan', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body)});
  const d = await r.json();
  const rows = document.getElementById('rows');
  rows.innerHTML='';
  document.getElementById('rx').textContent = body.regex || '(empty)';

  if (d.error){
    rows.innerHTML = '<tr><td colspan="3" class="warn">'+escapeHtml(d.error)+'</td></tr>';
    document.getElementById('count').textContent='';
  } else {
    if (!d.matches.length){
      rows.innerHTML = '<tr><td colspan="3" class="empty">No matches</td></tr>';
    } else {
      for (const m of d.matches){
        const showV = body.validation!=='none';
        const vcell = showV ? '<td><span class="pill '+(m.valid?'pass':'fail')+'">'+(m.valid?'PASS':'fail')+'</span></td>' : '<td style="display:none"></td>';
        const tr=document.createElement('tr');
        tr.innerHTML='<td>'+escapeHtml(m.match)+'</td><td>'+m.length+'</td>'+vcell;
        rows.appendChild(tr);
      }
    }
    const pass = d.matches.filter(m=>m.valid).length;
    document.getElementById('count').textContent = d.matches.length+' match(es)'+(body.validation!=='none'?', '+pass+' pass '+body.validation:'');
  }
  const warnEl = document.getElementById('re2warn');
  warnEl.innerHTML = (d.re2Warnings && d.re2Warnings.length)
    ? '<p class="warn">⚠ '+d.re2Warnings.map(escapeHtml).join('<br>⚠ ')+'</p>' : '';
  document.getElementById('tf').textContent = d.tf || '';
}
function escapeHtml(s){ return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

document.querySelectorAll('button.copy').forEach(b=>{
  b.onclick=()=>{ const t=document.getElementById(b.dataset.target).textContent;
    navigator.clipboard.writeText(t); b.textContent='Copied ✓'; setTimeout(()=>b.textContent=b.dataset.target==='rx'?'Copy regex':'Copy tfvars entry',1200); };
});

applyPreset('cc-loose');
</script>
</body>
</html>`;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/scan" && request.method === "POST") {
      let b = {};
      try { b = await request.json(); } catch {}
      const res = scan(b.text || "", b.regex || "", b.flags || "g", b.validation || "none");
      if (!res.error) res.tf = tfEntry(b.name, b.regex || "", b.validation || "none");
      return Response.json(res);
    }

    // curl-friendly: GET /api?regex=...&text=...&validation=luhn
    if (url.pathname === "/api") {
      const regex = url.searchParams.get("regex") || "";
      const text = url.searchParams.get("text") || "";
      const validation = url.searchParams.get("validation") || "none";
      return Response.json(scan(text, regex, "g", validation));
    }

    if (url.pathname === "/health") return new Response("ok");

    return new Response(html(), { headers: { "content-type": "text/html; charset=utf-8" } });
  },
};
