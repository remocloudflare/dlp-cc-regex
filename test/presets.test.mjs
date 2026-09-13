import test from "node:test";
import assert from "node:assert/strict";

import { PRESETS, scan, compatibilityWarnings } from "../src/index.js";

const productionPresets = PRESETS.filter((preset) => preset.id !== "custom");
const requiredCategories = [
  "Cloud providers",
  "Source control",
  "AI and API providers",
  "Messaging",
  "Credentials and infrastructure",
];

const requiredCredentialPresetMetadata = {
  "google-oauth-client-secret": {
    category: "Cloud providers",
    label: "Google OAuth client secret",
    validation: "none",
    note: "Google OAuth client secrets with the fixed GOCSPX- prefix and an exact 28-character URL-safe body. The final character is deliberately constrained to alphanumeric; because Rust regex has no lookaround, a supported trailing delimiter is included in the whole match when present so overlong '-' and '_' continuations cannot prefix-match.",
  },
  "azure-devops-pat": {
    category: "Source control",
    label: "Azure DevOps personal access token",
    validation: "none",
    note: "Azure DevOps PATs in the current 84-character format with the fixed AZDO signature.",
  },
  "azure-storage-account-key": {
    category: "Cloud providers",
    label: "Azure Storage account key",
    validation: "none",
    note: "Azure Storage account keys only when assigned to a bounded AccountKey field. To reject malformed suffixes without lookahead, a supported trailing delimiter is included in the whole match when present.",
  },
  "azure-storage-sas": {
    category: "Cloud providers",
    label: "Azure Storage shared access signature",
    validation: "none",
    note: "Azure Storage URLs or bounded SharedAccessSignature fields containing both bounded sv and sig query parameters. A supported trailing delimiter is included in the whole match when present to reject malformed suffixes without lookahead.",
  },
  "microsoft-entra-client-secret": {
    category: "Cloud providers",
    label: "Microsoft Entra client secret",
    validation: "none",
    note: "Microsoft Entra client secrets only when assigned to a bounded AppSecret or ClientSecret field. To reject malformed suffixes without lookahead, a supported trailing delimiter is included in the whole match when present.",
  },
};

test("preset IDs are unique", () => {
  const ids = PRESETS.map((preset) => preset.id);
  assert.equal(new Set(ids).size, ids.length);
});

test("each production preset has complete catalog metadata", () => {
  const requiredFields = [
    "id",
    "category",
    "label",
    "regex",
    "sample",
    "negativeSample",
    "note",
  ];

  for (const preset of productionPresets) {
    for (const field of requiredFields) {
      assert.equal(
        typeof preset[field],
        "string",
        `${preset.id}.${field} must be a string`,
      );
      assert.ok(preset[field].length > 0, `${preset.id}.${field} must not be empty`);
    }

    for (const field of ["positiveSamples", "negativeSamples"]) {
      assert.ok(Array.isArray(preset[field]), `${preset.id}.${field} must be an array`);
      assert.ok(preset[field].length > 0, `${preset.id}.${field} must not be empty`);
      for (const [index, fixture] of preset[field].entries()) {
        assert.equal(
          typeof fixture,
          "string",
          `${preset.id}.${field}[${index}] must be a string`,
        );
        assert.ok(
          fixture.length > 0,
          `${preset.id}.${field}[${index}] must not be empty`,
        );
      }
    }

    assert.equal(
      preset.sample,
      preset.positiveSamples.join("\n"),
      `${preset.id}.sample must mirror positiveSamples for the UI`,
    );
    assert.equal(
      preset.negativeSample,
      preset.negativeSamples.join("\n"),
      `${preset.id}.negativeSample must mirror negativeSamples for the UI`,
    );
  }
});

test("catalog includes every approved security category", () => {
  const categories = new Set(productionPresets.map((preset) => preset.category));

  for (const category of requiredCategories) {
    assert.ok(categories.has(category), `missing catalog category: ${category}`);
  }
});

test("catalog includes GCP and Azure credential presets with exact metadata", () => {
  for (const [id, expected] of Object.entries(requiredCredentialPresetMetadata)) {
    const preset = productionPresets.find((candidate) => candidate.id === id);
    assert.ok(preset, `missing preset: ${id}`);
    assert.deepEqual(
      {
        category: preset.category,
        label: preset.label,
        validation: preset.validation,
        note: preset.note,
      },
      expected,
      `${id} metadata`,
    );
  }
});

const unsupportedRegexCases = [
  ["lookahead", String.raw`foo(?=bar)`],
  ["lookbehind", String.raw`foo(?<=bar)`],
  ["backreference", String.raw`(foo)\1`],
  ["backreference", String.raw`(?<word>foo)\k<word>`],
  ["atomic group", String.raw`(?>foo)`],
];

for (const [construct, pattern] of unsupportedRegexCases) {
  test(`compatibility warnings identify ${construct} in ${pattern}`, () => {
    assert.ok(
      compatibilityWarnings(pattern).some((warning) => warning.includes(construct)),
      `${pattern} must warn about ${construct}`,
    );
  });
}

test("each production preset has no supplemental compatibility warnings", () => {
  for (const preset of productionPresets) {
    assert.deepEqual(compatibilityWarnings(preset.regex), [], preset.id);
  }
});

const claimedPositiveFamilies = {
  "aws-access-key-id": [/^AKIA/, /^ASIA/],
  "google-api-key": [/^AIza/],
  "google-oauth-client-secret": [/^GOCSPX-/],
  "azure-devops-pat": [/AZDO/],
  "azure-storage-account-key": [/^AccountKey=/i, /^accountkey\s+=\s+/i],
  "azure-storage-sas": [
    /^https:\/\/[^/]+\.blob\.core\.windows\.net\//,
    /^https:\/\/[^/]+\.dfs\.core\.windows\.net\//,
    /^SharedAccessSignature=/,
  ],
  "microsoft-entra-client-secret": [/^AppSecret=/i, /^clientsecret\s+=\s+/i],
  "github-token-classic": [/^ghp_/, /^gho_/, /^ghu_/, /^ghs_/, /^ghr_/],
  "github-token-fine-grained": [/^github_pat_/],
  "gitlab-personal-access-token": [/^glpat-/],
  "openai-project-service-key": [/^sk-proj-/, /^sk-svcacct-/],
  "openai-user-key": [/^sk-[A-Za-z0-9]{48}$/],
  "anthropic-api-key": [/^sk-ant-api03-/],
  "stripe-live-secret-key": [/^sk_live_/, /^rk_live_/],
  "slack-access-token": [
    /^xoxb-/,
    /^xoxp-/,
    /^xoxa-/,
    /^xoxr-/,
    /^xoxs-/,
    /^xapp-/,
    /^xwfp-/,
    /^xoxe-/,
    /^xoxe\.xoxb-/,
    /^xoxe\.xoxp-/,
  ],
  "slack-incoming-webhook": [/^https:\/\/hooks\.slack\.com\/services\//],
  "pem-private-key-header": [
    /^-----BEGIN PRIVATE KEY-----$/,
    /^-----BEGIN RSA PRIVATE KEY-----$/,
    /^-----BEGIN EC PRIVATE KEY-----$/,
    /^-----BEGIN DSA PRIVATE KEY-----$/,
    /^-----BEGIN OPENSSH PRIVATE KEY-----$/,
  ],
  "compact-jwt": [/^eyJ[^.]+\.[^.]+\.[^.]+$/],
  "authenticated-http-url": [/^http:\/\//, /^https:\/\//],
  "database-url-with-credentials": [
    /^postgres:\/\//,
    /^postgresql:\/\//,
    /^mysql:\/\//,
    /^mariadb:\/\//,
    /^mongodb:\/\//,
    /^mongodb\+srv:\/\//,
    /^redis:\/\//,
    /^rediss:\/\//,
  ],
};

function hasUnescapedUnboundedQuantifier(pattern) {
  let escaped = false;
  let inCharacterClass = false;
  for (const character of pattern) {
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\") {
      escaped = true;
      continue;
    }
    if (character === "[") {
      inCharacterClass = true;
      continue;
    }
    if (character === "]") {
      inCharacterClass = false;
      continue;
    }
    if (!inCharacterClass && (character === "+" || character === "*")) return true;
  }
  return false;
}

test("security preset regexes do not use unbounded plus or star quantifiers", () => {
  for (const preset of productionPresets) {
    assert.equal(
      hasUnescapedUnboundedQuantifier(preset.regex),
      false,
      `${preset.id} contains an unbounded + or * quantifier`,
    );
  }
});

test("security preset regexes fit the Cloudflare DLP UTF-8 byte limit", () => {
  for (const preset of productionPresets) {
    assert.ok(
      Buffer.byteLength(preset.regex, "utf8") <= 1024,
      `${preset.id} regex exceeds 1024 UTF-8 bytes`,
    );
  }
});

test("every claimed detector family has an individual positive fixture", () => {
  for (const [presetId, families] of Object.entries(claimedPositiveFamilies)) {
    const preset = productionPresets.find(({ id }) => id === presetId);
    assert.ok(preset, `missing preset: ${presetId}`);
    for (const family of families) {
      assert.ok(
        preset.positiveSamples.some((fixture) => family.test(fixture)),
        `${presetId} needs an individual fixture for ${family}`,
      );
    }
  }
});

test("each production preset matches every positive fixture", () => {
  for (const preset of productionPresets) {
    for (const [index, fixture] of preset.positiveSamples.entries()) {
      const result = scan(fixture, preset.regex, "g", "none");
      assert.equal(result.error, undefined, preset.id);
      assert.ok(
        result.matches.length > 0,
        `${preset.id}.positiveSamples[${index}] must match`,
      );
    }
  }
});

test("Azure Storage SAS matches bounded parameters before sv", () => {
  const preset = productionPresets.find(({ id }) => id === "azure-storage-sas");
  const fixture =
    "https://fixture.blob.core.windows.net/container/object?sp=r&st=2026-01-01&se=2030-01-01&sv=2024-11-04&sr=b&sig=AbCdEf0123456789%2Fxy%3D";
  const result = scan(fixture, preset.regex, "g", "none");
  assert.deepEqual(result.matches.map(({ match }) => match), [fixture]);
});

test("Azure Storage SAS matches Azure Data Lake dfs endpoints", () => {
  const preset = productionPresets.find(({ id }) => id === "azure-storage-sas");
  const fixture =
    "https://fixture123.dfs.core.windows.net/container/path?sv=2024-11-04&sp=r&sig=AbCdEf0123456789%2Fxy%3D";
  const result = scan(fixture, preset.regex, "g", "none");
  assert.deepEqual(result.matches.map(({ match }) => match), [fixture]);
});

test("Azure Storage SAS matches realistic user-delegation parameters", () => {
  const preset = productionPresets.find(({ id }) => id === "azure-storage-sas");
  const fixture =
    "https://fixture123.dfs.core.windows.net/container/path?skoid=11111111-1111-1111-1111-111111111111&sktid=22222222-2222-2222-2222-222222222222&skt=2026-09-11T12%3A00%3A00Z&ske=2026-09-12T12%3A00%3A00Z&sks=b&skv=2024-11-04&sr=b&sp=r&st=2026-09-11T12%3A00%3A00Z&se=2026-09-12T12%3A00%3A00Z&sv=2024-11-04&spr=https&sig=AbCdEf0123456789%2Fxy%3D";
  const result = scan(fixture, preset.regex, "g", "none");
  assert.deepEqual(result.matches.map(({ match }) => match), [fixture]);
});

test("Azure Storage SAS allows more than eight bounded parameters in every position and required-field order", () => {
  const preset = productionPresets.find(({ id }) => id === "azure-storage-sas");
  const genericParameters = Array.from(
    { length: 9 },
    (_, index) => `p${index}=value${index}`,
  );
  const sv = "sv=2024-11-04";
  const sig = "sig=AbCdEf0123456789%2Fxy%3D";
  const arrangements = [
    [...genericParameters, sv, sig],
    [...genericParameters, sig, sv],
    [sv, ...genericParameters, sig],
    [sig, ...genericParameters, sv],
    [sv, sig, ...genericParameters],
    [sig, sv, ...genericParameters],
  ];

  for (const parameters of arrangements) {
    const fixture = `SharedAccessSignature=${parameters.join("&")}`;
    assert.deepEqual(
      scan(fixture, preset.regex, "g", "none").matches.map(({ match }) => match),
      [fixture],
      fixture,
    );
  }
});

test("Azure Storage SAS includes bounded query parameters after the second required field", () => {
  const preset = productionPresets.find(({ id }) => id === "azure-storage-sas");
  const fixtures = [
    "https://fixture.blob.core.windows.net/container/object?sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D&sp=r",
    "SharedAccessSignature=sig=AbCdEf0123456789%2Fxy%3D&sv=2024-11-04&spr=https",
  ];

  for (const fixture of fixtures) {
    assert.deepEqual(
      scan(fixture, preset.regex, "g", "none").matches.map(({ match }) => match),
      [fixture],
      fixture,
    );
  }
});

test("Azure Storage SAS rejects malformed trailing query continuations", () => {
  const preset = productionPresets.find(({ id }) => id === "azure-storage-sas");
  const malformedFixtures = [
    "https://fixture.blob.core.windows.net/container/object?sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D!&sp=r",
    "https://fixture.blob.core.windows.net/container/object?sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D&sp",
    "SharedAccessSignature=sig=AbCdEf0123456789%2Fxy%3D&sv=2024-11-04&spr=",
  ];

  for (const fixture of malformedFixtures) {
    assert.deepEqual(
      scan(fixture, preset.regex, "g", "none").matches.map(({ match }) => match),
      [],
      fixture,
    );
  }
});

test("GCP tokens reject URL-safe alphabet continuations after an exact body", () => {
  const cases = [
    ["google-api-key", `AIza${"A".repeat(35)}`],
    ["google-oauth-client-secret", `GOCSPX-${"A".repeat(28)}`],
  ];

  for (const [presetId, token] of cases) {
    const preset = productionPresets.find(({ id }) => id === presetId);
    for (const suffix of ["-x", "_x"]) {
      assert.deepEqual(
        scan(`${token}${suffix}`, preset.regex, "g", "none").matches,
        [],
        `${presetId} must reject ${JSON.stringify(suffix)} continuation`,
      );
    }
  }
});

test("GCP token matches end at EOS or consume an allowed trailing delimiter", () => {
  const cases = [
    ["google-api-key", `AIza${"A_b-".repeat(8)}AbZ`],
    ["google-oauth-client-secret", `GOCSPX-${"A_b-".repeat(6)}A_bZ`],
  ];

  for (const [presetId, token] of cases) {
    const preset = productionPresets.find(({ id }) => id === presetId);
    assert.deepEqual(
      scan(token, preset.regex, "g", "none").matches.map(({ match }) => match),
      [token],
      `${presetId} at end of string`,
    );
    assert.deepEqual(
      scan(`(${token};next`, preset.regex, "g", "none").matches.map(({ match }) => match),
      [`${token};`],
      `${presetId} before delimiter`,
    );
  }
});

test("bounded token presets reject allowed-alphabet continuations at maximum length", () => {
  const cases = [
    ["gitlab-personal-access-token", `glpat-${"A".repeat(20)}`, ["-x", "_x", "A"]],
    ["github-token-fine-grained", `github_pat_${"A".repeat(82)}`, ["_x", "A"]],
    ["openai-project-service-key", `sk-proj-${"A".repeat(200)}`, ["-x", "_x", "A"]],
    ["anthropic-api-key", `sk-ant-api03-${"A".repeat(200)}`, ["-x", "_x", "A"]],
    ["stripe-live-secret-key", `sk_live_${"A".repeat(99)}`, ["A"]],
    ["slack-access-token", `xoxb-${"A".repeat(200)}`, ["-x", "A"]],
    ["slack-incoming-webhook", `https://hooks.slack.com/services/T00000000/B00000000/${"A".repeat(48)}`, ["A"]],
    ["authenticated-http-url", `https://user:password@example.invalid/${"a".repeat(1024)}`, ["x"]],
    ["database-url-with-credentials", `postgres://user:password@example.invalid/${"a".repeat(1024)}`, ["x"]],
  ];
  for (const [presetId, token, suffixes] of cases) {
    const preset = productionPresets.find(({ id }) => id === presetId);
    for (const suffix of suffixes) {
      assert.deepEqual(
        scan(`${token}${suffix}`, preset.regex, "g", "none").matches,
        [],
        `${presetId} must reject ${JSON.stringify(suffix)} continuation`,
      );
    }
  }
});

test("standalone Azure DevOps PAT matches exclude surrounding delimiters", () => {
  const token = `${"A".repeat(75)}AZDO${"B".repeat(5)}`;
  const preset = productionPresets.find(({ id }) => id === "azure-devops-pat");
  const result = scan(`(${token});`, preset.regex, "g", "none");
  assert.deepEqual(result.matches.map(({ match }) => match), [token]);
});

test("Azure Storage AccountKey includes an allowed trailing delimiter only when needed", () => {
  const preset = productionPresets.find(({ id }) => id === "azure-storage-account-key");
  const assignment = `AccountKey=${"A".repeat(86)}==`;

  assert.deepEqual(
    scan(assignment, preset.regex, "g", "none").matches.map(({ match }) => match),
    [assignment],
  );
  assert.deepEqual(
    scan(`${assignment};next=value`, preset.regex, "g", "none").matches.map(
      ({ match }) => match,
    ),
    [`${assignment};`],
  );
});

test("Microsoft Entra client secret includes an allowed trailing delimiter only when needed", () => {
  const preset = productionPresets.find(
    ({ id }) => id === "microsoft-entra-client-secret",
  );
  const minimumAssignment = `ClientSecret=${"A._-".repeat(5)}`;
  const maximumAssignment = `clientsecret = ${"z9~.".repeat(10)}`;

  assert.deepEqual(
    scan(minimumAssignment, preset.regex, "g", "none").matches.map(
      ({ match }) => match,
    ),
    [minimumAssignment],
  );
  assert.deepEqual(
    scan(`${maximumAssignment};next=value`, preset.regex, "g", "none").matches.map(
      ({ match }) => match,
    ),
    [`${maximumAssignment};`],
  );
});

test("rotating Slack composite fixtures match as complete tokens", () => {
  const preset = productionPresets.find(({ id }) => id === "slack-access-token");
  const compositeFixtures = preset.positiveSamples.filter((fixture) =>
    fixture.startsWith("xoxe.xox"),
  );

  assert.equal(compositeFixtures.length, 2);
  for (const fixture of compositeFixtures) {
    const result = scan(fixture, preset.regex, "g", "none");
    assert.deepEqual(
      result.matches.map(({ match }) => match),
      [fixture],
      `${fixture.slice(0, 14)}… must not be matched as only its inner xox token`,
    );
  }
});

test("each production preset rejects every negative fixture", () => {
  for (const preset of productionPresets) {
    for (const [index, fixture] of preset.negativeSamples.entries()) {
      const result = scan(fixture, preset.regex, "g", "none");
      assert.equal(result.error, undefined, preset.id);
      assert.equal(
        result.matches.length,
        0,
        `${preset.id}.negativeSamples[${index}] must not match`,
      );
    }
  }
});
