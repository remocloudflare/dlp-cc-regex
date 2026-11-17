import * as regexModuleNamespace from "./regex_validator.wasm";
import { createDlpRegexValidator } from "./regex-validator.js";

const regexExports = regexModuleNamespace.default
  ? new WebAssembly.Instance(regexModuleNamespace.default).exports
  : regexModuleNamespace;
export const validateDlpRegex = createDlpRegexValidator(regexExports);

/**
 * DLP Regex Builder — Cloudflare Worker
 *
 * A self-serve frontend where a customer authors and TESTS a regex for a
 * Cloudflare DLP custom entry, then copies out:
 *   - the raw Rust regex to paste into the DLP dashboard, AND
 *   - a ready-to-paste Terraform `dlp_custom_entries` object.
 *
 * Flagship preset: a loosely-formatted credit-card pattern that catches numbers
 * like `1 344-4343 12345` which Cloudflare's default PCI detector misses.
 *
 * DLP custom entries use Rust regex syntax. This tool validates with the real
 * Rust regex crate, scans with that same engine, and applies an OPTIONAL Luhn
 * post-filter in JS — because regex syntax cannot perform checksums.
 * In production, Luhn is expressed as the entry's `validation` option.
 */

// ---- presets -------------------------------------------------------------
const fixturePreset = ({ positiveSamples, negativeSamples, ...preset }) => ({
  ...preset,
  positiveSamples,
  negativeSamples,
  sample: positiveSamples.join("\n"),
  negativeSample: negativeSamples.join("\n"),
});

export const PRESETS = [
  fixturePreset({
    id: "cc-loose",
    category: "Financial data",
    label: "Credit card (loose separators) ★",
    regex: String.raw`\b\d(?:[ -]?\d){12,18}\b`,
    validation: "luhn",
    positiveSamples: [
      "1 344-4343 12345",
      "4242 4242 4242 4242",
      "My card is 5555 5555 5555 4444",
    ],
    negativeSamples: ["order#12345678 ref 999"],
    note: "13-19 digits, any pair may be split by a single space or dash.",
  }),
  fixturePreset({
    id: "cc-strict",
    category: "Financial data",
    label: "Credit card (canonical 4-4-4-4)",
    regex: String.raw`\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b`,
    validation: "luhn",
    positiveSamples: ["4242 4242 4242 4242", "4111-1111-1111-1111"],
    negativeSamples: ["4242 4242 4242"],
    note: "16 digits in standard grouping (what the default detector expects).",
  }),
  fixturePreset({
    id: "aws-access-key-id",
    category: "Cloud providers",
    label: "AWS access key ID",
    regex: String.raw`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`,
    validation: "none",
    positiveSamples: [
      "AKIAABCDEFGHIJKLMNOP",
      "ASIAQRSTUVWXYZ012345",
    ],
    negativeSamples: [
      "AKIAABCDEFGHIJKLMNO",
      "ASIAQRSTUVWXYZ01234!",
    ],
    note: "AWS long-term (AKIA) and temporary STS (ASIA) access key IDs.",
  }),
  fixturePreset({
    id: "google-api-key",
    category: "Cloud providers",
    label: "Google API key",
    regex: String.raw`\bAIza[0-9A-Za-z_-]{34}[0-9A-Za-z](?:$|[ \t\r\n,.;:!?'"){}<>/\\=+*&%$#@^~|\[\]])`,
    validation: "none",
    positiveSamples: [`AIza${"SYNTHETIC".repeat(3)}FIXTURE1`],
    negativeSamples: [
      `AIza${"SYNTHETIC".repeat(3)}FIXTURE`,
      `AIza${"A".repeat(35)}-x`,
      `AIza${"A".repeat(35)}_x`,
    ],
    note: "Google API keys with the fixed AIza prefix and an exact 35-character URL-safe body. The final character is deliberately constrained to alphanumeric; because Rust regex has no lookaround, a supported trailing delimiter is included in the whole match when present so overlong '-' and '_' continuations cannot prefix-match.",
  }),
  fixturePreset({
    id: "google-oauth-client-secret",
    category: "Cloud providers",
    label: "Google OAuth client secret",
    regex: String.raw`\bGOCSPX-[A-Za-z0-9_-]{27}[A-Za-z0-9](?:$|[ \t\r\n,.;:!?'"){}<>/\\=+*&%$#@^~|\[\]])`,
    validation: "none",
    positiveSamples: [
      `GOCSPX-${"A_b-".repeat(6)}A_bZ`,
      `client_secret=GOCSPX-${"Z9_-".repeat(6)}Z9_A;`,
    ],
    negativeSamples: [
      `GOCSPX-${"A".repeat(27)}`,
      `GOCSPX-${"A".repeat(29)}`,
      `GOCSPX-${"A".repeat(27)}-`,
      `xGOCSPX-${"A".repeat(28)}`,
      `GOCSPX-${"A".repeat(27)}_x`,
      `GOCSPX-${"A".repeat(28)}-x`,
      `GOCSPX-${"A".repeat(28)}_x`,
      `GOCSPY-${"A".repeat(28)}`,
    ],
    note: "Google OAuth client secrets with the fixed GOCSPX- prefix and an exact 28-character URL-safe body. The final character is deliberately constrained to alphanumeric; because Rust regex has no lookaround, a supported trailing delimiter is included in the whole match when present so overlong '-' and '_' continuations cannot prefix-match.",
  }),
  fixturePreset({
    id: "azure-devops-pat",
    category: "Source control",
    label: "Azure DevOps personal access token",
    regex: String.raw`\b[A-Za-z0-9]{75}AZDO[A-Za-z0-9]{5}\b`,
    validation: "none",
    positiveSamples: [
      `${"A".repeat(75)}AZDO${"B".repeat(5)}`,
      `pat=${"0a".repeat(37)}ZAZDO9xY2q;`,
    ],
    negativeSamples: [
      `${"A".repeat(74)}AZDO${"B".repeat(5)}`,
      `${"A".repeat(76)}AZDO${"B".repeat(5)}`,
      `x${"A".repeat(75)}AZDO${"B".repeat(5)}`,
      `${"A".repeat(75)}AZDO${"B".repeat(5)}x`,
      `${"A".repeat(75)}AZDX${"B".repeat(5)}`,
      `${"A".repeat(52)}`,
    ],
    note: "Azure DevOps PATs in the current 84-character format with the fixed AZDO signature.",
  }),
  fixturePreset({
    id: "azure-storage-account-key",
    category: "Cloud providers",
    label: "Azure Storage account key",
    regex: String.raw`\b[Aa][Cc][Cc][Oo][Uu][Nn][Tt][Kk][Ee][Yy][ \t]{0,8}=[ \t]{0,8}[A-Za-z0-9+/]{86}==(?:$|[ \t\r\n,;:'")}>]|\])`,
    validation: "none",
    positiveSamples: [
      `AccountKey=${"A".repeat(86)}==`,
      `accountkey   =  ${"aB9/".repeat(21)}a+==`,
    ],
    negativeSamples: [
      `${"A".repeat(86)}==`,
      `AccountName=${"A".repeat(86)}==`,
      `AccountKey=${"A".repeat(85)}==`,
      `AccountKey=${"A".repeat(87)}==`,
      `NotAccountKey=${"A".repeat(86)}==`,
      `AccountKey=${"A".repeat(86)}==A`,
      `AccountKey=${"A".repeat(86)}===`,
      `AccountKey         =${"A".repeat(86)}==`,
    ],
    note: "Azure Storage account keys only when assigned to a bounded AccountKey field. To reject malformed suffixes without lookahead, a supported trailing delimiter is included in the whole match when present.",
  }),
  fixturePreset({
    id: "azure-storage-sas",
    category: "Cloud providers",
    label: "Azure Storage shared access signature",
    regex: String.raw`(?:(?:https://[a-z0-9]{3,24}\.(?:blob|dfs|file|queue|table)\.core\.windows\.net/[^?\s#]{0,512}\?)|\b[Ss][Hh][Aa][Rr][Ee][Dd][Aa][Cc][Cc][Ee][Ss][Ss][Ss][Ii][Gg][Nn][Aa][Tt][Uu][Rr][Ee]=)(?:[^&\s#]{1,128}&){0,16}(?:sv=[^&\s#]{1,64}(?:&[^&\s#]{1,128}){0,16}&sig=[A-Za-z0-9%._~+/=-]{16,256}|sig=[A-Za-z0-9%._~+/=-]{16,256}(?:&[^&\s#]{1,128}){0,16}&sv=[^&\s#]{1,64})(?:&[A-Za-z0-9._~-]{1,64}=[A-Za-z0-9%._~+/=:-]{1,128}){0,16}(?:$|[ \t\r\n#;,:'")}>]|\])`,
    validation: "none",
    positiveSamples: [
      "https://fixture.blob.core.windows.net/container/object?sv=2024-11-04&sp=r&sig=AbCdEf0123456789%2Fxy%3D",
      "https://fixture123.dfs.core.windows.net/container/path?sv=2024-11-04&sp=r&sig=AbCdEf0123456789%2Fxy%3D",
      "https://fixture123.dfs.core.windows.net/container/path?skoid=11111111-1111-1111-1111-111111111111&sktid=22222222-2222-2222-2222-222222222222&skt=2026-09-11T12%3A00%3A00Z&ske=2026-09-12T12%3A00%3A00Z&sks=b&skv=2024-11-04&sr=b&sp=r&st=2026-09-11T12%3A00%3A00Z&se=2026-09-12T12%3A00%3A00Z&sv=2024-11-04&spr=https&sig=AbCdEf0123456789%2Fxy%3D",
      "https://fixture.blob.core.windows.net/container/object?sp=r&st=2026-01-01&se=2030-01-01&sv=2024-11-04&sr=b&sig=AbCdEf0123456789%2Fxy%3D",
      "https://fixture.blob.core.windows.net/container/object?sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D&sp=r",
      "https://fixture.file.core.windows.net/share/file?sig=AbCdEf0123456789%2Fxy%3D&se=2030-01-01&sv=2024-11-04",
      "SharedAccessSignature=sv=2024-11-04&sr=b&sig=AbCdEf0123456789%2Fxy%3D",
      "sharedaccesssignature=sig=AbCdEf0123456789%2Fxy%3D&sp=r&sv=2024-11-04",
      "SharedAccessSignature=sig=AbCdEf0123456789%2Fxy%3D&sv=2024-11-04&spr=https",
    ],
    negativeSamples: [
      "https://example.invalid/container/object?sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D",
      "https://fixture.blob.core.windows.net/container/object?sv=2024-11-04",
      "https://fixture.blob.core.windows.net/container/object?sig=AbCdEf0123456789%2Fxy%3D",
      "sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D",
      "SharedAccessSignature=sv=2024-11-04&sig=short",
      "SharedAccessSignature=sv=2024-11-04&sig=AbCdEf0123456789!",
      "NotSharedAccessSignature=sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D",
      "https://UPPER.blob.core.windows.net/container?sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D",
      "https://bad-name.blob.core.windows.net/container?sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D",
      "https://ab.blob.core.windows.net/container?sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D",
      `https://${"a".repeat(25)}.blob.core.windows.net/container?sv=2024-11-04&sig=AbCdEf0123456789%2Fxy%3D`,
    ],
    note: "Azure Storage URLs or bounded SharedAccessSignature fields containing both bounded sv and sig query parameters. A supported trailing delimiter is included in the whole match when present to reject malformed suffixes without lookahead.",
  }),
  fixturePreset({
    id: "microsoft-entra-client-secret",
    category: "Cloud providers",
    label: "Microsoft Entra client secret",
    regex: String.raw`\b(?:[Aa][Pp][Pp][Ss][Ee][Cc][Rr][Ee][Tt]|[Cc][Ll][Ii][Ee][Nn][Tt][Ss][Ee][Cc][Rr][Ee][Tt])[ \t]{0,8}=[ \t]{0,8}[A-Za-z0-9._~-]{20,40}(?:$|[ \t\r\n,;:'")}>]|\])`,
    validation: "none",
    positiveSamples: [
      `AppSecret=${"A._-".repeat(5)}`,
      `clientsecret = ${"z9~.".repeat(10)};`,
    ],
    negativeSamples: [
      `${"A._-".repeat(5)}`,
      `Secret=${"A".repeat(24)}`,
      `NotAppSecret=${"A".repeat(24)}`,
      `NotClientSecret=${"A".repeat(24)}`,
      `ClientSecret=${"A".repeat(19)}`,
      `ClientSecret=${"A".repeat(41)}`,
      `ClientSecret=${"A".repeat(20)}!${"A".repeat(20)}`,
      `ClientSecret=${"A".repeat(10)}!${"A".repeat(10)}`,
    ],
    note: "Microsoft Entra client secrets only when assigned to a bounded AppSecret or ClientSecret field. To reject malformed suffixes without lookahead, a supported trailing delimiter is included in the whole match when present.",
  }),
  fixturePreset({
    id: "github-token-classic",
    category: "Source control",
    label: "GitHub classic token families",
    regex: String.raw`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b`,
    validation: "none",
    positiveSamples: [
      `ghp_${"A".repeat(36)}`,
      `gho_${"B".repeat(36)}`,
      `ghu_${"C".repeat(36)}`,
      `ghs_${"D".repeat(36)}`,
      `ghr_${"E".repeat(36)}`,
    ],
    negativeSamples: [
      `ghx_${"A".repeat(36)}`,
      `ghp_${"A".repeat(35)}!`,
    ],
    note: "GitHub personal, OAuth, user-to-server, server-to-server, and refresh token prefixes.",
  }),
  fixturePreset({
    id: "github-token-fine-grained",
    category: "Source control",
    label: "GitHub fine-grained personal access token",
    regex: String.raw`\bgithub_pat_[A-Za-z0-9_]{82}\b`,
    validation: "none",
    positiveSamples: [`github_pat_${"A".repeat(82)}`],
    negativeSamples: [`github_pat_${"A".repeat(81)}!`],
    note: "GitHub fine-grained personal access tokens with their fixed prefix and body length.",
  }),
  fixturePreset({
    id: "gitlab-personal-access-token",
    category: "Source control",
    label: "GitLab personal access token",
    regex: String.raw`\bglpat-[A-Za-z0-9_-]{19}[A-Za-z0-9](?:$|[ \t\r\n,.;:!?'\"){}<>/\\=+*&%$#@^~|\[\]])`,
    validation: "none",
    positiveSamples: ["glpat-SYNTHETIC_FIXTURE_01"],
    negativeSamples: ["glpat-SYNTHETIC_FIXTURE!"],
    note: "GitLab tokens using the default glpat- prefix and a 20-character URL-safe body ending in alphanumeric. A supported trailing delimiter is included in the whole match when present to prevent overlong prefix matches.",
  }),
  fixturePreset({
    id: "openai-project-service-key",
    category: "AI and API providers",
    label: "OpenAI project or service-account API key",
    regex: String.raw`\b(?:sk-proj-|sk-svcacct-)[A-Za-z0-9_-]{19,199}[A-Za-z0-9](?:$|[ \t\r\n,.;:!?'\"){}<>/\\=+*&%$#@^~|\[\]])`,
    validation: "none",
    positiveSamples: [
      "sk-proj-SYNTHETIC_PROJECT_KEY_01",
      "sk-svcacct-SYNTHETIC_SERVICE_KEY_01",
    ],
    negativeSamples: [
      "sk-proj-SYNTHETIC_SHORT!",
      "sk-test-SYNTHETIC_PROJECT_KEY_01",
    ],
    note: "OpenAI project and service-account key prefixes with a 20-200 character URL-safe body ending in alphanumeric. A supported trailing delimiter is included in the whole match when present to prevent overlong prefix matches.",
  }),
  fixturePreset({
    id: "openai-user-key",
    category: "AI and API providers",
    label: "OpenAI user API key",
    regex: String.raw`\bsk-[A-Za-z0-9]{48}\b`,
    validation: "none",
    positiveSamples: [`sk-${"A".repeat(48)}`],
    negativeSamples: [`sk-${"A".repeat(47)}!`],
    note: "Legacy OpenAI user keys with the sk- prefix and fixed 48-character body.",
  }),
  fixturePreset({
    id: "anthropic-api-key",
    category: "AI and API providers",
    label: "Anthropic API key",
    regex: String.raw`\bsk-ant-api03-[A-Za-z0-9_-]{19,199}[A-Za-z0-9](?:$|[ \t\r\n,.;:!?'\"){}<>/\\=+*&%$#@^~|\[\]])`,
    validation: "none",
    positiveSamples: ["sk-ant-api03-SYNTHETIC_ANTHROPIC_01"],
    negativeSamples: ["sk-ant-api02-SYNTHETIC_ANTHROPIC_01"],
    note: "Anthropic API keys using the current sk-ant-api03 prefix and a 20-200 character URL-safe body ending in alphanumeric. A supported trailing delimiter is included in the whole match when present to prevent overlong prefix matches.",
  }),
  fixturePreset({
    id: "stripe-live-secret-key",
    category: "AI and API providers",
    label: "Stripe live secret or restricted key",
    regex: String.raw`\b(?:sk_live|rk_live)_[A-Za-z0-9]{24,99}(?:$|[ \t\r\n,.;:!?'\"){}<>/\\=+*&%$#@^~|\[\]_-])`,
    validation: "none",
    positiveSamples: [
      `sk_live_${"A".repeat(24)}`,
      `rk_live_${"B".repeat(24)}`,
    ],
    negativeSamples: [
      `sk_test_${"A".repeat(24)}`,
      `rk_live_${"B".repeat(23)}!`,
    ],
    note: "Stripe live-mode secret and restricted keys only; test-mode keys are intentionally excluded. A supported trailing delimiter is included in the whole match when present to prevent overlong prefix matches.",
  }),
  fixturePreset({
    id: "slack-access-token",
    category: "Messaging",
    label: "Slack access token",
    regex: String.raw`\b(?:xoxe\.xox[bp]-[0-9A-Za-z-]{19,199}[0-9A-Za-z]|xoxe-[0-9A-Za-z-]{19,199}[0-9A-Za-z]|(?:xox[bpars]|xapp|xwfp)-[0-9A-Za-z-]{19,199}[0-9A-Za-z])(?:$|[ \t\r\n,.;:!?'\"){}<>/\\=+*&%$#@^~|\[\]_])`,
    validation: "none",
    positiveSamples: [
      `${"xo" + "xb-"}${"A".repeat(20)}`,
      `${"xo" + "xp-"}${"B".repeat(20)}`,
      `${"xo" + "xa-"}${"C".repeat(20)}`,
      `${"xo" + "xr-"}${"D".repeat(20)}`,
      `${"xo" + "xs-"}${"E".repeat(20)}`,
      `${"xap" + "p-"}${"F".repeat(20)}`,
      `${"xwf" + "p-"}111111111111-222222222222-333333333333-abcdef0123456789abcdef0123456789`,
      `${"xox" + "e-1-"}${"A".repeat(147)}`,
      `${"xox" + "e.xoxb-1-"}${"B".repeat(146)}`,
      `${"xox" + "e.xoxp-1-"}${"C".repeat(146)}`,
    ],
    negativeSamples: [
      "xoxz-111111111111-222222222222-SYNTHETICSECRET000001",
      "xapp-short",
      "xwfp-contains_invalid_character!",
      `xoxe.xoxz-1-${"A".repeat(146)}`,
    ],
    note: "Slack xoxb, xoxp, xoxa, xoxr, xoxs, xapp, xwfp, and rotating xoxe access/refresh token families. Bodies end in alphanumeric, and a supported trailing delimiter is included in the whole match when present to prevent overlong prefix matches.",
  }),
  fixturePreset({
    id: "slack-incoming-webhook",
    category: "Messaging",
    label: "Slack incoming webhook URL",
    regex: String.raw`https://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,48}(?:$|[ \t\r\n,.;:!?'\"){}<>/\\=+*&%$#@^~|\[\]_-])`,
    validation: "none",
    positiveSamples: [
      `https://${"hooks.slack.com"}/services/T00000000/B00000000/${"A".repeat(24)}`,
    ],
    negativeSamples: [
      "https://hooks.slack.example/services/T00000000/B00000000/AAAAAAAAAAAAAAAAAAAAAAAA",
      "http://hooks.slack.com/services/T00000000/B00000000/AAAAAAAAAAAAAAAAAAAAAAAA",
    ],
    note: "Slack incoming webhook URLs with constrained workspace, channel, and secret segments. A supported trailing delimiter is included in the whole match when present to prevent an overlong secret segment from prefix-matching.",
  }),
  fixturePreset({
    id: "pem-private-key-header",
    category: "Credentials and infrastructure",
    label: "PEM private-key header",
    regex: String.raw`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`,
    validation: "none",
    positiveSamples: [
      "-----BEGIN PRIVATE KEY-----",
      "-----BEGIN RSA PRIVATE KEY-----",
      "-----BEGIN EC PRIVATE KEY-----",
      "-----BEGIN DSA PRIVATE KEY-----",
      "-----BEGIN OPENSSH PRIVATE KEY-----",
    ],
    negativeSamples: [
      "-----BEGIN PUBLIC KEY-----",
      "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    ],
    note: "PEM headers for PKCS#8, RSA, EC, DSA, and OpenSSH private keys.",
  }),
  fixturePreset({
    id: "compact-jwt",
    category: "Credentials and infrastructure",
    label: "Compact JSON Web Token",
    regex: String.raw`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`,
    validation: "none",
    positiveSamples: [
      "eyJhbGciOiJub25lIn0.U1lOVEhFVElDX1BBWUxPQUQ.U1lOVEhFVElDX1NJR05BVFVSRT",
    ],
    negativeSamples: [
      "eyJhbGciOiJub25lIn0.U1lOVEhFVElDX1BBWUxPQUQ",
      "eyJsh.U1lOVEhFVElD.U1lOVEhFVElD",
    ],
    note: "Compact JWTs with constrained base64url header, payload, and signature segments.",
  }),
  fixturePreset({
    id: "authenticated-http-url",
    category: "Credentials and infrastructure",
    label: "Authenticated HTTP(S) URL",
    regex: String.raw`https?://[A-Za-z0-9._~-]{1,128}:[A-Za-z0-9._~!$&'()*+,;=:%-]{1,256}@[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?(?:[/?#][^\s]{0,1024})?(?:$|[ \t\r\n])`,
    validation: "none",
    positiveSamples: [
      "http://fixture-user:not-a-password@example.invalid/private",
      "https://fixture-user:not-a-password@example.invalid:8443/private",
    ],
    negativeSamples: [
      "https://fixture-user@example.invalid/private",
      "ftp://fixture-user:not-a-password@example.invalid/private",
    ],
    note: "HTTP and HTTPS URLs containing explicit username and password userinfo. A trailing whitespace delimiter is consumed when present so an overlong URL cannot prefix-match.",
  }),
  fixturePreset({
    id: "database-url-with-credentials",
    category: "Credentials and infrastructure",
    label: "Database URL with credentials",
    regex: String.raw`\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss)://[A-Za-z0-9._~-]{1,128}:[A-Za-z0-9._~!$&'()*+,;=:%-]{1,256}@[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?(?:/[^\s]{0,1024})?(?:$|[ \t\r\n])`,
    validation: "none",
    positiveSamples: [
      "postgres://fixture-user:not-a-password@db.example.invalid:5432/app",
      "postgresql://fixture-user:not-a-password@db.example.invalid:5432/app",
      "mysql://fixture-user:not-a-password@db.example.invalid/app",
      "mariadb://fixture-user:not-a-password@db.example.invalid/app",
      "mongodb://fixture-user:not-a-password@db.example.invalid/app",
      "mongodb+srv://fixture-user:not-a-password@cluster.example.invalid/app",
      "redis://fixture-user:not-a-password@cache.example.invalid:6379/0",
      "rediss://fixture-user:not-a-password@cache.example.invalid:6380/0",
    ],
    negativeSamples: [
      "postgresql://db.example.invalid/app",
      "sqlite://fixture-user:not-a-password@db.example.invalid/app",
    ],
    note: "Common PostgreSQL, MySQL, MariaDB, MongoDB, and Redis URLs containing credentials. A trailing whitespace delimiter is consumed when present so an overlong URL cannot prefix-match.",
  }),
  {
    id: "custom",
    category: "Custom",
    label: "Custom (write your own)",
    regex: "",
    validation: "none",
    positiveSamples: [],
    negativeSamples: [],
    sample: "",
    negativeSample: "",
    note: "Type any Cloudflare DLP pattern using Rust regex syntax.",
  },
];

// Supplemental compatibility hints. The Rust compiler below remains authoritative.
export function compatibilityWarnings(src) {
  const w = [];
  if (/\(\?=|\(\?!/.test(src)) w.push("lookahead (?= / ?!) — incompatible with Rust regex syntax");
  if (/\(\?<=|\(\?<!/.test(src)) w.push("lookbehind (?<= / ?<!) — incompatible with Rust regex syntax");
  if (/\\(?:[1-9]|k<[^>]+>)/.test(src)) w.push("backreference (\\1 or \\k<name>) — incompatible with Rust regex syntax");
  if (/\(\?>/.test(src)) w.push("atomic group (?>) — incompatible with Rust regex syntax");
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

const DOCUMENTED_TEST_CARD_PREFIXES = ["424242", "400005", "555555", "378282"];
const demoRandomBytes = (length) => crypto.getRandomValues(new Uint8Array(length));
const randomDigits = (length, randomBytes) => Array.from(randomBytes(length), (byte) => String(byte % 10)).join("");

function luhnCheckDigit(partial) {
  for (let check = 0; check <= 9; check += 1) {
    if (luhnValid(`${partial}${check}`)) return String(check);
  }
  throw new Error("unable to calculate Luhn check digit");
}

function formatDemoCard(value, format) {
  const groups = value.match(/.{1,4}/g);
  if (format === "plain") return value;
  if (format === "spaces") return groups.join(" ");
  if (format === "dashes") return groups.join("-");
  if (format === "mixed") return groups.map((group, index) => index === 1 ? ` ${group}` : index > 1 ? `${index % 2 ? " " : "-"}${group}` : group).join("");
  throw new TypeError("card format must be plain, spaces, dashes, or mixed");
}

export function generateDemoData({ type, quantity = 10, format = "plain", randomBytes = demoRandomBytes } = {}) {
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
    throw new RangeError("quantity must be an integer from 1 through 100");
  }
  if (typeof randomBytes !== "function") throw new TypeError("randomBytes must be a function");
  if (type === "ssn") {
    return Array.from({ length: quantity }, () => `000-${randomDigits(2, randomBytes)}-${randomDigits(4, randomBytes)}`);
  }
  if (type !== "card") throw new TypeError("type must be card or ssn");
  return Array.from({ length: quantity }, (_, index) => {
    const prefix = DOCUMENTED_TEST_CARD_PREFIXES[index % DOCUMENTED_TEST_CARD_PREFIXES.length];
    const partial = `${prefix}${randomDigits(9, randomBytes)}`;
    return formatDemoCard(`${partial}${luhnCheckDigit(partial)}`, format);
  });
}

const X25519_PKCS8_PREFIX = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20]);
const X25519_SPKI_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);

function joinBytes(...arrays) {
  const joined = new Uint8Array(arrays.reduce((total, array) => total + array.length, 0));
  let offset = 0;
  for (const array of arrays) { joined.set(array, offset); offset += array.length; }
  return joined;
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function assertDerPrefix(bytes, prefix, label) {
  if (bytes.length !== prefix.length + 32 || !prefix.every((byte, index) => bytes[index] === byte)) {
    throw new Error(`unexpected X25519 ${label} encoding`);
  }
}

export async function deriveX25519PublicKey(privateBytes) {
  const bytes = new Uint8Array(privateBytes);
  if (bytes.byteLength !== 32) throw new TypeError("X25519 private key must be exactly 32 bytes");
  const privateKey = await crypto.subtle.importKey("pkcs8", joinBytes(X25519_PKCS8_PREFIX, bytes), { name: "X25519" }, true, ["deriveBits"]);
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  const publicKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "X25519", x: jwk.x, ext: true }, { name: "X25519" }, true, []);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
  assertDerPrefix(spki, X25519_SPKI_PREFIX, "SPKI");
  return spki.slice(X25519_SPKI_PREFIX.length);
}

export async function generatePayloadKeyPair() {
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  assertDerPrefix(pkcs8, X25519_PKCS8_PREFIX, "PKCS#8");
  assertDerPrefix(spki, X25519_SPKI_PREFIX, "SPKI");
  return {
    privateKey: bytesToBase64(pkcs8.slice(X25519_PKCS8_PREFIX.length)),
    publicKey: bytesToBase64(spki.slice(X25519_SPKI_PREFIX.length)),
  };
}

function withValidation(matches, validation) {
  if (validation !== "luhn") return matches;
  return matches.map((row) => {
    const digits = row.match.replace(/\D/g, "");
    return {
      ...row,
      digits: digits.length,
      valid: luhnValid(digits),
    };
  });
}

export function scan(text, regexSrc, flags = "g", validation = "none") {
  if (flags !== "g") return { error: "flags must be exactly g" };
  if (regexSrc === "") return { matches: [], truncated: false };
  const result = validateDlpRegex.scan(regexSrc, text, 500);
  return {
    ...result,
    matches: withValidation(result.matches, validation),
  };
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
function html(nonce) {
  const presetOptions = [...new Set(PRESETS.map(({ category }) => category))]
    .map((category) => `<optgroup label="${category}">${PRESETS
      .filter((preset) => preset.category === category)
      .map((preset) => `<option value="${preset.id}">${preset.label}</option>`)
      .join("")}</optgroup>`)
    .join("");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Regex Builder | DLP Demo Toolkit</title>
<style>
  :root { --bg:#0d1117; --panel:#161b22; --border:#30363d; --fg:#e6edf3;
          --muted:#8b949e; --accent:#f0883e; --ok:#3fb950; --warn:#d29922; --dim:#484f58; }
  * { box-sizing:border-box; }
  html { background:#050607; }
  body { margin:0; min-height:100vh; isolation:isolate;
         font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
         background:transparent; color:var(--fg); }
  body::before { content:""; position:fixed; inset:0; z-index:-2;
    background-image:url("https://itlinux.cc/assets/bg.webp?v=5");
    background-size:cover; background-position:center top; background-repeat:no-repeat;
    filter:saturate(.95) brightness(.72); }
  body::after { content:""; position:fixed; inset:0; z-index:-1;
    background:linear-gradient(180deg,rgba(4,5,7,.72),rgba(8,6,4,.9)),
               radial-gradient(circle at 78% 12%,rgba(240,136,62,.16),transparent 42%);
    pointer-events:none; }
  header, main, footer { position:relative; z-index:0; }
  header { padding:22px 28px; border-bottom:1px solid var(--border); background:rgba(5,6,7,.54); backdrop-filter:blur(4px); }
  header .nav { display:flex; align-items:center; gap:18px; margin-bottom:14px; font-size:13px; }
  header .nav a { color:var(--muted); text-decoration:none; }
  header .nav a:hover { color:var(--accent); }
  header .nav a.home { color:var(--fg); font-weight:600; }
  header .nav .sep { flex:1; }
  h1 { margin:0 0 4px; font-size:20px; color:var(--accent); }
  header p { margin:0; color:var(--muted); font-size:13px; max-width:820px; }
  .site-identity { margin-bottom:5px; color:var(--fg); font-size:12px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; }
  main { padding:24px 28px; }
  .toolkit-overview { margin-bottom:16px; padding:13px 16px; border:1px solid var(--border); border-radius:10px; background:rgba(22,27,34,.82); }
  .toolkit-overview h2 { margin:0 0 4px; font-size:13px; color:var(--fg); }
  .toolkit-overview p { margin:0; color:var(--muted); font-size:12px; }
  .toolkit-tabs { display:flex; gap:8px; overflow-x:auto; margin-bottom:18px; scrollbar-width:thin; }
  .toolkit-tabs button { flex:0 0 auto; background:#21262d; color:var(--muted); border:1px solid var(--border); border-radius:8px; padding:9px 14px; cursor:pointer; }
  .toolkit-tabs button[aria-selected="true"] { color:var(--fg); border-color:var(--accent); box-shadow:inset 0 -2px var(--accent); }
  .toolkit-panel[hidden] { display:none; }
  .regex-grid { display:grid; grid-template-columns:minmax(0,2fr) minmax(0,3fr); gap:20px; align-items:start; }
  .panel-grid { display:grid; grid-template-columns:minmax(0,2fr) minmax(0,3fr); gap:20px; align-items:start; }
  @media (max-width:920px){ .regex-grid,.panel-grid{ grid-template-columns:1fr; } main{ padding:18px; } }
  .card { background:rgba(22,27,34,.93); border:1px solid var(--border); border-radius:10px; padding:18px; backdrop-filter:blur(6px); }
  .card h2 { margin:0 0 12px; font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); }
  footer.bio { margin:0 28px 24px; padding:14px 18px; max-width:720px; border:1px solid var(--border);
    border-radius:10px; background:rgba(5,6,7,.84); backdrop-filter:blur(6px); color:var(--muted); font-size:12px; }
  footer.bio h2 { margin:0 0 4px; color:var(--accent); font-size:13px; }
  footer.bio p { margin:3px 0; }
  footer.bio a { color:var(--fg); text-decoration-color:var(--accent); text-underline-offset:2px; }
  footer.bio .attribution { margin-top:8px; color:var(--fg); }
  @media (max-width:920px){ footer.bio{ margin:0 18px 18px; } }
  label { display:block; font-size:12px; color:var(--muted); margin:12px 0 4px; }
  input[type=text], input[type=number], textarea, select {
    width:100%; background:var(--bg); color:var(--fg); border:1px solid var(--border);
    border-radius:8px; padding:10px 12px; font-family:ui-monospace,Menlo,monospace; font-size:13px; }
  textarea { min-height:130px; resize:vertical; }
  .row { display:flex; gap:12px; } .row > * { flex:1; min-width:0; }
  .actions { display:flex; flex-wrap:wrap; gap:8px; align-items:center; }
  .output-list { display:grid; gap:7px; margin-top:12px; }
  .output-row { display:flex; gap:8px; align-items:center; min-width:0; }
  .output-row code { flex:1; overflow-wrap:anywhere; word-break:break-word; }
  a { color:var(--fg); text-decoration-color:var(--accent); text-underline-offset:2px; }
  code.regex { display:block; background:var(--bg); border:1px solid var(--border); border-radius:8px;
    padding:12px; color:var(--accent); font-family:ui-monospace,monospace; font-size:13px;
    overflow-wrap:anywhere; word-break:break-word; margin-bottom:8px; }
  table { width:100%; min-width:0; table-layout:fixed; border-collapse:collapse; font-size:13px; }
  th,td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--border); font-family:ui-monospace,monospace;
    overflow-wrap:anywhere; word-break:break-word; }
  th:nth-child(2),td:nth-child(2),th:nth-child(3),td:nth-child(3) { width:68px; }
  th { color:var(--muted); font-weight:600; font-size:11px; text-transform:uppercase; }
  .pill { padding:1px 8px; border-radius:999px; font-size:11px; font-weight:600; }
  .pass { background:rgba(63,185,80,.15); color:var(--ok); }
  .fail { background:rgba(139,148,158,.15); color:var(--muted); }
  .empty { color:var(--dim); font-style:italic; }
  .warn { color:var(--warn); font-size:12px; margin:8px 0 0; }
  .status { font-size:12px; margin:8px 0 0; }
  .status.ok { color:var(--ok); }
  .status.bad { color:var(--warn); white-space:pre-wrap; }
  pre { background:var(--bg); border:1px solid var(--border); border-radius:8px; padding:12px;
        overflow:auto; font-size:12px; color:var(--fg); white-space:pre-wrap;
        overflow-wrap:anywhere; word-break:break-word; }
  .count { color:var(--muted); font-size:12px; margin:0 0 10px; }
  button.copy { background:#21262d; color:var(--fg); border:1px solid var(--border); border-radius:6px;
    padding:5px 11px; font-size:12px; cursor:pointer; margin-top:8px; }
  button.copy:hover { border-color:var(--accent); }
</style>
</head>
<body>
<header>
  <nav class="nav">
    <a class="home" href="https://itlinux.cc/">← itlinux.cc</a>
    <span class="sep"></span>
    <a href="https://whoami.itlinux.cc/">Who am I</a>
    <a href="https://aigw.itlinux.cc/">AI Gateway</a>
    <a href="https://demobot.itlinux.cc/">DemoBot</a>
  </nav>
  <div class="site-identity">DLP Demo Toolkit</div>
  <h1 id="toolkit-title">Regex Builder</h1>
  <p id="toolkit-intro">Author and test a Cloudflare DLP custom entry with the authoritative Rust regex engine, then copy the validated pattern into your DLP workflow.</p>
</header>
<main>
  <section class="toolkit-overview" aria-labelledby="toolkit-overview-title">
    <h2 id="toolkit-overview-title">What this toolkit does</h2>
    <p>Build and validate Rust-compatible DLP regexes, generate safe synthetic detector fixtures, and create browser-local X25519 payload logging keys.</p>
  </section>
  <nav class="toolkit-tabs" role="tablist" aria-label="DLP demo tools">
    <button id="tab-regex" role="tab" aria-controls="panel-regex" aria-selected="true" tabindex="0">Regex Builder</button>
    <button id="tab-synthetic" role="tab" aria-controls="panel-synthetic" aria-selected="false" tabindex="-1">Synthetic Demo Data</button>
    <button id="tab-keys" role="tab" aria-controls="panel-keys" aria-selected="false" tabindex="-1">Payload Logging Keys</button>
  </nav>
  <section id="panel-regex" class="toolkit-panel regex-grid" role="tabpanel" aria-labelledby="tab-regex">
  <section class="card">
    <h2>1 · Build your pattern</h2>
    <p class="count">Choose a preset or write your own pattern, test customer-safe sample text, review authoritative matches, and copy the result for Cloudflare DLP.</p>
    <label>Preset</label>
    <select id="preset">${presetOptions}</select>
    <p class="count" id="preset-note"></p>

    <label>Entry name (shown in DLP)</label>
    <input type="text" id="name" value="CC 13-19 digits, loose separators"/>

    <label>Regex (Rust regex syntax)</label>
    <input type="text" id="regex" spellcheck="false"/>
    <div id="validation-status" class="status"></div>
    <div id="compatibility-warn"></div>

    <label>Validation</label>
    <select id="validation">
      <option value="none">none (structural match only)</option>
      <option value="luhn">luhn (credit-card checksum)</option>
    </select>

    <label>Sample text to test against</label>
    <textarea id="in" spellcheck="false"></textarea>
  </section>

  <section class="card">
    <h2>2 · Authoritative Rust matches</h2>
    <p class="count" id="count"></p>
    <table>
      <thead><tr><th>Match</th><th>Len</th><th id="th-v">Valid</th></tr></thead>
      <tbody id="rows"></tbody>
    </table>
  </section>

  <section class="card">
    <h2>3 · Paste into DLP (dashboard)</h2>
    <code class="regex" id="rx"></code>
    <p class="count">Zero Trust → DLP → DLP profiles → Custom profile → add entry → Regex. Cloudflare documents Rust regex syntax. Set the entry's Validation to match the dropdown above.</p>
    <button class="copy" data-target="rx">Copy regex</button>
  </section>

  <section class="card">
    <h2>4 · Use the validated pattern</h2>
    <p class="count">Copy the Rust regex above into your Cloudflare DLP workflow. This local branch does not require Terraform.</p>
  </section>
  </section>

  <section id="panel-synthetic" class="toolkit-panel panel-grid" role="tabpanel" aria-labelledby="tab-synthetic" hidden>
    <section class="card">
      <h2>Generate safe synthetic data</h2>
      <p class="count">For demonstrations only. Card values are synthetic PAN-shaped detector fixtures using test BINs; SSNs use the non-issued 000 area. Generate a batch, then use Test in Regex Builder to verify the detector workflow without real customer data.</p>
      <div class="row">
        <div><label for="demo-type">Data type</label><select id="demo-type"><option value="card">Credit cards</option><option value="ssn">SSNs</option></select></div>
        <div><label for="demo-quantity">Quantity</label><input id="demo-quantity" type="number" min="1" max="100" step="1" value="10"/></div>
        <div><label for="demo-format">Card formatting</label><select id="demo-format"><option value="plain">Plain</option><option value="spaces">Spaces</option><option value="dashes">Dashes</option><option value="mixed">Mixed separators</option></select></div>
      </div>
      <button class="copy" id="generate-demo">Generate synthetic data</button>
    </section>
    <section class="card">
      <h2>Synthetic, non-production output</h2>
      <p class="count" id="demo-status" aria-live="polite">Nothing generated yet.</p>
      <div class="actions"><button class="copy" id="copy-all-demo" disabled>Copy all</button><button class="copy" id="test-demo" disabled>Test in Regex Builder</button></div>
      <div id="demo-output" class="output-list"></div>
    </section>
  </section>

  <section id="panel-keys" class="toolkit-panel panel-grid" role="tabpanel" aria-labelledby="tab-keys" hidden>
    <section class="card">
      <h2>Browser-local X25519 keys</h2>
      <p>Generate a Cloudflare-compatible X25519 key pair entirely in this browser. Copy the public key into Cloudflare payload logging; the private key downloads automatically and is retained only in page memory for re-download. Store it securely because Cloudflare cannot recover it.</p>
      <div class="actions"><button class="copy" id="generate-key">Generate key pair</button><button class="copy" id="download-key-again" disabled>Download again</button></div>
      <p class="status" id="key-status" role="status" aria-live="assertive"></p>
    </section>
    <section class="card">
      <h2>Public key</h2>
      <code class="regex" id="public-key">Generate a pair to show the public key.</code>
      <button class="copy" data-target="public-key">Copy public key</button>
      <p class="count">Official fallback: <code>./matched-data-cli generate-key-pair</code></p>
      <p class="count"><a href="https://developers.cloudflare.com/waf/managed-rules/payload-logging/command-line/generate-key-pair/" target="_blank" rel="noopener">Cloudflare key-generation documentation</a></p>
      <p class="count">Private key downloaded. Cloudflare cannot recover it; store it securely.</p>
    </section>
  </section>
</main>
<footer class="bio">
  <h2>Who am I</h2>
  <p>I'm Remo Mattei. I build practical Cloudflare One, Zero Trust, Workers, and Linux demos at <a href="https://itlinux.cc/">itlinux.cc</a>.</p>
  <p>See the <a href="https://whoami.itlinux.cc/">Who Am I demo</a>.</p>
  <p class="attribution">Built by <a href="https://itlinux.cc/">Remo Mattei</a> · Powered by <a href="https://www.cloudflare.com/zero-trust/products/">Cloudflare One</a></p>
</footer>

<script nonce="${nonce}">
const PRESETS = ${JSON.stringify(PRESETS)};
const TEST_CARD_PREFIXES = ${JSON.stringify(DOCUMENTED_TEST_CARD_PREFIXES)};
const SSN_REGEX = ['\\\\b000-','\\\\d{2}-','\\\\d{4}\\\\b'].join('');
const presetEl = document.getElementById('preset');

function applyPreset(id){
  const p = PRESETS.find(x=>x.id===id) || PRESETS[0];
  document.getElementById('regex').value = p.regex;
  document.getElementById('validation').value = p.validation;
  document.getElementById('in').value = p.sample;
  document.getElementById('preset-note').textContent = p.note;
  if (p.id !== 'custom') document.getElementById('name').value = p.label.replace(/ ★$/,'');
  run();
}
presetEl.onchange = () => applyPreset(presetEl.value);
['regex','validation','in','name'].forEach(id => document.getElementById(id).addEventListener('input', run));

let scanGeneration = 0;
let scanController;
async function run(){
  const scanSerial = ++scanGeneration;
  scanController?.abort();
  scanController = new AbortController();
  const body = {
    text: document.getElementById('in').value,
    regex: document.getElementById('regex').value,
    flags: 'g',
    validation: document.getElementById('validation').value,
    name: document.getElementById('name').value,
  };
  document.getElementById('th-v').style.display = body.validation==='none' ? 'none' : '';
  let r;
  try {
    r = await fetch('/scan', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body), signal:scanController.signal});
  } catch (error) {
    if (scanSerial !== scanGeneration || error.name === 'AbortError') return;
    throw error;
  }
  const d = await r.json();
  if (scanSerial !== scanGeneration) return;
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
  const validationEl = document.getElementById('validation-status');
  const rv = d.regexValidation;
  if (rv && rv.valid) {
    validationEl.className = 'status ok';
    validationEl.textContent = '✓ Valid Rust regex and Cloudflare DLP constraints ('+rv.byteLength+'/1,024 UTF-8 bytes)';
  } else if (rv) {
    const details = [rv.rust.diagnostic, ...(rv.cloudflare.diagnostics || [])].filter(Boolean);
    validationEl.className = 'status bad';
    validationEl.textContent = 'Invalid for Cloudflare DLP:\\n'+details.join('\\n');
  }
  const warnEl = document.getElementById('compatibility-warn');
  warnEl.innerHTML = (d.compatibilityWarnings && d.compatibilityWarnings.length)
    ? '<p class="warn">⚠ '+d.compatibilityWarnings.map(escapeHtml).join('<br>⚠ ')+'</p>' : '';
}
function escapeHtml(s){ return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

const tabs = [...document.querySelectorAll('[role="tab"]')];
const TOOL_CONTENT = {
  'tab-regex': {
    title: 'Regex Builder | DLP Demo Toolkit',
    heading: 'Regex Builder',
    intro: 'Author and test a Cloudflare DLP custom entry with the authoritative Rust regex engine, then copy the validated pattern into your DLP workflow.',
  },
  'tab-synthetic': {
    title: 'Synthetic Demo Data | DLP Demo Toolkit',
    heading: 'Synthetic Demo Data',
    intro: 'Generate safe, synthetic values for DLP demonstrations, copy them as fixtures, or send them directly to Test in Regex Builder.',
  },
  'tab-keys': {
    title: 'Payload Logging Keys | DLP Demo Toolkit',
    heading: 'Payload Logging Keys',
    intro: 'Generate X25519 keys for Cloudflare payload logging locally in your browser: copy the public key to Cloudflare and securely retain the automatically downloaded private key.',
  },
};
function selectTool(tab){
  tabs.forEach(candidate=>{
    const selected = candidate === tab;
    candidate.setAttribute('aria-selected', String(selected));
    candidate.tabIndex = selected ? 0 : -1;
    document.getElementById(candidate.getAttribute('aria-controls')).hidden = !selected;
  });
  const tool=TOOL_CONTENT[tab.id];
  document.title=tool.title;
  document.getElementById('toolkit-title').textContent=tool.heading;
  document.getElementById('toolkit-intro').textContent=tool.intro;
}
tabs.forEach((tab,index)=>{
  tab.onclick=()=>selectTool(tab);
  tab.onkeydown=event=>{
    if (!['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) return;
    event.preventDefault();
    const next = event.key==='Home' ? 0 : event.key==='End' ? tabs.length-1 : (index+(event.key==='ArrowRight'?1:-1)+tabs.length)%tabs.length;
    selectTool(tabs[next]); tabs[next].focus();
  };
});

function browserRandomDigits(length){
  return Array.from(crypto.getRandomValues(new Uint8Array(length)),byte=>String(byte%10)).join('');
}
function browserLuhnValid(value){
  let sum=0, alt=false;
  for(let index=value.length-1;index>=0;index--){ let digit=Number(value[index]); if(alt){digit*=2;if(digit>9)digit-=9;} sum+=digit;alt=!alt; }
  return sum%10===0;
}
function browserCheckDigit(partial){ for(let check=0;check<10;check++) if(browserLuhnValid(partial+check)) return String(check); }
function browserFormatCard(value,format){
  const groups=value.match(/.{1,4}/g);
  if(format==='plain')return value;
  if(format==='spaces')return groups.join(' ');
  if(format==='dashes')return groups.join('-');
  return groups.map((group,index)=>index===0?group:(index%2?' ':'-')+group).join('');
}
function browserGenerateDemoData(type,quantity,format){
  return Array.from({length:quantity},(_,index)=>{
    if(type==='ssn')return '000-'+browserRandomDigits(2)+'-'+browserRandomDigits(4);
    const partial=TEST_CARD_PREFIXES[index%TEST_CARD_PREFIXES.length]+browserRandomDigits(9);
    return browserFormatCard(partial+browserCheckDigit(partial),format);
  });
}
let generatedDemo=[];
function renderDemo(values,type){
  generatedDemo=values;
  const output=document.getElementById('demo-output'); output.replaceChildren();
  values.forEach(value=>{
    const row=document.createElement('div'); row.className='output-row';
    const code=document.createElement('code'); code.textContent=value;
    const button=document.createElement('button'); button.className='copy'; button.textContent='Copy one'; button.onclick=()=>navigator.clipboard.writeText(value);
    row.append(code,button); output.appendChild(row);
  });
  document.getElementById('demo-status').textContent=values.length+' synthetic '+(type==='ssn'?'non-issued SSN':'test card')+' value(s).';
  document.getElementById('copy-all-demo').disabled=false;
  document.getElementById('test-demo').disabled=false;
}
document.getElementById('demo-type').onchange=event=>document.getElementById('demo-format').disabled=event.target.value==='ssn';
document.getElementById('generate-demo').onclick=()=>{
  const type=document.getElementById('demo-type').value;
  const quantity=Number(document.getElementById('demo-quantity').value);
  if(!Number.isInteger(quantity)||quantity<1||quantity>100){document.getElementById('demo-status').textContent='Quantity must be an integer from 1 through 100.';return;}
  const values=browserGenerateDemoData(type,quantity,document.getElementById('demo-format').value);
  renderDemo(values,type);
};
document.getElementById('copy-all-demo').onclick=()=>navigator.clipboard.writeText(generatedDemo.join('\\n'));
document.getElementById('test-demo').onclick=()=>{
  if(document.getElementById('demo-type').value==='card')applyPreset('cc-loose');
  else {
    presetEl.value='custom';
    document.getElementById('regex').value=SSN_REGEX;
    document.getElementById('validation').value='none';
    document.getElementById('name').value='Synthetic non-issued SSN fixture';
  }
  document.getElementById('in').value=generatedDemo.join('\\n');
  run(); selectTool(document.getElementById('tab-regex'));
};

const PKCS8_PREFIX=[48,46,2,1,0,48,5,6,3,43,101,110,4,34,4,32], SPKI_PREFIX=[48,42,48,5,6,3,43,101,110,3,33,0];
function assertDerPrefix(bytes,prefix,label){
  if(bytes.length!==prefix.length+32||!prefix.every((byte,index)=>bytes[index]===byte))throw new Error('Unexpected X25519 '+label+' encoding.');
}
function encodeBase64(bytes){let binary='';for(const byte of bytes)binary+=String.fromCharCode(byte);return btoa(binary);}
let inMemoryPrivateKey;
let inMemoryFilename;
function keyFilename(){
  const date=new Date(); const pad=value=>String(value).padStart(2,'0');
  return 'cloudflare-payload-logging-private-key-'+date.getFullYear()+pad(date.getMonth()+1)+pad(date.getDate())+'-'+pad(date.getHours())+pad(date.getMinutes())+pad(date.getSeconds())+'.txt';
}
function downloadPrivateKey(){
  if(!inMemoryPrivateKey)return;
  const url=URL.createObjectURL(new Blob([inMemoryPrivateKey+'\\n'],{type:'text/plain;charset=utf-8'}));
  const anchor=document.createElement('a'); anchor.href=url; anchor.download=inMemoryFilename; anchor.click();
  setTimeout(()=>URL.revokeObjectURL(url),0);
}
document.getElementById('generate-key').onclick=async()=>{
  inMemoryPrivateKey=undefined; inMemoryFilename=undefined;
  const generateButton=document.getElementById('generate-key'), downloadButton=document.getElementById('download-key-again');
  const publicKey=document.getElementById('public-key'), status=document.getElementById('key-status');
  publicKey.textContent='Generate a pair to show the public key.'; status.textContent='Generating key pair…'; status.className='status';
  generateButton.disabled=true; downloadButton.disabled=true;
  try {
    const pair=await crypto.subtle.generateKey({name:'X25519'},true,['deriveBits']);
    const pkcs8=new Uint8Array(await crypto.subtle.exportKey('pkcs8',pair.privateKey));
    const spki=new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey));
    assertDerPrefix(pkcs8,PKCS8_PREFIX,'PKCS#8'); assertDerPrefix(spki,SPKI_PREFIX,'SPKI');
    inMemoryPrivateKey=encodeBase64(pkcs8.slice(PKCS8_PREFIX.length)); inMemoryFilename=keyFilename();
    publicKey.textContent=encodeBase64(spki.slice(SPKI_PREFIX.length));
    status.textContent='Private key downloaded. Cloudflare cannot recover it; store it securely.'; status.className='status ok';
    downloadButton.disabled=false; downloadPrivateKey();
  } catch(error) {
    inMemoryPrivateKey=undefined; inMemoryFilename=undefined;
    status.textContent='Unable to generate key pair in this browser. No private key was retained.'; status.className='status bad';
  } finally { generateButton.disabled=false; }
};
document.getElementById('download-key-again').onclick=downloadPrivateKey;
addEventListener('unload',()=>{inMemoryPrivateKey=undefined;inMemoryFilename=undefined;});

document.querySelectorAll('button.copy[data-target]').forEach(b=>{
  b.onclick=()=>{ const t=document.getElementById(b.dataset.target).textContent;
    const originalText=b.textContent;
    navigator.clipboard.writeText(t); b.textContent='Copied ✓'; setTimeout(()=>b.textContent=originalText,1200); };
});

applyPreset('cc-loose');
</script>
</body>
</html>`;
}

const MAX_REQUEST_BYTES = 128 * 1024;
const MAX_REGEX_BYTES = 1024;
const MAX_TEXT_BYTES = 64 * 1024;
const MAX_NAME_BYTES = 256;
const utf8Bytes = (value) => new TextEncoder().encode(value).byteLength;

async function readBoundedBody(body, maxBytes) {
  if (body === null) return { text: "" };
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        await reader.cancel("request body supplied a malformed chunk");
        return { error: "malformed request body" };
      }
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel("request body exceeds byte limit");
        return { tooLarge: true };
      }
      chunks.push(value);
    }
  } catch {
    return { error: "malformed request body" };
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return { text: new TextDecoder("utf-8", { fatal: true }).decode(bytes) };
  } catch {
    return { error: "request body is not valid UTF-8" };
  }
}

function inputError(input) {
  for (const field of ["regex", "text", "name", "flags", "validation"]) {
    if (input[field] !== undefined && typeof input[field] !== "string") {
      return { status: 400, error: `${field} must be a string` };
    }
  }
  const regex = input.regex ?? "";
  const text = input.text ?? "";
  const name = input.name ?? "";
  const flags = input.flags ?? "g";
  const validation = input.validation ?? "none";
  if (utf8Bytes(regex) > MAX_REGEX_BYTES) return { status: 413, error: "regex exceeds 1,024 UTF-8 bytes" };
  if (utf8Bytes(text) > MAX_TEXT_BYTES) return { status: 413, error: "text exceeds 65,536 UTF-8 bytes" };
  if (utf8Bytes(name) > MAX_NAME_BYTES) return { status: 400, error: "name exceeds 256 UTF-8 bytes" };
  if (flags !== "g") return { status: 400, error: "flags must be exactly g" };
  if (!new Set(["none", "luhn"]).has(validation)) return { status: 400, error: "validation must be none or luhn" };
  return null;
}

function scanResponse(validateDlpRegex, input) {
  const invalid = inputError(input);
  if (invalid) return { status: invalid.status, body: { error: invalid.error } };
  const regex = input.regex ?? "";
  const regexValidation = validateDlpRegex(regex);
  const warnings = compatibilityWarnings(regex);
  if (!regexValidation.valid) {
    const diagnostics = [
      regexValidation.rust.diagnostic,
      ...regexValidation.cloudflare.diagnostics,
    ].filter(Boolean);
    return {
      status: 400,
      body: {
        error: diagnostics.join("\n"),
        regexValidation,
        compatibilityWarnings: warnings,
      },
    };
  }

  const result = regex === ""
    ? { matches: [], truncated: false }
    : validateDlpRegex.scan(regex, input.text || "", 500);
  return {
    status: 200,
    body: {
      matches: withValidation(result.matches, input.validation ?? "none"),
      truncated: result.truncated,
      engine: "Rust regex 1.13.1 (authoritative)",
      regexValidation,
      compatibilityWarnings: warnings,
      tf: tfEntry(input.name, regex, input.validation ?? "none"),
    },
  };
}

export function createWorker(regexValidator = validateDlpRegex) {
  return {
    async fetch(request) {
      const url = new URL(request.url);

      const allowed = new Map([["/", "GET"], ["/health", "GET"], ["/api", "GET"], ["/scan", "POST"]]);
      if (!allowed.has(url.pathname)) {
        return Response.json({ error: "not found" }, { status: 404 });
      }
      if (request.method !== allowed.get(url.pathname)) {
        return Response.json({ error: "method not allowed" }, {
          status: 405,
          headers: { Allow: allowed.get(url.pathname) },
        });
      }

      if (url.pathname === "/scan") {
        const contentType = request.headers.get("content-type") || "";
        if (!contentType.toLowerCase().startsWith("application/json")) {
          return Response.json({ error: "content-type must be application/json" }, { status: 415 });
        }
        const declaredLength = request.headers.get("content-length");
        if (declaredLength !== null && (!/^\d+$/.test(declaredLength) || Number(declaredLength) > MAX_REQUEST_BYTES)) {
          return Response.json({ error: "request body exceeds 131,072 bytes" }, { status: 413 });
        }
        const bodyRead = await readBoundedBody(request.body, MAX_REQUEST_BYTES);
        if (bodyRead.tooLarge) {
          return Response.json({ error: "request body exceeds 131,072 bytes" }, { status: 413 });
        }
        if (bodyRead.error) {
          return Response.json({ error: bodyRead.error }, { status: 400 });
        }
        let input;
        try { input = JSON.parse(bodyRead.text); } catch {
          return Response.json({ error: "malformed JSON object" }, { status: 400 });
        }
        if (input === null || Array.isArray(input) || typeof input !== "object") {
          return Response.json({ error: "JSON body must be an object" }, { status: 400 });
        }
        const result = scanResponse(regexValidator, input);
        return Response.json(result.body, { status: result.status });
      }

      // curl-friendly: GET /api?regex=...&text=...&validation=luhn
      if (url.pathname === "/api") {
        const input = {
          regex: url.searchParams.get("regex") || "",
          text: url.searchParams.get("text") || "",
          validation: url.searchParams.get("validation") || "none",
          flags: url.searchParams.get("flags") || "g",
        };
        const result = scanResponse(regexValidator, input);
        return Response.json(result.body, { status: result.status });
      }

      if (url.pathname === "/health") return new Response("ok");

      const nonce = bytesToBase64(crypto.getRandomValues(new Uint8Array(18)));
      return new Response(html(nonce), { headers: {
        "content-type": "text/html; charset=utf-8",
        "content-security-policy": `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'unsafe-inline'; img-src https://itlinux.cc; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
        "referrer-policy": "no-referrer", "x-content-type-options": "nosniff",
      } });
    },
  };
}

export default createWorker();
