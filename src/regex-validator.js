const encoder = new TextEncoder();
const decoder = new TextDecoder();

function rustDiagnostic(exports) {
  const errorPointer = exports.error_ptr();
  const errorLength = exports.error_len();
  return decoder.decode(
    new Uint8Array(exports.memory.buffer, errorPointer, errorLength),
  );
}

function rustValidate(exports, pattern) {
  const bytes = encoder.encode(pattern);
  const pointer = exports.alloc(bytes.length);
  try {
    new Uint8Array(exports.memory.buffer, pointer, bytes.length).set(bytes);
    const valid = exports.validate(pointer, bytes.length) === 1;
    if (valid) return { valid: true, diagnostic: null };
    return { valid: false, diagnostic: rustDiagnostic(exports) };
  } finally {
    exports.dealloc(pointer, bytes.length);
  }
}

function rustScan(exports, pattern, text, maxMatches) {
  const patternBytes = encoder.encode(pattern);
  const textBytes = encoder.encode(text);
  const patternPointer = exports.alloc(patternBytes.length);
  const textPointer = exports.alloc(textBytes.length);
  try {
    new Uint8Array(exports.memory.buffer, patternPointer, patternBytes.length).set(patternBytes);
    new Uint8Array(exports.memory.buffer, textPointer, textBytes.length).set(textBytes);
    const ok = exports.scan(
      patternPointer,
      patternBytes.length,
      textPointer,
      textBytes.length,
      Math.min(Math.max(maxMatches, 0), 500),
    ) === 1;
    if (!ok) throw new Error(rustDiagnostic(exports));

    const offsetCount = exports.matches_len();
    const offsets = new Uint32Array(
      exports.memory.buffer,
      exports.matches_ptr(),
      offsetCount,
    );
    const matches = [];
    for (let i = 0; i < offsetCount; i += 2) {
      const byteStart = offsets[i];
      const byteEnd = offsets[i + 1];
      const match = decoder.decode(textBytes.subarray(byteStart, byteEnd));
      const index = decoder.decode(textBytes.subarray(0, byteStart)).length;
      matches.push({
        match,
        index,
        length: match.length,
        byteStart,
        byteEnd,
      });
    }
    return { matches, truncated: exports.scan_truncated() === 1 };
  } finally {
    exports.dealloc(patternPointer, patternBytes.length);
    exports.dealloc(textPointer, textBytes.length);
  }
}

export async function instantiateRegexValidator(moduleOrBytes) {
  const instantiated = await WebAssembly.instantiate(moduleOrBytes, {});
  return instantiated instanceof WebAssembly.Instance
    ? instantiated.exports
    : instantiated.instance.exports;
}

function hasUnboundedPlusOrStar(pattern) {
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
    if (character === "[" && !inCharacterClass) {
      inCharacterClass = true;
      continue;
    }
    if (character === "]" && inCharacterClass) {
      inCharacterClass = false;
      continue;
    }
    if (!inCharacterClass && (character === "+" || character === "*")) return true;
  }
  return false;
}

export function createDlpRegexValidator(wasmExports) {
  const validateDlpRegex = function validateDlpRegex(source) {
    const pattern = String(source);
    const byteLength = encoder.encode(pattern).length;
    const rust = rustValidate(wasmExports, pattern);
    const diagnostics = [];

    if (byteLength > 1024) {
      diagnostics.push(
        `Pattern is ${byteLength} UTF-8 bytes; Cloudflare DLP allows at most 1,024 UTF-8 bytes.`,
      );
    }
    if (hasUnboundedPlusOrStar(pattern)) {
      diagnostics.push(
        "Cloudflare DLP does not allow unbounded + or * quantifiers; use an explicit bounded quantifier such as {1,100}.",
      );
    }

    const cloudflare = { valid: diagnostics.length === 0, diagnostics };
    return {
      valid: rust.valid && cloudflare.valid,
      byteLength,
      rust,
      cloudflare,
    };
  };
  validateDlpRegex.scan = (pattern, text, maxMatches = 500) =>
    rustScan(wasmExports, String(pattern), String(text), maxMatches);
  return validateDlpRegex;
}
