/**
 * Credential facts: every detection path (provider regex, generic pattern,
 * hardcoded-literal heuristic, dotenv variable, base64 wrapper) first establishes
 * a fact describing WHERE the secret came from and the exact boundary of its key
 * material. Allowlisting then operates on that boundary: a stopword or sample
 * entry only exempts the credential when it covers the whole sensitive value,
 * so a short substring can no longer dismiss an entire real secret.
 */

export type CredentialSource =
  | 'provider-pattern'
  | 'generic-pattern'
  | 'hardcoded-literal'
  | 'env-var'
  | 'base64-wrapper';

export interface CredentialSpan {
  /** Inclusive start offset of the whole secret in the scanned file. */
  start: number;
  /** Exclusive end offset of the whole secret in the scanned file. */
  end: number;
}

export interface CredentialFact {
  /** Detection path that established the fact. */
  source: CredentialSource;
  /** Pattern or rule name that matched. */
  name: string;
  /** Full sensitive value, decoded first when the fact is a base64 wrapper. */
  value: string;
  /** The key-material portion of `value` (provider prefixes/schemes stripped). */
  material: string;
  /** File range of the whole secret; an exception has to cover it entirely. */
  span: CredentialSpan;
  /** Whether `value` was reconstructed from a base64 wrapper. */
  base64Wrapped?: boolean;
}

// ---------------------------------------------------------------------------
// Boundary-aware allowlist
// ---------------------------------------------------------------------------

/**
 * Stopwords marking placeholder/sample material. The same vocabulary as the
 * legacy substring filter, but here the matched ranges are used to compute how
 * much of the key material they actually cover.
 */
const STOPWORD =
  /example|sample|dummy|placeholder|your[_\-]?|yourkey|changeme|change[_\-]?me|replace[_\-]?me|redacted|xxxx|\.\.\.|<[^<>]*>|\$\{|\{\{|process\.env/gi;

/**
 * Exact, publicly published sample/decoy credentials. A credential only matches
 * when the ENTIRE value is one of these entries; substrings never qualify.
 */
const KNOWN_SAMPLE_CREDENTIALS = new Set<string>([
  // AWS documentation account (access key id + secret access key)
  'AKIAIOSFODNN7EXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
]);

/** Prose words a placeholder value is made of once stopwords were peeled off. */
const TEMPLATE_WORDS = new Set([
  'your', 'you', 'api', 'key', 'keys', 'secret', 'secrets', 'token', 'password',
  'credential', 'credentials', 'here', 'please', 'goes', 'enter', 'insert', 'paste',
  'copy', 'fill', 'need', 'needed', 'value', 'actual', 'real', 'me', 'change',
  'replace', 'dummy', 'sample', 'example', 'placeholder', 'redacted', 'to', 'the',
  'of', 'a', 'is', 'and', 'or', 'for', 'with', 'this', 'that', 'it', 'be', 'use',
  'used', 'using', 'get', 'app', 'client', 'auth', 'access', 'private', 'public',
  'account', 'id', 'name', 'type', 'mode', 'url', 'host',
]);

/** Separators that carry no key material when evaluating coverage. */
const SEPARATOR = /[_\-.\s:+/=]/;

/** Longest run of alphanumerics that each follow the previous one (1234, abcd, DCBA). */
function sequentialRuns(value: string): boolean[] {
  const inRun = new Array(value.length).fill(false);
  let runStart = 0;
  let dir = 0;
  const flush = (end: number): void => {
    if (end - runStart >= 4) {
      for (let j = runStart; j < end; j++) inRun[j] = true;
    }
  };
  for (let i = 1; i < value.length; i++) {
    const diff = value.charCodeAt(i) - value.charCodeAt(i - 1);
    const alnum = /[0-9a-zA-Z]/.test(value[i]) && /[0-9a-zA-Z]/.test(value[i - 1]);
    const continues = alnum && (diff === 1 || diff === -1) && (dir === 0 || dir === diff);
    if (continues) {
      if (dir === 0) {
        runStart = i - 1;
        dir = diff;
      }
    } else {
      flush(i);
      runStart = i;
      dir = 0;
    }
  }
  flush(value.length);
  return inRun;
}

/**
 * True when an alphanumeric remainder is pure placeholder prose: dictionary
 * words end-to-end (word-break), plus at most short digit chunks. Random key
 * material fails the break, so "your_api_key_goes_here" passes but
 * "changeme_9fA2xLq..." does not.
 */
function isTemplateProse(text: string): boolean {
  const lower = text.toLowerCase();
  let i = 0;
  while (i < lower.length) {
    if (/[0-9]/.test(lower[i])) {
      let j = i;
      while (j < lower.length && /[0-9]/.test(lower[j])) j++;
      if (j - i > 4) return false;
      i = j;
      continue;
    }
    let matched = -1;
    for (let j = lower.length; j > i; j--) {
      if (TEMPLATE_WORDS.has(lower.slice(i, j))) {
        matched = j;
        break;
      }
    }
    if (matched === -1) return false;
    i = matched;
  }
  return true;
}

/**
 * Decide whether a credential fact is an allowed (non-secret) value.
 *
 * Exemptions require full coverage of the key material:
 *  1. the whole value is a published sample/decoy credential, or
 *  2. stopword ranges plus template prose cover the whole material, or
 *  3. the material is one repeated character / one sequential run, or
 *  4. the material is empty after the structural prefix was stripped.
 * A stopword appearing anywhere inside otherwise random material is NOT enough.
 */
export function isAllowedCredential(fact: CredentialFact): boolean {
  const value = fact.value;
  if (!value) return true;
  if (KNOWN_SAMPLE_CREDENTIALS.has(value)) return true;

  const material = fact.material || value;
  if (material.length === 0) return true;

  const covered = new Array(material.length).fill(false);
  STOPWORD.lastIndex = 0;
  for (const match of material.matchAll(STOPWORD)) {
    if (match.index === undefined) continue;
    for (let i = match.index; i < match.index + match[0].length; i++) covered[i] = true;
  }

  const leftover = material
    .split('')
    .filter((ch, index) => !covered[index] && !SEPARATOR.test(ch))
    .join('');
  if (leftover === '' || isTemplateProse(leftover)) return true;

  const compact = material.split('').filter(ch => !SEPARATOR.test(ch)).join('');
  if (compact.length >= 8 && new Set(compact).size === 1) return true;

  const inRun = sequentialRuns(material);
  const remainder = material
    .split('')
    .filter((ch, index) => !inRun[index] && !SEPARATOR.test(ch))
    .join('');
  // A long sequential run (abcdefgh..., 12345678...) across the whole material
  // is a generated test value, never a real credential.
  const coveredByRun = material.split('').filter((_, index) => inRun[index]).length;
  return (remainder === '' && coveredByRun >= 8) || (remainder !== '' && isTemplateProse(remainder));
}

// ---------------------------------------------------------------------------
// Base64 wrapper decoding
// ---------------------------------------------------------------------------

export interface DecodedBase64 {
  /** Original token as written in the file. */
  encoded: string;
  /** Printable UTF-8 text reconstructed from the wrapper. */
  decoded: string;
}

/**
 * Decode a candidate base64 (standard or URL-safe) token. Returns null unless
 * the token round-trips exactly and decodes to printable ASCII text, so random
 * blobs, binary payloads (images, source maps) and ordinary prose stay quiet.
 */
export function decodeBase64Token(encoded: string): DecodedBase64 | null {
  if (encoded.length < 20) return null;
  const normalized = encoded.replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized)) return null;

  let decoded: Buffer;
  try {
    decoded = Buffer.from(normalized, 'base64');
  } catch {
    return null;
  }
  if (decoded.length < 8) return null;
  if (decoded.toString('base64') !== normalized && decoded.toString('base64url') !== encoded) {
    return null;
  }

  const text = decoded.toString('utf8');
  if (!/^[\t\n\r -~]*$/.test(text)) return null;
  return { encoded, decoded: text };
}

/** A standalone base64-ish string token, anchored so adjacent words cannot match. */
export const BASE64_TOKEN = /(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{20,}={0,2})(?![A-Za-z0-9+/=_-])/g;
