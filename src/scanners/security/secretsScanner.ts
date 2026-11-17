import type { Rule, RuleContext, RuleGroup } from '../../types/ruleTypes.js';
import { Severity, type Confidence, type Finding } from '../../types/findings.js';
import { getLineNumber, extractSnippet } from '../../utils/stringUtils.js';
import { RuleCategory } from '../../types/ruleTypes.js';
import {
  API_SECRET_PATTERNS,
  isPlaceholderValue,
  looksRandom,
  shannonEntropy,
  tokenizeIdentifier,
} from '../../utils/sensitiveDataPatterns.js';
import {
  BASE64_TOKEN,
  decodeBase64Token,
  isAllowedCredential,
  type CredentialFact,
  type CredentialSource,
} from '../../utils/credentialFacts.js';

interface Candidate {
  start: number;
  end: number;
  generic: boolean;
  name: string;
  value: string;
  matchedText: string;
  severity: Severity;
  confidence?: Confidence;
  description: string;
  suggestion: string;
}

interface EnvVar {
  name: string;
  value: string;
  line: number;
}

/** The line holding `index` plus the line before it (keyword prefilter window for loose patterns). */
function lineWindow(content: string, index: number): string {
  const lineStart = content.lastIndexOf('\n', index - 1) + 1;
  const prevStart = lineStart > 0 ? content.lastIndexOf('\n', lineStart - 2) + 1 : 0;
  const lineEnd = content.indexOf('\n', index);
  return content.substring(prevStart, lineEnd === -1 ? content.length : lineEnd);
}

function maskSecret(text: string): string {
  return text.length > 20 ? text.substring(0, 20) + '...[REDACTED]' : text.substring(0, 8) + '...[REDACTED]';
}

/** `NAME=value` lines of a dotenv file. Comment lines are not variables. */
function parseEnvVars(content: string): EnvVar[] {
  const vars: EnvVar[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$/);
    if (!m) continue;
    const name = m[1];
    let rest = m[2].trim();
    const quote = rest[0];

    if (quote === '"' || quote === "'") {
      // A quoted value may span several physical lines (e.g. a PEM block in an
      // .env file). Keep every line until the closing quote instead of only
      // retaining the first line.
      const closeOnSameLine = rest.indexOf(quote, 1);
      if (closeOnSameLine !== -1) {
        vars.push({ name, value: rest.slice(1, closeOnSameLine), line: i + 1 });
        continue;
      }
      const startLine = i + 1;
      const chunks = [rest.slice(1)];
      let closed = false;
      while (i + 1 < lines.length) {
        i++;
        const part = lines[i];
        const close = part.indexOf(quote);
        if (close === -1) {
          chunks.push(part);
        } else {
          chunks.push(part.slice(0, close));
          closed = true;
          break;
        }
      }
      if (closed) vars.push({ name, value: chunks.join('\n'), line: startLine });
      // Unterminated quote: dotenv ignores the value, and so do we
      continue;
    }

    rest = rest.replace(/\s+#.*$/, '').trim();
    vars.push({ name, value: rest, line: i + 1 });
  }
  return vars;
}

const SECRET_NAME_TOKENS = new Set([
  'key', 'secret', 'token', 'password', 'passwd', 'pwd', 'credential', 'credentials',
  'apikey', 'privatekey', 'secretkey', 'accesskey', 'authkey',
]);
const NON_SECRET_NAME_TOKENS = new Set([
  'enabled', 'disabled', 'url', 'uri', 'path', 'file', 'name', 'id', 'type', 'expiry', 'expires',
  'timeout', 'length', 'version', 'mode', 'publishable',
]);
const NON_VALUES = new Set(['true', 'false', 'null', 'undefined', 'none', 'empty', 'todo', 'tbd']);

function isSecretEnvVar({ name, value }: EnvVar): boolean {
  if (value.length < 6 || NON_VALUES.has(value.toLowerCase()) || /^\$/.test(value) || isPlaceholderValue(value)) {
    return false;
  }
  // Credentials embedded in a URL, e.g. DATABASE_URL=postgres://user:pass@host/db
  const urlCreds = value.match(/^[a-z][a-z0-9+.\-]*:\/\/[^/\s:@]+:([^/\s@]+)@/i);
  if (urlCreds) {
    const password = urlCreds[1];
    return (
      password.length >= 4 &&
      !isAllowedCredential({ source: 'env-var', name, value: password, material: password, span: { start: 0, end: password.length } })
    );
  }
  // Publishable identifiers (Firebase web key, Stripe pk_, Sentry DSN ...) are reported by API_KEY_EXPOSED as LOW
  if (API_SECRET_PATTERNS.some(p => p.publicByDesign && new RegExp(p.pattern.source, p.pattern.flags.replace('g', '')).test(value))) return false;
  // Boundary-aware allowlist: a stopword substring inside otherwise random material
  // (e.g. KEY=sk_live_example_<random>) does not exempt the whole credential.
  if (
    isAllowedCredential({
      source: 'env-var',
      name,
      value,
      material: value.replace(/^[A-Za-z][A-Za-z0-9+.\-]*:\/\//, ''),
      span: { start: 0, end: value.length },
    })
  )
    return false;
  const tokens = tokenizeIdentifier(name);
  if (tokens.some(t => NON_SECRET_NAME_TOKENS.has(t))) return false;
  return tokens.some(t => SECRET_NAME_TOKENS.has(t));
}

/** Trailing words that only say where a key is used, not what it is. */
const ENV_SUFFIX_TOKENS = new Set(['android', 'ios', 'web', 'prod', 'production', 'staging', 'stage', 'dev', 'development', 'test']);

const apiKeyDetectionRule: Rule = {
  id: 'API_KEY_EXPOSED',
  description: 'API keys or secrets exposed in source code',
  severity: Severity.HIGH,
  fileTypes: ['.js', '.jsx', '.ts', '.tsx', '.json', '.env*'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const fileContent = context.fileContent;
    const candidates: Candidate[] = [];
    // Ranges already explained by a provider-specific pattern, including ones dropped as
    // samples, so a loose pattern cannot report the same text a second time.
    const claimed: Array<[number, number]> = [];
    const overlapsClaimed = (s: number, e: number) => claimed.some(([cs, ce]) => s < ce && e > cs);

    const ordered = [
      ...API_SECRET_PATTERNS.filter(p => !p.generic),
      ...API_SECRET_PATTERNS.filter(p => p.generic),
    ];

    /**
     * Run the provider/generic pattern catalogue against one representation of
     * the file text. `source` says whether the text is the raw file or text
     * reconstructed from a base64 wrapper; in the wrapper case every span maps
     * back to the encoded token's range.
     */
    const runPatterns = (
      text: string,
      source: CredentialSource,
      spanOf?: (matchIndex: number, matchEnd: number) => [number, number],
      wrapped = false
    ): void => {
      for (const secretPattern of ordered) {
        for (const match of text.matchAll(secretPattern.pattern)) {
          if (match.index === undefined) continue;
          const matchedText = match[0];
          const matchEnd = match.index + matchedText.length;
          const value = secretPattern.valueGroup ? match[secretPattern.valueGroup] ?? '' : matchedText;
          if (!value) continue;

          const [start, end] = spanOf ? spanOf(match.index, matchEnd) : [match.index, matchEnd];
          if (overlapsClaimed(start, end)) continue;
          if (!secretPattern.generic) claimed.push([start, end]);

          if (secretPattern.contextKeyword && !secretPattern.contextKeyword.test(lineWindow(fileContent, start))) continue;
          if (secretPattern.minEntropy !== undefined && shannonEntropy(value) < secretPattern.minEntropy) continue;
          if (secretPattern.generic && !looksRandom(value, secretPattern.minEntropy ?? 3.5)) continue;

          const surrounding = fileContent.substring(Math.max(0, start - 150), Math.min(fileContent.length, end + 150));
          const refinement = secretPattern.refine?.(value, surrounding);
          if (refinement === 'skip') continue;

          // Boundary-aware allowlist: the fact carries source + material span,
          // and only a full-coverage exception may dismiss the credential.
          const fact: CredentialFact = {
            source,
            name: secretPattern.name,
            value,
            material: secretPattern.materialOf ? secretPattern.materialOf(value) : value,
            span: { start, end },
            base64Wrapped: wrapped,
          };
          if (isAllowedCredential(fact)) continue;

          if (secretPattern.generic) claimed.push([start, end]);
          candidates.push({
            start,
            end,
            generic: Boolean(secretPattern.generic),
            name: secretPattern.name,
            value,
            matchedText,
            severity: refinement?.severity ?? secretPattern.severity,
            confidence: refinement?.confidence ?? secretPattern.confidence,
            description:
              (refinement?.description ?? secretPattern.description) +
              (wrapped ? ' (base64-encoded wrapper)' : ''),
            suggestion:
              refinement?.suggestion ??
              secretPattern.suggestion ??
              `Move ${secretPattern.name} to environment variables or secure config management. Never commit secrets to version control.`,
          });
        }
      }
    };

    // Pass 1: plaintext provider and generic patterns
    runPatterns(fileContent, 'provider-pattern');

    // Pass 2: base64-wrapped secrets. Decode each standalone token and run the
    // same catalogue against the decoded text, mapping spans back to the token
    // so a wrapped provider key shares the plaintext rule's full context.
    for (const token of fileContent.matchAll(BASE64_TOKEN)) {
      if (token.index === undefined) continue;
      const encoded = token[1];
      const tokenStart = token.index + token[0].indexOf(encoded);
      const tokenEnd = tokenStart + encoded.length;
      if (overlapsClaimed(tokenStart, tokenEnd)) continue;

      const decoded = decodeBase64Token(encoded);
      if (!decoded) continue;

      runPatterns(
        decoded.decoded,
        'base64-wrapper',
        () => [tokenStart, tokenEnd],
        true
      );
    }

    // .env files: unquoted `API_KEY=value` / `CLIENT_SECRET=value` that no provider pattern knows
    const fileName = context.filePath.split(/[\\/]/).pop() ?? '';
    if (fileName.startsWith('.env')) {
      const lines = fileContent.split('\n');
      let offset = 0;
      const lineStarts = lines.map(l => {
        const s = offset;
        offset += l.length + 1;
        return s;
      });
      for (const v of parseEnvVars(fileContent)) {
        const tokens = tokenizeIdentifier(v.name);
        // The name must END in key/secret (optionally followed by an environment/platform suffix), so
        // identifiers such as APP_STORE_CONNECT_API_KEY_ISSUER_ID or API_KEY_ID are not treated as secrets
        const meaningful = [...tokens];
        while (meaningful.length > 1 && ENV_SUFFIX_TOKENS.has(meaningful[meaningful.length - 1])) meaningful.pop();
        const last = meaningful[meaningful.length - 1];
        const isApiKeyName =
          last === 'secret' ||
          last === 'apikey' ||
          (last === 'key' && (meaningful.includes('api') || meaningful.length === 1));
        if (!isApiKeyName || v.value.length < 20) continue;
        if (isPlaceholderValue(v.value, true) || !looksRandom(v.value, 3.5)) continue;
        const start = lineStarts[v.line - 1];
        const end = start + lines[v.line - 1].length;
        if (overlapsClaimed(start, end)) continue;
        if (
          isAllowedCredential({
            source: 'env-var',
            name: v.name,
            value: v.value,
            material: v.value,
            span: { start, end },
          })
        )
          continue;
        claimed.push([start, end]);
        candidates.push({
          start,
          end,
          generic: true,
          name: 'Generic API Key',
          value: v.value,
          matchedText: v.value,
          severity: Severity.MEDIUM,
          confidence: 'medium',
          description: 'Generic API key pattern detected',
          suggestion: 'Move the key to environment variables or secure config management. Never commit secrets to version control.',
        });
      }
    }

    candidates.sort((a, b) => a.start - b.start);
    return candidates.map(c => {
      const line = getLineNumber(fileContent, c.start);
      const finding: Finding = {
        ruleId: 'API_KEY_EXPOSED',
        description: `${c.description}: ${maskSecret(c.matchedText)}`,
        severity: c.severity,
        filePath: context.filePath,
        line,
        snippet: extractSnippet(fileContent, line),
        suggestion: c.suggestion,
      };
      if (c.confidence) finding.confidence = c.confidence;
      return finding;
    });
  },
};

const envFileCommittedRule: Rule = {
  id: 'ENV_FILE_COMMITTED',
  description: 'Environment file with secrets committed to repository',
  severity: Severity.HIGH,
  // The engine only hands over .env* files that git tracks
  fileTypes: ['.env*'],
  apply: async (context: RuleContext): Promise<Finding[]> => {
    const fileName = context.filePath.split(/[\\/]/).pop() ?? '';
    if (!fileName.startsWith('.env')) return [];

    const offending = parseEnvVars(context.fileContent).filter(isSecretEnvVar);
    if (offending.length === 0) return [];

    const first = offending[0];
    const masked = first.value.length >= 12 ? `${first.value.slice(0, 2)}****` : '****';
    const more = offending.length > 1 ? ` (and ${offending.length - 1} more)` : '';
    return [
      {
        ruleId: 'ENV_FILE_COMMITTED',
        description: `Git-tracked ${fileName} contains secret ${first.name}=${masked}${more}`,
        severity: Severity.HIGH,
        filePath: context.filePath,
        line: first.line,
        snippet: `${first.name}=${masked}`,
        suggestion: 'Remove the file from git (git rm --cached), add .env files to .gitignore and rotate the exposed secrets. Commit a .env.example with placeholder values instead.',
      },
    ];
  },
};

export const secretsRules: RuleGroup = {
  category: RuleCategory.STORAGE,
  rules: [
    apiKeyDetectionRule,
    envFileCommittedRule,
  ],
};
