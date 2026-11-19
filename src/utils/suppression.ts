/**
 * Inline suppression directives.
 *
 * Grammar (ASCII only; everything else is malformed and fails closed):
 *
 *   rnsec-ignore: RULE_ID[@VERSION][, RULE_ID[@VERSION]...] [until=YYYY-MM-DD] [reason text]
 *
 * Security properties:
 * - For JS/TS files directives are read from real AST comment nodes, so a
 *   `rnsec-ignore:` token inside a string/template literal can never suppress.
 * - The marker and rule ids are matched against strict ASCII character
 *   classes: Unicode lookalikes (homoglyphs, full-width punctuation) make the
 *   directive malformed instead of matching.
 * - A directive may only name rules that exist, pins the rule version it was
 *   reviewed against, may carry an expiry date, and every malformed/expired/
 *   conflicting directive fails closed (the finding stays reported).
 */
import { parse } from '@babel/parser';
import { RuleRegistry, DEFAULT_RULE_VERSION } from '../core/ruleRegistry.js';
import { languageForPath, maskStrings } from './nativeCode.js';

const MARKER = 'rnsec-ignore:';
const RULE_ID = /^[A-Z][A-Z0-9_]*$/;
const SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[\w.]+)?$/;
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

const JS_LIKE = /\.(?:[cm]?js|jsx|ts|tsx)$/;

/** File kinds that have no comment syntax: a directive token there can never be real. */
const NO_COMMENTS = /\.(?:json|lock)$|(^|\/)(?:package-lock|npm-shrinkwrap|pnpm-lock)\.yaml$|yarn\.lock$/;

/** Directives only exist inside comments; these are the comment styles each non-JS file kind allows. */
function lineCommentPatterns(filePath: string): RegExp[] {
  if (/\.(?:xml|plist|entitlements)$/.test(filePath)) return [/<!--[\s\S]*?-->/];
  if (/\.(?:properties|npmrc|env(?:\.[^.]*)?|yarnrc\.yml)$|(^|\/)\.env(\..+)?$/.test(filePath)) {
    return [/[#;!][^\n]*$/];
  }
  // native sources (.java/.kt/.swift/.m/.mm) and gradle: C/C++ style comments
  return [/\/\/[^\n]*$/, /\/\*[\s\S]*?(?:\*\/|$)/];
}

function isCommentOnlyLine(text: string, filePath: string): boolean {
  if (/\.(?:xml|plist|entitlements)$/.test(filePath)) return /^\s*<!--/.test(text);
  if (/\.(?:properties|npmrc|env(?:\.[^.]*)?|yarnrc\.yml)$|(^|\/)\.env(\..+)?$/.test(filePath)) {
    return /^\s*[#;!]/.test(text);
  }
  return /^\s*(?:\/\/|\/\*|\*|#)/.test(text);
}

export interface SuppressionEntry {
  ruleId: string;
  /** Rule version the suppression was reviewed against. */
  version: string;
  /** Optional UTC expiry (YYYY-MM-DD); the directive no longer suppresses at or past this date. */
  expiresOn?: string;
}

interface LineState {
  /** Rule ids this line accepts, each bound to the version reviewed. */
  accepted: Map<string, SuppressionEntry>;
  /** True when the directive on this line cannot be trusted: every rule fails closed. */
  malformed: boolean;
}

export interface SuppressionWarning {
  line: number;
  message: string;
}

export interface SuppressionMap {
  /** line (1-based) -> parsed state for the directive(s) on that line */
  byLine: Map<number, LineState>;
  /** Human-readable problems that made directives fail closed. */
  warnings: SuppressionWarning[];
}

class DirectiveError extends Error {}

/**
 * Parse one directive body (the text right after the marker).
 * Grammar: ENTRY (, ENTRY)* [until=DATE] [free-text reason]
 * Throws DirectiveError on anything that looks like a structured attempt but
 * does not match the grammar, so the caller can poison the whole line.
 */
function parseBody(body: string, registry: RuleRegistry): { entries: SuppressionEntry[]; expiresOn?: string } {
  const entries: SuppressionEntry[] = [];
  let rest = body.replace(/^\s+/, '');
  let expiresOn: string | undefined;

  const readId = (): string => {
    const m = rest.match(/^[A-Z][A-Z0-9_]*/);
    if (!m) throw new DirectiveError('expected a rule id (UPPER_SNAKE_CASE)');
    rest = rest.slice(m[0].length);
    return m[0];
  };

  // At least one entry; entries are comma separated, each optionally version-pinned.
  for (;;) {
    const ruleId = readId();
    let version = DEFAULT_RULE_VERSION;
    if (rest.startsWith('@')) {
      rest = rest.slice(1);
      const m = rest.match(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[\w.]+)?/);
      if (!m) throw new DirectiveError(`invalid rule version after "${ruleId}@"`);
      version = m[0];
      rest = rest.slice(m[0].length);
    }
    if (!RULE_ID.test(ruleId)) throw new DirectiveError(`malformed rule id "${ruleId}"`);
    if (!registry.has(ruleId)) throw new DirectiveError(`unknown rule id "${ruleId}"`);
    if (!SEMVER.test(version)) throw new DirectiveError(`invalid version "${version}" for ${ruleId}`);
    entries.push({ ruleId, version });

    if (rest.startsWith(',')) {
      rest = rest.slice(1).replace(/^\s+/, '');
      continue;
    }
    break;
  }

  // Remaining structured tokens (until=...) then free-text reason.
  rest = rest.replace(/^\s+/, '');
  while (rest.toLowerCase().startsWith('until=')) {
    rest = rest.slice('until='.length);
    const m = rest.match(/^\d{4}-\d{2}-\d{2}/);
    if (!m) throw new DirectiveError('until= expects a YYYY-MM-DD date');
    expiresOn = m[0];
    rest = rest.slice(m[0].length).replace(/^\s+/, '');
  }
  // Anything left is the free-text reason (may contain any character).
  return { entries, expiresOn };
}

function todayUTC(): string {
  return new Date().toISOString().slice(0, 10);
}

/**
 * Validate and record one directive occurrence on a physical source line.
 * `ownLine` means the comment occupies the whole line and also covers the next line.
 */
function addDirective(
  map: SuppressionMap,
  lineNo: number,
  ownLine: boolean,
  body: string,
  registry: RuleRegistry
): void {
  const targets = ownLine ? [lineNo, lineNo + 1] : [lineNo];

  let parsed: { entries: SuppressionEntry[]; expiresOn?: string };
  const poison = (message: string): void => {
    map.warnings.push({ line: lineNo, message });
    for (const line of targets) {
      const state = map.byLine.get(line) ?? { accepted: new Map<string, SuppressionEntry>(), malformed: false };
      state.malformed = true;
      state.accepted.clear();
      map.byLine.set(line, state);
    }
  };

  try {
    parsed = parseBody(body, registry);
  } catch (error) {
    poison(`rnsec-ignore directive on line ${lineNo} is malformed (${
      error instanceof Error ? error.message : String(error)
    }); no findings were suppressed`);
    return;
  }
  // A second marker inside the same comment cannot be a reason: treat it as malformed.
  if (body.includes(MARKER)) {
    poison(`rnsec-ignore directive on line ${lineNo} contains a nested marker; no findings were suppressed`);
    return;
  }

  for (const line of targets) {
    const state = map.byLine.get(line) ?? { accepted: new Map<string, SuppressionEntry>(), malformed: false };
    for (const entry of parsed.entries) {
      if (state.malformed) return;
      const withExpiry: SuppressionEntry = { ...entry, expiresOn: parsed.expiresOn };
      const previous = state.accepted.get(entry.ruleId);
      if (previous) {
        // Two directives on the same line/rule must agree, otherwise the intent is ambiguous.
        if (previous.version !== entry.version || previous.expiresOn !== parsed.expiresOn) {
          poison(`conflicting rnsec-ignore directives for ${entry.ruleId} on line ${line}; no findings were suppressed`);
          return;
        }
        continue;
      }
      state.accepted.set(entry.ruleId, withExpiry);
    }
    map.byLine.set(line, state);
  }
}

/** Extract directive candidates from real AST comments of a JS/TS source. */
function directivesFromAst(content: string, filePath: string, map: SuppressionMap, registry: RuleRegistry): void {
  let ast: any;
  try {
    ast = parse(content, {
      sourceType: 'module',
      plugins: [
        ...(/\.[cm]?ts$/.test(filePath) ? [] : ['jsx' as const]),
        'typescript',
        'decorators-legacy',
        'classProperties',
        'objectRestSpread',
        'asyncGenerators',
        'dynamicImport',
      ],
      errorRecovery: true,
    });
  } catch {
    // Unparseable source: fall back to line scanning with string/template
    // literals masked, so a marker quoted in code can never look like a comment.
    const masked = maskJsStrings(content);
    const fallbackMap: SuppressionMap = { byLine: new Map(), warnings: [] };
    directivesFromText(masked, filePath, fallbackMap, registry);
    map.byLine = fallbackMap.byLine;
    map.warnings.push(...fallbackMap.warnings);
    return;
  }

  const lines = content.split('\n');
  const seen = new Set<number>();
  for (const comment of ast.comments ?? []) {
    const startLine: number = comment.loc?.start?.line ?? 1;
    const endLine: number = comment.loc?.end?.line ?? startLine;
    const commentStartsColumn: number = comment.loc?.start?.column ?? 0;
    // Block comments may span lines: each physical line is checked on its own.
    for (let lineNo = startLine; lineNo <= endLine; lineNo++) {
      const text = lines[lineNo - 1] ?? '';
      let searchFrom = 0;
      let idx = text.indexOf(MARKER, searchFrom);
      while (idx >= 0) {
        // Several comments can share a line; only act on a marker once per physical line.
        if (!seen.has(lineNo)) {
          seen.add(lineNo);
          // A comment-only line (nothing but whitespace before the comment itself) also covers the next line.
          const ownLine = text.slice(0, commentStartsColumn).trim() === '';
          addDirective(map, lineNo, ownLine, text.slice(idx + MARKER.length), registry);
        }
        searchFrom = idx + MARKER.length;
        idx = text.indexOf(MARKER, searchFrom);
      }
    }
  }
}

/**
 * Blank the contents of string/template literals in JS-like source while
 * keeping line breaks and offsets. Used only when the real parser fails.
 */
function maskJsStrings(code: string): string {
  const out = code.split('');
  const n = out.length;
  let i = 0;
  while (i < n) {
    const ch = out[i];
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      const start = i + 1;
      i++;
      while (i < n) {
        if (out[i] === '\\') {
          i += 2;
          continue;
        }
        if (out[i] === quote) break;
        i++;
      }
      for (let j = start; j < Math.min(i, n); j++) {
        if (out[j] !== '\n') out[j] = ' ';
      }
      i++;
      continue;
    }
    i++;
  }
  return out.join('');
}

/** Line-based extraction for non-JS files (comments only; string literals are masked for native code). */
function directivesFromText(content: string, filePath: string, map: SuppressionMap, registry: RuleRegistry): void {
  const language = languageForPath(filePath);
  const source = language ? maskStrings(content, language) : content;
  const patterns = lineCommentPatterns(filePath);
  const lines = source.split('\n');

  lines.forEach((text, idx) => {
    const markerIdx = text.indexOf(MARKER);
    if (markerIdx < 0) return;
    // The marker must live inside an allowed comment for this file kind.
    const insideComment = patterns.some(pattern => {
      pattern.lastIndex = 0;
      const match = pattern.exec(text);
      return !!match && match.index <= markerIdx && match.index + match[0].length >= markerIdx + MARKER.length;
    });
    if (!insideComment) {
      // Marker outside any comment (e.g. string content): never a directive.
      return;
    }
    const lineNo = idx + 1;
    const ownLine = isCommentOnlyLine(text, filePath);
    addDirective(map, lineNo, ownLine, text.slice(markerIdx + MARKER.length), registry);
  });
}

export function parseSuppressions(content: string, filePath?: string): SuppressionMap {
  const map: SuppressionMap = { byLine: new Map(), warnings: [] };
  if (!content.includes(MARKER)) return map;
  const registry = RuleRegistry.shared();

  if (filePath && NO_COMMENTS.test(filePath)) return map;
  if (filePath && JS_LIKE.test(filePath)) {
    directivesFromAst(content, filePath, map, registry);
  } else if (filePath) {
    directivesFromText(content, filePath, map, registry);
  } else {
    // No path (legacy callers): AST parsing still protects JS-like syntax.
    directivesFromAst(content, 'inline.js', map, registry);
  }
  return map;
}

/**
 * Whether a finding is suppressed. Fails closed: malformed lines, unknown
 * rules, version mismatches, expired directives and conflicting directives
 * all leave the finding visible. File-level findings (no line) use line 1.
 */
export function isSuppressed(map: SuppressionMap, ruleId: string, line: number | undefined): boolean {
  const target = line ?? 1;
  const state = map.byLine.get(target);
  if (!state || state.malformed) return false;
  const entry = state.accepted.get(ruleId);
  if (!entry) return false;

  const current = RuleRegistry.shared().versionOf(ruleId);
  if (!current || current !== entry.version) return false;
  if (entry.expiresOn) {
    if (!ISO_DATE.test(entry.expiresOn)) return false;
    if (entry.expiresOn <= todayUTC()) return false;
  }
  return true;
}
