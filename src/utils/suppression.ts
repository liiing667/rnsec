/**
 * Inline suppression: `// rnsec-ignore: RULE_ID[, RULE_ID] optional reason`.
 *
 * Suppression is parsed from real comment tokens instead of per-line regex, so
 * the same text inside a string or template literal has no effect, and block
 * comments never suppress past their closing delimiter.
 *
 * - Rule IDs are mandatory and must be explicit (`[A-Z][A-Z0-9_]*`); there is
 *   no blanket ignore and a malformed directive never suppresses anything.
 * - A comment only affects its own line, the next line (when it stands alone)
 *   or, for a multi-line block comment, the lines inside its own block.
 * - Works in `//`, `/* *​/`, `#` and `<!-- -->` comments.
 */

export interface SuppressionMap {
  /** line (1-based) -> set of rule IDs suppressed on that line */
  byLine: Map<number, Set<string>>;
}

type ScanMode = 'js' | 'xml' | 'hash';
type LexerState = ScanMode | 'line' | 'block' | 'string' | 'template' | 'interpolation' | 'attrString';

interface CommentRange {
  start: number;
  end: number;
  kind: 'line' | 'block';
}

const ID_PATTERN = /[A-Z][A-Z0-9_]*/y;
const DIRECTIVE_PATTERN = /(?:^|[^A-Za-z0-9_-])rnsec-ignore:\s*/g;

/** Comment syntax depends on the file kind; e.g. XML prose may legitimately contain apostrophes. */
function modeForPath(filePath: string | undefined): ScanMode {
  if (!filePath) return 'js';
  if (/\.(xml|plist|entitlements)$/i.test(filePath)) return 'xml';
  if (/\.(env(\..*)?|properties|lock|yaml|yml)$/i.test(filePath) ||
      /(^|[\\/])(\.npmrc|\.yarnrc\.yml|yarn\.lock)$/.test(filePath)) {
    return 'hash';
  }
  return 'js';
}

/**
 * Tokenize a source string and return the byte ranges of real comments.
 * Strings, template literals and interpolations are consumed as code so text
 * that merely looks like a comment or directive inside them is never collected.
 */
function collectComments(content: string, mode: ScanMode): CommentRange[] {
  const comments: CommentRange[] = [];
  const n = content.length;
  const stack: LexerState[] = [];
  let state: LexerState = mode;
  let commentStart = -1;
  let quote = '';
  let inTag = false;

  const pushState = (next: LexerState): void => {
    stack.push(state);
    state = next;
  };

  let i = 0;
  while (i < n) {
    const c = content[i];
    const next = content[i + 1];

    if (state === 'line') {
      if (c === '\n') {
        comments.push({ start: commentStart, end: i, kind: 'line' });
        state = stack.pop() ?? mode;
      }
      i++;
      continue;
    }

    if (state === 'block') {
      if (c === '*' && next === '/') {
        comments.push({ start: commentStart, end: i + 2, kind: 'block' });
        state = stack.pop() ?? mode;
        i += 2;
        continue;
      }
      i++;
      continue;
    }

    if (state === 'string' || state === 'attrString') {
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === quote) {
        state = stack.pop() ?? mode;
      } else if (state === 'string' && c === '\n') {
        state = stack.pop() ?? mode;
      }
      i++;
      continue;
    }

    if (state === 'template') {
      if (c === '\\') {
        i += 2;
        continue;
      }
      if (c === '`') {
        state = stack.pop() ?? mode;
        i++;
        continue;
      }
      if (c === '$' && next === '{') {
        pushState('interpolation');
        i += 2;
        continue;
      }
      i++;
      continue;
    }

    if (state === 'interpolation') {
      if (c === '}') {
        state = stack.pop() ?? mode;
        i++;
        continue;
      }
      if (c === '`') {
        pushState('template');
        i++;
        continue;
      }
      if (c === '"' || c === "'") {
        quote = c;
        pushState('string');
        i++;
        continue;
      }
      i++;
      continue;
    }

    // code states: js / xml / hash (the state equals the mode while scanning code)
    if (state === 'xml') {
      if (c === '<' && next === '!') {
        const open = content.startsWith('<!--', i);
        if (open) {
          commentStart = i;
          pushState('block');
          i += 4;
          continue;
        }
      }
      if (c === '<') inTag = true;
      if (c === '>') inTag = false;
      if ((c === '"' || c === "'") && inTag) {
        quote = c;
        pushState('attrString');
        i++;
        continue;
      }
      i++;
      continue;
    }

    if (state === 'hash') {
      if (c === '#') {
        commentStart = i;
        pushState('line');
        i++;
        continue;
      }
      if (c === '"' || c === "'") {
        quote = c;
        pushState('string');
        i++;
        continue;
      }
      i++;
      continue;
    }

    // js-style code: //, /* */, #, <!--, quotes and template literals
    if (c === '/' && (next === '/' || next === '*')) {
      commentStart = i;
      pushState(next === '/' ? 'line' : 'block');
      i += 2;
      continue;
    }
    if (c === '#') {
      commentStart = i;
      pushState('line');
      i++;
      continue;
    }
    if (c === '<' && next === '!' && content.startsWith('<!--', i)) {
      commentStart = i;
      pushState('block');
      i += 4;
      continue;
    }
    if (c === '"' || c === "'") {
      if (content.startsWith(c.repeat(3), i)) {
        const close = content.indexOf(c.repeat(3), i + 3);
        i = close === -1 ? n : close + 3;
        continue;
      }
      quote = c;
      pushState('string');
      i++;
      continue;
    }
    if (c === '`') {
      pushState('template');
      i++;
      continue;
    }
    i++;
  }

  // An unterminated line/block comment still runs to the end of the input.
  if (state === 'line' || state === 'block') {
    comments.push({ start: commentStart, end: n, kind: state === 'line' ? 'line' : 'block' });
  }
  return comments;
}

/**
 * Parse the rule list right after `rnsec-ignore:`. Returns the IDs only when
 * every ID is explicit and well-formed; any malformed segment (missing ID,
 * blank list, bad characters) makes the whole directive ineffective.
 */
function parseDirectiveIds(text: string, pos: number): string[] | undefined {
  const ids: string[] = [];
  let expectId = true;

  while (pos < text.length) {
    const rest = text.slice(pos);
    const skipped = rest.match(/^\s*/)![0].length;
    pos += skipped;
    if (pos >= text.length) break;

    if (expectId) {
      ID_PATTERN.lastIndex = pos;
      const match = ID_PATTERN.exec(text);
      if (!match) return undefined;
      ids.push(match[0]);
      pos = ID_PATTERN.lastIndex;
      expectId = false;
      continue;
    }

    const ch = text[pos];
    if (ch === ',') {
      expectId = true;
      pos++;
      continue;
    }
    // Any other token starts the free-form reason; a pending comma (missing ID) is malformed.
    if (expectId) return undefined;
    break;
  }

  if (ids.length === 0 || expectId) return undefined;
  return ids;
}

function lineOf(content: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < content.length; i++) {
    if (content[i] === '\n') line++;
  }
  return line;
}

/** Line number of the last line covered by a multi-line block comment. */
function lastBlockLine(content: string, comment: CommentRange, startLine: number, endLine: number): number {
  if (comment.kind !== 'block' || endLine === startLine) return endLine;
  // `end` sits just after `*/`; the line holding the closing delimiter is still inside the block.
  return lineOf(content, comment.end - 1);
}

/**
 * Parse suppression comments from file content. Pass the file path so the
 * comment syntax (JS-style, XML or `#`-based configs) matches the file kind.
 */
export function parseSuppressions(content: string, filePath?: string): SuppressionMap {
  const byLine = new Map<number, Set<string>>();
  if (!content.includes('rnsec-ignore')) return { byLine };

  const mode = modeForPath(filePath);
  const add = (line: number, ids: string[]): void => {
    const set = byLine.get(line) ?? new Set<string>();
    ids.forEach(id => set.add(id));
    byLine.set(line, set);
  };
  const lineStartOf = (offset: number): number => content.lastIndexOf('\n', offset - 1) + 1;

  for (const comment of collectComments(content, mode)) {
    const body = content.slice(comment.start, comment.end);
    const startLine = lineOf(content, comment.start);
    const endLine = lineOf(content, comment.end);
    const lastSuppressedLine = lastBlockLine(content, comment, startLine, endLine);

    for (const match of body.matchAll(DIRECTIVE_PATTERN)) {
      const ids = parseDirectiveIds(body, match.index! + match[0].length);
      if (!ids) continue; // malformed directives never suppress anything

      for (let line = startLine; line <= lastSuppressedLine; line++) add(line, ids);

      const aloneOnLine = /^\s*$/.test(content.slice(lineStartOf(comment.start), comment.start));
      if (aloneOnLine && lastSuppressedLine === startLine) add(startLine + 1, ids);
    }
  }

  return { byLine };
}

/** Findings without a line number (file-level) can be suppressed from line 1. */
export function isSuppressed(map: SuppressionMap, ruleId: string, line: number | undefined): boolean {
  const target = line ?? 1;
  return map.byLine.get(target)?.has(ruleId) ?? false;
}
