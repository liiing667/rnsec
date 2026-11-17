import type { Finding, Severity } from '../types/findings.js';
import { relativeToRoot } from './baseline.js';

/** Severity ordering shared by every report (HIGH first, LOW last). */
export const SEVERITY_RANK: Record<Severity, number> = {
  HIGH: 0,
  MEDIUM: 1,
  LOW: 2,
};

/**
 * Canonical, deterministic finding order used by SARIF, Markdown and HTML so the
 * three reports always list the same findings in the same sequence. Findings of one
 * rule stay together in source order (line/column), even when severities differ;
 * rule id and file make the overall order deterministic without depending on scan
 * scheduling. The human reports re-bucket this single sequence into HIGH/MEDIUM/LOW
 * sections, and the fingerprint is the final tie-break for identical findings.
 */
export function compareFindings(a: Finding, b: Finding): number {
  return (
    a.ruleId.localeCompare(b.ruleId) ||
    a.filePath.localeCompare(b.filePath) ||
    (a.line ?? 0) - (b.line ?? 0) ||
    (a.column ?? 0) - (b.column ?? 0) ||
    SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity] ||
    a.description.localeCompare(b.description) ||
    (a.fingerprint ?? '').localeCompare(b.fingerprint ?? '')
  );
}

/** Returns a new array sorted with {@link compareFindings}. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(compareFindings);
}

/**
 * Repo-root-relative, forward-slash path shared by every report. Project-level
 * findings without a file render as an empty string; paths that cannot be made
 * relative fall back to their original representation.
 */
export function reportPath(finding: Finding, repoRoot: string): string {
  if (!finding.filePath) return '';
  return relativeToRoot(finding.filePath, repoRoot);
}

/** Location label used in human reports: `path` or `path:line`. */
export function reportLocation(finding: Finding, repoRoot: string): string {
  const path = reportPath(finding, repoRoot);
  if (!path) return '';
  return finding.line ? `${path}:${finding.line}` : path;
}

export interface SeverityCounts {
  high: number;
  medium: number;
  low: number;
  total: number;
}

/** Single source of truth for the summary counters shown by every report. */
export function countBySeverity(findings: readonly Finding[]): SeverityCounts {
  const counts: SeverityCounts = { high: 0, medium: 0, low: 0, total: findings.length };
  for (const finding of findings) {
    if (finding.severity === 'HIGH') counts.high++;
    else if (finding.severity === 'MEDIUM') counts.medium++;
    else counts.low++;
  }
  return counts;
}

/**
 * Groups findings by the same identity used across reports: rule id plus
 * description. Instances inside a group keep the canonical order.
 */
export function groupFindings(findings: readonly Finding[]): Map<string, Finding[]> {
  const grouped = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = `${finding.ruleId}::${finding.description}`;
    const bucket = grouped.get(key);
    if (bucket) bucket.push(finding);
    else grouped.set(key, [finding]);
  }
  return grouped;
}

const HTML_ESCAPES: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#039;',
};

/** Escapes every character with an HTML entity meaning. */
export function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, char => HTML_ESCAPES[char]);
}

/**
 * Escapes Markdown inline-code content. Backslashes are escaped first so a literal
 * backtick/backslash survives rendering; the text is meant to be wrapped in backticks.
 */
export function escapeMarkdownCode(text: string): string {
  return text.replace(/\\/g, '\\\\').replace(/`/g, '\\`');
}

/** Escapes text rendered outside code spans in Markdown reports. */
export function escapeMarkdownText(text: string): string {
  return text.replace(/\\/g, '\\\\').replace(/([`*_[\]<>])/g, '\\$1');
}
