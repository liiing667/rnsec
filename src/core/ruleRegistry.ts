import type { Rule } from '../types/ruleTypes.js';

/**
 * Every rule starts at this version. Bump a rule's `version` when its
 * detection logic changes in a way that previously-accepted risk must be
 * re-reviewed: inline suppressions and baseline entries are bound to the
 * version they were written against and stop hiding findings once it moves.
 */
export const DEFAULT_RULE_VERSION = '1.0.0';

/**
 * Central registry of the rule versions that ship with this tool build.
 * The CLI registers every rule once after loading all rule groups, and the
 * suppression machinery queries versions through here. Unknown ids mean a
 * directive cannot be validated, so they fail closed.
 */
export class RuleRegistry {
  private static instance: RuleRegistry | undefined;

  private readonly versions = new Map<string, string>();

  static shared(): RuleRegistry {
    if (!RuleRegistry.instance) RuleRegistry.instance = new RuleRegistry();
    return RuleRegistry.instance;
  }

  /** Replace the registry state (used by tests and when rule groups are rebuilt). */
  static reset(): void {
    RuleRegistry.instance = undefined;
  }

  register(rules: Rule[]): void {
    for (const rule of rules) {
      if (!this.versions.has(rule.id)) this.versions.set(rule.id, rule.version ?? DEFAULT_RULE_VERSION);
    }
  }

  has(ruleId: string): boolean {
    return this.versions.has(ruleId);
  }

  versionOf(ruleId: string): string | undefined {
    return this.versions.get(ruleId);
  }

  ids(): Set<string> {
    return new Set(this.versions.keys());
  }
}
