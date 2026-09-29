import { ExtensionAPI } from '@mariozechner/pi-coding-agent';

/**
 * pi-safeguard — LLM-as-judge guardrail for dangerous commands and sensitive file access.
 *
 * Architecture:
 *   1. Flagger (signals.ts) — wide net, boolean predicates, no reasoning.
 *      Answers "should the judge look at this?" with high recall.
 *   2. Judge (judge.ts) — sees the raw action + context, forms its own assessment.
 *      No hint about why the flagger triggered. Can approve, deny, or ask.
 *
 * When no budget model is available (e.g. user is already on the cheapest model),
 * falls back to "ask" mode — every flagged action prompts the user directly.
 *
 * Configuration:
 *   Global:  ~/.pi/agent/extensions/pi-safeguard.json
 *   Project: .pi/extensions/pi-safeguard.json (additive only)
 *
 * The agent never sees the judge's reasoning. On deny/ask it receives guidance
 * suggesting alternative approaches. Previous verdicts are stored in the
 * session and included in context so the judge can detect circumvention.
 *
 * Use /guard to add per-session trust directives, or the agent can propose
 * trust rules via the propose_trust tool.
 */

declare function export_default(pi: ExtensionAPI): void;

export { export_default as default };
