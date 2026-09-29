// src/index.ts
import { Type } from "@sinclair/typebox";
import { findBudgetModel } from "pi-budget-model";

// src/config.ts
import { readFileSync } from "fs";
import { join } from "path";
import { BudgetModelOptions as BudgetModelOptionsSchema } from "pi-budget-model";
import * as v from "valibot";
var CommandMatcher = v.union([v.string(), v.pipe(v.array(v.string()), v.minLength(1))]);
var SharedConfig = v.object({
  /** Command names to flag. String = any invocation; array = subcommand prefix match. */
  commands: v.optional(v.array(CommandMatcher), []),
  /** Regex patterns to flag anywhere in tool input text. */
  patterns: v.optional(v.array(v.string()), []),
  /** Natural language instructions appended to the judge system prompt. */
  instructions: v.optional(v.string())
});
var SafeguardConfig = v.object({
  ...SharedConfig.entries,
  /** Disable safeguard entirely (global only) */
  enabled: v.optional(v.boolean(), true),
  /** Judge model selection (global only) */
  judgeModel: v.optional(BudgetModelOptionsSchema, {}),
  /** Judge call timeout in ms (global only) */
  judgeTimeoutMs: v.optional(v.pipe(v.number(), v.minValue(1e3), v.maxValue(6e4)), 1e4)
});
var ProjectConfig = SharedConfig;
function globalConfigPath() {
  return join(process.env.HOME ?? "~", ".pi", "agent", "extensions", "pi-safeguard.json");
}
function projectConfigPath(cwd) {
  return join(cwd, ".pi", "extensions", "pi-safeguard.json");
}
function readJsonFile(path2, label) {
  try {
    return JSON.parse(readFileSync(path2, "utf-8"));
  } catch (err) {
    if (err.code === "ENOENT") return void 0;
    throw new Error(
      `safeguard: failed to read ${label} config at ${path2}: ${err instanceof Error ? err.message : err}`
    );
  }
}
function parseConfig(schema, raw, path2, label) {
  try {
    return v.parse(schema, raw);
  } catch (err) {
    throw new Error(`safeguard: invalid ${label} config at ${path2}: ${err instanceof Error ? err.message : err}`);
  }
}
function compilePatterns(patterns, label) {
  return patterns.map((p) => {
    try {
      return new RegExp(p);
    } catch (err) {
      throw new Error(
        `safeguard: invalid regex in ${label} patterns: "${p}" \u2014 ${err instanceof Error ? err.message : err}`
      );
    }
  });
}
function loadGlobalConfig() {
  const path2 = globalConfigPath();
  const raw = readJsonFile(path2, "global") ?? {};
  return parseConfig(SafeguardConfig, raw, path2, "global");
}
function loadProjectConfig(cwd) {
  const path2 = projectConfigPath(cwd);
  const raw = readJsonFile(path2, "project");
  if (raw === void 0) return void 0;
  return parseConfig(ProjectConfig, raw, path2, "project");
}
function loadMergedConfig(cwd) {
  const global = loadGlobalConfig();
  const project = loadProjectConfig(cwd);
  const commands = [...global.commands];
  const patternStrs = [...global.patterns];
  if (project) {
    commands.push(...project.commands);
    patternStrs.push(...project.patterns);
  }
  return {
    enabled: global.enabled,
    judgeModel: global.judgeModel,
    judgeTimeoutMs: global.judgeTimeoutMs,
    commands,
    patterns: compilePatterns(patternStrs, project ? "global+project" : "global"),
    globalInstructions: global.instructions,
    projectInstructions: project?.instructions
  };
}
function toBudgetModelOptions(config) {
  return config.judgeModel;
}
var TRUST_ENTRY_TYPE = "safeguard:trust";
var VERDICT_ENTRY_TYPE = "safeguard:verdict";
var MAX_CONTEXT_TOOLS = 8;
var USER_MSG_MAX = 300;
var USER_MSG_HEAD = 150;
var USER_MSG_TAIL = 100;
var BASH_DETAIL_LEN = 50;
var DEFAULT_DENY_GUIDANCE = "This action was blocked by the security guardrail. Consider a different approach, ask the user to run the command directly, or use the propose_trust tool to request permission for this session.";
var BASE_SYSTEM_PROMPT = `You are a security guardrail for an AI coding agent. You evaluate actions before they execute.

Your job: decide if the action is safe to proceed WITHOUT interrupting the user.

You receive:
- The action (a bash command or file operation)
- The agent's working directory
- User trust directives for this session (if any \u2014 these are set by the user and should be respected)
- Recent agent activity with tool calls, outcomes, and any previous guard verdicts

Respond with exactly one JSON object:
{ "verdict": "approve" | "deny" | "ask", "reason": "<one sentence, shown to user>", "guidance": "<one sentence advice for the agent>" }

Verdicts:
- approve: routine and safe in a development context
- deny: genuinely dangerous or clearly malicious
- ask: you need the user to decide \u2014 use this when uncertain, OR when you suspect circumvention

The "guidance" field is sent to the agent instead of your reasoning. It should suggest what to do:
- Ask the user to provide the needed value directly instead of reading secrets
- Suggest the user run the command themselves via the terminal
- Suggest using /guard to add a trust directive if repeated access is needed
- Suggest an alternative approach that doesn't require the sensitive operation

Circumvention detection:
If a previous action was denied and the agent is now attempting the same goal via different commands (e.g. denied "cat .env", now trying "head .env" or "grep . .env"), respond with "ask" to let the user decide. Note: solving the problem differently and safely (e.g. asking the user to provide a value, using a different approach entirely) is NOT circumvention.

Be pragmatic. Developers work with these files and commands constantly. Err toward approve for typical dev workflows.`;
function buildSystemPrompt(config) {
  const parts = [BASE_SYSTEM_PROMPT];
  if (config.globalInstructions) {
    parts.push(`

User instructions (global):
${config.globalInstructions}`);
  }
  if (config.projectInstructions) {
    parts.push(`

Project instructions:
${config.projectInstructions}`);
  }
  return parts.join("");
}

// src/types.ts
function isCustomEntry(entry, customType) {
  return entry.type === "custom" && entry.customType === customType;
}

// src/context.ts
function getTrustDirectives(ctx) {
  const directives = [];
  for (const entry of ctx.sessionManager.getBranch()) {
    if (isCustomEntry(entry, TRUST_ENTRY_TYPE)) {
      if (entry.data === null) directives.length = 0;
      else directives.push(entry.data);
    }
  }
  return directives;
}
function buildContext(ctx) {
  const branch = ctx.sessionManager.getBranch();
  let userIdx = -1;
  for (let i = branch.length - 1; i >= 0; i--) {
    if (branch[i].type === "message" && branch[i].message.role === "user") {
      userIdx = i;
      break;
    }
  }
  let userLine = "";
  const toolLines = [];
  const pendingCalls = [];
  let pendingVerdict = null;
  const start = userIdx >= 0 ? userIdx : Math.max(0, branch.length - 20);
  for (let i = start; i < branch.length; i++) {
    const entry = branch[i];
    if (isCustomEntry(entry, VERDICT_ENTRY_TYPE)) {
      pendingVerdict = entry.data;
      continue;
    }
    if (entry.type !== "message") continue;
    const msg = entry.message;
    if (msg.role === "user") {
      const text = typeof msg.content === "string" ? msg.content : msg.content.filter((c) => c.type === "text").map((c) => c.text).join(" ");
      userLine = `[user] ${abbreviate(text)}`;
      continue;
    }
    if (msg.role === "assistant") {
      for (const block of msg.content) {
        if (block.type === "toolCall") {
          const tc = block;
          pendingCalls.push({ name: tc.name, summary: summarizeToolCall(tc.name, tc.arguments) });
        }
      }
      continue;
    }
    if (msg.role === "toolResult") {
      const call = pendingCalls.shift();
      const callStr = call?.summary ?? msg.toolName;
      if (pendingVerdict && pendingVerdict.verdict !== "approve") {
        toolLines.push(`[tool] ${callStr} \u2192 ${pendingVerdict.verdict} (${pendingVerdict.reason})`);
      } else {
        const outcome = msg.isError ? "error" : "ok";
        const detail = msg.toolName === "bash" ? bashDetail(msg.content) : "";
        toolLines.push(`[tool] ${callStr} \u2192 ${outcome}${detail}`);
      }
      pendingVerdict = null;
    }
  }
  const lines = [];
  if (userLine) lines.push(userLine);
  if (toolLines.length > MAX_CONTEXT_TOOLS) {
    const omitted = toolLines.length - MAX_CONTEXT_TOOLS;
    lines.push(`[${omitted} previous tool calls omitted]`);
    lines.push(...toolLines.slice(-MAX_CONTEXT_TOOLS));
  } else {
    lines.push(...toolLines);
  }
  return lines.join("\n");
}
function abbreviate(text) {
  if (text.length <= USER_MSG_MAX) return text;
  return `${text.slice(0, USER_MSG_HEAD)}\u2026${text.slice(-USER_MSG_TAIL)}`;
}
function summarizeToolCall(name, args) {
  if (name === "bash") return `bash: ${args.command ?? ""}`;
  if (["read", "write", "edit", "grep", "find", "ls"].includes(name)) return `${name} ${args.path ?? ""}`;
  return name;
}
function bashDetail(content) {
  const text = content.filter((c) => c.type === "text").map((c) => c.text ?? "").join("");
  const lastLine = text.trim().split("\n").pop()?.trim() ?? "";
  if (!lastLine) return "";
  const trimmed = lastLine.length > BASH_DETAIL_LEN ? lastLine.slice(-BASH_DETAIL_LEN) : lastLine;
  return ` | ${trimmed}`;
}

// src/judge.ts
import { completeSimple } from "@mariozechner/pi-ai";
function parseVerdict(text) {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start < 0 || end <= start) {
    throw new Error(`no JSON object found in response: ${text.slice(0, 200)}`);
  }
  const parsed = JSON.parse(text.slice(start, end + 1));
  if (!["approve", "deny", "ask"].includes(parsed.verdict)) {
    throw new Error(`invalid verdict "${parsed.verdict}" in response: ${text.slice(0, 200)}`);
  }
  return { verdict: parsed.verdict, reason: parsed.reason ?? "", guidance: parsed.guidance ?? "" };
}
async function callJudge(model, auth, action, cwd, recentContext, trustDirectives, timeoutMs, systemPrompt, batchContext) {
  const parts = [`Action: ${action}`, `Working directory: ${cwd}`];
  if (batchContext && batchContext.length > 0) {
    parts.push(
      "",
      "Batch context: the agent planned multiple tool calls at once (before receiving any verdicts). Other calls in this batch:",
      ...batchContext.map((b) => `  - [${b.verdict}] ${b.action}`)
    );
  }
  if (trustDirectives.length > 0) {
    parts.push("", "User trust directives:", ...trustDirectives.map((d) => `  - ${d}`));
  }
  if (recentContext) {
    parts.push("", "Recent activity:", recentContext);
  }
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await completeSimple(
      model,
      {
        systemPrompt,
        messages: [{ role: "user", content: parts.join("\n"), timestamp: Date.now() }]
      },
      {
        ...auth,
        signal: controller.signal,
        maxTokens: 250,
        temperature: 0
      }
    );
    const text = response.content.filter((c) => c.type === "text").map((c) => c.text).join("");
    return parseVerdict(text);
  } finally {
    clearTimeout(timeout);
  }
}

// src/signals.ts
import * as path from "path";
import { isToolCallEventType } from "@mariozechner/pi-coding-agent";

// src/ast.ts
import {
  parse as parse2
} from "@aliou/sh";
function analyzeBashCommand(cmd) {
  const empty = { parsed: false, commands: [], isPipeline: false, allFiles: [], allParamRefs: [] };
  let ast;
  try {
    ({ ast } = parse2(cmd, { dialect: "bash" }));
  } catch {
    return empty;
  }
  const commands = [];
  let isPipeline = false;
  for (const stmt of ast.body) {
    walkStatement(stmt, commands, (v2) => {
      isPipeline = isPipeline || v2;
    });
  }
  const allFiles = commands.flatMap((c) => [...c.args.filter(looksLikePath), ...c.redirectTargets]);
  const allParamRefs = [...new Set(commands.flatMap((c) => c.paramRefs))];
  return { parsed: true, commands, isPipeline, allFiles, allParamRefs };
}
function walkStatement(stmt, out, setPipeline) {
  walkCommand(stmt.command, out, setPipeline);
}
function walkCommand(cmd, out, setPipeline) {
  switch (cmd.type) {
    case "SimpleCommand":
      out.push(extractSimpleCommand(cmd));
      break;
    case "Pipeline":
      setPipeline(true);
      for (const s of cmd.commands) {
        walkStatement(s, out, setPipeline);
      }
      break;
    case "Logical":
      walkStatement(cmd.left, out, setPipeline);
      walkStatement(cmd.right, out, setPipeline);
      break;
    case "Subshell":
    case "Block":
      for (const s of cmd.body) {
        walkStatement(s, out, setPipeline);
      }
      break;
    case "IfClause":
      for (const s of [...cmd.cond, ...cmd.then, ...cmd.else ?? []]) {
        walkStatement(s, out, setPipeline);
      }
      break;
    case "WhileClause":
      for (const s of [...cmd.cond, ...cmd.body]) {
        walkStatement(s, out, setPipeline);
      }
      break;
    case "ForClause":
      for (const s of cmd.body) {
        walkStatement(s, out, setPipeline);
      }
      break;
    case "CaseClause":
      for (const item of cmd.items ?? []) {
        for (const s of item.body) {
          walkStatement(s, out, setPipeline);
        }
      }
      break;
    case "DeclClause":
      out.push(extractDeclClause(cmd));
      break;
    case "TimeClause":
      if (cmd.command) walkStatement(cmd.command, out, setPipeline);
      break;
    case "FunctionDecl":
      break;
    // Ignore: TestClause, ArithCmd, CoprocClause, LetClause, CStyleLoop, SelectClause
    default:
      break;
  }
}
function extractSimpleCommand(cmd) {
  const words = (cmd.words ?? []).map(wordToString);
  const name = words[0] ?? "";
  const args = words.slice(1);
  const redirectTargets = (cmd.redirects ?? []).map((r) => wordToString(r.target));
  const paramRefs = collectParamRefs(cmd);
  return { name, args, redirectTargets, paramRefs };
}
function extractDeclClause(cmd) {
  const wordList = cmd.args ?? cmd.words ?? [];
  const args = wordList.map(wordToString);
  return { name: cmd.variant, args, redirectTargets: [], paramRefs: collectParamRefsFromWords(wordList) };
}
function wordToString(word) {
  return word.parts.map(partToString).join("");
}
function partToString(part) {
  switch (part.type) {
    case "Literal":
      return part.value;
    case "SglQuoted":
      return part.value;
    case "DblQuoted":
      return part.parts.map(partToString).join("");
    case "ParamExp":
      return `$${part.param?.value ?? ""}`;
    case "CmdSubst":
      return "$(...)";
    case "ArithExp":
      return "$((...))";
    case "ProcSubst":
      return "<(...)";
    default:
      return "";
  }
}
function collectParamRefs(cmd) {
  const refs = [];
  for (const w of cmd.words ?? []) {
    collectParamRefsFromParts(w.parts, refs);
  }
  for (const r of cmd.redirects ?? []) {
    collectParamRefsFromParts(r.target.parts, refs);
  }
  return refs;
}
function collectParamRefsFromWords(words) {
  const refs = [];
  for (const w of words) {
    collectParamRefsFromParts(w.parts, refs);
  }
  return refs;
}
function collectParamRefsFromParts(parts, refs) {
  for (const p of parts) {
    if (p.type === "ParamExp" && p.param?.value) {
      refs.push(p.param.value);
    }
    if (p.type === "DblQuoted") {
      collectParamRefsFromParts(p.parts, refs);
    }
  }
}
function looksLikePath(s) {
  return s.startsWith("/") || s.startsWith("./") || s.startsWith("../") || s.startsWith("~") || s.includes(".");
}

// src/signals.ts
function shouldFlag(event, ctx, config) {
  if (isToolCallEventType("bash", event)) {
    const analysis = analyzeBashCommand(event.input.command);
    if (bashSignals(analysis, event.input.command, ctx, config)) return true;
    if (textSignals(event.input.command, config)) return true;
    return false;
  }
  const filePath = getFilePath(event);
  if (filePath && pathSignals(filePath, ctx)) return true;
  const text = extractToolText(event);
  if (text) {
    if (contentSignals(text)) return true;
    if (textSignals(text, config)) return true;
  }
  return false;
}
function bashSignals(analysis, _rawCmd, ctx, config) {
  if (!analysis.parsed) return true;
  for (const cmd of analysis.commands) {
    if (PRIVILEGE_COMMANDS.has(cmd.name)) return true;
    if (isMutatingCommand(cmd.name) && hasFlag(cmd.args, "r", "R")) return true;
    if (cmd.name === "rm" && hasFlag(cmd.args, "f")) return true;
    if (hasRootTarget(cmd)) return true;
    if (cmd.name === "chmod" && cmd.args.includes("777")) return true;
    if (cmd.name === "chmod" && cmd.args.some((a) => a.includes("u+s") || a.includes("g+s"))) return true;
    if (cmd.name === "dd" && cmd.args.some((a) => a.startsWith("of="))) return true;
    if (cmd.name.startsWith("mkfs")) return true;
    if (ENV_DUMP_COMMANDS.has(cmd.name)) return true;
    if (cmd.name === "export" && cmd.args.includes("-p")) return true;
    if (INTERPRETER_COMMANDS.has(cmd.name) && hasInlineCode(cmd.name, cmd.args)) return true;
    const files = [...cmd.args.filter(looksLikePath2), ...cmd.redirectTargets];
    for (const f of files) {
      if (pathSignals(f, ctx)) return true;
    }
    if (cmd.name === "docker" && (cmd.args.includes("-e") || cmd.args.includes("--env-file"))) return true;
  }
  if (hasNetworkCommand(analysis) && hasSecretParamRefs(analysis)) return true;
  if (analysis.isPipeline && hasSensitiveSource(analysis, ctx) && hasNetworkCommand(analysis)) return true;
  if (analysis.isPipeline && analysis.commands.some((c) => ENV_DUMP_COMMANDS.has(c.name))) return true;
  if (config?.commands && matchUserCommands(analysis, config.commands)) return true;
  return false;
}
function pathSignals(filePath, ctx) {
  const resolved = resolvePath(filePath, ctx.cwd);
  if (!isUnder(resolved, ctx.cwd)) return true;
  if (isHomeDotfile(resolved, ctx.home)) return true;
  if (isSystemPath(resolved)) return true;
  if (SECRET_PATH_PATTERN.test(filePath)) return true;
  return false;
}
function resolvePath(filePath, cwd) {
  if (filePath.startsWith("~")) {
    return path.resolve(process.env.HOME ?? "/home", filePath.slice(1).replace(/^\//, ""));
  }
  return path.resolve(cwd, filePath);
}
function isUnder(resolved, dir) {
  const norm = dir.endsWith("/") ? dir : `${dir}/`;
  return resolved === dir || resolved.startsWith(norm);
}
function isHomeDotfile(resolved, home) {
  if (!isUnder(resolved, home)) return false;
  const relative = resolved.slice(home.length).replace(/^\//, "");
  const first = relative.split("/")[0];
  return first?.startsWith(".") ?? false;
}
var SYSTEM_PREFIXES = ["/etc", "/usr", "/var", "/boot", "/sys", "/proc", "/dev", "/sbin", "/lib"];
function isSystemPath(resolved) {
  return SYSTEM_PREFIXES.some((p) => resolved === p || resolved.startsWith(`${p}/`));
}
var SECRET_PATH_PATTERN = /(?:^|[/\\._-])(?:secret|credential|password|passwd|token|private[._-]?key|\.env(?:\.|$)|\.dev\.vars(?:$|[/\\])|id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts)|\.(?:pem|key)$/i;
var MUTATING_COMMANDS = /* @__PURE__ */ new Set(["rm", "chmod", "chown", "chgrp", "find", "xargs"]);
function isMutatingCommand(name) {
  return MUTATING_COMMANDS.has(name);
}
function hasFlag(args, ...flags) {
  return args.some((a) => {
    if (!a.startsWith("-")) return false;
    if (a.startsWith("--")) {
      return flags.some((f) => a === `--${LONG_FLAGS[f] ?? f}`);
    }
    return flags.some((f) => a.includes(f));
  });
}
var LONG_FLAGS = {
  r: "recursive",
  R: "recursive",
  f: "force"
};
function hasRootTarget(cmd) {
  const allTargets = [...cmd.args, ...cmd.redirectTargets];
  return allTargets.some((a) => a === "/" || a === "/*");
}
var PRIVILEGE_COMMANDS = /* @__PURE__ */ new Set(["sudo", "su", "doas", "pkexec"]);
var NETWORK_COMMANDS = /* @__PURE__ */ new Set(["curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "rsync", "ftp", "sftp"]);
var ENV_DUMP_COMMANDS = /* @__PURE__ */ new Set(["printenv", "env", "set"]);
var INTERPRETER_COMMANDS = /* @__PURE__ */ new Set([
  "eval",
  "bash",
  "sh",
  "zsh",
  "fish",
  "python",
  "python3",
  "node",
  "ruby",
  "perl"
]);
var INTERPRETER_INLINE_FLAGS = {
  eval: [],
  // eval always has inline code
  bash: ["-c"],
  sh: ["-c"],
  zsh: ["-c"],
  fish: ["-c"],
  python: ["-c"],
  python3: ["-c"],
  node: ["-e", "--eval"],
  ruby: ["-e"],
  perl: ["-e"]
};
function hasInlineCode(name, args) {
  const flags = INTERPRETER_INLINE_FLAGS[name];
  if (!flags) return false;
  if (flags.length === 0) return true;
  return flags.some((f) => args.includes(f));
}
var SECRET_VAR_PATTERN = /(SECRET|TOKEN|PASSWORD|PASSWD|PASSPHRASE|CREDENTIAL|API[_.]?KEY|PRIVATE[_.]?KEY|(?:^|_)AUTH(?:_|$))/i;
function hasNetworkCommand(analysis) {
  return analysis.commands.some((c) => NETWORK_COMMANDS.has(c.name));
}
function hasSecretParamRefs(analysis) {
  return analysis.allParamRefs.some((ref) => SECRET_VAR_PATTERN.test(ref));
}
function hasSensitiveSource(analysis, ctx) {
  return analysis.allFiles.some((f) => pathSignals(f, ctx));
}
var PRIVATE_KEY_PATTERN = /-----BEGIN\s[\w\s]*PRIVATE\sKEY-----/;
var SECRET_FORMAT_PATTERNS = [
  /ghp_[A-Za-z0-9_]{36,}/,
  // GitHub personal access token
  /gho_[A-Za-z0-9_]{36,}/,
  // GitHub OAuth token
  /ghs_[A-Za-z0-9_]{36,}/,
  // GitHub server token
  /github_pat_[A-Za-z0-9_]{22,}/,
  // GitHub fine-grained PAT
  /sk-[A-Za-z0-9]{20,}/,
  // OpenAI / Stripe secret key
  /sk-proj-[A-Za-z0-9-_]{20,}/,
  // OpenAI project key
  /AKIA[0-9A-Z]{16}/,
  // AWS access key
  /xoxb-[0-9]+-[A-Za-z0-9]+/,
  // Slack bot token
  /xoxp-[0-9]+-[A-Za-z0-9]+/,
  // Slack user token
  /xoxs-[0-9]+-[A-Za-z0-9]+/
  // Slack session token
];
function contentSignals(text) {
  if (PRIVATE_KEY_PATTERN.test(text)) return true;
  for (const pattern of SECRET_FORMAT_PATTERNS) {
    if (pattern.test(text)) return true;
  }
  return false;
}
var BUILTIN_TEXT_PATTERNS = [/\bsudo\b/, /\bsafeguard\b/];
function textSignals(text, config) {
  for (const pattern of BUILTIN_TEXT_PATTERNS) {
    if (pattern.test(text)) return true;
  }
  if (config?.patterns) {
    for (const pattern of config.patterns) {
      if (pattern.test(text)) return true;
    }
  }
  return false;
}
function matchUserCommands(analysis, matchers) {
  for (const cmd of analysis.commands) {
    for (const matcher of matchers) {
      if (typeof matcher === "string") {
        if (cmd.name === matcher) return true;
      } else {
        if (cmd.name !== matcher[0]) continue;
        const prefix = matcher.slice(1);
        if (prefix.length === 0 || prefix.every((sub, i) => cmd.args[i] === sub)) return true;
      }
    }
  }
  return false;
}
function extractToolText(event) {
  if (isToolCallEventType("write", event)) return event.input.content;
  if (isToolCallEventType("edit", event)) return event.input.newText;
  return "";
}
function getFilePath(event) {
  if (isToolCallEventType("read", event)) return event.input.path;
  if (isToolCallEventType("write", event)) return event.input.path;
  if (isToolCallEventType("edit", event)) return event.input.path;
  if (isToolCallEventType("grep", event)) return event.input.path;
  return void 0;
}
function looksLikePath2(s) {
  return s.startsWith("/") || s.startsWith("./") || s.startsWith("../") || s.startsWith("~") || s.includes("/") || s.startsWith(".");
}
function describeAction(event) {
  if (isToolCallEventType("bash", event)) return `bash: ${event.input.command}`;
  if (isToolCallEventType("read", event)) return `read ${event.input.path}`;
  if (isToolCallEventType("write", event)) return `write ${event.input.path}`;
  if (isToolCallEventType("edit", event)) return `edit ${event.input.path}`;
  if (isToolCallEventType("grep", event)) return `grep ${event.input.path ?? ""}`;
  if (isToolCallEventType("find", event)) return `find ${event.input.path ?? ""}`;
  if (isToolCallEventType("ls", event)) return `ls ${event.input.path ?? ""}`;
  return event.toolName;
}
function isRelevantTool(event) {
  return ["bash", "read", "write", "edit", "grep", "find", "ls"].includes(event.toolName);
}

// src/index.ts
function index_default(pi) {
  const config = loadMergedConfig(process.cwd());
  if (!config.enabled) return;
  const systemPrompt = buildSystemPrompt(config);
  pi.registerCommand("guard", {
    description: "Manage safeguard: /guard <trust directive> or /guard reset",
    handler: async (args, ctx) => {
      const trimmed = args.trim();
      if (!trimmed) {
        const directives = getTrustDirectives(ctx);
        if (directives.length === 0) {
          ctx.ui.notify("No trust directives set for this session.");
        } else {
          ctx.ui.notify(`Trust directives:
${directives.map((d, i) => `  ${i + 1}. ${d}`).join("\n")}`);
        }
        return;
      }
      if (trimmed === "reset") {
        pi.appendEntry(TRUST_ENTRY_TYPE, null);
        ctx.ui.notify("\u{1F6E1}\uFE0F Trust directives cleared for this session.");
        return;
      }
      pi.appendEntry(TRUST_ENTRY_TYPE, trimmed);
      ctx.ui.notify(`\u{1F6E1}\uFE0F Trust directive added: ${trimmed}`);
    }
  });
  pi.registerTool({
    name: "propose_trust",
    label: "Propose Trust Rule",
    description: "Request permission for something the security guardrail blocked. Proposes a trust rule for the user to accept or reject. Accepted rules instruct the security judge for the remainder of the session, so propose broad rules covering your task rather than one-off approvals.",
    promptSnippet: "Request permission for something the security guardrail blocked (proposes a session-wide trust rule for the user to approve)",
    promptGuidelines: [
      "When blocked by the security guardrail, use propose_trust to request permission instead of asking the user to type /guard manually.",
      "Accepted rules last for the entire session, so propose rules that cover the task broadly rather than one-off approvals.",
      "Keep rules brief but explicit about what is allowed. Good: 'Allow .env file access', 'Allow terraform plan and apply'. Bad: 'Allow dangerous commands', 'Allow everything needed for this task'.",
      "The reason field is optional. Only include it if the rule isn't self-explanatory. Don't repeat information from the rule."
    ],
    parameters: Type.Object({
      rule: Type.String({
        description: "Brief, explicit trust rule stating what is allowed (e.g. 'Allow .env file access', 'Allow terraform commands', 'Allow editing safeguard source')"
      }),
      reason: Type.Optional(
        Type.String({
          description: "Only if the rule isn't self-explanatory. Don't repeat the rule."
        })
      )
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      if (!ctx) {
        return {
          content: [{ type: "text", text: "Rejected: no UI context available." }],
          details: {}
        };
      }
      if (!ctx.hasUI) {
        return {
          content: [{ type: "text", text: "Rejected: no interactive UI available." }],
          details: {}
        };
      }
      const lines = ["\u{1F6E1}\uFE0F Trust rule proposed", `
\u{1F4CB} ${params.rule}`];
      if (params.reason) lines.push(`
\u{1F4AC} ${params.reason}`);
      lines.push("");
      const choice = await ctx.ui.select(lines.join("\n"), ["Accept", "Reject"]);
      if (choice === "Accept") {
        pi.appendEntry(TRUST_ENTRY_TYPE, params.rule);
        return {
          content: [
            {
              type: "text",
              text: `Trust rule accepted for this session: "${params.rule}". You can now retry the blocked action.`
            }
          ],
          details: {}
        };
      }
      return {
        content: [
          {
            type: "text",
            text: "Trust rule rejected by user. Try a different approach, or ask the user to run the command directly."
          }
        ],
        details: {}
      };
    }
  });
  let currentTurnBatch = [];
  let denialInCurrentTurn = false;
  let denialInPreviousTurn = false;
  let flowVerdicts = [];
  pi.on("agent_start", async (_event, ctx) => {
    currentTurnBatch = [];
    denialInCurrentTurn = false;
    denialInPreviousTurn = false;
    flowVerdicts = [];
    ctx.ui.setWidget("safeguard", void 0);
  });
  pi.on("turn_start", async () => {
    denialInPreviousTurn = denialInCurrentTurn;
    denialInCurrentTurn = false;
    currentTurnBatch = [];
  });
  pi.on("agent_end", async (_event, ctx) => {
    if (flowVerdicts.length > 0) {
      ctx.ui.setWidget("safeguard", void 0);
      flowVerdicts = [];
    }
  });
  pi.on("tool_call", async (event, ctx) => {
    const signalCtx = {
      cwd: ctx.cwd,
      home: process.env.HOME ?? "/home"
    };
    let flagged = shouldFlag(event, signalCtx, config);
    if (!flagged && denialInPreviousTurn && isRelevantTool(event)) {
      flagged = true;
    }
    if (!flagged) return;
    const action = describeAction(event);
    const batchContext = currentTurnBatch.length > 0 ? [...currentTurnBatch] : void 0;
    const result = await evaluate(pi, ctx, config, systemPrompt, action, batchContext, flowVerdicts);
    const verdict = result ? "deny" : "approve";
    currentTurnBatch.push({ action, verdict });
    if (result) {
      denialInCurrentTurn = true;
    }
    if (denialInPreviousTurn) {
      denialInPreviousTurn = false;
    }
    return result;
  });
}
async function evaluate(pi, ctx, config, systemPrompt, action, batchContext, flowVerdicts) {
  let judge;
  try {
    judge = await resolveJudgeModel(ctx, config);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return askUser(pi, ctx, action, `Judge model unavailable: ${msg}`);
  }
  const recentContext = buildContext(ctx);
  const trustDirectives = getTrustDirectives(ctx);
  try {
    const verdict = await callJudge(
      judge.model,
      judge.auth,
      action,
      ctx.cwd,
      recentContext,
      trustDirectives,
      config.judgeTimeoutMs,
      systemPrompt,
      batchContext
    );
    if (verdict.verdict === "approve") {
      flowVerdicts.push({ action, verdict: "\u2705", reason: verdict.reason });
      updateWidget(ctx, flowVerdicts);
      pi.appendEntry(VERDICT_ENTRY_TYPE, {
        action,
        verdict: "approve",
        reason: verdict.reason
      });
      return;
    }
    if (verdict.verdict === "deny") {
      flowVerdicts.push({ action, verdict: "\u274C", reason: verdict.reason });
      updateWidget(ctx, flowVerdicts);
      pi.appendEntry(VERDICT_ENTRY_TYPE, { action, verdict: "deny", reason: verdict.reason });
      return { block: true, reason: verdict.guidance || DEFAULT_DENY_GUIDANCE };
    }
    return askUser(pi, ctx, action, verdict.reason);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return askUser(pi, ctx, action, `Judge error: ${msg}`);
  }
}
function updateWidget(ctx, verdicts) {
  const approved = verdicts.filter((v2) => v2.verdict === "\u2705").length;
  const denied = verdicts.filter((v2) => v2.verdict === "\u274C").length;
  const parts = [];
  if (approved > 0) parts.push(`${approved} approved`);
  if (denied > 0) parts.push(`${denied} denied`);
  ctx.ui.setWidget("safeguard", [`\u{1F6E1}\uFE0F ${parts.join(", ")}`]);
}
async function resolveJudgeModel(ctx, config) {
  return findBudgetModel(ctx, toBudgetModelOptions(config));
}
async function askUser(pi, ctx, action, explanation) {
  if (!ctx.hasUI) {
    pi.appendEntry(VERDICT_ENTRY_TYPE, { action, verdict: "user-deny", reason: "no UI" });
    return { block: true, reason: DEFAULT_DENY_GUIDANCE };
  }
  const lines = ["Command needs approval. Agent's explanation:", `> ${explanation}`, `
${action}`];
  const choice = await ctx.ui.select(lines.join("\n"), ["Allow", "Deny", "Stop"]);
  if (choice === "Allow") {
    pi.appendEntry(VERDICT_ENTRY_TYPE, { action, verdict: "user-approve", reason: explanation });
    return;
  }
  if (choice === "Stop") {
    pi.appendEntry(VERDICT_ENTRY_TYPE, { action, verdict: "user-deny", reason: "user stopped" });
    ctx.abort();
    return { block: true, reason: "The user stopped execution. Wait for their next instructions." };
  }
  pi.appendEntry(VERDICT_ENTRY_TYPE, { action, verdict: "user-deny", reason: explanation });
  return { block: true, reason: DEFAULT_DENY_GUIDANCE };
}
export {
  index_default as default
};
