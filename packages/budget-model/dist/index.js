// src/index.ts
import * as v from "valibot";
var ModelStrategy = v.picklist(["same-provider", "any-provider"]);
var BudgetModelAuth = v.object({
  apiKey: v.optional(v.string()),
  headers: v.optional(v.record(v.string(), v.string()))
});
var ModelOverride = v.union([
  v.pipe(v.string(), v.regex(/^[^/]+\/.+$/, 'must be "provider/model-id"')),
  v.object({
    model: v.pipe(v.string(), v.regex(/^[^/]+\/.+$/, 'must be "provider/model-id"')),
    auth: BudgetModelAuth
  })
]);
var BudgetModelOptions = v.object({
  modelOverride: v.optional(ModelOverride),
  strategy: v.optional(ModelStrategy, "same-provider"),
  costRatio: v.optional(v.pipe(v.number(), v.minValue(0), v.maxValue(1)), 0.5),
  /** How many major versions to search. 1 = latest only, 2 = latest + previous, 0 = all. */
  majorVersions: v.optional(v.pipe(v.number(), v.integer(), v.minValue(0)), 1)
});
var NoBudgetModelError = class extends Error {
  reason;
  sameProvider;
  cheapestOverall;
  constructor(reason, candidates = {}) {
    const lines = [
      "Tried to auto-detect a budget model for a background task, but couldn't find one.",
      `Reason: ${reason}`
    ];
    if (candidates.sameProvider) {
      const c = candidates.sameProvider;
      lines.push(
        `Best same-provider option: ${c.provider}/${c.modelId} ($${c.costInput}/$${c.costOutput} per M tokens)`
      );
    }
    if (candidates.cheapestOverall?.hasApiKey) {
      const c = candidates.cheapestOverall;
      lines.push(`Cheapest with API key: ${c.provider}/${c.modelId} ($${c.costInput}/$${c.costOutput} per M tokens)`);
    }
    lines.push(
      "To fix: configure a model explicitly in the extension settings, or switch to a provider with cheaper models."
    );
    super(lines.join("\n"));
    this.name = "NoBudgetModelError";
    this.reason = reason;
    this.sameProvider = candidates.sameProvider ?? null;
    this.cheapestOverall = candidates.cheapestOverall ?? null;
  }
};
async function findBudgetModel(ctx, options) {
  const opts = v.parse(BudgetModelOptions, options ?? {});
  if (opts.modelOverride) {
    return resolveModelOverride(ctx, opts.modelOverride);
  }
  const activeModel = ctx.model;
  if (!activeModel) {
    throw new NoBudgetModelError("no active model set");
  }
  if (opts.strategy === "any-provider") {
    return findAnyProvider(ctx, activeModel, opts.costRatio, opts.majorVersions);
  }
  return findSameProvider(ctx, activeModel, opts.costRatio, opts.majorVersions);
}
async function resolveAuth(ctx, model) {
  const result = await ctx.modelRegistry.getApiKeyAndHeaders(model);
  if (!result.ok) return null;
  return { apiKey: result.apiKey, headers: result.headers };
}
async function findSameProvider(ctx, activeModel, costRatio, majorVersions) {
  const activeProvider = String(activeModel.provider);
  const allModels = ctx.modelRegistry.getAll();
  const providerModels = allModels.filter((m) => String(m.provider) === activeProvider);
  const lazyCheapestOverall = () => findCheapestCandidate(ctx, allModels, majorVersions);
  if (providerModels.length === 0) {
    throw new NoBudgetModelError(`no models found for provider "${activeProvider}"`, {
      cheapestOverall: await lazyCheapestOverall()
    });
  }
  const candidates = findCheapestInMajorVersions(providerModels, majorVersions);
  if (candidates.length === 0) {
    throw new NoBudgetModelError(`no versioned models found for provider "${activeProvider}"`, {
      cheapestOverall: await lazyCheapestOverall()
    });
  }
  const minCost = candidates[0].cost.input;
  if (minCost >= activeModel.cost.input * costRatio) {
    const sameProvider2 = await toCandidate(ctx, candidates[0], activeProvider);
    throw new NoBudgetModelError(
      `cheapest model in ${activeProvider} is $${minCost}/M input \u2014 not significantly cheaper than active model ($${activeModel.cost.input}/M input)`,
      { sameProvider: sameProvider2, cheapestOverall: await lazyCheapestOverall() }
    );
  }
  for (const candidate of candidates) {
    if (candidate.cost.input >= activeModel.cost.input * costRatio) break;
    const auth = await resolveAuth(ctx, candidate);
    if (auth) {
      return { model: candidate, auth };
    }
  }
  const sameProvider = await toCandidate(ctx, candidates[0], activeProvider);
  throw new NoBudgetModelError(`no API key available for cheapest models in provider "${activeProvider}"`, {
    sameProvider,
    cheapestOverall: await lazyCheapestOverall()
  });
}
async function findAnyProvider(ctx, activeModel, costRatio, majorVersions) {
  const allModels = ctx.modelRegistry.getAll();
  const byProvider = /* @__PURE__ */ new Map();
  for (const m of allModels) {
    const p = String(m.provider);
    if (!byProvider.has(p)) byProvider.set(p, []);
    byProvider.get(p).push(m);
  }
  const allCandidates = [];
  for (const [, models] of byProvider) {
    allCandidates.push(...findCheapestInMajorVersions(models, majorVersions));
  }
  allCandidates.sort((a, b) => a.cost.input - b.cost.input);
  const cheapestCost = allCandidates[0]?.cost.input ?? Number.POSITIVE_INFINITY;
  if (cheapestCost >= activeModel.cost.input * costRatio) {
    throw new NoBudgetModelError(
      `cheapest model across all providers is $${cheapestCost}/M input \u2014 not significantly cheaper than active model ($${activeModel.cost.input}/M input)`
    );
  }
  for (const model of allCandidates) {
    if (model.cost.input >= activeModel.cost.input * costRatio) break;
    const auth = await resolveAuth(ctx, model);
    if (auth) {
      return { model, auth };
    }
  }
  throw new NoBudgetModelError("no budget models with API keys found across any provider");
}
async function resolveModelOverride(ctx, override) {
  const modelId = typeof override === "string" ? override : override.model;
  const slashIndex = modelId.indexOf("/");
  const provider = modelId.slice(0, slashIndex);
  const id = modelId.slice(slashIndex + 1);
  const model = ctx.modelRegistry.find(provider, id);
  if (!model) {
    throw new NoBudgetModelError(`model override "${modelId}" not found in registry`);
  }
  if (typeof override !== "string") {
    return { model, auth: override.auth };
  }
  const auth = await resolveAuth(ctx, model);
  if (!auth) {
    throw new NoBudgetModelError(`no API key for model override "${modelId}"`);
  }
  return { model, auth };
}
function findCheapestInMajorVersions(models, majorVersions) {
  const allVersions = /* @__PURE__ */ new Set();
  for (const m of models) {
    const ver = extractMajorVersion(m.id);
    if (ver !== null) allVersions.add(ver);
  }
  const sorted = [...allVersions].sort((a, b) => b - a);
  if (sorted.length === 0) return [];
  const included = majorVersions === 0 ? sorted : sorted.slice(0, majorVersions);
  const includedSet = new Set(included);
  const eligible = models.filter((m) => {
    const ver = extractMajorVersion(m.id);
    return ver !== null && includedSet.has(ver);
  });
  eligible.sort((a, b) => {
    const costDiff = a.cost.input - b.cost.input;
    if (costDiff !== 0) return costDiff;
    return compareVersions(a, b);
  });
  return eligible;
}
async function toCandidate(ctx, model, provider) {
  return {
    provider,
    modelId: model.id,
    costInput: model.cost.input,
    costOutput: model.cost.output,
    hasApiKey: ctx.modelRegistry.hasConfiguredAuth(model)
  };
}
async function findCheapestCandidate(ctx, allModels, majorVersions) {
  const byProvider = /* @__PURE__ */ new Map();
  for (const m of allModels) {
    const p = String(m.provider);
    if (!byProvider.has(p)) byProvider.set(p, []);
    byProvider.get(p).push(m);
  }
  let best = null;
  for (const [provider, models] of byProvider) {
    const candidates = findCheapestInMajorVersions(models, majorVersions);
    if (candidates[0] && (!best || candidates[0].cost.input < best.model.cost.input)) {
      best = { model: candidates[0], provider };
    }
  }
  if (!best) return null;
  return toCandidate(ctx, best.model, best.provider);
}
function extractMajorVersion(id) {
  const tokens = id.replace(/[._\-:]/g, " ").split(/\s+/);
  for (const t of tokens) {
    if (/^\d+$/.test(t) && t.length >= 8) continue;
    const m = t.match(/(\d+)/);
    if (m) return Number.parseInt(m[1], 10);
  }
  return null;
}
function extractVersionNumbers(id) {
  const tokens = id.replace(/[._\-:]/g, " ").split(/\s+/);
  const nums = [];
  for (const t of tokens) {
    if (/^\d+$/.test(t) && t.length >= 8) continue;
    const m = t.match(/(\d+)/);
    if (m) nums.push(Number.parseInt(m[1], 10));
  }
  return nums;
}
function compareVersions(a, b) {
  const av = extractVersionNumbers(a.id);
  const bv = extractVersionNumbers(b.id);
  for (let i = 0; i < Math.max(av.length, bv.length); i++) {
    const diff = (bv[i] ?? 0) - (av[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return av.length - bv.length;
}
export {
  BudgetModelAuth,
  BudgetModelOptions,
  ModelOverride,
  ModelStrategy,
  NoBudgetModelError,
  extractMajorVersion,
  extractVersionNumbers,
  findBudgetModel,
  findCheapestInMajorVersions
};
