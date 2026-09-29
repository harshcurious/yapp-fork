import { Model, Api } from '@mariozechner/pi-ai';
import { ExtensionContext } from '@mariozechner/pi-coding-agent';
import * as v from 'valibot';

/**
 * pi-budget-model — auto-select the cheapest available model for background tasks.
 *
 * Single entry point: `findBudgetModel(ctx, options?)` with configurable strategy:
 * - `"same-provider"` (default) — cheapest in the active provider.
 *   On failure, includes the cheapest-overall candidate on the error.
 * - `"any-provider"` — cheapest across ALL providers with an API key.
 *
 * The `majorVersions` option controls how many major version families to search:
 * - 1 (default) = latest major version only
 * - 2 = latest + previous major version (often dramatically cheaper)
 * - 0 = all major versions
 *
 * Both strategies enforce a cost ratio check against the active model.
 * Options are validated at runtime with valibot.
 */

declare const ModelStrategy: v.PicklistSchema<["same-provider", "any-provider"], undefined>;
type ModelStrategy = v.InferOutput<typeof ModelStrategy>;
/**
 * Auth material for calling a model, mirroring the success branch of the model
 * registry's `getApiKeyAndHeaders` result and the fields `pi-ai`'s `StreamOptions`
 * accepts. Both fields are optional: most providers use `apiKey`, some use `headers`
 * (e.g. an out-of-band `Authorization` header), and some use neither (e.g. AWS
 * Bedrock with SDK-resolved credentials). Spread into `completeSimple`/`stream`
 * options as `{ ...auth, signal, ... }`.
 */
declare const BudgetModelAuth: v.ObjectSchema<{
    readonly apiKey: v.OptionalSchema<v.StringSchema<undefined>, undefined>;
    readonly headers: v.OptionalSchema<v.RecordSchema<v.StringSchema<undefined>, v.StringSchema<undefined>, undefined>, undefined>;
}, undefined>;
type BudgetModelAuth = v.InferOutput<typeof BudgetModelAuth>;
/**
 * Pin a specific model, bypassing auto-selection.
 *
 * - String form `"provider/model-id"`: registry resolves both the model metadata
 *   and the auth credentials. Equivalent to v1.
 * - Object form `{ model, auth }`: registry resolves the model metadata via
 *   `find()`, but auth is taken straight from the option — the registry's auth
 *   resolution is not invoked. Use this as an escape hatch when the registry's
 *   auth pipeline misbehaves for your provider.
 */
declare const ModelOverride: v.UnionSchema<[v.SchemaWithPipe<readonly [v.StringSchema<undefined>, v.RegexAction<string, "must be \"provider/model-id\"">]>, v.ObjectSchema<{
    readonly model: v.SchemaWithPipe<readonly [v.StringSchema<undefined>, v.RegexAction<string, "must be \"provider/model-id\"">]>;
    readonly auth: v.ObjectSchema<{
        readonly apiKey: v.OptionalSchema<v.StringSchema<undefined>, undefined>;
        readonly headers: v.OptionalSchema<v.RecordSchema<v.StringSchema<undefined>, v.StringSchema<undefined>, undefined>, undefined>;
    }, undefined>;
}, undefined>], undefined>;
type ModelOverride = v.InferOutput<typeof ModelOverride>;
declare const BudgetModelOptions: v.ObjectSchema<{
    readonly modelOverride: v.OptionalSchema<v.UnionSchema<[v.SchemaWithPipe<readonly [v.StringSchema<undefined>, v.RegexAction<string, "must be \"provider/model-id\"">]>, v.ObjectSchema<{
        readonly model: v.SchemaWithPipe<readonly [v.StringSchema<undefined>, v.RegexAction<string, "must be \"provider/model-id\"">]>;
        readonly auth: v.ObjectSchema<{
            readonly apiKey: v.OptionalSchema<v.StringSchema<undefined>, undefined>;
            readonly headers: v.OptionalSchema<v.RecordSchema<v.StringSchema<undefined>, v.StringSchema<undefined>, undefined>, undefined>;
        }, undefined>;
    }, undefined>], undefined>, undefined>;
    readonly strategy: v.OptionalSchema<v.PicklistSchema<["same-provider", "any-provider"], undefined>, "same-provider">;
    readonly costRatio: v.OptionalSchema<v.SchemaWithPipe<readonly [v.NumberSchema<undefined>, v.MinValueAction<number, 0, undefined>, v.MaxValueAction<number, 1, undefined>]>, 0.5>;
    /** How many major versions to search. 1 = latest only, 2 = latest + previous, 0 = all. */
    readonly majorVersions: v.OptionalSchema<v.SchemaWithPipe<readonly [v.NumberSchema<undefined>, v.IntegerAction<number, undefined>, v.MinValueAction<number, 0, undefined>]>, 1>;
}, undefined>;
type BudgetModelOptions = v.InferOutput<typeof BudgetModelOptions>;
/**
 * A model selected for a background task, plus the auth material needed to call it.
 *
 * `auth` is the same shape `pi-ai`'s `StreamOptions` accepts. The intended call
 * pattern is to spread it directly:
 *
 * ```ts
 * const { model, auth } = await findBudgetModel(ctx);
 * await completeSimple(model, ctx, { ...auth, signal, maxTokens });
 * ```
 */
interface BudgetModel {
    model: Model<Api>;
    auth: BudgetModelAuth;
}
/** A model candidate found during search — may not have passed all checks. */
interface ModelCandidate {
    provider: string;
    modelId: string;
    costInput: number;
    costOutput: number;
    hasApiKey: boolean;
}
/**
 * Error thrown when no suitable budget model can be found.
 *
 * - `reason`: why the search failed
 * - `sameProvider`: best candidate from the active provider (only for "same-provider" strategy)
 * - `cheapestOverall`: cheapest model across all providers (only for "same-provider" strategy)
 *
 * Callers can catch this and use the candidates for custom fallback logic,
 * or let it propagate — pi surfaces the message to the user.
 */
declare class NoBudgetModelError extends Error {
    readonly reason: string;
    readonly sameProvider: ModelCandidate | null;
    readonly cheapestOverall: ModelCandidate | null;
    constructor(reason: string, candidates?: {
        sameProvider?: ModelCandidate | null;
        cheapestOverall?: ModelCandidate | null;
    });
}
/**
 * Find the cheapest available model for background tasks.
 *
 * If `options.modelOverride` is set, selection is skipped:
 * - String form `"provider/model-id"`: registry resolves both model and auth.
 * - Object form `{ model, auth }`: registry resolves only the model metadata
 *   via `find()`; auth is taken from the option, bypassing the registry's
 *   auth pipeline. Useful as an escape hatch when registry auth misbehaves.
 *
 * Otherwise the configured `strategy` (`"same-provider"` or `"any-provider"`)
 * walks candidate models cheapest-first, gated by `costRatio` against the
 * active model, and returns the first candidate the registry can authenticate.
 *
 * @param ctx - Extension context
 * @param options - Strategy, cost ratio, major version depth, and optional override (validated at runtime)
 * @throws NoBudgetModelError if no suitable model is found
 */
declare function findBudgetModel(ctx: ExtensionContext, options?: BudgetModelOptions): Promise<BudgetModel>;
/**
 * Find the cheapest models across the top N major version groups, sorted by cost then version.
 *
 * @param models - All models to search (typically filtered to one provider)
 * @param majorVersions - How many major versions to include: 1 = latest only, 2 = latest + previous, 0 = all
 * @returns Cheapest models sorted by cost (ascending) then version (descending)
 */
declare function findCheapestInMajorVersions(models: Model<Api>[], majorVersions: number): Model<Api>[];
/**
 * Extract the major version number from a model ID.
 * Finds the first digit sequence in any token, skipping date-like tokens (≥8 digits).
 */
declare function extractMajorVersion(id: string): number | null;
/**
 * Extract version numbers from a model ID, skipping date-like tokens.
 */
declare function extractVersionNumbers(id: string): number[];

export { type BudgetModel, BudgetModelAuth, BudgetModelOptions, type ModelCandidate, ModelOverride, ModelStrategy, NoBudgetModelError, extractMajorVersion, extractVersionNumbers, findBudgetModel, findCheapestInMajorVersions };
