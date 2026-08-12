import { randomBytes } from "node:crypto";

import type { DisposableLike } from "../../services/ScanResultStore";
import type { RemediationPlan } from "./RemediationPlan";

export const MAXIMUM_PREVIEW_AGE_MS = 10 * 60 * 1_000;
const MAXIMUM_PREVIEWS = 32;

export interface RemediationPreviewRecord {
  readonly token: string;
  readonly plan: RemediationPlan;
  readonly generation: number;
  readonly createdAt: number;
  readonly expiresAt: number;
}

export interface RemediationPreviewRegistryOptions {
  readonly clock?: () => number;
  readonly maximumAgeMs?: number;
}

/**
 * Session-only, one-use preview authority. Tokens are opaque and the plan is
 * never accepted back from a command or Webview.
 */
export class RemediationPreviewRegistry implements DisposableLike {
  private readonly records = new Map<string, RemediationPreviewRecord>();
  private readonly clock: () => number;
  private readonly maximumAgeMs: number;
  private generation = 0;

  public constructor(options: RemediationPreviewRegistryOptions = {}) {
    this.clock = options.clock ?? Date.now;
    const age = options.maximumAgeMs ?? MAXIMUM_PREVIEW_AGE_MS;
    if (!Number.isSafeInteger(age) || age < 1_000 || age > MAXIMUM_PREVIEW_AGE_MS) {
      throw new RangeError("maximumAgeMs must be between 1000 and 600000");
    }
    this.maximumAgeMs = age;
  }

  public issue(plan: RemediationPlan): RemediationPreviewRecord {
    this.pruneExpired();
    while (this.records.size >= MAXIMUM_PREVIEWS) {
      const oldest = this.records.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.records.delete(oldest);
    }
    const createdAt = this.clock();
    const token = randomBytes(32).toString("base64url");
    const record = Object.freeze({
      token,
      plan,
      generation: this.generation,
      createdAt,
      expiresAt: createdAt + this.maximumAgeMs,
    });
    this.records.set(token, record);
    return record;
  }

  public peek(token: string): RemediationPreviewRecord | undefined {
    if (!/^[A-Za-z0-9_-]{43}$/u.test(token)) return undefined;
    const record = this.records.get(token);
    if (
      record === undefined ||
      record.generation !== this.generation ||
      record.expiresAt <= this.clock()
    ) {
      this.records.delete(token);
      return undefined;
    }
    return record;
  }

  public consume(token: string): RemediationPreviewRecord | undefined {
    const record = this.peek(token);
    if (record !== undefined) this.records.delete(token);
    return record;
  }

  public revoke(token: string): void {
    this.records.delete(token);
  }

  public invalidateAll(): void {
    this.generation += 1;
    this.records.clear();
  }

  public dispose(): void {
    this.invalidateAll();
  }

  private pruneExpired(): void {
    const now = this.clock();
    for (const [token, record] of this.records) {
      if (record.generation !== this.generation || record.expiresAt <= now) {
        this.records.delete(token);
      }
    }
  }
}
