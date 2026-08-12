export type NetworkErrorCode =
  | "CANCELLED"
  | "TIMEOUT"
  | "INVALID_REQUEST"
  | "HTTPS_REQUIRED"
  | "HOST_NOT_ALLOWED"
  | "REDIRECT_REJECTED"
  | "RATE_LIMITED"
  | "HTTP_ERROR"
  | "TLS_ERROR"
  | "NETWORK_ERROR"
  | "RESPONSE_TOO_LARGE"
  | "INVALID_RESPONSE";

export class NetworkServiceError extends Error {
  public readonly status: number | undefined;
  public readonly retryAfterMs: number | undefined;

  public constructor(
    public readonly code: NetworkErrorCode,
    message: string,
    public readonly retryable: boolean,
    options: {
      readonly status?: number;
      readonly retryAfterMs?: number;
      readonly cause?: unknown;
    } = {},
  ) {
    super(message, { cause: options.cause });
    this.name = "NetworkServiceError";
    this.status = options.status;
    this.retryAfterMs = options.retryAfterMs;
  }
}

export interface HeadersLike {
  get(name: string): string | null;
}

export interface BodyReaderLike {
  read(): Promise<{
    readonly done: boolean;
    readonly value?: Uint8Array;
  }>;
  cancel?(reason?: unknown): Promise<void>;
  releaseLock?(): void;
}

export interface ResponseBodyLike {
  getReader(): BodyReaderLike;
  cancel?(reason?: unknown): Promise<void>;
}

export interface ResponseLike {
  readonly status: number;
  readonly headers: HeadersLike;
  readonly body: ResponseBodyLike | null;
}

export interface FetchRequestInitLike {
  readonly method: "GET" | "POST";
  readonly headers: Readonly<Record<string, string>>;
  readonly redirect: "manual";
  readonly signal: AbortSignal;
  readonly body?: string;
}

export type FetchLike = (
  url: string,
  init: FetchRequestInitLike,
) => Promise<ResponseLike>;

export type SleepPurpose = "timeout" | "backoff";

export type Sleeper = (
  milliseconds: number,
  signal: AbortSignal,
  purpose: SleepPurpose,
) => Promise<void>;

export type Clock = () => number;

export interface NetworkServiceOptions {
  readonly allowedHosts: readonly string[];
  readonly timeoutMs?: number;
  readonly maximumAttempts?: number;
  readonly initialBackoffMs?: number;
  readonly maximumBackoffMs?: number;
  readonly maximumRetryAfterMs?: number;
  readonly maximumResponseBytes?: number;
  readonly maximumRequestBytes?: number;
  readonly fetch?: FetchLike;
  readonly sleeper?: Sleeper;
  readonly clock?: Clock;
}

export interface NetworkRequestOptions {
  readonly method?: "GET" | "POST";
  readonly body?: unknown;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAXIMUM_ATTEMPTS = 3;
const DEFAULT_INITIAL_BACKOFF_MS = 250;
const DEFAULT_MAXIMUM_BACKOFF_MS = 5_000;
const DEFAULT_MAXIMUM_RETRY_AFTER_MS = 30_000;
const DEFAULT_MAXIMUM_RESPONSE_BYTES = 2 * 1024 * 1024;
const DEFAULT_MAXIMUM_REQUEST_BYTES = 256 * 1024;
const MAXIMUM_HOST_LENGTH = 253;

const RETRYABLE_HTTP_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);
const TLS_ERROR_CODE_PATTERN =
  /(?:CERT|TLS|SSL|SELF_SIGNED|UNABLE_TO_VERIFY|DEPTH_ZERO)/iu;
const RETRY_AFTER_EXCEEDS_LIMIT = Symbol("retry-after-exceeds-limit");

function abortError(): Error {
  const error = new Error("Operation aborted");
  error.name = "AbortError";
  return error;
}

const defaultSleeper: Sleeper = (milliseconds, signal) =>
  new Promise<void>((resolve, reject) => {
    if (signal.aborted) {
      reject(abortError());
      return;
    }

    const handle = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, milliseconds);
    const onAbort = (): void => {
      clearTimeout(handle);
      reject(abortError());
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });

const defaultFetch: FetchLike = async (url, init) => {
  const response = await fetch(url, init);
  return response as unknown as ResponseLike;
};

function requirePositiveSafeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${name} must be a positive safe integer`);
  }
  return value;
}

function normalizeAllowedHost(host: string): string {
  const normalized = host.trim().toLowerCase();
  if (
    normalized.length === 0 ||
    normalized.length > MAXIMUM_HOST_LENGTH ||
    normalized.includes(":") ||
    normalized.includes("/") ||
    normalized.includes("@")
  ) {
    throw new TypeError("allowedHosts must contain host names without ports");
  }
  return normalized;
}

function getErrorCode(error: unknown): string | undefined {
  if (typeof error !== "object" || error === null || !("code" in error)) {
    return undefined;
  }
  const code = error.code;
  return typeof code === "string" ? code : undefined;
}

function isTlsFailure(error: unknown): boolean {
  let candidate: unknown = error;
  for (let depth = 0; depth < 4; depth += 1) {
    const code = getErrorCode(candidate);
    if (code !== undefined && TLS_ERROR_CODE_PATTERN.test(code)) {
      return true;
    }
    if (
      typeof candidate !== "object" ||
      candidate === null ||
      !("cause" in candidate)
    ) {
      return false;
    }
    candidate = candidate.cause;
  }
  return false;
}

function isJsonContentType(contentType: string): boolean {
  const mediaType = contentType.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  return mediaType === "application/json" || mediaType.endsWith("+json");
}

async function discardResponseBody(response: ResponseLike): Promise<void> {
  try {
    await response.body?.cancel?.();
  } catch {
    // The response is already being rejected; cancellation is best effort.
  }
}

function parseRetryAfter(
  value: string | null,
  now: number,
  maximumDelay: number,
): number | typeof RETRY_AFTER_EXCEEDS_LIMIT | undefined {
  if (value === null) {
    return undefined;
  }

  const trimmed = value.trim();
  if (/^\d+(?:\.\d+)?$/u.test(trimmed)) {
    const seconds = Number(trimmed);
    if (Number.isFinite(seconds) && seconds >= 0) {
      const milliseconds = Math.ceil(seconds * 1_000);
      return milliseconds > maximumDelay
        ? RETRY_AFTER_EXCEEDS_LIMIT
        : milliseconds;
    }
    return undefined;
  }

  const date = Date.parse(trimmed);
  if (!Number.isFinite(date)) {
    return undefined;
  }
  const milliseconds = Math.max(0, date - now);
  return milliseconds > maximumDelay
    ? RETRY_AFTER_EXCEEDS_LIMIT
    : milliseconds;
}

function cancellationError(): NetworkServiceError {
  return new NetworkServiceError(
    "CANCELLED",
    "The network request was cancelled.",
    false,
  );
}

function timeoutError(): NetworkServiceError {
  return new NetworkServiceError(
    "TIMEOUT",
    "The vulnerability provider request timed out.",
    true,
  );
}

export class NetworkService {
  private readonly allowedHosts: ReadonlySet<string>;
  private readonly timeoutMs: number;
  private readonly maximumAttempts: number;
  private readonly initialBackoffMs: number;
  private readonly maximumBackoffMs: number;
  private readonly maximumRetryAfterMs: number;
  private readonly maximumResponseBytes: number;
  private readonly maximumRequestBytes: number;
  private readonly fetchImplementation: FetchLike;
  private readonly sleeper: Sleeper;
  private readonly clock: Clock;

  public constructor(options: NetworkServiceOptions) {
    const allowedHosts = new Set(options.allowedHosts.map(normalizeAllowedHost));
    if (allowedHosts.size === 0) {
      throw new TypeError("At least one allowed host is required");
    }

    this.allowedHosts = allowedHosts;
    this.timeoutMs = requirePositiveSafeInteger(
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      "timeoutMs",
    );
    this.maximumAttempts = requirePositiveSafeInteger(
      options.maximumAttempts ?? DEFAULT_MAXIMUM_ATTEMPTS,
      "maximumAttempts",
    );
    this.initialBackoffMs = requirePositiveSafeInteger(
      options.initialBackoffMs ?? DEFAULT_INITIAL_BACKOFF_MS,
      "initialBackoffMs",
    );
    this.maximumBackoffMs = requirePositiveSafeInteger(
      options.maximumBackoffMs ?? DEFAULT_MAXIMUM_BACKOFF_MS,
      "maximumBackoffMs",
    );
    this.maximumRetryAfterMs = requirePositiveSafeInteger(
      options.maximumRetryAfterMs ?? DEFAULT_MAXIMUM_RETRY_AFTER_MS,
      "maximumRetryAfterMs",
    );
    this.maximumResponseBytes = requirePositiveSafeInteger(
      options.maximumResponseBytes ?? DEFAULT_MAXIMUM_RESPONSE_BYTES,
      "maximumResponseBytes",
    );
    this.maximumRequestBytes = requirePositiveSafeInteger(
      options.maximumRequestBytes ?? DEFAULT_MAXIMUM_REQUEST_BYTES,
      "maximumRequestBytes",
    );
    this.fetchImplementation = options.fetch ?? defaultFetch;
    this.sleeper = options.sleeper ?? defaultSleeper;
    this.clock = options.clock ?? Date.now;
  }

  public async requestJson(
    rawUrl: string,
    options: NetworkRequestOptions = {},
    signal?: AbortSignal,
  ): Promise<unknown> {
    const url = this.validateUrl(rawUrl);
    const method = options.method ?? "GET";
    const body = this.serializeRequestBody(method, options.body);

    for (let attempt = 1; attempt <= this.maximumAttempts; attempt += 1) {
      this.throwIfCancelled(signal);
      try {
        return await this.executeAttempt(url, method, body, signal);
      } catch (error: unknown) {
        const failure = this.normalizeFailure(error, signal);
        if (!failure.retryable || attempt === this.maximumAttempts) {
          throw failure;
        }

        const delay =
          failure.retryAfterMs ?? this.exponentialDelay(attempt);
        await this.waitForRetry(delay, signal);
      }
    }

    throw new NetworkServiceError(
      "NETWORK_ERROR",
      "The vulnerability provider request failed.",
      false,
    );
  }

  private validateUrl(rawUrl: string): URL {
    let url: URL;
    try {
      url = new URL(rawUrl);
    } catch (error: unknown) {
      throw new NetworkServiceError(
        "INVALID_REQUEST",
        "The vulnerability provider URL is invalid.",
        false,
        { cause: error },
      );
    }

    if (url.protocol !== "https:") {
      throw new NetworkServiceError(
        "HTTPS_REQUIRED",
        "Vulnerability provider requests require HTTPS.",
        false,
      );
    }
    if (url.username.length > 0 || url.password.length > 0 || url.hash.length > 0) {
      throw new NetworkServiceError(
        "INVALID_REQUEST",
        "The vulnerability provider URL contains forbidden components.",
        false,
      );
    }
    if (url.port.length > 0 && url.port !== "443") {
      throw new NetworkServiceError(
        "HOST_NOT_ALLOWED",
        "The vulnerability provider port is not allowed.",
        false,
      );
    }
    if (!this.allowedHosts.has(url.hostname.toLowerCase())) {
      throw new NetworkServiceError(
        "HOST_NOT_ALLOWED",
        "The vulnerability provider host is not allowed.",
        false,
      );
    }
    return url;
  }

  private serializeRequestBody(
    method: "GET" | "POST",
    value: unknown,
  ): string | undefined {
    if (method === "GET") {
      if (value !== undefined) {
        throw new NetworkServiceError(
          "INVALID_REQUEST",
          "GET vulnerability provider requests cannot contain a body.",
          false,
        );
      }
      return undefined;
    }
    if (value === undefined) {
      return undefined;
    }

    let serialized: string | undefined;
    try {
      serialized = JSON.stringify(value);
    } catch (error: unknown) {
      throw new NetworkServiceError(
        "INVALID_REQUEST",
        "The vulnerability provider request body is not valid JSON.",
        false,
        { cause: error },
      );
    }
    if (serialized === undefined) {
      throw new NetworkServiceError(
        "INVALID_REQUEST",
        "The vulnerability provider request body is not valid JSON.",
        false,
      );
    }
    if (new TextEncoder().encode(serialized).byteLength > this.maximumRequestBytes) {
      throw new NetworkServiceError(
        "INVALID_REQUEST",
        "The vulnerability provider request body is too large.",
        false,
      );
    }
    return serialized;
  }

  private async executeAttempt(
    url: URL,
    method: "GET" | "POST",
    body: string | undefined,
    externalSignal: AbortSignal | undefined,
  ): Promise<unknown> {
    const requestController = new AbortController();
    const watchdogController = new AbortController();
    let active = true;
    let cancelled = false;
    let timedOut = false;
    let rejectTermination: (reason: NetworkServiceError) => void = () => undefined;
    const termination = new Promise<never>((_resolve, reject) => {
      rejectTermination = reject;
    });

    const onCancellation = (): void => {
      if (!active) {
        return;
      }
      cancelled = true;
      requestController.abort();
      rejectTermination(cancellationError());
    };
    externalSignal?.addEventListener("abort", onCancellation, { once: true });
    if (externalSignal?.aborted === true) {
      onCancellation();
    }

    const watchdog = this.sleeper(
      this.timeoutMs,
      watchdogController.signal,
      "timeout",
    ).then(
      () => {
        if (!active) {
          return;
        }
        timedOut = true;
        requestController.abort();
        rejectTermination(timeoutError());
      },
      () => {
        if (!active || watchdogController.signal.aborted) {
          return;
        }
        timedOut = true;
        requestController.abort();
        rejectTermination(timeoutError());
      },
    );

    const headers: Record<string, string> = { Accept: "application/json" };
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
    }
    const init: FetchRequestInitLike =
      body === undefined
        ? {
            method,
            headers,
            redirect: "manual",
            signal: requestController.signal,
          }
        : {
            method,
            headers,
            redirect: "manual",
            signal: requestController.signal,
            body,
          };

    const operation = this.fetchImplementation(url.toString(), init)
      .then((response) => this.handleResponse(response))
      .catch((error: unknown) => {
        if (cancelled || externalSignal?.aborted === true) {
          throw cancellationError();
        }
        if (timedOut) {
          throw timeoutError();
        }
        throw error;
      });

    try {
      return await Promise.race([operation, termination]);
    } finally {
      active = false;
      watchdogController.abort();
      externalSignal?.removeEventListener("abort", onCancellation);
      await watchdog;
    }
  }

  private async handleResponse(response: ResponseLike): Promise<unknown> {
    if (
      !Number.isSafeInteger(response.status) ||
      response.status < 100 ||
      response.status > 599
    ) {
      await discardResponseBody(response);
      throw new NetworkServiceError(
        "INVALID_RESPONSE",
        "The vulnerability provider returned an invalid HTTP status.",
        false,
      );
    }

    if (response.status >= 300 && response.status <= 399) {
      await discardResponseBody(response);
      throw new NetworkServiceError(
        "REDIRECT_REJECTED",
        "Vulnerability provider redirects are not allowed.",
        false,
        { status: response.status },
      );
    }

    if (RETRYABLE_HTTP_STATUSES.has(response.status)) {
      const retryAfterMs = parseRetryAfter(
        response.headers.get("retry-after"),
        this.checkedNow(),
        this.maximumRetryAfterMs,
      );
      await discardResponseBody(response);
      if (retryAfterMs === RETRY_AFTER_EXCEEDS_LIMIT) {
        throw new NetworkServiceError(
          response.status === 429 ? "RATE_LIMITED" : "HTTP_ERROR",
          "The vulnerability provider requested a retry delay beyond the configured limit.",
          false,
          { status: response.status },
        );
      }
      if (response.status === 429) {
        throw new NetworkServiceError(
          "RATE_LIMITED",
          "The vulnerability provider rate limit was reached.",
          true,
          { status: response.status, ...(retryAfterMs === undefined ? {} : { retryAfterMs }) },
        );
      }
      throw new NetworkServiceError(
        "HTTP_ERROR",
        "The vulnerability provider returned a transient HTTP error.",
        true,
        { status: response.status, ...(retryAfterMs === undefined ? {} : { retryAfterMs }) },
      );
    }

    if (response.status < 200 || response.status > 299) {
      await discardResponseBody(response);
      throw new NetworkServiceError(
        "HTTP_ERROR",
        "The vulnerability provider returned an HTTP error.",
        false,
        { status: response.status },
      );
    }

    return this.readBoundedJson(response);
  }

  private async readBoundedJson(response: ResponseLike): Promise<unknown> {
    const contentType = response.headers.get("content-type");
    if (contentType === null || !isJsonContentType(contentType)) {
      await discardResponseBody(response);
      throw new NetworkServiceError(
        "INVALID_RESPONSE",
        "The vulnerability provider response is not JSON.",
        false,
      );
    }

    const contentLength = response.headers.get("content-length");
    if (contentLength !== null) {
      if (!/^\d+$/u.test(contentLength.trim())) {
        await discardResponseBody(response);
        throw new NetworkServiceError(
          "INVALID_RESPONSE",
          "The vulnerability provider returned an invalid content length.",
          false,
        );
      }
      const declaredLength = Number(contentLength);
      if (
        !Number.isSafeInteger(declaredLength) ||
        declaredLength > this.maximumResponseBytes
      ) {
        await discardResponseBody(response);
        throw new NetworkServiceError(
          "RESPONSE_TOO_LARGE",
          "The vulnerability provider response is too large.",
          false,
        );
      }
    }

    if (response.body === null) {
      throw new NetworkServiceError(
        "INVALID_RESPONSE",
        "The vulnerability provider returned an empty response.",
        false,
      );
    }

    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) {
          break;
        }
        if (!(chunk.value instanceof Uint8Array) || chunk.value.byteLength === 0) {
          throw new NetworkServiceError(
            "INVALID_RESPONSE",
            "The vulnerability provider returned an invalid response stream.",
            false,
          );
        }
        if (chunk.value.byteLength > this.maximumResponseBytes - totalBytes) {
          await reader.cancel?.();
          throw new NetworkServiceError(
            "RESPONSE_TOO_LARGE",
            "The vulnerability provider response is too large.",
            false,
          );
        }
        chunks.push(chunk.value);
        totalBytes += chunk.value.byteLength;
      }
    } finally {
      reader.releaseLock?.();
    }

    if (totalBytes === 0) {
      throw new NetworkServiceError(
        "INVALID_RESPONSE",
        "The vulnerability provider returned an empty response.",
        false,
      );
    }

    const combined = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      combined.set(chunk, offset);
      offset += chunk.byteLength;
    }

    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(combined);
      return JSON.parse(text) as unknown;
    } catch (error: unknown) {
      throw new NetworkServiceError(
        "INVALID_RESPONSE",
        "The vulnerability provider returned malformed JSON.",
        false,
        { cause: error },
      );
    }
  }

  private normalizeFailure(
    error: unknown,
    signal: AbortSignal | undefined,
  ): NetworkServiceError {
    if (error instanceof NetworkServiceError) {
      return error;
    }
    if (signal?.aborted === true) {
      return cancellationError();
    }
    if (isTlsFailure(error)) {
      return new NetworkServiceError(
        "TLS_ERROR",
        "The vulnerability provider TLS connection failed.",
        false,
        { cause: error },
      );
    }
    return new NetworkServiceError(
      "NETWORK_ERROR",
      "The vulnerability provider network request failed.",
      true,
      { cause: error },
    );
  }

  private exponentialDelay(completedAttempt: number): number {
    const multiplier = 2 ** Math.max(0, completedAttempt - 1);
    return Math.min(this.maximumBackoffMs, this.initialBackoffMs * multiplier);
  }

  private async waitForRetry(
    milliseconds: number,
    externalSignal: AbortSignal | undefined,
  ): Promise<void> {
    this.throwIfCancelled(externalSignal);
    const controller = new AbortController();
    const onCancellation = (): void => {
      controller.abort();
    };
    externalSignal?.addEventListener("abort", onCancellation, { once: true });
    if (externalSignal?.aborted === true) {
      onCancellation();
    }
    try {
      await this.sleeper(milliseconds, controller.signal, "backoff");
    } catch (error: unknown) {
      if (
        controller.signal.aborted ||
        externalSignal?.aborted === true
      ) {
        throw cancellationError();
      }
      throw new NetworkServiceError(
        "NETWORK_ERROR",
        "The vulnerability provider retry delay failed.",
        false,
        { cause: error },
      );
    } finally {
      externalSignal?.removeEventListener("abort", onCancellation);
    }
    this.throwIfCancelled(externalSignal);
  }

  private throwIfCancelled(signal: AbortSignal | undefined): void {
    if (signal?.aborted === true) {
      throw cancellationError();
    }
  }

  private checkedNow(): number {
    const now = this.clock();
    if (!Number.isFinite(now)) {
      throw new NetworkServiceError(
        "INVALID_RESPONSE",
        "The network clock returned an invalid value.",
        false,
      );
    }
    return now;
  }
}
