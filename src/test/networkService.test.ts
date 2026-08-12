import { strict as assert } from "node:assert";
import { test } from "node:test";

import {
  NetworkService,
  NetworkServiceError,
  type FetchLike,
  type FetchRequestInitLike,
  type HeadersLike,
  type ResponseBodyLike,
  type ResponseLike,
  type Sleeper,
} from "../services/NetworkService";

class TestHeaders implements HeadersLike {
  private readonly values: ReadonlyMap<string, string>;

  public constructor(values: Readonly<Record<string, string>> = {}) {
    this.values = new Map(
      Object.entries(values).map(([name, value]) => [name.toLowerCase(), value]),
    );
  }

  public get(name: string): string | null {
    return this.values.get(name.toLowerCase()) ?? null;
  }
}

function abortedSleep(): Error {
  const error = new Error("aborted");
  error.name = "AbortError";
  return error;
}

function pendingTimeoutSleeper(
  backoffDelays: number[] = [],
): Sleeper {
  return async (milliseconds, signal, purpose) => {
    if (purpose === "backoff") {
      backoffDelays.push(milliseconds);
      return;
    }
    await new Promise<void>((_resolve, reject) => {
      if (signal.aborted) {
        reject(abortedSleep());
        return;
      }
      signal.addEventListener("abort", () => reject(abortedSleep()), {
        once: true,
      });
    });
  };
}

function bodyFromChunks(
  chunks: readonly Uint8Array[],
  onCancel: () => void = () => undefined,
): ResponseBodyLike {
  let index = 0;
  return {
    getReader: () => ({
      read: async () => {
        const value = chunks[index];
        index += 1;
        return value === undefined
          ? { done: true }
          : { done: false, value };
      },
      cancel: async () => {
        onCancel();
      },
    }),
    cancel: async () => {
      onCancel();
    },
  };
}

function response(
  status: number,
  body: ResponseBodyLike | null,
  headers: Readonly<Record<string, string>> = {},
): ResponseLike {
  return {
    status,
    body,
    headers: new TestHeaders(headers),
  };
}

function jsonResponse(status: number, value: unknown): ResponseLike {
  const encoded = new TextEncoder().encode(JSON.stringify(value));
  return response(status, bodyFromChunks([encoded]), {
    "content-type": "application/json; charset=utf-8",
    "content-length": encoded.byteLength.toString(),
  });
}

async function expectCode(
  promise: Promise<unknown>,
  code: NetworkServiceError["code"],
): Promise<NetworkServiceError> {
  let captured: NetworkServiceError | undefined;
  await assert.rejects(promise, (error: unknown) => {
    assert.ok(error instanceof NetworkServiceError);
    assert.equal(error.code, code);
    captured = error;
    return true;
  });
  assert.ok(captured !== undefined);
  return captured;
}

void test("enforces HTTPS and an exact host allowlist before fetching", async () => {
  let fetchCount = 0;
  const fetchImplementation: FetchLike = async () => {
    fetchCount += 1;
    return jsonResponse(200, {});
  };
  const service = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    fetch: fetchImplementation,
    sleeper: pendingTimeoutSleeper(),
  });

  await expectCode(
    service.requestJson("http://api.osv.dev/v1/query"),
    "HTTPS_REQUIRED",
  );
  await expectCode(
    service.requestJson("https://api.osv.dev.evil.example/v1/query"),
    "HOST_NOT_ALLOWED",
  );
  await expectCode(
    service.requestJson("https://api.osv.dev:8443/v1/query"),
    "HOST_NOT_ALLOWED",
  );
  assert.equal(fetchCount, 0);
});

void test("posts JSON, rejects redirects, and never follows their location", async () => {
  let capturedInit: FetchRequestInitLike | undefined;
  const fetchImplementation: FetchLike = async (_url, init) => {
    capturedInit = init;
    return response(302, null, {
      location: "http://127.0.0.1/internal",
    });
  };
  const service = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    maximumAttempts: 1,
    fetch: fetchImplementation,
    sleeper: pendingTimeoutSleeper(),
  });

  const failure = await expectCode(
    service.requestJson(
      "https://api.osv.dev/v1/query",
      { method: "POST", body: { package: { name: "demo" } } },
    ),
    "REDIRECT_REJECTED",
  );

  assert.equal(failure.status, 302);
  assert.equal(capturedInit?.redirect, "manual");
  assert.equal(capturedInit?.method, "POST");
  assert.equal(capturedInit?.body, '{"package":{"name":"demo"}}');
});

void test("honors bounded Retry-After then uses exponential backoff", async () => {
  const replies = [
    response(429, null, { "retry-after": "2" }),
    response(503, null),
    jsonResponse(200, { vulns: [] }),
  ];
  let fetchCount = 0;
  const fetchImplementation: FetchLike = async () => {
    const reply = replies[fetchCount];
    fetchCount += 1;
    assert.ok(reply !== undefined);
    return reply;
  };
  const delays: number[] = [];
  const service = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    maximumAttempts: 3,
    initialBackoffMs: 100,
    maximumBackoffMs: 1_000,
    maximumRetryAfterMs: 5_000,
    fetch: fetchImplementation,
    sleeper: pendingTimeoutSleeper(delays),
    clock: () => 1_000,
  });

  const result = await service.requestJson("https://api.osv.dev/v1/query");

  assert.deepEqual(result, { vulns: [] });
  assert.equal(fetchCount, 3);
  assert.deepEqual(delays, [2_000, 200]);
});

void test("retries HTTP 500 and succeeds without treating it as a clean result", async () => {
  const replies = [response(500, null), jsonResponse(200, { vulns: [] })];
  let fetchCount = 0;
  const fetchImplementation: FetchLike = async () => {
    const reply = replies[fetchCount];
    fetchCount += 1;
    assert.ok(reply !== undefined);
    return reply;
  };
  const delays: number[] = [];
  const service = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    maximumAttempts: 2,
    initialBackoffMs: 50,
    fetch: fetchImplementation,
    sleeper: pendingTimeoutSleeper(delays),
  });

  assert.deepEqual(
    await service.requestJson("https://api.osv.dev/v1/query"),
    { vulns: [] },
  );
  assert.equal(fetchCount, 2);
  assert.deepEqual(delays, [50]);
});

void test("does not retry earlier than an excessive Retry-After delay", async () => {
  let fetchCount = 0;
  const service = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    maximumAttempts: 3,
    maximumRetryAfterMs: 5_000,
    fetch: async () => {
      fetchCount += 1;
      return response(429, null, { "retry-after": "3600" });
    },
    sleeper: pendingTimeoutSleeper(),
  });

  const failure = await expectCode(
    service.requestJson("https://api.osv.dev/v1/query"),
    "RATE_LIMITED",
  );
  assert.equal(failure.retryable, false);
  assert.equal(fetchCount, 1);
});

void test("returns a typed timeout even when fetch ignores abort", async () => {
  const neverResolvingFetch: FetchLike = async () =>
    new Promise<ResponseLike>(() => undefined);
  const timeoutImmediately: Sleeper = async (_milliseconds, signal, purpose) => {
    if (purpose === "timeout") {
      return;
    }
    if (signal.aborted) {
      throw abortedSleep();
    }
  };
  const service = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    maximumAttempts: 1,
    fetch: neverResolvingFetch,
    sleeper: timeoutImmediately,
  });

  await expectCode(
    service.requestJson("https://api.osv.dev/v1/query"),
    "TIMEOUT",
  );
});

void test("cancellation interrupts an in-flight request and is not retried", async () => {
  let fetchCount = 0;
  const neverResolvingFetch: FetchLike = async () => {
    fetchCount += 1;
    return new Promise<ResponseLike>(() => undefined);
  };
  const service = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    fetch: neverResolvingFetch,
    sleeper: pendingTimeoutSleeper(),
  });
  const controller = new AbortController();

  const request = service.requestJson(
    "https://api.osv.dev/v1/query",
    {},
    controller.signal,
  );
  controller.abort();

  await expectCode(request, "CANCELLED");
  assert.equal(fetchCount, 1);
});

void test("bounds streamed bodies before JSON parsing", async () => {
  let cancelCount = 0;
  const fetchImplementation: FetchLike = async () =>
    response(
      200,
      bodyFromChunks(
        [new TextEncoder().encode('{"a":'), new TextEncoder().encode('"12345"}')],
        () => {
          cancelCount += 1;
        },
      ),
      { "content-type": "application/json" },
    );
  const service = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    maximumAttempts: 1,
    maximumResponseBytes: 8,
    fetch: fetchImplementation,
    sleeper: pendingTimeoutSleeper(),
  });

  await expectCode(
    service.requestJson("https://api.osv.dev/v1/query"),
    "RESPONSE_TOO_LARGE",
  );
  assert.equal(cancelCount, 1);
});

void test("does not retry certificate failures", async () => {
  let fetchCount = 0;
  const fetchImplementation: FetchLike = async () => {
    fetchCount += 1;
    throw new TypeError("fetch failed", {
      cause: { code: "SELF_SIGNED_CERT_IN_CHAIN" },
    });
  };
  const service = new NetworkService({
    allowedHosts: ["api.osv.dev"],
    fetch: fetchImplementation,
    sleeper: pendingTimeoutSleeper(),
  });

  await expectCode(
    service.requestJson("https://api.osv.dev/v1/query"),
    "TLS_ERROR",
  );
  assert.equal(fetchCount, 1);
});
