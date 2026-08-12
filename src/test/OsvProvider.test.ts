import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import type { Dependency } from "../models/Dependency";
import type { Logger } from "../services/Logger";
import type {
  NetworkRequestOptions,
  NetworkService,
} from "../services/NetworkService";
import {
  OsvProvider,
  isSafeNpmPackageName,
} from "../vulnerability/providers/OsvProvider";
import { VulnerabilityNormalizationError } from "../vulnerability/VulnerabilityNormalizer";

const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const fixtureDirectory = join(
  process.cwd(),
  "src",
  "test",
  "fixtures",
  "mock-osv",
);

type RequestHandler = (
  url: string,
  options?: NetworkRequestOptions,
  signal?: AbortSignal,
) => Promise<unknown>;

class TestLogger implements Logger {
  public readonly infoMessages: string[] = [];
  public readonly warningMessages: string[] = [];
  public readonly errorMessages: string[] = [];
  public showCount = 0;

  public info(message: string): void {
    this.infoMessages.push(message);
  }

  public warn(message: string): void {
    this.warningMessages.push(message);
  }

  public error(message: string): void {
    this.errorMessages.push(message);
  }

  public show(): void {
    this.showCount += 1;
  }
}

function mockNetwork(handler: RequestHandler): NetworkService {
  return { requestJson: handler } as unknown as NetworkService;
}

function fixture(name: string): unknown {
  return JSON.parse(
    readFileSync(join(fixtureDirectory, name), "utf8"),
  ) as unknown;
}

function dependency(
  name: string,
  installedVersion: string,
): Dependency {
  return {
    name,
    ecosystem: "npm",
    installedVersion,
    dependencyType: "transitive",
    environment: "production",
    packageJsonPath: "/workspace/package.json",
    lockfilePath: "/workspace/package-lock.json",
  };
}

function exactVersionVulnerability(
  id: string,
  packageName: string,
  version: string,
): unknown {
  return {
    id,
    modified: "2026-03-01T00:00:00Z",
    summary: `${id} summary`,
    affected: [
      {
        package: { ecosystem: "npm", name: packageName },
        versions: [version],
      },
    ],
  };
}

function requestBody(
  options: NetworkRequestOptions | undefined,
): {
  readonly package: { readonly ecosystem: string; readonly name: string };
  readonly version: string;
  readonly page_token?: string;
} {
  assert.ok(options !== undefined);
  assert.equal(options.method, "POST");
  assert.ok(typeof options.body === "object" && options.body !== null);
  return options.body as ReturnType<typeof requestBody>;
}

function abortError(): Error {
  const error = new Error("cancelled by test");
  error.name = "AbortError";
  return error;
}

void test("sends only the minimal npm package identity and version", async () => {
  const logger = new TestLogger();
  const requests: Array<{
    readonly url: string;
    readonly options: NetworkRequestOptions | undefined;
    readonly signal: AbortSignal | undefined;
  }> = [];
  const provider = new OsvProvider(
    mockNetwork(async (url, options, signal) => {
      requests.push({ url, options, signal });
      return fixture("empty.json");
    }),
    logger,
  );

  const result = await provider.checkPackage("axios", "npm", "1.6.2");

  assert.deepEqual(result, []);
  assert.deepEqual(requests, [
    {
      url: OSV_QUERY_URL,
      options: {
        method: "POST",
        body: {
          package: { ecosystem: "npm", name: "axios" },
          version: "1.6.2",
        },
      },
      signal: undefined,
    },
  ]);
  assert.deepEqual(logger.infoMessages, ["OSV query: npm / axios / 1.6.2"]);
});

void test("normalizes an empty OSV response", async () => {
  const provider = new OsvProvider(
    mockNetwork(async () => fixture("empty.json")),
    new TestLogger(),
  );

  assert.deepEqual(
    await provider.checkPackage("fixture-package", "npm", "1.2.3"),
    [],
  );
});

void test("queries a canonical non-npm ecosystem identity", async () => {
  let body: ReturnType<typeof requestBody> | undefined;
  const provider = new OsvProvider(
    mockNetwork(async (_url, options) => {
      body = requestBody(options);
      return {
        vulns: [
          {
            id: "PYSEC-TEST-1",
            modified: "2026-08-01T00:00:00Z",
            affected: [
              {
                package: { ecosystem: "PyPI", name: "requests" },
                versions: ["2.31.0"],
              },
            ],
          },
        ],
      };
    }),
    new TestLogger(),
  );

  const results = await provider.checkPackage(
    "requests",
    "PyPI",
    "2.31.0",
  );

  assert.deepEqual(body, {
    package: { ecosystem: "PyPI", name: "requests" },
    version: "2.31.0",
  });
  assert.equal(results[0]?.ecosystem, "PyPI");
  assert.equal(results[0]?.packageName, "requests");
});

void test("normalizes one affected vulnerability with aliases and a fix", async () => {
  const provider = new OsvProvider(
    mockNetwork(async () => fixture("one-vulnerability.json")),
    new TestLogger(),
  );

  const vulnerabilities = await provider.checkPackage(
    "fixture-package",
    "npm",
    "1.2.3",
  );

  assert.deepEqual(vulnerabilities, [
    {
      id: "GHSA-aaaa-bbbb-cccc",
      aliases: ["CVE-2026-0001"],
      packageName: "fixture-package",
      ecosystem: "npm",
      installedVersion: "1.2.3",
      severity: "HIGH",
      summary: "Deterministic fixture vulnerability",
      details: "Used only by the offline provider tests.",
      affectedRange: ">=1.0.0 <1.2.4",
      fixedVersions: ["1.2.4"],
      remediationCandidates: ["1.2.4"],
      fixedVersion: "1.2.4",
      references: [
        "https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc",
      ],
      published: "2026-01-01T00:00:00Z",
      modified: "2026-01-02T03:04:05Z",
      source: "OSV",
      providerSeverity: "HIGH",
    },
  ]);
});

void test("normalizes multiple vulnerabilities without losing aliases", async () => {
  const provider = new OsvProvider(
    mockNetwork(async () => fixture("multiple-vulnerabilities.json")),
    new TestLogger(),
  );

  const vulnerabilities = await provider.checkPackage(
    "fixture-package",
    "npm",
    "1.2.3",
  );

  assert.deepEqual(
    vulnerabilities.map((vulnerability) => vulnerability.id),
    ["OSV-TEST-ONE", "OSV-TEST-TWO"],
  );
  assert.deepEqual(vulnerabilities[1]?.aliases, [
    "CVE-2026-0002",
    "GHSA-dddd-eeee-ffff",
  ]);
  assert.deepEqual(
    vulnerabilities.map((vulnerability) => vulnerability.severity),
    ["MEDIUM", "LOW"],
  );
});

void test("deduplicates alias-connected OSV records conservatively", async () => {
  const affected = (fixed: string): Record<string, unknown> => ({
    package: { ecosystem: "npm", name: "fixture-package" },
    ranges: [
      {
        type: "SEMVER",
        events: [{ introduced: "0" }, { fixed }],
      },
    ],
  });
  const provider = new OsvProvider(
    mockNetwork(async () => ({
      vulns: [
        {
          id: "GHSA-first",
          aliases: ["CVE-2026-9999", "GHSA-second"],
          modified: "2026-01-01T00:00:00Z",
          summary: "First source record",
          affected: [affected("1.2.4")],
          database_specific: { severity: "HIGH" },
          references: [
            { type: "ADVISORY", url: "https://example.test/first" },
          ],
        },
        {
          id: "GHSA-second",
          aliases: ["CVE-2026-9999", "GHSA-first"],
          modified: "2026-01-02T00:00:00Z",
          summary: "Second source record",
          affected: [affected("1.3.0")],
          database_specific: { severity: "CRITICAL" },
          references: [
            { type: "ADVISORY", url: "https://example.test/second" },
          ],
        },
      ],
    })),
    new TestLogger(),
  );

  const vulnerabilities = await provider.checkPackage(
    "fixture-package",
    "npm",
    "1.2.3",
  );

  assert.equal(vulnerabilities.length, 1);
  assert.equal(vulnerabilities[0]?.id, "GHSA-first");
  assert.deepEqual(vulnerabilities[0]?.aliases, [
    "CVE-2026-9999",
    "GHSA-second",
  ]);
  assert.equal(vulnerabilities[0]?.severity, "CRITICAL");
  assert.equal(vulnerabilities[0]?.fixedVersion, undefined);
  assert.deepEqual(vulnerabilities[0]?.fixedVersions, ["1.2.4", "1.3.0"]);
  assert.equal(vulnerabilities[0]?.fixedVersionConflict, true);
  assert.deepEqual(vulnerabilities[0]?.references, [
    "https://example.test/first",
    "https://example.test/second",
  ]);
});

void test("keeps a no-fix advisory as a valid provider finding", async () => {
  const provider = new OsvProvider(
    mockNetwork(async () => ({
      vulns: [
        {
          id: "OSV-NO-FIX",
          modified: "2026-08-01T00:00:00Z",
          affected: [
            {
              package: { ecosystem: "npm", name: "fixture-package" },
              versions: ["1.2.3"],
            },
          ],
        },
      ],
    })),
    new TestLogger(),
  );

  const vulnerabilities = await provider.checkPackage(
    "fixture-package",
    "npm",
    "1.2.3",
  );

  assert.equal(vulnerabilities.length, 1);
  assert.deepEqual(vulnerabilities[0]?.fixedVersions, []);
  assert.equal(vulnerabilities[0]?.fixedVersion, undefined);
  assert.equal(vulnerabilities[0]?.fixedVersionConflict, undefined);
});

void test("keeps package identity stable across concurrent paginated queries", async () => {
  const requests: Array<{
    readonly name: string;
    readonly version: string;
    readonly pageToken?: string;
  }> = [];
  const provider = new OsvProvider(
    mockNetwork(async (_url, options) => {
      const body = requestBody(options);
      requests.push({
        name: body.package.name,
        version: body.version,
        ...(body.page_token === undefined
          ? {}
          : { pageToken: body.page_token }),
      });
      if (body.page_token === undefined) {
        return {
          vulns: [
            exactVersionVulnerability(
              `${body.package.name}-page-one`,
              body.package.name,
              body.version,
            ),
          ],
          next_page_token: `${body.package.name}-next`,
        };
      }
      assert.equal(body.page_token, `${body.package.name}-next`);
      return {
        vulns: [
          exactVersionVulnerability(
            `${body.package.name}-page-two`,
            body.package.name,
            body.version,
          ),
        ],
      };
    }),
    new TestLogger(),
  );

  const vulnerabilities = await provider.checkPackages([
    dependency("alpha", "1.0.0"),
    dependency("beta", "2.0.0"),
  ]);

  assert.equal(requests.length, 4);
  assert.deepEqual(
    vulnerabilities
      .map((vulnerability) => [
        vulnerability.id,
        vulnerability.packageName,
        vulnerability.installedVersion,
      ])
      .sort(([left], [right]) => String(left).localeCompare(String(right))),
    [
      ["alpha-page-one", "alpha", "1.0.0"],
      ["alpha-page-two", "alpha", "1.0.0"],
      ["beta-page-one", "beta", "2.0.0"],
      ["beta-page-two", "beta", "2.0.0"],
    ],
  );
});

void test("rejects unsafe package names and traversal before networking", async () => {
  let requestCount = 0;
  const provider = new OsvProvider(
    mockNetwork(async () => {
      requestCount += 1;
      return fixture("empty.json");
    }),
    new TestLogger(),
  );
  const unsafeNames = [
    "../lodash",
    "@scope/../lodash",
    "/absolute",
    "C:\\temp",
    "lodash\nforged",
  ];

  for (const packageName of unsafeNames) {
    assert.equal(isSafeNpmPackageName(packageName), false);
    await assert.rejects(
      provider.checkPackage(packageName, "npm", "1.0.0"),
      TypeError,
    );
  }
  assert.equal(requestCount, 0);
});

void test("rejects non-exact and malformed versions before networking", async () => {
  let requestCount = 0;
  const provider = new OsvProvider(
    mockNetwork(async () => {
      requestCount += 1;
      return fixture("empty.json");
    }),
    new TestLogger(),
  );

  for (const version of ["^1.2.3", "1.2", "latest", "1.2.3\n"]) {
    await assert.rejects(
      provider.checkPackage("safe-package", "npm", version),
      TypeError,
    );
  }
  assert.equal(requestCount, 0);
});

void test("bounds checkPackages network concurrency at five", async () => {
  let activeRequests = 0;
  let maximumActiveRequests = 0;
  let requestCount = 0;
  const provider = new OsvProvider(
    mockNetwork(async () => {
      requestCount += 1;
      activeRequests += 1;
      maximumActiveRequests = Math.max(maximumActiveRequests, activeRequests);
      try {
        await new Promise<void>((resolve) => setImmediate(resolve));
        return fixture("empty.json");
      } finally {
        activeRequests -= 1;
      }
    }),
    new TestLogger(),
  );
  const dependencies = Array.from({ length: 20 }, (_value, index) =>
    dependency(`package-${index.toString()}`, `1.0.${index.toString()}`),
  );

  assert.deepEqual(await provider.checkPackages(dependencies), []);
  assert.equal(requestCount, 20);
  assert.equal(maximumActiveRequests, 5);
});

void test("cancellation aborts active work and prevents new scheduling", async () => {
  const controller = new AbortController();
  let requestCount = 0;
  let notifyFiveStarted: (() => void) | undefined;
  const fiveStarted = new Promise<void>((resolve) => {
    notifyFiveStarted = resolve;
  });
  const provider = new OsvProvider(
    mockNetwork(async (_url, _options, signal) => {
      requestCount += 1;
      if (requestCount === 5) {
        notifyFiveStarted?.();
      }
      return new Promise<never>((_resolve, reject) => {
        if (signal?.aborted === true) {
          reject(abortError());
          return;
        }
        signal?.addEventListener("abort", () => reject(abortError()), {
          once: true,
        });
      });
    }),
    new TestLogger(),
  );
  const dependencies = Array.from({ length: 20 }, (_value, index) =>
    dependency(`cancel-package-${index.toString()}`, "1.0.0"),
  );

  const scan = provider.checkPackages(dependencies, controller.signal);
  await fiveStarted;
  controller.abort();
  await assert.rejects(scan, (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.name, "AbortError");
    return true;
  });
  assert.equal(requestCount, 5);
});

void test("a package failure aborts peers and stops further scheduling", async () => {
  const expectedFailure = new Error("deterministic provider failure");
  let requestCount = 0;
  const provider = new OsvProvider(
    mockNetwork(async (_url, options, signal) => {
      requestCount += 1;
      if (requestBody(options).package.name === "failure-package-0") {
        throw expectedFailure;
      }
      return new Promise<never>((_resolve, reject) => {
        if (signal?.aborted === true) {
          reject(abortError());
          return;
        }
        signal?.addEventListener("abort", () => reject(abortError()), {
          once: true,
        });
      });
    }),
    new TestLogger(),
  );
  const dependencies = Array.from({ length: 20 }, (_value, index) =>
    dependency(`failure-package-${index.toString()}`, "1.0.0"),
  );

  await assert.rejects(
    provider.checkPackages(dependencies),
    (error: unknown) => error === expectedFailure,
  );
  assert.equal(requestCount, 5);
});

void test("rejects malformed responses and repeated pagination tokens", async () => {
  const malformedProvider = new OsvProvider(
    mockNetwork(async () => ({ vulns: {} })),
    new TestLogger(),
  );
  await assert.rejects(
    malformedProvider.checkPackage("safe-package", "npm", "1.0.0"),
    VulnerabilityNormalizationError,
  );

  let requestCount = 0;
  const repeatedTokenProvider = new OsvProvider(
    mockNetwork(async () => {
      requestCount += 1;
      return { vulns: [], next_page_token: "same-token" };
    }),
    new TestLogger(),
  );
  await assert.rejects(
    repeatedTokenProvider.checkPackage("safe-package", "npm", "1.0.0"),
    (error: unknown) => {
      assert.ok(error instanceof VulnerabilityNormalizationError);
      assert.match(error.message, /repeated pagination token/u);
      return true;
    },
  );
  assert.equal(requestCount, 2);
});
