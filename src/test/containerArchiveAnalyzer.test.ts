import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { analyzeContainerArchive } from "../core/container";

interface FixtureTarEntry {
  readonly path: string;
  readonly data?: Uint8Array;
  readonly type?: number;
}

function writeAscii(
  target: Uint8Array,
  offset: number,
  length: number,
  value: string,
): void {
  const bytes = Buffer.from(value, "ascii");
  target.set(bytes.subarray(0, length), offset);
}

function octal(value: number, digits: number): string {
  return value.toString(8).padStart(digits - 1, "0") + "\0";
}

function buildTar(entries: readonly FixtureTarEntry[]): Uint8Array {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const data = Buffer.from(entry.data ?? new Uint8Array());
    const header = Buffer.alloc(512);
    writeAscii(header, 0, 100, entry.path);
    writeAscii(header, 100, 8, octal(0o644, 8));
    writeAscii(header, 108, 8, octal(0, 8));
    writeAscii(header, 116, 8, octal(0, 8));
    writeAscii(header, 124, 12, octal(data.byteLength, 12));
    writeAscii(header, 136, 12, octal(0, 12));
    header.fill(32, 148, 156);
    header[156] = entry.type ?? 48;
    writeAscii(header, 257, 6, "ustar\0");
    writeAscii(header, 263, 2, "00");
    let checksum = 0;
    for (const byte of header) {
      checksum += byte;
    }
    writeAscii(header, 148, 8, `${checksum.toString(8).padStart(6, "0")}\0 `);
    parts.push(header, data);
    const padding = (512 - (data.byteLength % 512)) % 512;
    if (padding > 0) {
      parts.push(Buffer.alloc(padding));
    }
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

function json(value: unknown): Uint8Array {
  return Buffer.from(JSON.stringify(value), "utf8");
}

function digest(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}

function dockerFixture(): Uint8Array {
  const dpkg = Buffer.from(
    [
      "Package: libc6",
      "Status: install ok installed",
      "Version: 2.36-9",
      "Architecture: amd64",
      "",
      "Package: removed-package",
      "Status: deinstall ok config-files",
      "Version: 1.0",
      "Architecture: amd64",
      "",
    ].join("\n"),
    "utf8",
  );
  const layer = buildTar([
    { path: "var/lib/dpkg/status", data: dpkg },
  ]);
  const config = json({ architecture: "amd64", os: "linux" });
  return buildTar([
    {
      path: "manifest.json",
      data: json([
        {
          Config: "config.json",
          RepoTags: ["example/app:1.0"],
          Layers: ["layer/layer.tar"],
        },
      ]),
    },
    { path: "config.json", data: config },
    { path: "layer/layer.tar", data: layer },
  ]);
}

void test("statically inventories an uncompressed Docker archive without claiming vulnerability coverage", () => {
  const result = analyzeContainerArchive(dockerFixture());
  assert.equal(result.format, "docker-archive");
  assert.equal(result.status, "incomplete");
  assert.equal(result.coverage.archiveMetadata, "complete");
  assert.equal(result.coverage.vulnerabilities, "not-configured");
  assert.equal(result.images.length, 1);
  assert.deepEqual(result.images[0]?.osPackages, [
    {
      packageManager: "dpkg",
      name: "libc6",
      version: "2.36-9",
      architecture: "amd64",
    },
  ]);
  assert.equal(result.images[0]?.reference, "example/app:1.0");
  assert.match(result.images[0]?.digest ?? "", /^sha256:[a-f0-9]{64}$/u);
  assert.equal(
    result.issues[0]?.code,
    "VULNERABILITY_PROVIDER_NOT_CONFIGURED",
  );
});

void test("applies package database whiteouts in layer order", () => {
  const first = buildTar([
    {
      path: "lib/apk/db/installed",
      data: Buffer.from("P:busybox\nV:1.36.1-r0\nA:x86_64\n\n", "utf8"),
    },
  ]);
  const second = buildTar([
    { path: "lib/apk/db/.wh.installed", data: new Uint8Array() },
  ]);
  const archive = buildTar([
    {
      path: "manifest.json",
      data: json([
        {
          Config: "config.json",
          RepoTags: [],
          Layers: ["one/layer.tar", "two/layer.tar"],
        },
      ]),
    },
    { path: "config.json", data: json({ os: "linux", architecture: "amd64" }) },
    { path: "one/layer.tar", data: first },
    { path: "two/layer.tar", data: second },
  ]);
  const result = analyzeContainerArchive(archive);
  assert.equal(result.images[0]?.layersAnalyzed, 2);
  assert.deepEqual(result.images[0]?.osPackages, []);
});

void test("verifies an OCI manifest and uncompressed layer digest", () => {
  const layer = buildTar([
    {
      path: "lib/apk/db/installed",
      data: Buffer.from("P:musl\nV:1.2.4-r2\nA:x86_64\n\n", "utf8"),
    },
  ]);
  const config = json({ os: "linux", architecture: "amd64" });
  const layerDigest = digest(layer);
  const configDigest = digest(config);
  const manifest = json({
    schemaVersion: 2,
    config: {
      mediaType: "application/vnd.oci.image.config.v1+json",
      digest: `sha256:${configDigest}`,
      size: config.byteLength,
    },
    layers: [
      {
        mediaType: "application/vnd.oci.image.layer.v1.tar",
        digest: `sha256:${layerDigest}`,
        size: layer.byteLength,
      },
    ],
  });
  const manifestDigest = digest(manifest);
  const archive = buildTar([
    { path: "oci-layout", data: json({ imageLayoutVersion: "1.0.0" }) },
    {
      path: "index.json",
      data: json({
        schemaVersion: 2,
        manifests: [
          {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: `sha256:${manifestDigest}`,
            size: manifest.byteLength,
            annotations: { "org.opencontainers.image.ref.name": "stable" },
          },
        ],
      }),
    },
    { path: `blobs/sha256/${manifestDigest}`, data: manifest },
    { path: `blobs/sha256/${configDigest}`, data: config },
    { path: `blobs/sha256/${layerDigest}`, data: layer },
  ]);
  const result = analyzeContainerArchive(archive);
  assert.equal(result.format, "oci-archive");
  assert.equal(result.images[0]?.digest, `sha256:${manifestDigest}`);
  assert.equal(result.images[0]?.reference, "stable");
  assert.equal(result.images[0]?.osPackages[0]?.name, "musl");
});

void test("rejects compressed OCI layers explicitly instead of treating the image as clean", () => {
  const config = json({ os: "linux", architecture: "amd64" });
  const layer = Buffer.from("not-a-layer", "utf8");
  const layerDigest = digest(layer);
  const configDigest = digest(config);
  const manifest = json({
    schemaVersion: 2,
    config: { digest: `sha256:${configDigest}`, size: config.byteLength },
    layers: [
      {
        mediaType: "application/vnd.oci.image.layer.v1.tar+gzip",
        digest: `sha256:${layerDigest}`,
        size: layer.byteLength,
      },
    ],
  });
  const manifestDigest = digest(manifest);
  const archive = buildTar([
    { path: "oci-layout", data: json({ imageLayoutVersion: "1.0.0" }) },
    {
      path: "index.json",
      data: json({
        schemaVersion: 2,
        manifests: [
          {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: `sha256:${manifestDigest}`,
            size: manifest.byteLength,
          },
        ],
      }),
    },
    { path: `blobs/sha256/${manifestDigest}`, data: manifest },
    { path: `blobs/sha256/${configDigest}`, data: config },
    { path: `blobs/sha256/${layerDigest}`, data: layer },
  ]);
  const result = analyzeContainerArchive(archive);
  assert.equal(result.status, "unsupported");
  assert.equal(result.issues[0]?.code, "UNSUPPORTED_LAYER");
  assert.deepEqual(result.images, []);
});

void test("rejects traversal, link, duplicate, checksum, and byte-limit attacks", () => {
  const traversal = analyzeContainerArchive(
    buildTar([{ path: "../manifest.json", data: json([]) }]),
  );
  assert.equal(traversal.issues[0]?.code, "UNSAFE_ARCHIVE_ENTRY");

  const link = analyzeContainerArchive(
    buildTar([{ path: "manifest.json", type: 50, data: new Uint8Array() }]),
  );
  assert.equal(link.issues[0]?.code, "UNSAFE_ARCHIVE_ENTRY");

  const duplicate = analyzeContainerArchive(
    buildTar([
      { path: "manifest.json", data: json([]) },
      { path: "manifest.json", data: json([]) },
    ]),
  );
  assert.equal(duplicate.issues[0]?.code, "INVALID_ARCHIVE");

  const damaged = dockerFixture().slice();
  damaged[0] = (damaged[0] ?? 0) ^ 1;
  const checksum = analyzeContainerArchive(damaged);
  assert.equal(checksum.issues[0]?.code, "INVALID_ARCHIVE");

  const limited = analyzeContainerArchive(dockerFixture(), {
    limits: { maximumArchiveBytes: 512 },
  });
  assert.equal(limited.issues[0]?.code, "LIMIT_EXCEEDED");
});

void test("cancellation and malformed package databases fail closed", () => {
  const controller = new AbortController();
  controller.abort();
  const cancelled = analyzeContainerArchive(dockerFixture(), {
    signal: controller.signal,
  });
  assert.equal(cancelled.issues[0]?.code, "CANCELLED");

  const layer = buildTar([
    {
      path: "var/lib/dpkg/status",
      data: Buffer.from(
        "Package: bad package\nStatus: install ok installed\nVersion: 1.0\n\n",
        "utf8",
      ),
    },
  ]);
  const malformed = analyzeContainerArchive(
    buildTar([
      {
        path: "manifest.json",
        data: json([{ Config: "config.json", RepoTags: [], Layers: ["layer.tar"] }]),
      },
      { path: "config.json", data: json({ os: "linux" }) },
      { path: "layer.tar", data: layer },
    ]),
  );
  assert.equal(malformed.issues[0]?.code, "PACKAGE_DATABASE_INVALID");
  assert.deepEqual(malformed.images, []);
});
