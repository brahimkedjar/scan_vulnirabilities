import assert from "node:assert/strict";
import { test } from "node:test";

import type {
  CoreDirectoryEntry,
  CoreFileIdentity,
  CoreFileSystem,
  CoreFileSystemRoot,
  CoreTextFile,
} from "../core/host/HostContracts";
import { analyzeWorkspaceReachability } from "../core/reachability/NodeSourceCollector";

const identity: CoreFileIdentity = {
  device: "1",
  inode: "1",
  size: 0,
  modifiedMs: 0,
};

class MemorySourceFileSystem implements CoreFileSystem {
  public reads = 0;

  public constructor(
    private readonly entries: ReadonlyMap<string, readonly CoreDirectoryEntry[]>,
    private readonly files: ReadonlyMap<string, string>,
  ) {}

  public async openRoot(path: string): Promise<CoreFileSystemRoot> {
    return { path, realPath: path };
  }

  public async readDirectory(
    _root: CoreFileSystemRoot,
    directory: string,
  ): Promise<readonly CoreDirectoryEntry[]> {
    return this.entries.get(directory) ?? [];
  }

  public async readTextFile(
    _root: CoreFileSystemRoot,
    file: string,
    maximumBytes: number,
  ): Promise<CoreTextFile> {
    this.reads += 1;
    const text = this.files.get(file);
    if (text === undefined || Buffer.byteLength(text) > maximumBytes) {
      throw new Error("unsafe fixture read");
    }
    return { path: file, text, bytes: Buffer.byteLength(text), identity };
  }
}

function entry(
  name: string,
  path: string,
  type: "file" | "directory" | "symlink",
  size = 0,
): CoreDirectoryEntry {
  return { name, path, type, size, identity: { ...identity, size } };
}

void test("collects bounded application source and never traverses node_modules", async () => {
  const source = "import { vulnerableApi } from 'fixture-package'; vulnerableApi();";
  const fileSystem = new MemorySourceFileSystem(
    new Map([
      [
        "/repo",
        [
          entry("src", "/repo/src", "directory"),
          entry("node_modules", "/repo/node_modules", "directory"),
        ],
      ],
      ["/repo/src", [entry("index.ts", "/repo/src/index.ts", "file", Buffer.byteLength(source))]],
      [
        "/repo/node_modules",
        [entry("evil.js", "/repo/node_modules/evil.js", "file", 10)],
      ],
    ]),
    new Map([["/repo/src/index.ts", source]]),
  );
  const result = await analyzeWorkspaceReachability(
    fileSystem,
    "/repo",
    [
      {
        targetId: "finding-1",
        ecosystem: "npm",
        packageName: "fixture-package",
        affectedSymbols: ["vulnerableApi"],
      },
    ],
  );
  assert.equal(result.findings[0]?.status, "REACHABLE");
  assert.deepEqual(result.findings[0]?.path, [
    "src/index.ts",
    "fixture-package",
    "vulnerableApi",
  ]);
  assert.equal(fileSystem.reads, 1);
});

void test("symlinks and byte-limit omissions force UNKNOWN rather than NOT_OBSERVED", async () => {
  const fileSystem = new MemorySourceFileSystem(
    new Map([
      [
        "/repo",
        [
          entry("linked.ts", "/repo/linked.ts", "symlink"),
          entry("large.ts", "/repo/large.ts", "file", 100),
        ],
      ],
    ]),
    new Map([["/repo/large.ts", "x".repeat(100)]]),
  );
  const result = await analyzeWorkspaceReachability(
    fileSystem,
    "/repo",
    [
      {
        targetId: "finding-1",
        ecosystem: "npm",
        packageName: "fixture-package",
      },
    ],
    { maximumCandidateBytes: 10, maximumSourceBytesPerFile: 10 },
  );
  assert.equal(result.findings[0]?.status, "UNKNOWN");
  assert.equal(result.coverage.analysisComplete, false);
  assert.equal(fileSystem.reads, 0);
});

void test("cancellation stops collection without a clean reachability claim", async () => {
  const controller = new AbortController();
  controller.abort();
  const fileSystem = new MemorySourceFileSystem(
    new Map([["/repo", []]]),
    new Map(),
  );
  const result = await analyzeWorkspaceReachability(
    fileSystem,
    "/repo",
    [
      {
        targetId: "finding-1",
        ecosystem: "PyPI",
        packageName: "requests",
      },
    ],
    { signal: controller.signal },
  );
  assert.equal(result.findings[0]?.status, "UNKNOWN");
  assert.equal(result.coverage.cancelled, true);
});

