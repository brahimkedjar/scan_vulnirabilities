import { strict as assert } from "node:assert";
import { Module } from "node:module";
import { test } from "node:test";

import type * as vscode from "vscode";

import type { WorkspaceRegistrySnapshot } from "../package-managers/npm/NpmRegistryProvenance";

interface ReaderModule {
  discoverWorkspaceRegistrySnapshot(
    workspaceFolder: vscode.Uri,
    signal?: AbortSignal,
    cancellationToken?: vscode.CancellationToken,
  ): Promise<WorkspaceRegistrySnapshot>;
}

interface FakeUri extends vscode.Uri {
  readonly path: string;
  readonly fsPath: string;
}

interface FakeState {
  matches: FakeUri[];
  readonly contents: Map<string, Uint8Array>;
  readonly findCalls: Array<{
    readonly pattern: string;
    readonly exclude: string;
    readonly maximum: number;
    readonly token?: vscode.CancellationToken;
  }>;
  readonly reads: string[];
  cancelAfterRead: vscode.CancellationToken | undefined;
}

type ModuleLoader = (
  request: string,
  parent: unknown,
  isMain: boolean,
) => unknown;

function fakeUri(path: string): FakeUri {
  const normalized = path.replaceAll("\\", "/");
  return {
    scheme: "file",
    authority: "",
    path: normalized,
    fsPath: normalized,
    query: "",
    fragment: "",
    with: () => fakeUri(normalized),
    toJSON: () => ({ path: normalized }),
    toString: () => `file:${normalized}`,
  } as FakeUri;
}

function joinPath(base: FakeUri, ...segments: readonly string[]): FakeUri {
  const parts = base.path.split("/");
  for (const segment of segments) {
    if (segment === "..") {
      parts.pop();
    } else {
      parts.push(segment);
    }
  }
  return fakeUri(parts.join("/"));
}

function fakeVscode(state: FakeState): object {
  return {
    RelativePattern: class {
      public constructor(
        _base: unknown,
        public readonly pattern: string,
      ) {}
    },
    Uri: {
      joinPath,
    },
    workspace: {
      findFiles: async (
        pattern: { readonly pattern: string },
        exclude: string,
        maximum: number,
        token?: vscode.CancellationToken,
      ): Promise<readonly FakeUri[]> => {
        state.findCalls.push({
          pattern: pattern.pattern,
          exclude,
          maximum,
          ...(token === undefined ? {} : { token }),
        });
        return state.matches;
      },
      fs: {
        stat: async (uri: FakeUri): Promise<{ readonly size: number }> => ({
          size: state.contents.get(uri.path)?.byteLength ?? 0,
        }),
        readFile: async (uri: FakeUri): Promise<Uint8Array> => {
          state.reads.push(uri.path);
          const bytes = state.contents.get(uri.path) ?? new Uint8Array();
          if (state.cancelAfterRead !== undefined) {
            Object.assign(state.cancelAfterRead, {
              isCancellationRequested: true,
            });
          }
          return bytes;
        },
      },
    },
  };
}

async function loadReader(vscodeStub: object): Promise<ReaderModule> {
  const loader = Module as unknown as { _load: ModuleLoader };
  const originalLoad = loader._load;
  loader._load = function loadWithVscodeStub(
    this: unknown,
    request: string,
    parent: unknown,
    isMain: boolean,
  ): unknown {
    return request === "vscode"
      ? vscodeStub
      : originalLoad.call(this, request, parent, isMain);
  };
  try {
    return (await import(
      "../package-managers/npm/NpmRegistryProvenanceReader.js"
    )) as ReaderModule;
  } finally {
    loader._load = originalLoad;
  }
}

void test("registry discovery stays workspace-local, bounded, deterministic, and cancellable", async () => {
  const encoder = new TextEncoder();
  const state: FakeState = {
    matches: [fakeUri("/workspace/z/.npmrc"), fakeUri("/workspace/.yarnrc")],
    contents: new Map([
      [
        "/workspace/z/.npmrc",
        encoder.encode("registry=https://private.example.test"),
      ],
      [
        "/workspace/.yarnrc",
        encoder.encode('registry "https://registry.yarnpkg.com/"'),
      ],
    ]),
    findCalls: [],
    reads: [],
    cancelAfterRead: undefined,
  };
  const reader = await loadReader(fakeVscode(state));
  const token = { isCancellationRequested: false } as vscode.CancellationToken;
  const scan = new AbortController();
  const result = await reader.discoverWorkspaceRegistrySnapshot(
    fakeUri("/workspace"),
    scan.signal,
    token,
  );
  const reused = await reader.discoverWorkspaceRegistrySnapshot(
    fakeUri("/workspace"),
    scan.signal,
    token,
  );

  assert.deepEqual(state.reads, [
    "/workspace/.yarnrc",
    "/workspace/z/.npmrc",
  ]);
  assert.equal(result.incomplete, false);
  assert.deepEqual(
    result.configs.map((candidate) => candidate.directoryPath),
    ["/workspace", "/workspace/z"],
  );
  assert.equal(result.configs[0]?.blockAll, false);
  assert.equal(result.configs[1]?.blockAll, true);
  assert.equal(state.findCalls.length, 1);
  assert.equal(reused, result);
  assert.equal(
    state.findCalls[0]?.pattern,
    "**/{.npmrc,.yarnrc,.yarnrc.yml,bunfig.toml}",
  );
  assert.match(state.findCalls[0]?.exclude ?? "", /node_modules/u);
  assert.equal(state.findCalls[0]?.maximum, 129);
  assert.equal(state.findCalls[0]?.token, token);
  assert.equal(state.reads.some((path) => path.includes("/home/")), false);

  state.matches = [
    fakeUri("/workspace/a/.npmrc"),
    fakeUri("/workspace/b/.npmrc"),
  ];
  state.contents.set(
    "/workspace/a/.npmrc",
    encoder.encode("registry=https://registry.npmjs.org/"),
  );
  state.contents.set(
    "/workspace/b/.npmrc",
    encoder.encode("registry=https://registry.npmjs.org/"),
  );
  state.reads.length = 0;
  const cancelledToken = {
    isCancellationRequested: false,
  } as vscode.CancellationToken;
  state.cancelAfterRead = cancelledToken;
  const cancelledScan = new AbortController();

  await assert.rejects(
    reader.discoverWorkspaceRegistrySnapshot(
      fakeUri("/workspace"),
      cancelledScan.signal,
      cancelledToken,
    ),
    (error: unknown) =>
      error instanceof DOMException && error.name === "AbortError",
  );
  assert.deepEqual(state.reads, ["/workspace/a/.npmrc"]);

  state.cancelAfterRead = undefined;
  state.matches = [fakeUri("/workspace/oversized/.npmrc")];
  state.contents.set(
    "/workspace/oversized/.npmrc",
    new Uint8Array(64 * 1024 + 1),
  );
  const oversized = await reader.discoverWorkspaceRegistrySnapshot(
    fakeUri("/workspace"),
  );
  assert.equal(oversized.configs[0]?.blockAll, true);
});
