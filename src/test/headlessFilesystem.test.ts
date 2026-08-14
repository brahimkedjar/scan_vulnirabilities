import assert from "node:assert/strict";
import {
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { discoverDependencyProjects } from "../core/discovery/StaticDependencyDiscovery";
import {
  NodeFileSystem,
  NodeFileSystemError,
} from "../core/host/NodeFileSystem";

async function temporaryDirectory(): Promise<string> {
  return mkdtemp(join(tmpdir(), "dependency-auditor-core-"));
}

void test("Node filesystem rejects traversal and bounds UTF-8 reads", async () => {
  const directory = await temporaryDirectory();
  const outside = await temporaryDirectory();
  try {
    const file = join(directory, "package.json");
    await writeFile(file, '{"dependencies":{}}', "utf8");
    await writeFile(join(outside, "secret"), "not workspace metadata", "utf8");
    const fileSystem = new NodeFileSystem();
    const root = await fileSystem.openRoot(directory);
    await assert.rejects(
      fileSystem.readTextFile(root, join(outside, "secret"), 1_024),
      (error: unknown) =>
        error instanceof NodeFileSystemError && error.code === "PATH_ESCAPE",
    );
    await assert.rejects(
      fileSystem.readTextFile(root, file, 2),
      (error: unknown) =>
        error instanceof NodeFileSystemError && error.code === "FILE_TOO_LARGE",
    );
    await writeFile(join(directory, "invalid.txt"), new Uint8Array([0xc3, 0x28]));
    await assert.rejects(
      fileSystem.readTextFile(root, join(directory, "invalid.txt"), 8),
      (error: unknown) =>
        error instanceof NodeFileSystemError && error.code === "INVALID_UTF8",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

void test("discovery never follows a directory symlink or junction", async (context) => {
  const directory = await temporaryDirectory();
  const outside = await temporaryDirectory();
  try {
    await writeFile(join(directory, "package.json"), '{"dependencies":{}}', "utf8");
    await writeFile(
      join(directory, "package-lock.json"),
      '{"lockfileVersion":3,"packages":{"":{}}}',
      "utf8",
    );
    await writeFile(join(outside, "Cargo.toml"), '[package]\nname="outside"\nversion="1.0.0"', "utf8");
    const link = join(directory, "linked-project");
    try {
      await symlink(outside, link, process.platform === "win32" ? "junction" : "dir");
    } catch (error: unknown) {
      const code =
        typeof error === "object" && error !== null && "code" in error
          ? error.code
          : undefined;
      if (code === "EPERM" || code === "EACCES") {
        context.skip("This host does not permit creating a test symlink/junction");
        return;
      }
      throw error;
    }
    const result = await discoverDependencyProjects(
      new NodeFileSystem(),
      directory,
      { maximumFiles: 100, maximumBytes: 1_000_000 },
    );
    assert.equal(result.complete, false);
    assert.equal(
      result.issues.some((issue) => issue.code === "SYMLINK_SKIPPED"),
      true,
    );
    assert.equal(
      result.files.some((file) => file.path.includes("Cargo.toml")),
      false,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

void test("discovery reports entry limits and cancellation deterministically", async () => {
  const directory = await temporaryDirectory();
  try {
    await mkdir(join(directory, "nested"));
    await writeFile(join(directory, "package.json"), "{}", "utf8");
    await writeFile(join(directory, "package-lock.json"), "{}", "utf8");
    const limited = await discoverDependencyProjects(
      new NodeFileSystem(),
      directory,
      { maximumFiles: 1, maximumBytes: 1_000_000 },
    );
    assert.equal(limited.complete, false);
    assert.equal(limited.issues.some((issue) => issue.code === "FILE_LIMIT"), true);

    const controller = new AbortController();
    controller.abort();
    await assert.rejects(
      discoverDependencyProjects(new NodeFileSystem(), directory, {
        maximumFiles: 100,
        maximumBytes: 1_000_000,
        signal: controller.signal,
      }),
      (error: unknown) => error instanceof DOMException && error.name === "AbortError",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

