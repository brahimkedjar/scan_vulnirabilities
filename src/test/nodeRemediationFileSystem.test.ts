import { strict as assert } from "node:assert";
import {
  mkdtemp,
  link,
  lstat,
  mkdir,
  readFile,
  readdir,
  rename,
  rm,
  symlink,
  truncate,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import type * as vscode from "vscode";

import { ApplyError } from "../remediation/apply/ApplyError";
import { sha256 } from "../remediation/apply/FileSnapshot";
import { NodeRemediationFileSystem } from "../remediation/apply/NodeRemediationFileSystem";

function fileUri(path: string): vscode.Uri {
  return {
    scheme: "file",
    path,
    fsPath: path,
    toString: () => `file://${path}`,
  } as unknown as vscode.Uri;
}

async function directoryLink(target: string, path: string): Promise<void> {
  await symlink(target, path, process.platform === "win32" ? "junction" : "dir");
}

void test("node file adapter rejects a symlink or reparse parent component", async () => {
  const root = await mkdtemp(join(tmpdir(), "dependency-auditor-parent-link-"));
  try {
    const real = join(root, "real");
    const project = join(real, "project");
    const link = join(root, "linked");
    await mkdir(project, { recursive: true });
    await writeFile(join(project, "package.json"), "{}\n", "utf8");
    await directoryLink(real, link);
    const adapter = new NodeRemediationFileSystem();
    await assert.rejects(
      adapter.inspect(fileUri(join(link, "project", "package.json"))),
      (error: unknown) =>
        error instanceof ApplyError && error.code === "UNSAFE_FILE_TYPE",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test("node file adapter refuses a parent swapped to a junction after preview", async () => {
  const root = await mkdtemp(join(tmpdir(), "dependency-auditor-parent-swap-"));
  try {
    const project = join(root, "project");
    const moved = join(root, "moved-project");
    const manifest = join(project, "package.json");
    await mkdir(project, { recursive: true });
    await writeFile(manifest, '{"before":true}\n', "utf8");
    const adapter = new NodeRemediationFileSystem();
    const preview = await adapter.inspect(fileUri(manifest));
    await rename(project, moved);
    await directoryLink(moved, project);
    await assert.rejects(
      adapter.replaceFileAtomic(
        fileUri(manifest),
        new TextEncoder().encode('{"after":true}\n'),
        preview.identity,
        "0".repeat(64),
      ),
      (error: unknown) =>
        error instanceof ApplyError && error.code === "UNSAFE_FILE_TYPE",
    );
    assert.equal(
      await readFile(join(moved, "package.json"), "utf8"),
      '{"before":true}\n',
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test("node file adapter fail-closes before staging when conditional atomic replacement is unavailable", async () => {
  const root = await mkdtemp(join(tmpdir(), "dependency-auditor-no-cas-"));
  try {
    const manifest = join(root, "package.json");
    await writeFile(manifest, '{"before":true}\n', "utf8");
    const adapter = new NodeRemediationFileSystem();
    const preview = await adapter.inspect(fileUri(manifest));
    const beforeBytes = new Uint8Array(await readFile(manifest));
    const beforeStats = await lstat(manifest);
    assert.equal(adapter.canGuaranteeAtomicReplace(fileUri(manifest)), false);
    await assert.rejects(
      adapter.replaceFileAtomic(
        fileUri(manifest),
        new TextEncoder().encode('{"after":true}\n'),
        preview.identity,
        sha256(beforeBytes),
      ),
      (error: unknown) =>
        error instanceof ApplyError &&
        error.code === "ATOMIC_REPLACE_UNAVAILABLE",
    );
    const afterBytes = new Uint8Array(await readFile(manifest));
    const afterStats = await lstat(manifest);
    assert.deepEqual(afterBytes, beforeBytes);
    assert.equal(afterStats.dev, beforeStats.dev);
    assert.equal(afterStats.ino, beforeStats.ino);
    assert.equal(afterStats.birthtimeMs, beforeStats.birthtimeMs);
    assert.equal(afterStats.mtimeMs, beforeStats.mtimeMs);
    assert.equal(afterStats.mode, beforeStats.mode);
    assert.deepEqual(await readdir(root), ["package.json"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test("node file adapter preserves a same-identity user edit made after preview", async () => {
  const root = await mkdtemp(join(tmpdir(), "dependency-auditor-in-place-edit-"));
  try {
    const manifest = join(root, "package.json");
    const original = new TextEncoder().encode('{"before":true}\n');
    const userEdit = '{"userEdit":true}\n';
    await writeFile(manifest, original);
    const adapter = new NodeRemediationFileSystem();
    const preview = await adapter.inspect(fileUri(manifest));
    await writeFile(manifest, userEdit, "utf8");
    const edited = await adapter.inspect(fileUri(manifest));
    assert.equal(edited.identity.value, preview.identity.value);

    await assert.rejects(
      adapter.replaceFileAtomic(
        fileUri(manifest),
        new TextEncoder().encode('{"after":true}\n'),
        preview.identity,
        sha256(original),
      ),
      (error: unknown) =>
        error instanceof ApplyError &&
        error.code === "ATOMIC_REPLACE_UNAVAILABLE",
    );
    assert.equal(await readFile(manifest, "utf8"), userEdit);
    assert.deepEqual(await readdir(root), ["package.json"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test("node file adapter cannot overwrite a hard-linked external alias", async () => {
  const root = await mkdtemp(join(tmpdir(), "dependency-auditor-hardlink-"));
  try {
    const workspace = join(root, "workspace");
    const external = join(root, "external-package.json");
    const manifest = join(workspace, "package.json");
    const original = new TextEncoder().encode('{"external":true}\n');
    await mkdir(workspace);
    await writeFile(external, original);
    await link(external, manifest);
    const adapter = new NodeRemediationFileSystem();
    const preview = await adapter.inspect(fileUri(manifest));

    await assert.rejects(
      adapter.replaceFileAtomic(
        fileUri(manifest),
        new TextEncoder().encode('{"after":true}\n'),
        preview.identity,
        sha256(original),
      ),
      (error: unknown) =>
        error instanceof ApplyError &&
        error.code === "ATOMIC_REPLACE_UNAVAILABLE",
    );
    assert.deepEqual(new Uint8Array(await readFile(manifest)), original);
    assert.deepEqual(new Uint8Array(await readFile(external)), original);
    assert.deepEqual(await readdir(workspace), ["package.json"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test("node file adapter rejects a final leaf symlink before reading it", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "dependency-auditor-leaf-link-"));
  try {
    const external = join(root, "external-package.json");
    const manifest = join(root, "package.json");
    await writeFile(external, '{"secret":true}\n', "utf8");
    try {
      await symlink(external, manifest, "file");
    } catch (error: unknown) {
      if (
        process.platform === "win32" &&
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        (error as { code?: unknown }).code === "EPERM"
      ) {
        context.skip("Creating file symlinks requires Windows Developer Mode.");
        return;
      }
      throw error;
    }
    const adapter = new NodeRemediationFileSystem();
    await assert.rejects(
      adapter.readFile(fileUri(manifest)),
      (error: unknown) =>
        error instanceof ApplyError && error.code === "UNSAFE_FILE_TYPE",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test("node file adapter bounds local remediation reads before allocation", async () => {
  const root = await mkdtemp(join(tmpdir(), "dependency-auditor-read-limit-"));
  try {
    const manifest = join(root, "package-lock.json");
    await writeFile(manifest, "", "utf8");
    await truncate(manifest, 32 * 1024 * 1024 + 1);
    const adapter = new NodeRemediationFileSystem();
    await assert.rejects(
      adapter.readFile(fileUri(manifest)),
      (error: unknown) =>
        error instanceof ApplyError && error.code === "RESOURCE_LIMIT",
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

void test("node file adapter refusal does not inspect or modify Git metadata", async () => {
  const root = await mkdtemp(join(tmpdir(), "dependency-auditor-git-noop-"));
  try {
    const externalGitDirectory = join(root, "external-git-directory");
    const workspace = join(root, "workspace");
    const gitFile = join(workspace, ".git");
    const externalIndex = join(externalGitDirectory, "index");
    const manifest = join(workspace, "package.json");
    const gitPointer = `gitdir: ${externalGitDirectory}\n`;
    const indexSentinel = new TextEncoder().encode("opaque-index-sentinel\0");
    const original = new TextEncoder().encode('{"before":true}\n');
    await mkdir(externalGitDirectory);
    await mkdir(workspace);
    await writeFile(gitFile, gitPointer, "utf8");
    await writeFile(externalIndex, indexSentinel);
    await writeFile(manifest, original);
    const gitFileBefore = await lstat(gitFile);
    const indexBefore = await lstat(externalIndex);
    const adapter = new NodeRemediationFileSystem();
    const preview = await adapter.inspect(fileUri(manifest));

    await assert.rejects(
      adapter.replaceFileAtomic(
        fileUri(manifest),
        new TextEncoder().encode('{"after":true}\n'),
        preview.identity,
        sha256(original),
      ),
      (error: unknown) =>
        error instanceof ApplyError &&
        error.code === "ATOMIC_REPLACE_UNAVAILABLE",
    );

    const gitFileAfter = await lstat(gitFile);
    const indexAfter = await lstat(externalIndex);
    assert.equal(await readFile(gitFile, "utf8"), gitPointer);
    assert.deepEqual(new Uint8Array(await readFile(externalIndex)), indexSentinel);
    assert.equal(gitFileAfter.mtimeMs, gitFileBefore.mtimeMs);
    assert.equal(indexAfter.mtimeMs, indexBefore.mtimeMs);
    assert.deepEqual(new Uint8Array(await readFile(manifest)), original);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
