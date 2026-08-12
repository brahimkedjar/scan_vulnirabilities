import * as vscode from "vscode";

import { GENERATED_DIRECTORY_GLOB } from "../../discovery/dependencyFiles";
import {
  isCancellation,
  readBoundedText,
  throwIfCancelled,
  uriPath,
} from "../yarn/JavaScriptAdapterUtils";
import {
  inspectWorkspaceBunfigConfig,
  inspectWorkspaceRegistryConfig,
  unreadableWorkspaceRegistryConfig,
  type WorkspaceRegistryConfigKind,
  type WorkspaceRegistrySnapshot,
} from "./NpmRegistryProvenance";

const REGISTRY_CONFIG_GLOB =
  "**/{.npmrc,.yarnrc,.yarnrc.yml,bunfig.toml}";
const MAX_REGISTRY_CONFIG_FILES = 128;
const MAX_REGISTRY_CONFIG_BYTES = 64 * 1024;
const MAX_TOTAL_REGISTRY_CONFIG_CHARACTERS = 512 * 1024;
const SNAPSHOTS_BY_SCAN = new WeakMap<
  AbortSignal,
  Map<string, Promise<WorkspaceRegistrySnapshot>>
>();

function configKind(uri: vscode.Uri): WorkspaceRegistryConfigKind | undefined {
  const name = uri.path.split("/").at(-1)?.toLowerCase();
  if (name === ".npmrc") {
    return "npmrc";
  }
  if (name === ".yarnrc") {
    return "yarnrc";
  }
  if (name === ".yarnrc.yml") {
    return "yarnrc-yaml";
  }
  return name === "bunfig.toml" ? "bunfig-toml" : undefined;
}

function folderPattern(
  workspaceFolder: vscode.Uri,
  pattern: string,
): vscode.RelativePattern {
  return new vscode.RelativePattern(
    {
      uri: workspaceFolder,
      name: workspaceFolder.path.split("/").at(-1) ?? "workspace",
      index: 0,
    },
    pattern,
  );
}

/**
 * Reads only registry configuration files physically exposed by the active
 * workspace file-system provider. User, global, and package-manager home
 * configuration is deliberately never consulted.
 */
async function discoverWorkspaceRegistrySnapshotUncached(
  workspaceFolder: vscode.Uri,
  signal?: AbortSignal,
  cancellationToken?: vscode.CancellationToken,
): Promise<WorkspaceRegistrySnapshot> {
  throwIfCancelled(signal, cancellationToken);
  let matches: readonly vscode.Uri[];
  try {
    matches = await vscode.workspace.findFiles(
      folderPattern(workspaceFolder, REGISTRY_CONFIG_GLOB),
      GENERATED_DIRECTORY_GLOB,
      MAX_REGISTRY_CONFIG_FILES + 1,
      cancellationToken,
    );
    throwIfCancelled(signal, cancellationToken);
  } catch (error: unknown) {
    if (isCancellation(error)) {
      throw error;
    }
    return { configs: [], incomplete: true };
  }

  let incomplete = matches.length > MAX_REGISTRY_CONFIG_FILES;
  let totalCharacters = 0;
  const configs: WorkspaceRegistrySnapshot["configs"][number][] = [];
  const retained = [...matches]
    .sort((left, right) => left.path.localeCompare(right.path))
    .slice(0, MAX_REGISTRY_CONFIG_FILES);
  for (const uri of retained) {
    throwIfCancelled(signal, cancellationToken);
    const kind = configKind(uri);
    if (kind === undefined) {
      incomplete = true;
      continue;
    }
    const path = uriPath(uri);
    const directoryPath = uriPath(vscode.Uri.joinPath(uri, ".."));
    try {
      const content = await readBoundedText(
        uri,
        MAX_REGISTRY_CONFIG_BYTES,
        signal,
        cancellationToken,
      );
      totalCharacters += content.length;
      if (totalCharacters > MAX_TOTAL_REGISTRY_CONFIG_CHARACTERS) {
        incomplete = true;
        break;
      }
      configs.push(
        kind === "bunfig-toml"
          ? await inspectWorkspaceBunfigConfig({
              path,
              directoryPath,
              content,
            })
          : inspectWorkspaceRegistryConfig({
              path,
              directoryPath,
              kind,
              content,
            }),
      );
    } catch (error: unknown) {
      if (isCancellation(error)) {
        throw error;
      }
      configs.push(
        unreadableWorkspaceRegistryConfig(
          path,
          directoryPath,
          kind === "bunfig-toml" ? ["bun"] : undefined,
        ),
      );
    }
  }
  throwIfCancelled(signal, cancellationToken);
  return { configs, incomplete };
}

/**
 * Shares one discovery/read pass across npm-family adapters and independently
 * detected projects in the same scan. The AbortSignal is the lifetime key, so
 * resolved snapshots cannot persist beyond the owning scan.
 */
export async function discoverWorkspaceRegistrySnapshot(
  workspaceFolder: vscode.Uri,
  signal?: AbortSignal,
  cancellationToken?: vscode.CancellationToken,
): Promise<WorkspaceRegistrySnapshot> {
  throwIfCancelled(signal, cancellationToken);
  if (signal === undefined) {
    return discoverWorkspaceRegistrySnapshotUncached(
      workspaceFolder,
      undefined,
      cancellationToken,
    );
  }
  const workspaceKey = workspaceFolder.toString();
  let snapshots = SNAPSHOTS_BY_SCAN.get(signal);
  if (snapshots === undefined) {
    snapshots = new Map<string, Promise<WorkspaceRegistrySnapshot>>();
    SNAPSHOTS_BY_SCAN.set(signal, snapshots);
  }
  let pending = snapshots.get(workspaceKey);
  if (pending === undefined) {
    pending = discoverWorkspaceRegistrySnapshotUncached(
      workspaceFolder,
      signal,
      cancellationToken,
    );
    snapshots.set(workspaceKey, pending);
    const remove = (): void => {
      if (snapshots?.get(workspaceKey) === pending) {
        snapshots.delete(workspaceKey);
        if (snapshots.size === 0) {
          SNAPSHOTS_BY_SCAN.delete(signal);
        }
      }
    };
    signal.addEventListener("abort", remove, { once: true });
    void pending.catch(() => {
      remove();
    });
  }
  const result = await pending;
  throwIfCancelled(signal, cancellationToken);
  return result;
}
