/**
 * Sandbox security validation — blocks dangerous Docker configurations.
 *
 * Threat model: local-trusted config, but protect against foot-guns and config injection.
 * Enforced at runtime when creating sandbox containers.
 *
 * Defense layers:
 *   1. BLOCKED_HOST_PATHS — denylist of system dirs and docker socket paths
 *   2. ALLOWED_HOST_PATHS — exact-match allowlist for paths under blocked prefixes
 *      (e.g., SSH agent socket under /run). Checked AFTER normalization but BEFORE
 *      the blocklist, so only exact matches bypass the block.
 *   3. Symlink escape hardening — resolves real paths via realpathSync and re-checks
 *      against the blocklist. Fails closed (throws) if resolution fails.
 *   4. Network/seccomp/apparmor validation — blocks "host" networking and "unconfined"
 *      security profiles.
 */

import { existsSync, realpathSync } from "node:fs";
import { posix } from "node:path";

// Targeted denylist: host paths that should never be exposed inside sandbox containers.
// Exported for reuse in security audit collectors.
export const BLOCKED_HOST_PATHS = [
  "/etc",
  "/private/etc",
  "/proc",
  "/sys",
  "/dev",
  "/root",
  "/boot",
  // Directories that commonly contain (or alias) the Docker socket.
  "/run",
  "/var/run",
  "/private/var/run",
  "/var/run/docker.sock",
  "/private/var/run/docker.sock",
  "/run/docker.sock",
];

// Exact paths that are safe despite living under blocked prefixes.
// Uses Set.has() for O(1) exact-match lookup — siblings, parents, and path
// traversals all fail to match. Docker Desktop's host-service proxies (SSH
// agent forwarding) live under /run/host-services/ and are NOT the Docker socket.
// See validate-sandbox-security.test.ts for regression tests covering:
//   - allowlisted path passes
//   - sibling paths still blocked
//   - parent directory still blocked
//   - path traversal (../../) still blocked
const ALLOWED_HOST_PATHS = new Set(["/run/host-services/ssh-auth.sock"]);

const BLOCKED_NETWORK_MODES = new Set(["host"]);
const BLOCKED_SECCOMP_PROFILES = new Set(["unconfined"]);
const BLOCKED_APPARMOR_PROFILES = new Set(["unconfined"]);

export type BlockedBindReason =
  | { kind: "targets"; blockedPath: string }
  | { kind: "covers"; blockedPath: string }
  | { kind: "non_absolute"; sourcePath: string };

/**
 * Parse the host/source path from a Docker bind mount string.
 * Format: `source:target[:mode]`
 */
export function parseBindSourcePath(bind: string): string {
  const trimmed = bind.trim();
  const firstColon = trimmed.indexOf(":");
  if (firstColon <= 0) {
    // No colon or starts with colon — treat as source.
    return trimmed;
  }
  return trimmed.slice(0, firstColon);
}

/**
 * Normalize a POSIX path: resolve `.`, `..`, collapse `//`, strip trailing `/`.
 */
export function normalizeHostPath(raw: string): string {
  const trimmed = raw.trim();
  return posix.normalize(trimmed).replace(/\/+$/, "") || "/";
}

/**
 * String-only blocked-path check (no filesystem I/O).
 * Blocks:
 * - binds that target blocked paths (equal or under)
 * - binds that cover the system root (mounting "/" is never safe)
 * - non-absolute source paths (relative / volume names) because they are hard to validate safely
 */
export function getBlockedBindReason(bind: string): BlockedBindReason | null {
  const sourceRaw = parseBindSourcePath(bind);
  if (!sourceRaw.startsWith("/")) {
    return { kind: "non_absolute", sourcePath: sourceRaw };
  }

  const normalized = normalizeHostPath(sourceRaw);
  return getBlockedReasonForSourcePath(normalized);
}

export function getBlockedReasonForSourcePath(sourceNormalized: string): BlockedBindReason | null {
  if (sourceNormalized === "/") {
    return { kind: "covers", blockedPath: "/" };
  }
  if (ALLOWED_HOST_PATHS.has(sourceNormalized)) {
    return null;
  }
  for (const blocked of BLOCKED_HOST_PATHS) {
    if (sourceNormalized === blocked || sourceNormalized.startsWith(blocked + "/")) {
      return { kind: "targets", blockedPath: blocked };
    }
  }

  return null;
}

function tryRealpathAbsolute(path: string): string | null {
  if (!path.startsWith("/")) {
    console.error(`Sandbox security: tryRealpathAbsolute called with non-absolute path "${path}"`);
    return null;
  }
  if (!existsSync(path)) {
    return path;
  }
  try {
    // Use native when available (keeps platform semantics); normalize for prefix checks.
    return normalizeHostPath(realpathSync.native(path));
  } catch (err) {
    // Security: if we can't resolve the real path, we cannot verify it is safe.
    console.error(`Sandbox security: failed to resolve real path for "${path}": ${String(err)}`);
    return null;
  }
}

function formatBindBlockedError(params: { bind: string; reason: BlockedBindReason }): Error {
  if (params.reason.kind === "non_absolute") {
    return new Error(
      `Sandbox security: bind mount "${params.bind}" uses a non-absolute source path ` +
        `"${params.reason.sourcePath}". Only absolute POSIX paths are supported for sandbox binds.`,
    );
  }
  const verb = params.reason.kind === "covers" ? "covers" : "targets";
  return new Error(
    `Sandbox security: bind mount "${params.bind}" ${verb} blocked path "${params.reason.blockedPath}". ` +
      "Mounting system directories (or Docker socket paths) into sandbox containers is not allowed. " +
      "Use project-specific paths instead (e.g. /home/user/myproject).",
  );
}

/**
 * Validate bind mounts — throws if any source path is dangerous.
 * Includes a symlink/realpath pass when the source path exists.
 */
export function validateBindMounts(binds: string[] | undefined): void {
  if (!binds?.length) {
    return;
  }

  for (const rawBind of binds) {
    const bind = rawBind.trim();
    if (!bind) {
      continue;
    }

    // Fast string-only check (covers .., //, ancestor/descendant logic).
    const blocked = getBlockedBindReason(bind);
    if (blocked) {
      throw formatBindBlockedError({ bind, reason: blocked });
    }

    // Symlink escape hardening: resolve existing absolute paths and re-check.
    const sourceRaw = parseBindSourcePath(bind);
    const sourceNormalized = normalizeHostPath(sourceRaw);
    const sourceReal = tryRealpathAbsolute(sourceNormalized);
    if (sourceReal === null) {
      throw new Error(
        `Sandbox security: cannot resolve real path for bind mount "${bind}". ` +
          "The source path exists but realpath resolution failed (symlink loop or permission issue).",
      );
    }
    if (sourceReal !== sourceNormalized) {
      const reason = getBlockedReasonForSourcePath(sourceReal);
      if (reason) {
        throw formatBindBlockedError({ bind, reason });
      }
    }
  }
}

export function validateNetworkMode(network: string | undefined): void {
  if (network && BLOCKED_NETWORK_MODES.has(network.trim().toLowerCase())) {
    throw new Error(
      `Sandbox security: network mode "${network}" is blocked. ` +
        'Network "host" mode bypasses container network isolation. ' +
        'Use "bridge" or "none" instead.',
    );
  }
}

export function validateSeccompProfile(profile: string | undefined): void {
  if (profile && BLOCKED_SECCOMP_PROFILES.has(profile.trim().toLowerCase())) {
    throw new Error(
      `Sandbox security: seccomp profile "${profile}" is blocked. ` +
        "Disabling seccomp removes syscall filtering and weakens sandbox isolation. " +
        "Use a custom seccomp profile file or omit this setting.",
    );
  }
}

export function validateApparmorProfile(profile: string | undefined): void {
  if (profile && BLOCKED_APPARMOR_PROFILES.has(profile.trim().toLowerCase())) {
    throw new Error(
      `Sandbox security: apparmor profile "${profile}" is blocked. ` +
        "Disabling AppArmor removes mandatory access controls and weakens sandbox isolation. " +
        "Use a named AppArmor profile or omit this setting.",
    );
  }
}

export function validateSandboxSecurity(cfg: {
  binds?: string[];
  network?: string;
  seccompProfile?: string;
  apparmorProfile?: string;
}): void {
  validateBindMounts(cfg.binds);
  validateNetworkMode(cfg.network);
  validateSeccompProfile(cfg.seccompProfile);
  validateApparmorProfile(cfg.apparmorProfile);
}
