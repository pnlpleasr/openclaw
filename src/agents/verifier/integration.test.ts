import http from "node:http";
import { afterAll, describe, expect, it } from "vitest";
import { runVerifier } from "./index.js";

const TEST_PORT = 19877;

function createAndListen(
  handler: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<http.Server> {
  return new Promise<http.Server>((resolve) => {
    const s = http.createServer(handler);
    s.listen(TEST_PORT, () => resolve(s));
  });
}

function close(server: http.Server): Promise<void> {
  return new Promise<void>((resolve) => server.close(() => resolve()));
}

describe("verifier integration", () => {
  let server: http.Server | null = null;

  afterAll(async () => {
    if (server) {
      await close(server);
    }
  });

  it("end-to-end: webhook allow", async () => {
    server = await createAndListen((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: "allow" }));
    });

    const result = await runVerifier({
      config: {
        enabled: true,
        webhook: { url: `http://127.0.0.1:${TEST_PORT}/verify` },
      },
      toolName: "exec",
      params: { command: "echo hello" },
      agentId: "main",
    });
    expect(result.blocked).toBe(false);

    await close(server);
    server = null;
  });

  it("end-to-end: webhook deny", async () => {
    server = await createAndListen((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ decision: "deny", reason: "dangerous" }));
    });

    const result = await runVerifier({
      config: {
        enabled: true,
        webhook: { url: `http://127.0.0.1:${TEST_PORT}/verify` },
      },
      toolName: "exec",
      params: { command: "rm -rf /" },
    });
    expect(result.blocked).toBe(true);
    if (result.blocked) {
      expect(result.reason).toContain("dangerous");
    }

    await close(server);
    server = null;
  });

  it("end-to-end: scope excludes tool (webhook never called)", async () => {
    const result = await runVerifier({
      config: {
        enabled: true,
        scope: { include: ["exec"] },
        webhook: { url: "http://this-should-not-be-called.invalid" },
      },
      toolName: "read",
      params: {},
    });
    expect(result.blocked).toBe(false);
  });

  it("end-to-end: failMode deny blocks on unreachable webhook", async () => {
    const result = await runVerifier({
      config: {
        enabled: true,
        failMode: "deny",
        webhook: { url: "http://127.0.0.1:19999/unreachable", timeout: 1 },
      },
      toolName: "exec",
      params: { command: "ls" },
    });
    expect(result.blocked).toBe(true);
  });

  it("end-to-end: failMode allow passes on unreachable webhook", async () => {
    const result = await runVerifier({
      config: {
        enabled: true,
        failMode: "allow",
        webhook: { url: "http://127.0.0.1:19999/unreachable", timeout: 1 },
      },
      toolName: "exec",
      params: { command: "ls" },
    });
    expect(result.blocked).toBe(false);
  });

  it("end-to-end: redacts content in write tool params", async () => {
    let receivedBody = "";
    server = await createAndListen((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("end", () => {
        receivedBody = Buffer.concat(chunks).toString();
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ decision: "allow" }));
      });
    });

    await runVerifier({
      config: {
        enabled: true,
        webhook: { url: `http://127.0.0.1:${TEST_PORT}/verify` },
      },
      toolName: "write",
      params: { path: "/tmp/test.txt", content: "secret-content-here" },
    });

    const parsed = JSON.parse(receivedBody) as { tool: { params: { content: string } } };
    expect(parsed.tool.params.content).toContain("REDACTED");
    expect(parsed.tool.params.content).not.toContain("secret-content-here");

    await close(server);
    server = null;
  });
});
