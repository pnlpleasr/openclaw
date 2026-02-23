import { describe, expect, it } from "vitest";
import { formatTelegramApprovalMessage, isAllowedSender } from "./telegram.js";

describe("formatTelegramApprovalMessage", () => {
  it("formats a readable approval message", () => {
    const message = formatTelegramApprovalMessage({
      toolName: "exec",
      params: { command: "curl https://example.com" },
      agentId: "main",
      sessionKey: "agent:main:main",
    });
    expect(message).toContain("exec");
    expect(message).toContain("curl https://example.com");
    expect(message).toContain("main");
  });

  it("truncates long commands", () => {
    const longCommand = "a".repeat(500);
    const message = formatTelegramApprovalMessage({
      toolName: "exec",
      params: { command: longCommand },
      agentId: "main",
    });
    expect(message.length).toBeLessThan(600);
  });

  it("uses redacted params for write tool", () => {
    const message = formatTelegramApprovalMessage({
      toolName: "write",
      params: { path: "/tmp/secret.txt", content: "[REDACTED: 100 chars]" },
      agentId: "main",
    });
    expect(message).toContain("REDACTED");
    expect(message).not.toContain("secret-data");
  });

  it("serializes non-command params as JSON", () => {
    const message = formatTelegramApprovalMessage({
      toolName: "read",
      params: { path: "/etc/hosts" },
      agentId: "main",
    });
    expect(message).toContain("/etc/hosts");
  });
});

describe("isAllowedSender", () => {
  it("allows any sender when allowedUserIds is empty", () => {
    expect(isAllowedSender(12345, undefined)).toBe(true);
    expect(isAllowedSender(12345, [])).toBe(true);
  });

  it("allows sender in allowedUserIds list", () => {
    expect(isAllowedSender(12345, [12345, 67890])).toBe(true);
  });

  it("rejects sender not in allowedUserIds list", () => {
    expect(isAllowedSender(99999, [12345, 67890])).toBe(false);
  });
});
