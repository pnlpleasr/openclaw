import { createSubsystemLogger } from "../../logging/subsystem.js";
import type { VerifierDecision } from "./webhook.js";

const log = createSubsystemLogger("verifier/telegram");
const MAX_MESSAGE_LENGTH = 400;
const POLL_INTERVAL_MS = 1500;

/**
 * Check if a Telegram user ID is in the allowed senders list.
 * If no list is configured, any user can respond.
 */
export function isAllowedSender(userId: number, allowedUserIds: number[] | undefined): boolean {
  if (!allowedUserIds || allowedUserIds.length === 0) {
    return true;
  }
  return allowedUserIds.includes(userId);
}

export function formatTelegramApprovalMessage(params: {
  toolName: string;
  params: Record<string, unknown>;
  agentId?: string;
  sessionKey?: string;
}): string {
  const commandStr =
    typeof params.params.command === "string"
      ? params.params.command
      : JSON.stringify(params.params);
  const truncated =
    commandStr.length > MAX_MESSAGE_LENGTH
      ? `${commandStr.slice(0, MAX_MESSAGE_LENGTH)}...`
      : commandStr;
  const lines = [
    "\u{1f512} Tool verification request",
    "",
    `Tool: ${params.toolName}`,
    `Details: ${truncated}`,
  ];
  if (params.agentId) {
    lines.push(`Agent: ${params.agentId}`);
  }
  if (params.sessionKey) {
    lines.push(`Session: ${params.sessionKey}`);
  }
  return lines.join("\n");
}

/**
 * Send a Telegram approval request and wait for a callback response.
 *
 * Architecture: Uses direct bot.api calls (no long-polling). Sends the message
 * with inline keyboard, then polls getUpdates for callback_query updates that
 * match the sent message_id. This avoids:
 * - Creating competing bot instances (409 Conflict)
 * - Race conditions between sendMessage and bot.start()
 * - Lost callbacks from drop_pending_updates
 */
export async function callTelegramVerifier(params: {
  botToken: string;
  chatId: string;
  timeout: number;
  toolName: string;
  toolParams: Record<string, unknown>;
  agentId?: string;
  sessionKey?: string;
  requestId: string;
  allowedUserIds?: number[];
}): Promise<VerifierDecision> {
  try {
    const { Bot, InlineKeyboard } = await import("grammy");
    const bot = new Bot(params.botToken);

    const message = formatTelegramApprovalMessage({
      toolName: params.toolName,
      params: params.toolParams,
      agentId: params.agentId,
      sessionKey: params.sessionKey,
    });

    const keyboard = new InlineKeyboard()
      .text("\u2705 Allow", `verifier:allow:${params.requestId}`)
      .text("\u274c Deny", `verifier:deny:${params.requestId}`);

    const sent = await bot.api.sendMessage(params.chatId, message, {
      reply_markup: keyboard,
    });

    const deadline = Date.now() + params.timeout * 1000;
    let updateOffset = 0;

    while (Date.now() < deadline) {
      try {
        const updates = await bot.api.getUpdates({
          offset: updateOffset,
          timeout: Math.min(5, Math.ceil((deadline - Date.now()) / 1000)),
          allowed_updates: ["callback_query"],
        });

        for (const update of updates) {
          updateOffset = update.update_id + 1;

          if (!update.callback_query?.message) {
            continue;
          }
          if (update.callback_query.message.message_id !== sent.message_id) {
            continue;
          }

          const data = update.callback_query.data;
          if (!data) {
            continue;
          }

          const match = data.match(/^verifier:(allow|deny):(.+)$/);
          if (!match || match[2] !== params.requestId) {
            continue;
          }

          const senderId = update.callback_query.from.id;
          if (!isAllowedSender(senderId, params.allowedUserIds)) {
            await bot.api.answerCallbackQuery(update.callback_query.id, {
              text: "You are not authorized to approve/deny this request.",
              show_alert: true,
            });
            continue;
          }

          const decision = match[1] as "allow" | "deny";

          await bot.api.answerCallbackQuery(update.callback_query.id, {
            text: decision === "allow" ? "\u2705 Allowed" : "\u274c Denied",
          });
          await bot.api.editMessageReplyMarkup(params.chatId, sent.message_id, {
            reply_markup: undefined,
          });

          return {
            decision,
            reason: decision === "deny" ? "Denied via Telegram" : undefined,
          };
        }
      } catch (pollErr) {
        log.warn(`Telegram getUpdates error: ${String(pollErr)}`);
        await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
      }
    }

    // Timeout — remove the keyboard to indicate expiry
    try {
      await bot.api.editMessageText(
        params.chatId,
        sent.message_id,
        message + "\n\n\u23f1 Timed out \u2014 no response received.",
      );
    } catch {
      /* best effort */
    }

    return { decision: "error", reason: "Telegram approval timed out" };
  } catch (err) {
    return {
      decision: "error",
      reason: `Telegram verifier failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}
