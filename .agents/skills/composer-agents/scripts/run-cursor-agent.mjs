#!/usr/bin/env node

/**
 * Launch a local Cursor SDK agent pinned to composer-2.5 using the same harness
 * Conductor uses (Application Support @cursor/sdk + CURSOR_API_KEY).
 *
 * Env:
 *   CURSOR_API_KEY              required
 *   CONDUCTOR_INTERNAL_BIN_DIR  optional; defaults to Conductor app-support bin
 *   CONDUCTOR_CURSOR_SDK_REQUIRE_PATH  optional require root for @cursor/sdk
 *
 * Args:
 *   --worktree ABS_PATH
 *   --prompt-file ABS_PATH
 *   --effort medium|high|xhigh|max  accepted for sibling-skill CLI parity; ignored
 *                                   (Composer has no effort tiers)
 *   --name optional agent name
 */

import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";

const MODEL_ID = "composer-2.5";

function usage(exitCode = 2) {
  process.stderr.write(
    [
      "Usage: run-cursor-agent.mjs --worktree ABS_PATH --prompt-file ABS_PATH",
      "                            [--effort medium|high|xhigh|max] [--name NAME]",
      "",
      "Note: --effort is accepted for CLI parity with sibling agent skills but is",
      `ignored. Composer has no effort tiers; model is always ${MODEL_ID}.`,
      "",
    ].join("\n"),
  );
  process.exit(exitCode);
}

function requireValue(flag, value) {
  if (value === undefined || value === "" || value.startsWith("-")) {
    process.stderr.write(`Missing value for ${flag}\n`);
    usage(2);
  }
  return value;
}

function parseArgs(argv) {
  const out = {
    worktree: "",
    promptFile: "",
    effort: "",
    name: "",
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case "--worktree":
        out.worktree = requireValue(arg, argv[++i]);
        break;
      case "--prompt-file":
        out.promptFile = requireValue(arg, argv[++i]);
        break;
      case "--effort":
        out.effort = requireValue(arg, argv[++i]);
        break;
      case "--name":
        out.name = requireValue(arg, argv[++i]);
        break;
      case "-h":
      case "--help":
        usage(0);
        break;
      default:
        process.stderr.write(`Unknown argument: ${arg}\n`);
        usage(2);
    }
  }
  return out;
}

function defaultConductorBinDir() {
  return path.join(
    os.homedir(),
    "Library",
    "Application Support",
    "com.conductor.app",
    "bin",
  );
}

function loadCursorSdk() {
  const binDir =
    process.env.CONDUCTOR_INTERNAL_BIN_DIR?.trim() || defaultConductorBinDir();
  const requireRoot =
    process.env.CONDUCTOR_CURSOR_SDK_REQUIRE_PATH?.trim() ||
    path.join(binDir, ".internal", "cursor-node-worker.mjs");

  if (!fs.existsSync(requireRoot)) {
    throw new Error(
      `Conductor Cursor harness not found at ${requireRoot}. Is Conductor.app installed?`,
    );
  }

  const require = createRequire(pathToFileURL(requireRoot).href);
  return require("@cursor/sdk");
}

function assertAbsolutePath(kind, value, check) {
  if (!path.isAbsolute(value)) {
    throw new Error(`${kind} must be an existing absolute ${check}: ${value}`);
  }
  let st;
  try {
    st = fs.statSync(value);
  } catch (err) {
    if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
      throw new Error(`${kind} must be an existing absolute ${check}: ${value}`);
    }
    throw err;
  }
  if (check === "directory" && !st.isDirectory()) {
    throw new Error(`${kind} must be an existing absolute directory: ${value}`);
  }
  if (check === "file" && !st.isFile()) {
    throw new Error(`${kind} must be an existing absolute file: ${value}`);
  }
}

function textFromContent(content) {
  if (typeof content === "string") {
    return content;
  }
  if (!Array.isArray(content)) {
    return "";
  }
  const parts = [];
  for (const block of content) {
    if (!block || typeof block !== "object") {
      continue;
    }
    if (block.type === "text" && typeof block.text === "string") {
      parts.push(block.text);
    }
  }
  return parts.join("");
}

// Assistant events arrive as deltas. Write them verbatim and terminate the
// line only once the stream ends, otherwise every token lands on its own line.
let assistantStreamOpen = false;

function emitAssistantText(text) {
  if (!text) {
    return;
  }
  process.stdout.write(text);
  assistantStreamOpen = !text.endsWith("\n");
}

function closeAssistantStream() {
  if (assistantStreamOpen) {
    process.stdout.write("\n");
    assistantStreamOpen = false;
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.worktree || !args.promptFile) {
    usage(2);
  }
  if (args.effort) {
    switch (args.effort) {
      case "medium":
      case "high":
      case "xhigh":
      case "max":
        process.stderr.write(
          `[composer-agents] ignoring --effort ${args.effort}: Composer has no effort tiers\n`,
        );
        break;
      default:
        process.stderr.write(`Invalid effort: ${args.effort}\n`);
        usage(2);
    }
  }

  assertAbsolutePath("Worktree", args.worktree, "directory");
  assertAbsolutePath("Prompt file", args.promptFile, "file");

  const apiKey = process.env.CURSOR_API_KEY?.trim();
  if (!apiKey) {
    throw new Error(
      "CURSOR_API_KEY is not set. Export it or store it in Conductor provider settings.",
    );
  }

  const prompt = fs.readFileSync(args.promptFile, "utf8");
  if (!prompt.trim()) {
    throw new Error(`Prompt file is empty: ${args.promptFile}`);
  }

  // Pin the non-Fast inference variant so runs bill at the standard rate
  // instead of consuming fast credits, exactly as the grok-agents launcher
  // does. The value is the STRING "false", the parameter form @cursor/sdk
  // expects.
  const model = { id: MODEL_ID, params: [{ id: "fast", value: "false" }] };

  const { Agent } = loadCursorSdk();
  const agentId = `composer-agents-${randomUUID()}`;
  const name = args.name?.trim() || MODEL_ID;

  process.stderr.write(
    `[composer-agents] launching local Cursor agent model=${MODEL_ID} fast=false cwd=${args.worktree} id=${agentId}\n`,
  );

  const agent = await Agent.create({
    agentId,
    apiKey,
    model,
    name,
    local: {
      cwd: args.worktree,
    },
  });

  let sawStreamError = false;
  let streamErrorMessage = "";

  try {
    const run = await agent.send(prompt, { model });
    process.stderr.write(`[composer-agents] run started id=${run.id}\n`);

    for await (const event of run.stream()) {
      if (!event || typeof event !== "object") {
        continue;
      }
      if (event.type === "assistant") {
        emitAssistantText(textFromContent(event.message?.content));
      } else if (event.type === "thinking" && typeof event.text === "string" && event.text) {
        process.stderr.write(`[composer-agents:thinking] ${event.text}\n`);
      } else if (event.type === "tool_call") {
        const status = event.status ?? "unknown";
        const toolName = event.name ?? "tool";
        if (status === "running") {
          process.stderr.write(`[composer-agents:tool] ${toolName} starting\n`);
        } else if (status === "error") {
          process.stderr.write(`[composer-agents:tool] ${toolName} error\n`);
        }
      } else if (event.type === "status" && event.status === "ERROR") {
        sawStreamError = true;
        streamErrorMessage = event.message ?? "Cursor agent failed";
        process.stderr.write(`[composer-agents] status error: ${streamErrorMessage}\n`);
      }
    }

    closeAssistantStream();

    const result = await run.wait();
    const status = result?.status ?? run.status;
    process.stderr.write(
      `[composer-agents] run finished status=${status} model=${run.model?.id ?? model.id}\n`,
    );

    if (sawStreamError) {
      throw new Error(streamErrorMessage || "Cursor Composer agent reported a stream ERROR");
    }
    if (status === "error") {
      throw new Error(run.result ?? result?.result ?? "Cursor Composer agent failed");
    }
    if (status === "cancelled") {
      throw new Error("Cursor Composer agent was cancelled");
    }
  } finally {
    try {
      agent.close();
    } catch (closeErr) {
      const message = closeErr instanceof Error ? closeErr.message : String(closeErr);
      process.stderr.write(`[composer-agents] agent.close() failed: ${message}\n`);
    }
  }
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`[composer-agents] ${message}\n`);
  process.exitCode = 1;
});
