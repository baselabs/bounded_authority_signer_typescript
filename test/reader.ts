// Explicit candidate/published modes: both run every documented Node journey, not just Quickstart.
import { test } from "node:test";
import assert from "node:assert/strict";
import { executeNode, prepare, samples, typecheck, type Mode } from "./sample-runner.js";

const selected = process.env.BAP_SAMPLE_MODE ?? "both";
assert.ok(["candidate", "published", "both"].includes(selected), "BAP_SAMPLE_MODE must be candidate, published or both");
const modes: Mode[] = selected === "both" ? ["candidate", "published"] : [selected as Mode];
for (const mode of modes) test(`${mode}: every Node journey typechecks installed declarations and matches recorded output`, () => {
  const consumer = prepare(mode);
  try {
    assert.ok(samples.filter((s) => s.kind === "run").length > 10);
    typecheck(consumer.directory, false);
    executeNode(consumer.directory);
  } finally { consumer.cleanup(); }
});
