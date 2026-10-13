// The bundle-size gate (pnpm size, which builds first): the committed limits hold, and the gate is
// red-capable (a limit one byte below the current measurement fails, as does a missing limit).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
// @ts-expect-error tools/bundle-size.mjs is untyped JavaScript
import { LIMITS_FILE, measure, overLimit } from "../tools/bundle-size.mjs";

type Sizes = Record<string, { min: number; gzip: number }>;
const measured = (await measure()) as Sizes;
const limits = (JSON.parse(readFileSync(LIMITS_FILE, "utf8")) as { limits: Sizes }).limits;

test("every shape is within its committed limit", (t) => {
  assert.deepEqual(overLimit(measured, limits), []);
  for (const [shape, m] of Object.entries(measured)) t.diagnostic(`${shape}: ${m.min} B minified, ${m.gzip} B gzip`);
});

test("red-proof: a limit one byte below the current measurement fails, for each shape and each measure", () => {
  for (const [shape, m] of Object.entries(measured)) {
    for (const key of ["min", "gzip"] as const) {
      const tight: Sizes = { ...limits, [shape]: { ...limits[shape]!, [key]: m[key] - 1 } };
      assert.equal(overLimit(measured, tight).length, 1, `${shape} ${key}`);
    }
  }
});

test("red-proof: a shape without a limit fails", () => {
  const { [Object.keys(measured)[0]!]: _dropped, ...rest } = limits;
  assert.equal(overLimit(measured, rest).length, 1);
});
