// Erratum 6, the producer half (REQ1/REQ2-SIGNING-integral-float-selector): RFC 8785 writes an
// integral float (0.0, -0.0, 10.0) as integer text, which decodes integer-tagged, so a grant whose
// selector value holds a float-tagged integral number at any depth would not mean what the issuer
// gave. The v1 and v2 grant signers refuse such a grant after the verifier's producer accepts its
// shape (so the operations walked here are well formed and depth-bounded); the v3 producer refuses it
// itself (src/v3.ts checkNode).
import type { Tagged } from "@bounded-authority-protocol/verifier";

function holdsIntegralFloat(v: Tagged): boolean {
  switch (v.t) {
    case "float": return Number.isInteger(v.v);
    case "array": return v.v.some(holdsIntegralFloat);
    case "object": return [...v.v.values()].some(holdsIntegralFloat);
    default: return false;
  }
}

type ValuedSelector =
  | "all"
  | { readonly kind: "all" }
  | { readonly kind: "one_of"; readonly values: readonly Tagged[] }
  | { readonly kind: "equals" | "lte" | "gte"; readonly value: Tagged };

/** True when an `equals` value, `one_of` member, or `lte`/`gte` bound holds a float-tagged integral number. */
export function selectorsHoldIntegralFloat(operations: readonly { readonly selectors: readonly ValuedSelector[] }[]): boolean {
  return operations.some((op) => op.selectors.some((s) => {
    if (s === "all" || s.kind === "all") return false;
    return s.kind === "one_of" ? s.values.some(holdsIntegralFloat) : holdsIntegralFloat(s.value);
  }));
}
