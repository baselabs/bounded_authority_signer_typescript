// The default proof id. crypto.randomUUID exists only in a secure context (HTTPS, localhost, or a
// non-browser runtime); on a plain-HTTP page it is absent and calling it throws a TypeError. The call
// therefore sits inside a try, and a caller-visible failure is the closed producer_error, never an
// escaped exception. An explicit proofId never touches the random source.
export function defaultProofId(explicit: string | undefined): string | undefined {
  if (explicit !== undefined) return explicit;
  try {
    return crypto.randomUUID();
  } catch {
    return undefined;
  }
}
