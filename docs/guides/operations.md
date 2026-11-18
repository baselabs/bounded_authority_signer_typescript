---
title: "Operate signing custody"
category: Guides
---

# Operate signing custody

The signer has no application, network, database or key store to start. The host starts its custody
client, chooses credentials and deadlines, and owns lifecycle, rotation, availability and audit logs.
The only runtime dependency is the verifier. An async handle may reach any custodian; the package
never retries that call or imposes a network timeout on it.

## Event ordering

A signing operation synchronously emits `start` before input validation. It emits one terminal
`stop` after signature checking and assembly, or `error` after a closed refusal. The event contains
only `kind` and `phase`; no duration, error code, key ID or correlation ID. Factory construction does
not emit signing events. Concurrent calls can interleave; closures must associate each call with its
own start time. See [telemetry](telemetry.md) for an executable example.

A throwing listener is caught and ignored at each emission and cannot change the result. The
listener is a synchronous callback: do not return a rejecting Promise; handle exporter failures
inside your own listener. Long callbacks add latency. A handle that never resolves also prevents a
terminal event: enforce deadlines and cancellation in the host's custody client.

## Diagnose custody failures

`invalid_key_handle` happens before signing when public-key resolution, issuer role or atomic
identity is unusable. Confirm suite, public-key width and identity snapshot without logging key
material. Factory admission also checks a non-extractable pair and a real probe signature.
`signing_failed` means the sign call failed, returned the wrong encoding/width, or failed strict
verification. Check the custodian's algorithm, message-versus-digest setting, DER conversion and
key version. Compare a public-key fingerprint with your configured key version through a safe
operator interface. Never disable the wrong-key check to recover availability.

## Retry and rotation

Do not retry malformed input or selector refusal. Classify a real custody exception in the host
client before mapping it to the signer's value-free error. Retry only transient custody failures
within the host deadline; do not regenerate grants blindly. An uncertain request outcome requires
the host's idempotency/replay protocol. A fresh proof ID does not authorize repeating an effect.
On holder rotation, obtain a new holder-bound grant. On issuer or chain rotation, build a new
handle and update trusted intervals through the host's controlled trust process. See [rotation](rotate-keys.md).
