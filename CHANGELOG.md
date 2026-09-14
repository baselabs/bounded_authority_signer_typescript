# Changelog

## [0.1.0] — 2026-09-14

- First release: the TypeScript port of the Elixir bounded_authority_report_adapter
  (tracked against its 0.6.0 / protocol 0.4.0). The five companion signers (report,
  local-loopback report, anchor, key transition, grant), the caller-owned key-handle
  contract with atomic identity snapshots, the C1 issuer-role gate, the wrong-key
  signature guard, and the closed error-code set. All outputs oracle-verified through the
  independent @bounded-authority-protocol/verifier package in CI; closure gates are
  red-capable.
