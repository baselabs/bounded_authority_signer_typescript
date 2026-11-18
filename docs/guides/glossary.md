---
title: "Glossary"
category: Guides
---

# Glossary

| Term | Meaning |
|---|---|
| Grant | Issuer-signed bounds, audiences, validity window and holder thumbprint |
| Holder | Entity whose key signs the request proof |
| Proof | Holder signature binding the grant and exact request |
| Envelope | Grant and proof compacts, without an authorization decision |
| Compact | ASCII JWS bytes with protected-header, payload and signature segments |
| Contract major | Explicit wire-format and verification profile; separate from package SemVer |
| Selector | Constraint on a path in typed request arguments |
| Key handle | Caller-owned signing capability exposing public facts and a sign method |
| Atomic identity | Key ID and public key, plus issuer role where required, in one snapshot |
| Thumbprint | RFC 7638 hash of a canonical public JWK, encoded base64url |
| Anchor | Signed chain checkpoint |
| Key transition | Signed handover description; does not update external trust |
| Facts | Verified, value-bearing data; never execution credentials |
| Host | Application/runtime that owns trust, authorization, replay, revocation and effects |
