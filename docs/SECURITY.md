# Cybersecurity Architecture & Threat Model

This document outlines the threat analysis and defensive security mechanisms implemented in the **mikrotik-mesh** suite.

---

## 1. Attack Surface and Mitigated Threats

| Attack Vector | Risk | Defensive Mechanism Implemented |
| :--- | :--- | :--- |
| **Authentication Timing Attacks** | Deduction of password hashes by measuring sub-millisecond variations during authentication. | Strict constant-time comparisons via the `subtle::ConstantTimeEq` crate. Zero secret-dependent branching. |
| **RAM Password Extraction (Memory Dumping)** | Leaking plaintext credentials or ephemeral keys after session termination. | `SensitiveBytes` type wrapped with the `ZeroizeOnDrop` trait from the `zeroize` crate. Memory buffers are wiped with zeros upon dropping out of scope. |
| **Small-Subgroup Attacks on Elliptic Curves** | Forging null shared secrets by injecting weak points on Curve25519. | Strict ephemeral point validation (`!pt.is_small_order()`). Low-order points are rejected immediately during handshake. |
| **Buffer Overflow / Memory Corruption** | Packets with falsified length headers attempting to read uninitialized memory (*Heartbleed-like*). | Strictly bounds-checked zero-copy parsing without `unsafe` blocks. Declared length greater than buffer generates `ProtoError::EoipLengthMismatch`. |
| **Resource Exhaustion (DoS / Session Flood)** | Mass packet flooding targeting the MAC-Telnet service to freeze the daemon. | Finite, asynchronous session table managed by the Tokio runtime, with automatic pruning timeouts for idle connections. |

---

## 2. Built-in Security Test Battery

The suite provides a dedicated CLI command for automated cybersecurity audits:

```bash
cargo run -p mkt-cli -- security-audit
```

This verification runs tests across four key pillars:
1. **Constant-Time Verification:** Confirms that proofs \(M_1\) and \(M_2\) use constant-time bitwise comparisons.
2. **Memory Zeroization:** Validates that sensitive cryptographic key buffers are scrubbed upon drop.
3. **Malformed Packet Fuzzing:** Tests resistance against truncated headers, oversize length fields, and incomplete TLVs.
4. **Zero-Knowledge Handshake Integrity:** Verifies bidirectional cryptographic proof exchange before opening shell access.
