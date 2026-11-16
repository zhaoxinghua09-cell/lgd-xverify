# Security Policy

**安全政策。包含一条与普通开源仓不同的声明：本仓的产出不是认证。**

## Reporting a vulnerability

Open a GitHub issue titled `security: <summary>`, or if the report involves an unpatched exploitation path, email the maintainer listed in `CODEOWNERS`. Include the record that produces the wrong verdict; for verdict bugs the record *is* the report.

What counts as a vulnerability here:

1. A record that reaches `PASS` while any signature went unchecked.
2. A record whose payload was edited after signing that reaches anything other than `FAIL`.
3. A key substitution that is accepted: a record signed by an attacker's key but verified against a pinned key must fail.
4. A malformed or negative-signature input that makes the verifier raise an unhandled exception instead of returning `FAIL`.
5. A crash or hang on adversarial JSON (deep nesting, huge ints, non-UTF-8 bytes).

Not vulnerabilities, by design and documented in `README.md`: absence of JWS/COSE parsing, no constant-time execution, no delegation-chain verification while ARIA's `delegationDepth` is always `0`, and no auto-detection of hardware attestation.

## What this tool is not

A verdict from this tool is a **recomputable process result**, not a certification, accreditation, or an attestation with legal effect. It does not claim that an agent is safe, compliant, or approved. It states what the presented evidence does and does not support, and names the layer where records disagree.

Anyone who needs a legally effective evaluation report must go to a body holding the relevant qualification. This project deliberately does not compete in that business and does not imply equivalence to it.

## Cryptographic scope

`lgd_ed25519.py` is a pure-Python RFC 8032 implementation, validated against the RFC's test vectors. It is **not constant-time** and must never hold private keys for production signing. Use it to verify evidence on a machine that has no network and no dependency budget; use a maintained, constant-time library wherever secrets are involved.

## Supply chain

Zero third-party dependencies, so the dependency attack surface is the Python standard library and this repository's own bytes. Corpus fixtures are signed with the RFC 8032 TEST 2 keypair, which is public and holds nothing; a signature from that key proves integrity of the fixture, never authority.

## 中文

本仓产出是**可被第三方复算的过程结果**，不是认证、不是资质，也不带法律效力；它说的是"这份证据支持什么、不支持什么、哪一层在打架"，不是"这个 agent 安全合规"。需要具备法律效力的评测报告，必须找持相应资质的机构——本仓刻意不与那门生意竞争，也不暗示等价。把"无签名"读成"没问题"、把"验不了"读成"通过"，都属于本仓要报的漏洞。
