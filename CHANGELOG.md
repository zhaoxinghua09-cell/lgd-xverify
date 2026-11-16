# Changelog

**版本与兼容政策。** 语料与 CLI 行为视为稳定；Python 接口在 1.0 前可能变。

## 0.2.0 — 2026-11-17

Signature verification actually performed; PASS becomes reachable.

**Added**
- `lgd_ed25519.py` — pure-Python Ed25519 sign/verify (RFC 8032 §5.1.6/§5.1.7), no dependencies.
  Self-test covers four §7.1 vectors, byte-exact signature reproduction, five negative controls.
- `detached_signature` binding: `{"kid", "alg": "Ed25519", "value_hex"}`, signed over canonical JSON
  of the record minus that field.
- `--keys` file: `{"kids": {"<kid>": "<64 hex>"}}`.
- `corpus/` — three records about one agent, one per format, each signed with the RFC 8032 TEST 2
  keypair, plus `keys.json`, plus the expected verdict `PASS`.
- `examples/gen_corpus.py` — regenerates the corpus and asserts its verdict, including a CLI replay.

**Changed**
- `PASS` requires verified signatures. A record with an unchecked or unkeyable signature is
  `INCONCLUSIVE`; a record whose signature fails is `FAIL`.
- Verdict reasons are emitted per rule, not as a single string.

**Known limits (unchanged, documented)**
- No JWS / COSE parsing; one binding only.
- No constant-time execution.
- No delegation-chain verification while ARIA `delegationDepth` is always `0`.
- No hardware-attestation assumption; TRACE permits `runtime.platform = "software-only"`.

## 0.1.0 — 2026-11-17

First version, usable only as a demonstration of the failure it warns about.

**Added**
- `lgd_xverify.py` with structural format detection, three normalizers, three-valued verdict.
- Field cross-map for the three formats, derived from their specifications.

**Known defect at this version**
- `PASS` was documented as requiring a verified signature while no verification existed, which made
  `PASS` dead code. The self-test asserted that `PASS` could not be minted, and that assertion is
  what forced 0.2.0. Recorded here rather than quietly removed: a spec that promises a check it
  does not perform is the silent failure this project catalogs.

## Compatibility policy

- **Corpus** — changes require a changelog entry naming the verdict delta. Silent amendments are
  rejected in review.
- **CLI** — flags and exit codes are stable; new flags may be added.
- **Rust/Python API** — pre-1.0, may change with a changelog note.

## 中文

0.1.0 有个**记录在案的真缺陷**：文档写着 `PASS` 要求"签名已验证"，而当时根本没有验签，所以 `PASS` 是死代码；自检里那句"本版本不得铸出 PASS"正是逼出 0.2.0 的东西。这条**不删**，因为"规范承诺了一个它不做的检查"正是本仓要报的那类静默失效。语料的任何变动都要在日志里写明结论变化，悄悄改语料在评审中一律驳回。
