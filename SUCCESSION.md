# Succession

**接替负责人与交接清单。** 目标：任何具备 Python 基础的人在一个工作日内接手，不需要问原作者。

## Who takes over, and what they need

| Item | Value |
|---|---|
| Current maintainer | Steven Zhao / 赵兴华 (see `CODEOWNERS`) |
| Bus factor | 1 — stated plainly; a two-person project that claims resilience it does not have is its own kind of false record |
| Handover prerequisites | Python 3.9+, git, ability to read a JSON schema table |
| Time to first independent verdict | under an hour with `QUICKSTART.md` |

## 60-minute handover

1. `python lgd_ed25519.py --selftest` → must be `PASS`. If not, nothing downstream is trustworthy.
2. `python lgd_xverify.py --selftest` → `PASS — 10 cases`.
3. `python examples/gen_corpus.py --check` → `PASS`, CLI replay included.
4. Read `docs/adr/ADR-001-*.md` and `docs/adr/ADR-002-*.md`. These are the two decisions everything else follows from: canonical-JSON signature binding, and absence never being PASS.
5. Read `ARCHITECTURE.md` §2.3 (verdict rules). If you can explain why an unsigned record is `INCONCLUSIVE` rather than `PASS`, you are ready.

## Where the bodies are buried

- **`canonical()` refuses floats.** Not a bug, not a TODO to "just add float support": JCS number formatting is unimplemented and a silent second encoding is worse than a refusal.
- **Detection is structural.** Adding a format means adding a detector branch *and* a negative control proving a mislabelled record is still rejected.
- **Corpus is frozen.** Amend a rule and re-derive; never edit a fixture to make a case pass.
- **`PASS` is load-bearing.** Any change that widens it needs a negative control proving the old failure still fails.
- **The RFC vectors in `lgd_ed25519.py` are the root of trust.** If a "fix" makes a vector fail, the fix is wrong, not the vector.

## What has not been done

- No independent external verification of this implementation yet. Claims of correctness rest on the RFC vectors and the negative controls, which is a real but limited basis.
- No JWS / COSE adapter. Anyone adding one inherits the obligation to state that the binding changed.
- No fuzzing. Adversarial-input handling is asserted by hand-written controls, not by a fuzzer.

## 中文

接替清单四步：验签器自检 → 判定器自检 → 语料重算 → 读两份 ADR（规范化 JSON 的签名绑定；缺失永不等于 PASS）。**最容易被踩的三处**：`canonical()` 拒绝浮点是设计而不是待办；加格式必须同时加一条"贴错标签的载荷仍被拒"的负向对照；`PASS` 是有承重的，任何放宽都要附一条"原来的失败仍然失败"的证明。**本仓的信任根是 `lgd_ed25519.py` 里那四组 RFC 向量**——如果某个"修复"让向量失败，错的是修复，不是向量。
