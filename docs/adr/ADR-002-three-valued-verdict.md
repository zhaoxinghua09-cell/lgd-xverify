# ADR-002: Three-valued verdicts, and why absence is never PASS

Status: accepted · 2026-11-17

## Context

The obvious design is a boolean: does this evidence set pass? Two problems appear immediately.

**First, a boolean forces a wrong answer.** A record with a well-formed structure and no signature is
neither a pass nor a fail; it is "not checkable". Reporting that as `false` invites the reader to
conclude tampering. Reporting it as `true` invites the reader to conclude safety. Both are wrong, and
both are confident.

**Second, a boolean cannot express the failure that matters most in this domain** — the failure where
nothing is wrong *because nothing was checked*. An empty record set, a record whose key we were not
given, a record whose signature lives in an armour we do not parse: all of these are cleanly
"true" under a boolean, and all of them mean the verifier did no work.

## Decision

Three values, and the rule that decides each:

| Value | Condition |
|---|---|
| `FAIL` | Subjects disagree across envelopes, a digest is malformed, or a signature fails to verify over its payload |
| `INCONCLUSIVE` | Any record is incomplete, unanchored, has unknown revocation state, carries a signature that cannot be checked, or the input set is empty |
| `PASS` | Every record complete, digests well-formed, anchoring present, no conflicts, **and every signature verified** |

Two invariants are enforced by the self-test rather than by documentation:

1. **An empty record set is never `PASS`.** Zero records means zero evidence and zero checks.
2. **A signature that was not verified is never `PASS`.** Not "unlikely to matter" — never.

`INCONCLUSIVE` exits non-zero from the CLI, deliberately: a pipeline that only inspects the exit code
must not read "we could not check" as success.

## Why not four values (e.g. ERROR)

Errors are raised as exceptions, not scored. A record that cannot be parsed is not a verdict about the
agent; it is a verdict about our input handling. Mixing the two produces records that look evaluated
but were merely eaten by a parser.

## Consequences

- Downstream automation must handle three outcomes, and will resist. That resistance is useful: it
  forces the operator to decide what "we could not check" means in their pipeline.
- Dashboards will want a number. Refusing to synthesize one (no 0–100 score here) is intentional:
  a score invites comparison across evidence sets that were never comparable. Positioning a score as
  the differentiator was also rejected for a second reason — an adjacent project already ships a
  posture score, and adding another would be imitation dressed as innovation.
- `PASS` becomes rare, and that is the correct outcome for a domain where most records do not carry
  verifiable signatures.

## Alternatives rejected

1. **Boolean pass/fail.** Rejected: conflates "no evidence" with "bad evidence".
2. **Numeric score with weights.** Rejected: weights would be invented, and a number hides which
   layer disagreed — the one thing worth reporting.
3. **Treat unverified signatures as PASS with a warning.** Rejected: warnings are not read; that is
   the operating assumption behind this whole project.
4. **Refuse to judge when any record is unverifiable.** Rejected: that collapses `INCONCLUSIVE` into
   "no output" and removes the partial findings — such as two envelopes naming different agents — that
   are still worth stating.

## 中文

**为什么是三值**：布尔立刻逼出错误答案——"结构齐但没签名"既不是通过也不是失败，报 `false` 会让人以为被篡改，报 `true` 会让人以为安全，两个都很自信、都错。更要紧的是布尔表达不了本领域最关键的失效：**没查出问题，是因为根本没查**（空输入、没给公钥、签名在不解析的外壳里——布尔下全是"true"）。**两条不变量由自检钉住而不是写在文档里**：空集合永不是 `PASS`；没验过的签名永不是 `PASS`。**明确拒绝打分**：分数会诱导跨"本来不可比"的证据集做比较，而且相邻项目已经有 posture score，再加一个是把模仿当创新。**被否决的第四条**值得记住：不能因为有一条记录不可验就整体不判——那会把"两份信封指着不同 agent"这种仍然有价值的发现一起丢掉。
