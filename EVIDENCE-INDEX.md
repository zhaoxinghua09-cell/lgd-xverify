# EVIDENCE-INDEX — lgd-xverify

## 现状

| 级 | 结果 | 证据位置 | 说明 |
|---|---|---|---|
| L1 自我复现 | **有** | `tests/test_verdicts.py`、`tests/test_negative_controls.py`、`tests/negative_control_must_fail.py`、`.github/workflows/gates.yml`、`corpus/{1f916-agent-record,aria-1.0,trace-v0.2,keys}.json`、`examples/gen_corpus.py` | **带反证用例**：`negative_control_must_fail.py` 要求被篡改的记录必须验签失败；语料可自行重算 |
| L2 异体审查 | **0** | — | 无外部审查记录 |
| L3 第二实现 | **0** | — | `lgd_ed25519.py` 是自带实现，未与标准库/其他库交叉验证 |
| L3.5 外部语料 | **0** | — | `corpus/` 为自制语料（含固定 `keys.json`），非外部机构记录 |
| L4 外部节点 | **0** | — | 无第三方使用证据 |

## 已知不硬的地方

1. **自带 Ed25519 实现未做交叉验证。** `lgd_ed25519.py` 是纯标准库实现，正确性只靠自测；应与成熟实现（如 OpenSSL/PyNaCl）对同一签名做逐字节比对。
2. **语料是自制的。** 三份语料（1F916 / TRACE / ARIA）由 `examples/gen_corpus.py` 生成，**能证明"自洽"，不能证明"能处理真实世界记录"**。
3. **三值裁决的边界靠 ADR 定义。** `docs/adr/ADR-002-three-valued-verdict.md` 定义了 PASS/FAIL/UNKNOWN，但缺"什么情况下必须判 UNKNOWN"的穷举清单，边界可能漂移。

## 维护约定

- 新增格式支持 → 必须同时给出篡改用例（反证）与合法用例 → 更新本表 L1 行。
- 引入外部签名库对照 → 才可把 L3 从 0 起算。
- 等级只降不升。
