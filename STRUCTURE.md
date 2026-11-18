# STRUCTURE — 分层与改动代价

## 四层

| 层 | 文件 | 内容 |
|---|---|---|
| L1 密码 | `lgd_ed25519.py` | 纯标准库 Ed25519 签名与验签 |
| L2 裁决 | `lgd_xverify.py` | 三种信封（1F916 / TRACE v0.2 / ARIA 1.0）解析与三值裁决 |
| L3 决策记录 | `docs/adr/ADR-001-canonical-json-detached-signature.md`、`ADR-002-three-valued-verdict.md` | 规范化 JSON 与detached 签名、三值语义的来源 |
| L4 检验 | `tests/{test_verdicts,test_negative_controls,negative_control_must_fail}.py`、`corpus/`、`.github/workflows/gates.yml` | 正例、反例、语料、门禁 |

## 改动代价

| 你想做 | 改哪里 | 必须重跑 | 必须同步 |
|---|---|---|---|
| 改规范化规则 | `lgd_xverify.py` | 全部测试（签名对规范形式极敏感） | ADR-001、`corpus/` 重生成 |
| 改三值语义 | 裁决逻辑 | `test_verdicts.py` 全量 | ADR-002、`API.md`/`ARCHITECTURE.md` |
| 加一种格式 | 解析器 + 语料 | 正例 + 反例成对 | README 格式表 |

## 边界

本仓只回答**记录是否完整、签名是否有效、授权是否仍在有效期**；
身份记录的形状归 `ai-passport-spec`，变更是否越界归 `lcas`。
