# Quickstart (5 minutes)

**从零到一次真实判定，5 分钟。**

## 0. Requirements

Python 3.9 or newer. No third-party packages.

```
python --version
```

## 1. Prove the crypto before trusting the tool

```
python lgd_ed25519.py --selftest
```

Expected: `PASS — 4 RFC vectors verified, 5 negative controls rejected`. This runs the RFC 8032 §7.1 vectors, checks that signing reproduces those signatures byte for byte, and confirms five malformed signatures are rejected. If any line says `FAIL`, stop — the verifier is not trustworthy.

## 2. Prove the verdict logic

```
python lgd_xverify.py --selftest
```

Expected: `PASS — 10 cases`. Three of these are the argument in miniature: a signed, anchored, well-formed record reaches `PASS`; editing one field after signing turns it `FAIL`; stripping the key turns it `INCONCLUSIVE`.

## 3. Get a verdict on the frozen corpus

```
python lgd_xverify.py corpus/trace-v0.2.json corpus/aria-1.0.json \
                      corpus/1f916-agent-record.json --keys corpus/keys.json
```

Expected first line: `verdict: PASS`.

## 4. Break it deliberately

```
python - <<'EOF'
import json, sys
sys.path.insert(0, '.')
from lgd_xverify import normalize, verdict
keys = json.load(open('corpus/keys.json'))['kids']
rec = json.load(open('corpus/trace-v0.2.json'))
rec['policy']['enforcement_mode'] = 'advisory'
print(verdict([normalize(rec, keys)])[0])
EOF
```

Expected: `FAIL`. If you got `PASS`, the build is wrong.

## 5. Point it at your own records

Any JSON file whose shape matches one of the three formats is accepted. Format is detected by structure, not by a declared field, so a record cannot avoid scrutiny by mislabelling itself:

- TRACE — has `eat_profile` starting `tag:agentrust-io.com` and a `subject`
- ARIA — has `@context` with the W3C credentials context and `credentialSubject`
- 1F916 — has a `dossier` object

```
python lgd_xverify.py my-record.json --keys my-keys.json
```

## What you should be skeptical of

This tool does not parse JWS or COSE, does not run in constant time, and cannot verify an ARIA delegation chain because ARIA does not yet issue one. Those limits are listed in `README.md` and `ARCHITECTURE.md`; if you find the tool claiming otherwise anywhere, that is a defect worth reporting.

## 中文速览

三步：`lgd_ed25519.py --selftest`（验签器自身对不对，4 组 RFC 向量 + 5 条负向对照）→ `lgd_xverify.py --selftest`（判定逻辑对不对，10 例）→ 对 `corpus/` 三条记录出结论（应为 `PASS`）→ 然后**故意改一个字段**，结论必须变 `FAIL`。格式按结构识别而不是按声明的字段识别，避免记录靠贴错标签逃过审查。
