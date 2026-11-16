# Troubleshooting

**故障排查。每一条都是实测遇到过的，不是设想。**

## `unrecognized envelope: not TRACE, ARIA or 1F916`

Detection is structural. Check the shape rather than the declared type:

| You think it is | It must contain |
|---|---|
| TRACE | `eat_profile` beginning `tag:agentrust-io.com`, and `subject` |
| ARIA | `@context` including the W3C credentials v2 context, and `credentialSubject` |
| 1F916 | a top-level `dossier` object |

A record that declares `"type": "TRACE"` but lacks the fields is not accepted: declaring a format does not adopt it. If your record is genuinely a variant, open an issue with the file (redacted as needed) rather than editing the detector locally.

## `no public key supplied for kid '...'`

The `--keys` file is missing that `kid`, or the file shape is wrong. It must be `{"kids": {"<kid>": "<64 hex>"}}`, not a flat mapping. Result is `INCONCLUSIVE`, which is correct behaviour — stop treating it as a bug to work around.

## `signature does not verify over the canonical payload`

Three causes, in order of likelihood:

1. **The record was edited after signing.** This is what the tool exists to catch. Compare the signed copy byte for byte.
2. **The signature was produced over a different canonical form.** This tool signs `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`. A signer using key-order-preserving JSON or inserting spaces produces a different byte string. Both are "JSON", only one is covered here.
3. **A float is in the payload.** Refused by design: `floats are not allowed in a signed payload`. Convert to integer or string at the source.

## Verdict is `INCONCLUSIVE` and I expected `PASS`

Check, in this order: signature present? key supplied? digest well-formed (64 hex, or `sha256:` + 64 hex)? anchoring present (TRACE `transparency` or `runtime.measurement`; 1F916 checkpoint with witnesses)? ARIA `credentialStatus` present? Any of these missing yields `INCONCLUSIVE` by design — absence of evidence is not evidence of quality.

## Verdict is `FAIL` but nothing looks wrong

`FAIL` is emitted on three conditions: subjects disagree across envelopes, a digest is malformed, or a signature fails. The reason lines name which. Subject disagreement is the most common surprise: two records about `did:example:a` and `did:example:b` are two agents, however similar their other fields.

## `--selftest` prints FAIL

Do not use the build. The self-test is the gate: `lgd_ed25519.py --selftest` failing means the signature layer is broken; `lgd_xverify.py --selftest` failing means a verdict rule is broken. Both failures are absolute, not warnings.

## Running inside another project

`lgd_xverify.py` inserts its own directory into `sys.path` to import `lgd_ed25519`. If you vendor it elsewhere, keep both files in the same directory, or add both to your path explicitly.

## Python version

3.9+ required. On 3.8 the `dict | dict` merge and some f-string forms used in the tooling fail. CI runs 3.9 and 3.12.

## 中文

`unrecognized envelope` = 结构不对（不是声明不对）：贴了 `"type": "TRACE"` 但没有 TRACE 的字段，**不算** TRACE。`no public key supplied` 判 `INCONCLUSIVE` 是**正确行为**，不是 bug，别去绕。`signature does not verify` 最常见的原因就是**签发后改了载荷**——那正是这个工具存在的理由。`INCONCLUSIVE` 但预期是 `PASS`：按"签名在不在、公钥给没给、摘要形不形、锚定在不在、ARIA 状态在不在"的顺序查。
