# lgd-xverify

**A three-envelope, cross-format verdict for AI agent trust records — with signature verification that is actually performed, and a corpus anyone can recompute.**

Three formats describe an AI agent today, and each answers a different question:

| Format | Question it answers | What it does *not* answer |
|---|---|---|
| **1F916** agent record | Who is this agent, and is its history intact? | Whether it was authorized to act |
| **TRACE v0.2** | Where does it run, on what model, under what policy? | Who allowed it |
| **ARIA 1.0** | Who authorized it, for what, and is that still valid? | What it actually did at runtime |

Cross-format verification is therefore not "merging three formats". It is asking whether three pieces fit into one sentence. This tool answers that with a three-valued verdict, and treats *disagreement between envelopes* as a finding rather than a failure to hide.

## What it does

```
python lgd_xverify.py corpus/trace-v0.2.json corpus/aria-1.0.json \
                      corpus/1f916-agent-record.json --keys corpus/keys.json
verdict: PASS
  - structure complete, digests well-formed, anchoring present, no conflict across envelopes
```

`PASS` / `INCONCLUSIVE` / `FAIL`:

- **PASS** — every record well-formed, digests shaped correctly, anchoring present, envelopes do not contradict each other, **and every signature verified**.
- **INCONCLUSIVE** — something is missing or unverifiable. Absence of evidence is not evidence of quality.
- **FAIL** — two envelopes name different agents, a digest is malformed, or **a signature does not verify over its payload**.

Run the tool's own checks:

```
python lgd_ed25519.py --selftest    # 4 RFC 8032 §7.1 vectors, 4 signatures reproduced byte-for-byte, 5 negative controls
python lgd_xverify.py --selftest    # 10 cases
python examples/gen_corpus.py       # regenerate and verify the frozen corpus
```

## What it does not do

Stated plainly, because a verifier that overstates its reach is the failure it was built to catch:

1. **No JWS / COSE parsing.** Real TRACE records carry signatures in JWS or COSE envelopes. This tool handles one binding only: a detached signature over canonical JSON. Calling it "TRACE support" without that qualifier would be wrong.
2. **No constant-time execution.** This verifies evidence; it is not a signing service and should not hold secrets.
3. **No delegation-chain verification.** ARIA's `delegationDepth` is currently always `0` (per its own planned page): no registry issues signed sub-agent credentials yet, so there is nothing to verify.
4. **No assumption of hardware attestation.** TRACE explicitly permits `runtime.platform = "software-only"`. Quoting a TRACE record without reading `platform` is how people accidentally claim a TEE.
5. **No claim of being a certification body.** Output is a recomputable process, not a certificate. See `SECURITY.md` and `NOTICE`-style wording in the docs.

## Signature verification

A record may carry:

```json
"detached_signature": {"kid": "...", "alg": "Ed25519", "value_hex": "..."}
```

The signed message is the **canonical JSON of the record minus that field** (sorted keys, no whitespace, floats refused rather than formatted). Public keys come from a `--keys` file:

```json
{"kids": {"<kid>": "<64 hex chars>"}}
```

Ed25519 is implemented here in pure Python (`lgd_ed25519.py`) and validated against RFC 8032 §7.1 test vectors — including that the signing path reproduces the RFC's signatures **byte for byte**. A scheme that only agrees with itself proves nothing about interoperability.

## The corpus

`corpus/` holds three records about one agent, one per format, each signed, plus `keys.json`. The signing key is the RFC 8032 TEST 2 keypair: published in the standard, holds nothing. That is deliberate — the corpus exists so a third party can recompute the same bytes without asking us for a key.

If your verifier disagrees with this corpus, that disagreement is the interesting result. Please open an issue with the record and the verdict you got.

## Install

No dependencies. Python 3.9+ standard library only.

```
git clone <this repo> && cd lgd-xverify
python lgd_ed25519.py --selftest
```

## 中文说明

**三信封跨格式判定器：对 AI agent 信任记录做「能否拼成一句完整的话」的判定，签名真的验，语料可被外人复算。**

三种格式回答三个不同问题：**1F916** 回答"这个 agent 是谁、历史有没有被篡改"；**TRACE v0.2** 回答"它跑在哪里、什么模型、什么策略"；**ARIA 1.0** 回答"谁授权、授了什么、现在还有效吗"。所以跨格式互验不是"三合一"，而是问这三张拼图能不能拼成一句完整的话；**信封之间互相打架，本身就是要报出来的发现**，不是要抹平的瑕疵。

判定三值：**PASS**（结构齐、摘要有形、锚定在、不冲突、**且签名全部验过**）／**INCONCLUSIVE**（缺东西或不可验——没有证据不等于证据合格）／**FAIL**（主体不一致、摘要畸形、**签名验不过**）。

**明确不做的四件事**：不解析 JWS/COSE（只处理"分离签名 + 规范化 JSON"一种绑定，说"支持 TRACE"必须带这个限定）；不做常量时间（这是验证据的工具，不是保管密钥的签名服务）；不验委托链（ARIA 的 `delegationDepth` 目前恒为 0，对面还没签发）；不假定硬件证明（TRACE 明确允许 `software-only`，引用时先读 `platform`）。

Ed25519 是本仓自己用纯 Python 实现的，用 RFC 8032 §7.1 的官方测试向量验证——包括**sign() 必须逐字节复现 RFC 的签名**，否则"只跟自己一致"对互操作毫无价值。语料用 RFC 里公开的 TEST 2 密钥对签名，因为它不持有任何东西，任何人可复现同样的字节。
