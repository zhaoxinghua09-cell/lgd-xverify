# Architecture

**架构说明：为什么是"一句完整的话"，而不是"三合一"。**

## 1. The problem this solves

An agent can present three well-formed records and still be unaccountable. Each format is internally consistent and each covers a different question:

```
1F916 agent record   -> identity and history integrity   ("who, and was it tampered with")
TRACE v0.2           -> runtime and policy context       ("where, on what, under what rules")
ARIA 1.0             -> authorization and scope          ("allowed by whom, to do what, still valid")
```

A verifier that accepts any one of them, alone, answers one third of the question and implies the rest. That implication is the defect. So the unit of judgment here is the **set**: do these records describe one agent, without contradiction, with each layer's claim intact?

## 2. Pipeline

```
  JSON file
     |
     v
  detect(doc)         structural detection, not a declared field
     |
     v
  PARSERS[fmt]        per-format normalizer -> Record
     |                 (subject, digests, anchoring, scope, conflicts)
     v
  check_detached_signature(doc, keys)
     |                 canonical JSON over the payload, real Ed25519
     v
  verdict([records])  three-valued
```

### 2.1 Detection is structural

`detect()` looks at shape: `eat_profile` + `subject` for TRACE, W3C credentials context + `credentialSubject` for ARIA, a `dossier` object for 1F916. A record cannot escape a stricter parse by declaring the wrong format, and an unrecognized shape raises instead of silently passing.

### 2.2 Normalization to one accountability record

| Field | TRACE source | ARIA source | 1F916 source |
|---|---|---|---|
| `subject` | `subject` | `credentialSubject.id` | `dossier.agent_handle` |
| `digest_ok` | `model.weights_digest` shape | — | — |
| `anchored` | `transparency` receipt or `runtime.measurement` | — | `dossier.checkpoint` with witnesses |
| `scope` | `policy.bundle_hash` | `credentialSubject.policy` | none (by design) |
| `revocation_known` | — | `credentialStatus` present | — |
| `signature_present` | `signature` or detached | `proof` or detached | `dossier.signature` or detached |

1F916 having **no** scope is correct, not a gap: it records history, not authority. Grading it as "missing authorization" would be grading a passport for not being a visa.

### 2.3 Verdict rules

```
FAIL          if any conflict: subject disagreement, malformed digest,
                or a signature that fails to verify over its payload
INCONCLUSIVE  if any record is incomplete, unanchored, has an unknown
                revocation state, or carries a signature we cannot check
PASS          only if every record is complete, digests are well-formed,
                anchoring is present, no conflicts, and every signature verified
```

Two properties are deliberate:

- **Absence is never PASS.** A record with no signature is `INCONCLUSIVE`, not "probably fine". This is the silent-failure class the project exists to catalog.
- **An empty input set is never PASS.** Zero records means zero evidence and zero checks performed.

### 2.4 Signature binding

The signed message is the canonical JSON of the record minus `detached_signature`:

- keys sorted, no whitespace, UTF-8, `ensure_ascii=False`
- **floats refused, not formatted.** JCS number formatting is unimplemented here; producing two encodings of one value would make signatures fail for an uninteresting reason, so the choice is refusal.

This is one binding among several that exist in the wild. JWS and COSE wrap the same claim in different armor; parsing those is explicitly out of scope (see `README.md` §"What it does not do").

## 3. Ed25519

`lgd_ed25519.py` implements verification and signing from RFC 8032 §5.1.6/§5.1.7 with affine twisted-Edwards arithmetic and no dependencies. Correctness is established two ways, both against the RFC's own bytes, never against this repo's own output:

1. four §7.1 vectors verify (`verify=True`)
2. signing with the RFC's secret keys reproduces the RFC's public keys and signatures exactly (`pubkey=True signature=True`)

Plus five negative controls (flipped byte, altered message, wrong key, `S >= L`, truncated signature). A verifier that accepts everything passes every positive vector, so the negative controls are part of the proof, not decoration.

Not implemented: constant-time comparison, Ed25519ctx and Ed25519ph variants. Deliberate: this must not hold secrets.

## 4. Module map

| File | Role |
|---|---|
| `lgd_ed25519.py` | RFC 8032 Ed25519 sign/verify + self-test |
| `lgd_xverify.py` | detection, three normalizers, canonical JSON, signature binding, three-valued verdict, CLI, self-test |
| `examples/gen_corpus.py` | regenerates `corpus/` and asserts its verdict is PASS |
| `tests/test_verdicts.py` | positive paths and rule coverage |
| `tests/test_negative_controls.py` | each rule must be able to fail |
| `docs/adr/` | why the decisions are what they are |

## 5. What would falsify this

Concrete, so future work has a target:

- a record that reaches PASS while a signature was not checked
- a corpus amendment that changes the verdict without changing the bytes
- an envelope pair with contradictory subjects that is reported as anything other than FAIL
- a second independent implementation that disagrees on the frozen corpus

The last one is the interesting one. `corpus/` exists for exactly that.

## 中文要点

判定的单位是**记录集合**，不是单条记录：任何单一信封都只回答三分之一的问题，接受它就等于默示了其余三分之二——那个"默示"正是缺陷。格式按**结构**识别，记录不能靠贴错标签逃过更严格的解析；1F916 没有授权范围是**对的**（它记历史不记授权），拿它当"缺授权"来扣分等于拿护照去查签证。两条硬性质：**缺失永远不是 PASS**，**空输入永远不是 PASS**。签名绑定只做"分离签名 + 规范化 JSON"一种，浮点一律拒绝而不是格式化——因为没实现 JCS 数字格式化，悄悄生成两种编码会让签名因为一个不相干的理由失败。
