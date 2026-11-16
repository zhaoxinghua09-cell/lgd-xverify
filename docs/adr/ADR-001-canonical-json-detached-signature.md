# ADR-001: A detached Ed25519 signature over canonical JSON

Status: accepted · 2026-11-17 · supersedes nothing

## Context

Three formats, three signature armours. TRACE carries a JWS or COSE signature; ARIA uses a W3C
data-integrity proof; 1F916 defines its own prefixed attestation strings
(`1f916.record.v1:<sha256_hex>`, `1f916.seal.v1:<handle>:<label>:<content_sha256_hex>`). A
cross-format verdict has to answer one question first: *did anyone actually check anything?*

The tempting shortcut is to declare signatures present and move on. That is precisely the silent
failure class this project catalogs — a field that promises a check nobody performed. A verdict of
`PASS` printed next to an unchecked signature is worse than no verdict, because it is believed.

## Decision

1. **One binding is handled in v0**: a detached signature in the record itself —

   ```json
   "detached_signature": {"kid": "...", "alg": "Ed25519", "value_hex": "..."}
   ```

   The signed message is the canonical JSON of the record with that field removed.

2. **Canonical form**: `json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
   encoded UTF-8.

3. **Floats are refused, not formatted.** `canonical()` raises on any float in the payload.

4. **Each format's own signature field is evidence of intent, not of verification.** `signature`,
   `proof`, and `dossier.signature` mark a record as claiming a signature; only `detached_signature`
   can be verified here. Claims without verifiable bytes yield `INCONCLUSIVE`.

## Why not implement JWS and COSE now

JWS parsing means base64url segments, protected-header canonicalization, algorithm negotiation and
key resolution; COSE means CBOR encoding, and CBOR canonicalization is its own specification. Both
are tractable and both would arrive before the corpus is trustworthy to anyone but us. The order
matters: a verifier that cannot be independently recomputed is a black box regardless of how many
formats it parses.

So: one binding, verified end to end, with a corpus a stranger can recompute. Adding JWS later is
an extension with a stated compatibility cost; shipping JWS now would mean shipping a claim
("supports TRACE") we cannot demonstrate.

## Why refuse floats instead of formatting them

JCS (RFC 8785) specifies number serialization down to the exponent form. Implementing it partially
produces two encodings of one value — and then signatures fail for a reason that looks like tampering
but is arithmetic. A refusal is visible, actionable, and honest: the payload must use integers or
strings. This is the same choice as "absence is not PASS", one level down.

## Consequences

**Good**
- `PASS` means something checkable: every signature was verified, not merely present.
- A stranger can recompute the verdict: the corpus uses an RFC-published keypair, and the canonical
  form is written down here in one sentence.
- Failures are separable: `FAIL` (evidence contradicts itself) versus `INCONCLUSIVE` (nothing to
  check) imply different next actions.

**Bad**
- Records whose signatures live in JWS/COSE are not verified, and must be reported as
  `INCONCLUSIVE`. This over-reports uncertainty for legitimate records. Accepted: under-reporting
  confidence is the safe direction.
- Payloads with floats are rejected outright, which will annoy someone with a timestamp as a float.
  Accepted: they can convert at the source.
- We now maintain a canonicalizer and a curve implementation that the ecosystem already has. Accepted
  for the zero-dependency property; the corpus provides the cross-check.

## Alternatives rejected

1. **Trust the presence of a signature field.** Rejected: this is the exact defect the tool exists to
   find. A verifier with that rule would certify a record whose signature is 64 zero bytes.
2. **Verify with `cryptography`, allow a dependency.** Rejected for the *verifier* role: a stranger
   must be able to rerun it offline in five minutes, and "we verify signatures" must not depend on
   someone else's wheel. Reconsider if this ever needs to hold keys.
3. **Sign the raw file bytes instead of canonical JSON.** Rejected: whitespace or key order would
   change the verdict, which turns a formatting accident into an integrity accusation.
4. **Declare `delegationDepth` unsupported without saying why.** Rejected: the reason is that ARIA
   does not issue signed sub-agent credentials yet. "Unsupported" without a cause reads as our gap
   rather than the state of the ecosystem.

## 中文

**决策**：v0 只处理一种绑定——记录内自带的分离签名，签的对象是"去掉该字段后的规范化 JSON"；浮点一律拒绝而不是格式化。**理由**：三种格式各有签名外壳（TRACE 用 JWS/COSE、ARIA 用数据完整性证明、1F916 用自定义前缀串），若只"声明签名存在"就判 PASS，那正是本仓要抓的静默失效。**不立刻做 JWS/COSE 的顺序理由**：能被别人独立复算的验证器才有意义，先做一种绑定并配一份陌生人能重算的语料，比先做三种格式的解析器更值。**代价如实写**：合法的 JWS/COSE 记录会被判成 `INCONCLUSIVE`（宁可少报信心），浮点载荷会被直接拒（源头改掉即可）。**被否决的替代方案**里第一条最值得记住：**"信任签名字段存在"会让一个 64 字节全零的签名通过验证。**
