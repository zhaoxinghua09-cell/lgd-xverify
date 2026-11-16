# API

**命令行与 Python 接口。**

## CLI

```
python lgd_xverify.py [FILE ...] [--keys KEYS.json]
python lgd_xverify.py --selftest
python lgd_ed25519.py [--selftest]
python examples/gen_corpus.py [--check]
```

`FILE` may be any number of JSON files in any of the three formats. Format is detected per file by structure.

`--keys` takes a JSON file:

```json
{"kids": {"<kid>": "<64 hex characters>"}}
```

Records without a matching `kid` are `INCONCLUSIVE`; records whose signature fails are `FAIL`.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | verdict is `PASS` |
| 1 | verdict is `FAIL` |
| 2 | usage error, or `INCONCLUSIVE` |
| 3 | unreadable or unparsable input |

`INCONCLUSIVE` exits non-zero on purpose: a pipeline that only checks "did it exit 0" must not read "we could not check" as success.

## Python

```python
from lgd_xverify import normalize, verdict, canonical

rec  = normalize(doc, keys)        # Record; keys optional dict kid -> pubkey hex
v, why = verdict([rec, rec2])      # ("PASS" | "INCONCLUSIVE" | "FAIL", [reasons])
msg  = canonical(payload)          # canonical JSON bytes for signature payloads
```

`Record` fields: `fmt`, `subject`, `digest_ok`, `anchored`, `scope`, `revocation_known`,
`signature_present`, `signature_verified`, `conflicts`, `verification_note`, `extra`.

`fmt` is one of `trace`, `aria`, `1f916` (lowercase identifiers; the documentation uses the
uppercase names TRACE / ARIA / 1F916 as display names for the same formats).

`lgd_ed25519`:

```python
verify(pubkey: bytes, message: bytes, signature: bytes) -> bool
sign(secret: bytes, message: bytes) -> bytes
public_key(secret: bytes) -> bytes
```

`sign` and `public_key` exist to build fixtures and are checked against RFC 8032 vectors. Do not use them to protect real secrets: there is no constant-time guarantee.

## Accepted shapes

Minimum fields read, per format. Everything else in the record is preserved in `Record.extra` and otherwise ignored.

| Format | Read |
|---|---|
| TRACE | `eat_profile`, `subject`, `model.weights_digest`, `policy.bundle_hash`, `runtime.measurement`, `runtime.platform`, `transparency`, `signature` |
| ARIA | `issuer`, `credentialSubject.id`, `credentialSubject.policy`, `credentialStatus`, `validFrom`, `proof` |
| 1F916 | `dossier.agent_handle`, `dossier.keys`, `dossier.checkpoint`, `dossier.signature` |

Any of the three may additionally carry `detached_signature`.

## Stability

Pre-1.0. Corpus and CLI behaviour are treated as stable; the Python surface may change. See `CHANGELOG.md`.

## 中文

`INCONCLUSIVE` **故意**非零退出：只判"退出码是不是 0"的流水线，绝不能把"我们没验成"读成"通过"。`--keys` 给不到的 `kid` 判 `INCONCLUSIVE`，签名验不过判 `FAIL`——这两种错必须分开，因为处理方式完全不同：前者去补证据，后者要查是不是有人在改载荷。
