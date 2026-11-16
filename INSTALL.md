# Install

**安装说明。本仓零依赖。**

## Requirements

| Item | Value |
|---|---|
| Python | 3.9+ (standard library only) |
| Packages | none — no `cryptography`, no `PyNaCl`, no `pip install` step |
| Network | not required at runtime |
| Disk | under 1 MB |

## Install from source

```
git clone https://github.com/zhaoxinghua09-cell/lgd-xverify.git
cd lgd-xverify
python lgd_ed25519.py --selftest
python lgd_xverify.py --selftest
```

Both must print `PASS`. Nothing else is needed.

## Why no dependencies

The project needed Ed25519 verification and the usual answer is "install `cryptography`". That answer is correct for a service that holds keys. It is the wrong answer for a verifier that a stranger is supposed to rerun in five minutes on a machine with no network, and it makes the claim "we verify signatures" depend on someone else's binary.

So verification is implemented here (`lgd_ed25519.py`, ~140 lines) and its correctness rests on RFC 8032 §7.1 test vectors, not on trust in a package. If you prefer a maintained implementation, the corpus in `corpus/` is format-neutral: any verifier that reaches the same verdict on the same bytes is a valid cross-check, and a disagreement is worth an issue.

Trade-off accepted openly: this implementation is **not constant-time**. It verifies evidence; it must not be handed secrets.

## Using it as a library

```
import sys; sys.path.insert(0, '<repo>')
from lgd_xverify import normalize, verdict
```

`normalize(doc, keys)` returns a `Record`; `verdict([records])` returns `(verdict, reasons)`.

## Version pinning

Track `main`. This is pre-1.0: corpus compatibility is promised, Python API stability is not. See `CHANGELOG.md`.

## 中文

零依赖：只用 Python 3.9+ 标准库，不装 `cryptography`、不装 `PyNaCl`、无需联网。做法不是省事，而是让"我们验了签名"这句话**不依赖别人的二进制**——正确性建立在 RFC 8032 官方向量上，而不是建立在某个包的公信力上。代价也写明：不是常量时间，它是验证据的工具，不能拿去保管密钥。
