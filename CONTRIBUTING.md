# Contributing

**贡献指南。最有价值的贡献是"你的实现和我的不一致"。**

## The contribution this repo wants most

`corpus/` is frozen so a second independent implementation can be compared against it. If you build a verifier from the format specifications rather than from this code, **and your verdict differs**, that difference is the result worth publishing. Open an issue with:

1. which record,
2. the verdict you produced,
3. the field or rule that decided it,
4. the clause in the specification you relied on.

A disagreement backed by a spec clause is more useful than a patch that makes the two implementations agree quietly.

## Ground rules

- **No claim this repo cannot support.** Do not add "first", "only", "most secure", "independently verified", "certified", "in production use" to docs or output. The project's credibility rests on stating limits precisely.
- **Every rule needs a negative control.** A verdict rule added without a case that proves it can fail will be rejected in review. The same discipline applies to tests: a test file that can pass with zero tests executed is itself the defect class this repo catalogs.
- **Absence must never become PASS.** Any change that lets a missing signature, missing key, or missing anchor reach `PASS` is a regression regardless of intent.
- **Do not weaken the corpus to make a case pass.** Amend the rule and re-derive; never edit the fixture.

## Workflow

1. Branch from `main`; never push to it directly (branch protection enforces pull requests).
2. Before pushing: `python lgd_ed25519.py --selftest`, `python lgd_xverify.py --selftest`, `python -m unittest discover -s tests -v`, `python examples/gen_corpus.py --check`.
3. Open a PR describing what rule changed and which negative control proves it.
4. CI must be green. Review is not required by policy; a green gate is.

## Style

- Python 3.9 compatible, standard library only. No new dependencies: the zero-dependency property is a feature of the product, not an accident.
- Comments explain *why*, especially where a choice refuses something (floats, undeclared formats, empty inputs).
- Docs are bilingual where the main claim lives (`README.md`, this file's key points); English first, Chinese after.

## 中文

最想要的贡献不是补代码，而是**"我的独立实现和你结论不一致"**——带上记录、你的结论、做出该结论的字段/规则、以及你依据的规范条款。一条有规范依据的分歧，比一个让两方悄悄对齐的补丁有用得多。三条硬规矩：**不许加本仓支撑不了的措辞**（首个/唯一/最安全/已独立验证/已获认证/已在生产使用）；**每条规则都要有一条能证明它会失败的负向对照**；**绝不允许把缺失变成 PASS**，也不许为了让用例通过去改语料——改规则、重新推导。
