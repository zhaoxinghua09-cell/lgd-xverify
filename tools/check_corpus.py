#!/usr/bin/env python3
"""check_corpus.py — 语料结构完整性检查（只验结构，不验签名）。

跑法：python tools/check_corpus.py
退出码 0 = 三份语料结构齐全；非 0 = 缺口，逐条打印。

诚实边界：本脚本不执行签名验证，签名正确性由 tests/ 下的用例负责。
"""
import json, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"
EXPECT = {
    "1f916-agent-record.json": ["agent", "history"],
    "trace-v0.2.json": ["runtime", "model"],
    "aria-1.0.json": ["authority", "scope"],
}
KEYS = CORPUS / "keys.json"

def main():
    fails = []
    if not KEYS.exists():
        fails.append("corpus/keys.json 缺失")
    else:
        try:
            k = json.loads(KEYS.read_text(encoding="utf-8"))
            if not k:
                fails.append("corpus/keys.json 为空对象")
        except Exception as e:
            fails.append(f"corpus/keys.json 解析失败: {e}")

    for name, fields in EXPECT.items():
        p = CORPUS / name
        if not p.exists():
            fails.append(f"{name} 缺失"); continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as e:
            fails.append(f"{name} 解析失败: {e}"); continue
        if not isinstance(data, dict):
            fails.append(f"{name} 顶层不是对象"); continue
        for f in fields:
            if f not in data:
                fails.append(f"{name} 缺字段 {f}")
        # 每个信封必须带签名段，否则无法验签
        if "signature" not in data and "sig" not in data:
            fails.append(f"{name} 无 signature/sig 字段")

    if fails:
        print("FAIL")
        for f in fails:
            print("  -", f)
        return 1
    print("OK: 三份语料结构齐全，含签名段")
    return 0

if __name__ == "__main__":
    sys.exit(main())
