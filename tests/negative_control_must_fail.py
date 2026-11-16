"""The gate's own negative control.

This job must fail the build when the verifier stops being able to fail. It takes
a corpus record that is expected to PASS, tampers with one field without
re-signing, and asserts the verdict changes. If it does not change, the verifier
is no longer checking anything, and a green build would be a false claim.

Run: python tests/negative_control_must_fail.py
"""

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lgd_xverify import normalize, verdict  # noqa: E402

CORPUS = ROOT / "corpus"
KEYS = json.loads((CORPUS / "keys.json").read_text(encoding="utf-8"))["kids"]

failures = []


def check(name, doc, expected):
    v, why = verdict([normalize(doc, KEYS)])
    ok = v == expected
    print("  %-4s %-46s want=%-13s got=%-13s" % ("ok" if ok else "FAIL", name, expected, v))
    if not ok:
        failures.append((name, expected, v, why))


def tampered(name, mutate):
    doc = copy.deepcopy(json.loads((CORPUS / name).read_text(encoding="utf-8")))
    mutate(doc)
    return doc


print("negative_control_must_fail")
print("--------------------------")

check("tampered policy after signing",
      tampered("trace-v0.2.json", lambda d: d["policy"].__setitem__("enforcement_mode", "advisory")),
      "FAIL")

check("tampered subject after signing",
      tampered("aria-1.0.json", lambda d: d["credentialSubject"].__setitem__("id", "did:example:x")),
      "FAIL")

check("zeroed signature bytes",
      tampered("trace-v0.2.json", lambda d: d["detached_signature"].__setitem__("value_hex", "0" * 128)),
      "FAIL")

# and the positive side, so this job cannot pass by rejecting everything
check("untouched corpus record",
      json.loads((CORPUS / "trace-v0.2.json").read_text(encoding="utf-8")), "PASS")

print()
if failures:
    print("FAIL — %d control(s) did not behave as required; the verifier may no longer check"
          % len(failures))
    for name, expected, got, why in failures:
        print("  %s: wanted %s, got %s (%s)" % (name, expected, got, why))
    sys.exit(1)
print("PASS — the verifier still fails when it must, and passes when it should")
sys.exit(0)
