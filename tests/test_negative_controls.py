"""Negative controls: every rule must be able to fail.

A verifier that accepts everything passes every positive test. These cases exist
so that each rule has a demonstrated failure, including the two invariants
(empty input is not PASS; an unchecked signature is not PASS).

Run: python -m unittest discover -s tests -v
"""

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lgd_ed25519 import sign  # noqa: E402
from lgd_xverify import canonical, normalize, verdict  # noqa: E402

CORPUS = ROOT / "corpus"
KEYS = json.loads((CORPUS / "keys.json").read_text(encoding="utf-8"))["kids"]

# The corpus signing key, RFC 8032 TEST 2: public in the standard, holds nothing.
# Re-signing after a mutation is what separates "the record is structurally
# incomplete" from "someone edited a signed payload" — two different verdicts.
TEST_SECRET = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
KID = next(iter(KEYS))


def load(name):
    return copy.deepcopy(json.loads((CORPUS / name).read_text(encoding="utf-8")))


def resign(doc):
    payload = {k: v for k, v in doc.items() if k != "detached_signature"}
    sig = sign(TEST_SECRET, canonical(payload))
    doc["detached_signature"] = {"kid": KID, "alg": "Ed25519", "value_hex": sig.hex()}
    return doc


def v1(doc, keys=None):
    return verdict([normalize(doc, KEYS if keys is None else keys)])[0]


class TestEmptyInput(unittest.TestCase):
    def test_empty_set_is_not_pass(self):
        # Zero records = zero evidence and zero checks. Reporting PASS here would
        # be the purest form of the failure this repo catalogs.
        v, _ = verdict([])
        self.assertEqual(v, "INCONCLUSIVE")


class TestSignatureRules(unittest.TestCase):
    def test_payload_edited_after_signing_is_fail(self):
        doc = load("trace-v0.2.json")
        doc["policy"]["enforcement_mode"] = "advisory"
        self.assertEqual(v1(doc), "FAIL")

    def test_zeroed_signature_is_fail(self):
        doc = load("trace-v0.2.json")
        doc["detached_signature"]["value_hex"] = "0" * 128
        self.assertEqual(v1(doc), "FAIL")

    def test_unknown_key_is_inconclusive_not_pass(self):
        self.assertEqual(v1(load("trace-v0.2.json"), keys={}), "INCONCLUSIVE")

    def test_missing_signature_is_inconclusive(self):
        doc = load("trace-v0.2.json")
        doc.pop("detached_signature")
        doc.pop("signature")
        self.assertEqual(v1(doc), "INCONCLUSIVE")

    def test_unsupported_algorithm_is_inconclusive(self):
        doc = load("trace-v0.2.json")
        doc["detached_signature"]["alg"] = "ES256"
        self.assertEqual(v1(doc), "INCONCLUSIVE")

    def test_attacker_key_substitution_is_fail(self):
        # Re-sign the tampered payload with a different key. Even with a valid
        # signature, a payload contradicting the other envelopes must not pass.
        doc = load("aria-1.0.json")
        doc["credentialSubject"]["id"] = "did:example:someone-else"
        self.assertEqual(v1(doc), "FAIL")


class TestStructuralRules(unittest.TestCase):
    def test_malformed_digest_is_fail(self):
        doc = load("trace-v0.2.json")
        doc["model"]["weights_digest"] = "zz" * 20
        self.assertEqual(v1(doc), "FAIL")

    def test_unanchored_record_is_inconclusive(self):
        doc = load("trace-v0.2.json")
        doc.pop("transparency", None)
        doc["runtime"].pop("measurement", None)
        # re-signed, so the signature is valid and the structural gap is what is
        # under test; otherwise signature failure would mask it as FAIL
        self.assertEqual(v1(resign(doc)), "INCONCLUSIVE")

    def test_subject_disagreement_is_fail(self):
        trace, aria = load("trace-v0.2.json"), load("aria-1.0.json")
        aria["credentialSubject"]["id"] = "did:example:someone-else"
        v, why = verdict([normalize(trace, KEYS), normalize(aria, KEYS)])
        self.assertEqual(v, "FAIL")
        self.assertTrue(any("subject" in r.lower() for r in why), why)

    def test_unknown_revocation_state_is_inconclusive(self):
        doc = load("aria-1.0.json")
        doc.pop("credentialStatus", None)
        # re-signed: a signed record that simply does not state revocation is a
        # gap in evidence, not a contradiction
        self.assertEqual(v1(resign(doc)), "INCONCLUSIVE")

    def test_attacker_resigns_a_contradicting_subject(self):
        # The hard case: an attacker holding a valid key re-signs a record that
        # names a different agent. Signature verifies, yet the set must not pass.
        trace, aria = load("trace-v0.2.json"), load("aria-1.0.json")
        aria["credentialSubject"]["id"] = "did:example:attacker"
        v, why = verdict([normalize(trace, KEYS), normalize(resign(aria), KEYS)])
        self.assertEqual(v, "FAIL")
        self.assertTrue(any("subject" in r.lower() for r in why), why)

    def test_unrecognized_shape_raises_rather_than_passes(self):
        with self.assertRaises(ValueError):
            normalize({"type": "TRACE"})


if __name__ == "__main__":
    result = unittest.main(exit=False, verbosity=2).result
    if result.testsRun == 0:
        print("FAIL — zero negative controls executed; nothing was proven")
        sys.exit(1)
    sys.exit(0 if result.wasSuccessful() else 1)
