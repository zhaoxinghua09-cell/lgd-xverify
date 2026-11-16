"""Positive-path tests: the rules do what the documentation says they do.

Run: python -m unittest discover -s tests -v
"""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lgd_ed25519 import public_key, sign, verify  # noqa: E402
from lgd_xverify import canonical, detect, normalize, verdict  # noqa: E402

CORPUS = ROOT / "corpus"
KEYS = json.loads((CORPUS / "keys.json").read_text(encoding="utf-8"))["kids"]


def load(name):
    return json.loads((CORPUS / name).read_text(encoding="utf-8"))


class TestDetection(unittest.TestCase):
    def test_trace_detected_by_shape(self):
        self.assertEqual(detect(load("trace-v0.2.json")), "trace")

    def test_aria_detected_by_shape(self):
        self.assertEqual(detect(load("aria-1.0.json")), "aria")

    def test_1f916_detected_by_shape(self):
        self.assertEqual(detect(load("1f916-agent-record.json")), "1f916")

    def test_empty_document_is_unrecognized(self):
        self.assertIsNone(detect({}))

    def test_declared_type_does_not_adopt_a_format(self):
        # A record claiming to be TRACE but lacking TRACE structure must not be
        # parsed as TRACE. Declaring a format is not the same as being one.
        doc = {"type": "TRACE", "subject": "did:example:x"}
        self.assertIsNone(detect(doc))


class TestCanonical(unittest.TestCase):
    def test_key_order_does_not_change_bytes(self):
        self.assertEqual(canonical({"b": 1, "a": 2}), canonical({"a": 2, "b": 1}))

    def test_no_whitespace(self):
        self.assertNotIn(b" ", canonical({"a": 1, "b": [1, 2]}))

    def test_floats_are_refused(self):
        # Not a TODO: JCS number formatting is unimplemented here, and a silent
        # second encoding would make signatures fail for an uninteresting reason.
        with self.assertRaises(ValueError):
            canonical({"a": 1.5})

    def test_nested_float_is_refused(self):
        with self.assertRaises(ValueError):
            canonical({"a": {"b": [2.5]}})


class TestCorpusVerdict(unittest.TestCase):
    def test_frozen_corpus_reaches_pass(self):
        records = [normalize(load(n), KEYS) for n in
                   ("trace-v0.2.json", "aria-1.0.json", "1f916-agent-record.json")]
        v, why = verdict(records)
        self.assertEqual(v, "PASS", why)

    def test_trace_without_keys_is_inconclusive(self):
        v, _ = verdict([normalize(load("trace-v0.2.json"), {})])
        self.assertEqual(v, "INCONCLUSIVE")

    def test_records_are_normalized_to_one_subject(self):
        subs = {normalize(load(n), KEYS).subject for n in
                ("trace-v0.2.json", "aria-1.0.json", "1f916-agent-record.json")}
        self.assertEqual(len(subs), 1, subs)


class TestEd25519(unittest.TestCase):
    # The RFC vectors live in the module's self-test; here we assert the library
    # surface behaves as documented, using a throwaway keypair.
    def test_sign_then_verify(self):
        secret = bytes(range(32))
        pub = public_key(secret)
        sig = sign(secret, b"hello")
        self.assertTrue(verify(pub, b"hello", sig))

    def test_signature_is_deterministic(self):
        secret = bytes(range(32))
        self.assertEqual(sign(secret, b"x"), sign(secret, b"x"))

    def test_public_key_is_32_bytes(self):
        self.assertEqual(len(public_key(bytes(range(32)))), 32)


if __name__ == "__main__":
    # A test runner that exits 0 with zero tests executed is the failure this
    # repo catalogs. Make that impossible rather than trusting the runner.
    result = unittest.main(exit=False, verbosity=2).result
    if result.testsRun == 0:
        print("FAIL — zero tests executed; a green result here would be a lie")
        sys.exit(1)
    sys.exit(0 if result.wasSuccessful() else 1)
