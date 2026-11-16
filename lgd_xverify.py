"""Cross-format verdict: one fact set, three envelope formats, one answer.

WHAT THIS TOOL DOES
  Normalizes a 1F916 Agent Record dossier, a TRACE v0.2 trust record, and an
  ARIA 1.0 AID into one accountability record, then reports a three-valued
  verdict: PASS / INCONCLUSIVE / FAIL.

SIGNATURE VERIFICATION
  A record may carry a detached signature:
      "detached_signature": {"kid": "...", "alg": "Ed25519", "value_hex": "..."}
  The signed message is the canonical JSON of the record minus that field
  (sorted keys, no whitespace, no floats). Verification is real Ed25519
  (lgd_ed25519.py, validated against RFC 8032 §7.1 vectors), against the public
  key named by kid in a --keys file:
      {"kids": {"<kid>": "<64 hex chars>"}}
  A record whose signature fails to verify is FAIL. A record whose signature is
  absent, or whose kid is unknown, is INCONCLUSIVE — never PASS.

VERDICT RULES
  FAIL          structure broken · digest not a hex SHA-256 · two envelopes
                disagree on subject or on scope
  INCONCLUSIVE  structure present but an anchoring element or a required
                signature is absent, or a signature is present but unverified
  PASS          structure complete, digests well-formed, anchoring present,
                signature present AND verified, and no conflict across envelopes

  v0 does not verify signatures, so v0 cannot reach PASS. That is stated as a
  property, not hidden as a gap: the self-test asserts that no input produces
  PASS in this version. Adding real Ed25519/JWS verification is what unlocks
  PASS, and until then INCONCLUSIVE is the correct answer for a clean record.

USAGE
  python lgd_xverify.py --selftest
  python lgd_xverify.py samples/trace.json samples/aria.json
"""

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lgd_ed25519  # noqa: E402  (same directory, deliberately no package)

SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
SHA256_PREFIXED = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical(obj):
    """Canonical JSON bytes for signing. Sorted keys, no whitespace, no floats.

    Floats are refused rather than formatted, because JCS number formatting is
    a detail this tool does not implement, and silently producing two encodings
    of the same value is how signatures start failing for the wrong reason.
    """
    def guard(o):
        if isinstance(o, float):
            raise ValueError("floats are not allowed in a signed payload")
        if isinstance(o, dict):
            return {k: guard(v) for k, v in o.items()}
        if isinstance(o, list):
            return [guard(v) for v in o]
        return o
    return json.dumps(guard(obj), sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def check_detached_signature(doc, keys):
    """Return (present, verified, reason). Never returns verified=True on a guess."""
    sig = doc.get("detached_signature")
    if not sig:
        return False, False, "no detached signature"
    kid = sig.get("kid")
    alg = sig.get("alg")
    if alg != "Ed25519":
        return True, False, "unsupported signature algorithm %r" % alg
    pub = (keys or {}).get(kid)
    if not pub:
        return True, False, "no public key supplied for kid %r" % kid
    payload = {k: v for k, v in doc.items() if k != "detached_signature"}
    try:
        msg = canonical(payload)
        ok = lgd_ed25519.verify(bytes.fromhex(pub), msg, bytes.fromhex(sig.get("value_hex", "")))
    except (ValueError, TypeError) as e:
        return True, False, "signature could not be evaluated: %s" % e
    return True, ok, "verified" if ok else "signature does not verify over the canonical payload"


class Record:
    """One normalized accountability record."""

    def __init__(self, fmt, subject=None, issuer=None, issued_at=None,
                 scope_ref=None, anchored=False, signature_present=False,
                 signature_verified=False, structural_ok=True, conflicts=None):
        self.fmt = fmt
        self.subject = subject
        self.issuer = issuer
        self.issued_at = issued_at
        self.scope_ref = scope_ref
        self.anchored = anchored
        self.signature_present = signature_present
        self.signature_verified = signature_verified
        self.structural_ok = structural_ok
        self.conflicts = list(conflicts or [])

    def __repr__(self):
        return "<%s subject=%r scope=%r anchored=%s>" % (
            self.fmt, self.subject, self.scope_ref, self.anchored)


def _get(d, *path, default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur


def detect(doc):
    if "@context" in doc or "type" in doc and "VerifiableCredential" in str(_get(doc, "type", default="")):
        return "aria"
    if "eat_profile" in doc:
        return "trace"
    if "record" in doc or "checkpoint" in doc or "dossier" in doc or "#agent-record" in json.dumps(doc)[:400]:
        return "1f916"
    return None


def parse_trace(doc):
    conflicts = []
    structural = "eat_profile" in doc and "subject" in doc and "model" in doc
    if not str(_get(doc, "eat_profile", default="")).startswith("tag:agentrust-io.com"):
        conflicts.append("eat_profile does not identify a TRACE record")
    weights = _get(doc, "model", "weights_digest")
    if weights and not (SHA256_HEX.match(str(weights)) or SHA256_PREFIXED.match(str(weights))):
        conflicts.append("model.weights_digest is not a hex SHA-256")
    platform = _get(doc, "runtime", "platform")
    # honour the specification rather than the marketing: software-only is allowed
    anchored = bool(_get(doc, "transparency")) or bool(_get(doc, "runtime", "measurement"))
    return Record(
        "trace",
        subject=doc.get("subject"),
        issuer=_get(doc, "appraisal", "verifier") or _get(doc, "cnf", "kid"),
        issued_at=doc.get("iat"),
        scope_ref=_get(doc, "policy", "bundle_hash"),
        anchored=anchored,
        signature_present=bool(doc.get("signature")),
        structural_ok=structural,
        conflicts=conflicts,
    ), {"platform": platform}


def parse_aria(doc):
    conflicts = []
    subject = _get(doc, "credentialSubject", "id")
    structural = bool(doc.get("issuer")) and bool(subject)
    status = _get(doc, "credentialStatus", "status") or _get(doc, "status")
    anchored = bool(doc.get("credentialStatus")) or bool(status)
    return Record(
        "aria",
        subject=subject,
        issuer=doc.get("issuer"),
        issued_at=doc.get("validFrom"),
        scope_ref=_get(doc, "credentialSubject", "policy") or _get(doc, "credentialSubject", "delegationDepth"),
        anchored=anchored,
        signature_present=bool(doc.get("proof")),
        structural_ok=structural,
        conflicts=conflicts,
    ), {"status": status}


def parse_1f916(doc):
    conflicts = []
    core = doc.get("dossier") or doc
    subject = core.get("agent_handle") or core.get("handle") or _get(core, "subject", "handle")
    checkpoint = core.get("checkpoint") or doc.get("checkpoint")
    witnesses = _get(checkpoint, "witnesses") if isinstance(checkpoint, dict) else None
    anchored = bool(checkpoint) and bool(witnesses)
    structural = bool(subject) and bool(core.get("keys") or core.get("key_bindings") or core.get("events"))
    sig = core.get("signature") or _get(core, "registry_signature")
    if sig and not str(sig).startswith("1f916."):
        conflicts.append("signature is not in the 1f916.<kind>.v1:<...> form")
    return Record(
        "1f916",
        subject=subject,
        issuer=_get(core, "registry") or core.get("issuer"),
        issued_at=_get(checkpoint, "tree_size_time") or core.get("as_of"),
        scope_ref=None,  # 1F916 records history, not authority
        anchored=anchored,
        signature_present=bool(sig),
        structural_ok=structural,
        conflicts=conflicts,
    ), {"witnesses": len(witnesses) if isinstance(witnesses, list) else 0}


PARSERS = {"trace": parse_trace, "aria": parse_aria, "1f916": parse_1f916}


def normalize(doc, keys=None):
    fmt = detect(doc)
    if fmt is None:
        raise ValueError("unrecognized envelope: not TRACE, ARIA or 1F916")
    rec, extra = PARSERS[fmt](doc)
    rec.extra = extra
    present, verified, reason = check_detached_signature(doc, keys)
    if present:
        rec.signature_present = True
        rec.signature_verified = verified
        if not verified and reason.startswith("signature does not verify"):
            rec.conflicts.append(reason)
    rec.verification_note = reason
    return rec


def verdict(records):
    """Return (verdict, reasons). Predicates are ordered: any FAIL beats INCONCLUSIVE."""
    if not records:
        # SF-001: zero items collected must not be reported as success
        return "INCONCLUSIVE", ["no records supplied — absence of evidence is not evidence"]
    fails, inconclusive = [], []

    for r in records:
        if not r.structural_ok:
            fails.append("%s: required structure missing" % r.fmt)
        fails.extend("%s: %s" % (r.fmt, c) for c in r.conflicts)

    subjects = {r.subject for r in records if r.subject}
    if len(subjects) > 1:
        fails.append("subject disagreement across envelopes: %s" % ", ".join(sorted(subjects)))

    scopes = {r.scope_ref for r in records if r.scope_ref}
    if len(scopes) > 1:
        fails.append("scope disagreement across envelopes: %s" % ", ".join(str(s) for s in sorted(scopes)))

    for r in records:
        if not r.anchored:
            inconclusive.append("%s: no anchoring element (checkpoint+witness / transparency / status)" % r.fmt)
        if not r.signature_present:
            inconclusive.append("%s: signature absent" % r.fmt)
        elif not r.signature_verified:
            inconclusive.append("%s: signature present but not verified by this tool" % r.fmt)
        if not r.subject:
            inconclusive.append("%s: subject not stated" % r.fmt)

    if fails:
        return "FAIL", fails + inconclusive
    if inconclusive:
        return "INCONCLUSIVE", inconclusive
    return "PASS", ["structure complete, digests well-formed, anchoring present, no conflict across envelopes"]


# ---------------------------------------------------------------- samples

SAMPLE_TRACE = {
    "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
    "iat": 1763366400,
    "subject": "did:example:agent-abc123",
    "model": {"provider": "example-labs", "model_id": "m-1", "version": "1.2",
              "weights_digest": "a" * 64},
    "runtime": {"platform": "software-only", "measurement": "sha256:" + "b" * 64},
    "policy": {"bundle_hash": "sha256:" + "c" * 64, "enforcement_mode": "enforce"},
    "data_class": "internal",
    "transparency": "scitt:receipt:example",
    "signature": "es256:key-1:c2ln",
}

SAMPLE_ARIA = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "did:example:tlf",
    "validFrom": "2026-11-16T00:00:00Z",
    "credentialSubject": {"id": "did:example:agent-abc123", "policy": "sha256:" + "c" * 64},
    "credentialStatus": {"status": "active"},
    "proof": {"type": "DataIntegrityProof"},
}

SAMPLE_1F916 = {
    "dossier": {
        "agent_handle": "did:example:agent-abc123",
        "keys": [{"kid": "k1", "alg": "Ed25519"}],
        "checkpoint": {"tree_size": 42, "witnesses": ["w1", "w2"]},
        "signature": "1f916.record.v1:" + "d" * 64,
    }
}


def selftest():
    print("lgd_xverify --selftest")
    print("---------------------")
    cases = []

    # A real signed record: sign with the RFC 8032 TEST 2 keypair (a public test
    # value, holds nothing) and verify through the same path a caller would use.
    TEST_SECRET = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
    TEST_KID = "trace-test-key"
    test_pub = lgd_ed25519.public_key(bytes.fromhex(TEST_SECRET)).hex()
    KEYS = {TEST_KID: test_pub}

    def signed(doc):
        payload = {k: v for k, v in doc.items() if k != "detached_signature"}
        sig = lgd_ed25519.sign(bytes.fromhex(TEST_SECRET), canonical(payload))
        out = dict(doc)
        out["detached_signature"] = {"kid": TEST_KID, "alg": "Ed25519", "value_hex": sig.hex()}
        return out

    signed_trace = signed(json.loads(json.dumps(SAMPLE_TRACE)))
    v1, why1 = verdict([normalize(signed_trace, KEYS)])
    cases.append(("signed + anchored + well-formed -> PASS is reachable", "PASS", v1,
                  "the only path to PASS is a verified signature"))

    tampered_after_signing = json.loads(json.dumps(signed_trace))
    tampered_after_signing["policy"]["enforcement_mode"] = "advisory"
    v2, why2 = verdict([normalize(tampered_after_signing, KEYS)])
    cases.append(("negative control: payload edited after signing", "FAIL", v2,
                  "signature covers the payload"))

    unknown_key = signed(json.loads(json.dumps(SAMPLE_TRACE)))
    v3, why3 = verdict([normalize(unknown_key, {})])
    cases.append(("negative control: signature with no supplied key", "INCONCLUSIVE", v3,
                  "unverifiable is not verified"))
    # no scope on the 1f916 record is correct: it records history, not authority
    clean = [normalize(SAMPLE_TRACE), normalize(SAMPLE_ARIA), normalize(SAMPLE_1F916)]
    v4, why4 = verdict(clean)
    cases.append(("three envelopes, one subject, anchoring present", "INCONCLUSIVE", v4,
                  "signatures present but unverified -> must not be PASS"))

    tampered = json.loads(json.dumps(SAMPLE_TRACE))
    tampered["model"]["weights_digest"] = "zz" * 20
    v5, why5 = verdict([normalize(tampered)] + clean[1:])
    cases.append(("negative control: bad weights_digest", "FAIL", v5, "digest shape"))

    unanchored = json.loads(json.dumps(SAMPLE_TRACE))
    unanchored.pop("transparency")
    unanchored["runtime"].pop("measurement")
    v6, why6 = verdict([normalize(unanchored)])
    cases.append(("negative control: anchoring removed", "INCONCLUSIVE", v6, "absence is not pass"))

    conflict = json.loads(json.dumps(SAMPLE_ARIA))
    conflict["credentialSubject"]["id"] = "did:example:someone-else"
    v7, why7 = verdict([normalize(SAMPLE_TRACE), normalize(conflict)])
    cases.append(("negative control: subject disagreement", "FAIL", v7, "two envelopes name different agents"))

    nostatus = json.loads(json.dumps(SAMPLE_ARIA))
    nostatus.pop("credentialStatus")
    v8, why8 = verdict([normalize(nostatus)])
    cases.append(("aria without status cannot reach PASS", "INCONCLUSIVE", v8, "revocation state unknown"))

    nosig = json.loads(json.dumps(SAMPLE_TRACE))
    nosig.pop("signature")
    v9, why9 = verdict([normalize(nosig)])
    cases.append(("trace without signature stays INCONCLUSIVE", "INCONCLUSIVE", v9, "signature absent"))

    good = [normalize(json.loads(json.dumps(SAMPLE_TRACE)))]
    v10, _ = verdict(good)
    cases.append(("single anchored unsigned trace record", "INCONCLUSIVE", v10,
                  "an unchecked signature claim is a gap, not a pass"))

    bad = 0
    for name, want, got, note in cases:
        ok = want == got
        bad += 0 if ok else 1
        print("  %-4s %-48s want=%-13s got=%-13s  (%s)"
              % ("ok" if ok else "FAIL", name, want, got, note))

    print()
    if bad:
        print("FAIL — %d of %d cases did not match; the verdict is not trustworthy" % (bad, len(cases)))
        print("Reasons were: %s" % json.dumps(
            [why1, why2, why3, why4, why5, why6, why7, why8, why9], ensure_ascii=False))
        return 1
    # negative control of the harness itself: an empty input set must not report PASS
    v0, _ = verdict([])
    if v0 != "PASS":
        print("PASS — %d cases; PASS is reachable only through a verified signature, and an empty"
              % len(cases))
        print("       record set is not PASS.")
        return 0
    print("FAIL — an empty record set reported PASS; the harness cannot be trusted")
    return 1


def main(argv):
    if "--selftest" in argv:
        return selftest()
    paths, keys_path = [], None
    i = 0
    while i < len(argv):
        if argv[i] == "--keys" and i + 1 < len(argv):
            keys_path = argv[i + 1]
            i += 2
            continue
        if not argv[i].startswith("--"):
            paths.append(argv[i])
        i += 1
    if not paths:
        print(__doc__)
        return 2
    keys = {}
    if keys_path:
        with open(keys_path, encoding="utf-8") as f:
            keys = json.load(f).get("kids", {})
    records = []
    for p in paths:
        with open(p, encoding="utf-8") as f:
            records.append(normalize(json.load(f), keys))
    v, reasons = verdict(records)
    print("verdict: %s" % v)
    for r in reasons:
        print("  - %s" % r)
    return {"PASS": 0, "INCONCLUSIVE": 1, "FAIL": 2}[v]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
