"""Freeze a three-envelope corpus with real signatures, and assert its verdict.

The corpus is the deliverable a third party can recompute: three records about
one agent, each in its own format, each signed with Ed25519 over canonical JSON,
plus the public keys and the expected verdict. If someone else's verifier
disagrees with `expected.json`, that disagreement is the finding.

  python gen_corpus.py            # writes ./corpus, then verifies it
  python gen_corpus.py --check    # verify the corpus as it stands, write nothing

The signing key is the RFC 8032 TEST 2 keypair: it is published in the RFC
itself, it holds nothing, and using it means a third party can reproduce these
exact bytes without asking us for a key.
"""

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import lgd_ed25519  # noqa: E402
from lgd_xverify import canonical, normalize, verdict  # noqa: E402

CORPUS = HERE / "corpus"
SECRET = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
KID = "rfc8032-test2-key"
SUBJECT = "did:example:agent-abc123"
SCOPE = "sha256:" + "c" * 64

RECORDS = {
    "trace-v0.2.json": {
        "eat_profile": "tag:agentrust-io.com,2026:trace-v0.2",
        "iat": 1763366400,
        "subject": SUBJECT,
        "model": {"provider": "example-labs", "model_id": "m-1", "version": "1.2",
                  "weights_digest": "a" * 64},
        "runtime": {"platform": "software-only", "measurement": "sha256:" + "b" * 64},
        "policy": {"bundle_hash": SCOPE, "enforcement_mode": "enforce"},
        "data_class": "internal",
        "transparency": "scitt:receipt:example",
        "signature": "es256:key-1:c2gn",
    },
    "aria-1.0.json": {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": "did:example:tlf",
        "validFrom": "2026-11-16T00:00:00Z",
        "credentialSubject": {"id": SUBJECT, "policy": SCOPE},
        "credentialStatus": {"status": "active"},
        "proof": {"type": "DataIntegrityProof"},
    },
    "1f916-agent-record.json": {
        "dossier": {
            "agent_handle": SUBJECT,
            "keys": [{"kid": "k1", "alg": "Ed25519"}],
            "checkpoint": {"tree_size": 42, "witnesses": ["w1", "w2"]},
            "signature": "1f916.record.v1:" + "d" * 64,
        }
    },
}


def sign(record):
    payload = {k: v for k, v in record.items() if k != "detached_signature"}
    sig = lgd_ed25519.sign(SECRET, canonical(payload))
    out = dict(record)
    out["detached_signature"] = {"kid": KID, "alg": "Ed25519", "value_hex": sig.hex()}
    return out


def write_corpus():
    CORPUS.mkdir(exist_ok=True)
    (CORPUS / "keys.json").write_text(
        json.dumps({"kids": {KID: lgd_ed25519.public_key(SECRET).hex()}},
                   indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for name, rec in RECORDS.items():
        (CORPUS / name).write_text(
            json.dumps(sign(rec), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("wrote %d records + keys.json into %s" % (len(RECORDS), CORPUS))


def check_corpus():
    keys = json.loads((CORPUS / "keys.json").read_text(encoding="utf-8"))["kids"]
    records = [normalize(json.loads((CORPUS / n).read_text(encoding="utf-8")), keys)
               for n in RECORDS]
    v, reasons = verdict(records)
    print("verdict over the frozen corpus: %s" % v)
    for r in reasons:
        print("  - %s" % r)
    return v


def main(argv):
    if "--check" not in argv:
        write_corpus()
    v = check_corpus()
    if v != "PASS":
        print("FAIL — the corpus does not reach PASS; publishing it would claim a verdict it"
              " does not have")
        return 1
    # the corpus must also be reproducible through the CLI a stranger would use
    probe = subprocess.run(
        [sys.executable, str(HERE / "lgd_xverify.py"),
         str(CORPUS / "trace-v0.2.json"), str(CORPUS / "aria-1.0.json"),
         str(CORPUS / "1f916-agent-record.json"), "--keys", str(CORPUS / "keys.json")],
        capture_output=True, text=True)
    print("CLI replay: exit=%d  %s" % (probe.returncode, probe.stdout.splitlines()[0] if probe.stdout else ""))
    if probe.returncode != 0:
        print("FAIL — the CLI path disagrees with the in-process verdict")
        return 1
    print("PASS — corpus frozen, verdict PASS, and the CLI replay agrees")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
