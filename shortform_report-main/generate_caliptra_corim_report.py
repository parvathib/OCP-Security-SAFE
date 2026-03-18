"""
Script for generating signed CoRIM reports for each Caliptra firmware
component (FMC, Runtime, ROM).

Reads the existing Caliptra JSON short-form reports, builds a ShortFormReport
per component, and uses OcpReportLib to generate and sign each CoRIM
individually.  Outputs unsigned CBOR, signed CBOR, and a JSON representation
for each component.

Usage:
    .venv/bin/python generate_caliptra_corim_report.py [--reports-dir <path>]

Author: OCP SAFE SFR
Date  : March 2026
"""

from OcpReportLib import ShortFormReport
import argparse
import cbor2
import hashlib
import json
import os
import sys
import traceback

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1, derive_private_key
from cryptography.x509 import CertificateBuilder, NameAttribute, BasicConstraints
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import cryptography.x509 as x509

# Default path to Caliptra JSON report files
DEFAULT_REPORTS_DIR = os.path.join(
    os.path.dirname(__file__),
    "..", "Reports", "CHIPS_Alliance", "2023", "Caliptra",
)

# Report file patterns (name -> filename)
REPORT_FILES = {
    "FMC": "OCP_SAFE_-_caliptra_-_FMC.json",
    "Runtime": "OCP_SAFE_-_caliptra_-_Runtime.json",
    "ROM": "OCP_SAFE_-_caliptra_-_ROM.json",
}

# Key configuration
DEFAULT_TEST_KEY_SEED = "safe-report-default-test-signing-key"
PRIV_KEY_FILE = "testkey_p384.pem"
PUB_KEY_FILE = "testkey_ecdsa_p384.pub"
CERT_FILE = "testkey_p384_cert.der"
SIGN_ALGO = "ES384"
COSE_ALG = -35   # ES384 / P-384
KEY_ID = "Caliptra SAFE Report Signer"


def corim_to_json_serializable(obj, context=None):
    """Convert a CoRIM dict (with CBOR types) to a JSON-serializable structure
    with human-readable field names derived from the CoRIM spec and CDDL schema."""

    # Label maps: integer key -> human-readable name, per context
    LABELS = {
        "corim": {0: "corim-id", 1: "tags", 3: "profile", 5: "entities"},
        "comid": {1: "tag-identity", 4: "triples"},
        "tag-identity": {0: "tag-id"},
        "triples": {10: "conditional-endorsement-triples"},
        "environment": {0: "class"},
        "class": {0: "class-id", 1: "vendor", 2: "model"},
        "measurement": {1: "mval"},
        "mval": {-1: "ocp-safe-sfr", 2: "digests"},
        "ocp-safe-sfr": {
            0: "review-framework-version", 1: "report-version",
            2: "completion-date", 3: "scope-number",
            4: "fw-identifiers", 5: "issues",
        },
        "fw-identifier": {
            0: "fw-version", 1: "fw-file-digests",
            2: "repo-tag", 3: "src-manifest",
        },
        "fw-version": {0: "version", 1: "version-scheme"},
        "issue": {0: "title", 1: "description", 2: "assessment", 3: "cwe", 4: "cve"},
        "cvss": {0: "cvss-score", 1: "cvss-vector", 2: "cvss-version"},
        "entity": {0: "entity-name", 2: "roles"},
    }

    # Child context to use when descending into a labelled field
    CHILD_CTX = {
        "tag-identity": "tag-identity", "triples": "triples",
        "class": "class", "mval": "mval",
        "ocp-safe-sfr": "ocp-safe-sfr", "fw-version": "fw-version",
        "assessment": "cvss", "entities": "entity",
    }

    HASH_ALG_NAMES = {-43: "sha-384", -44: "sha-512"}
    TAG_NAMES = {501: "corim", 506: "comid", 111: "oid", 1: "time"}

    if isinstance(obj, cbor2.CBORTag):
        tag_name = TAG_NAMES.get(obj.tag, f"tag-{obj.tag}")
        value = obj.value
        if isinstance(value, bytes):
            try:
                value = cbor2.loads(value)
            except Exception:
                pass
        child_ctx = {"corim": "corim", "comid": "comid"}.get(tag_name, context)
        return {f"cbor-tag-{obj.tag} ({tag_name})": corim_to_json_serializable(value, child_ctx)}

    if isinstance(obj, bytes):
        return obj.hex()

    if isinstance(obj, dict):
        labels = LABELS.get(context, {})
        result = {}
        for k, v in obj.items():
            label = labels.get(k, str(k)) if isinstance(k, int) else str(k)
            child_ctx = CHILD_CTX.get(label, context)
            result[label] = corim_to_json_serializable(v, child_ctx)
        return result

    if isinstance(obj, (list, tuple)):
        # Detect digest pair: [alg-id, hash-bytes]
        if (len(obj) == 2 and isinstance(obj[0], int)
                and obj[0] in HASH_ALG_NAMES and isinstance(obj[1], bytes)):
            return {"algorithm": HASH_ALG_NAMES[obj[0]], "digest": obj[1].hex()}

        # Infer child context for list items
        child_ctx = context
        items = []
        for item in obj:
            item_ctx = child_ctx
            if isinstance(item, dict):
                keys = set(item.keys())
                # Detect environment-map (has key 0 -> dict with class-id, vendor, or model)
                if 0 in keys and isinstance(item.get(0), dict):
                    inner = item[0]
                    has_class_id = 0 in inner
                    has_vendor_model = isinstance(inner.get(1, None), str) and isinstance(inner.get(2, None), str)
                    if has_class_id or has_vendor_model:
                        item_ctx = "environment"
                # Detect measurement-map (has key 1 -> dict)
                if keys == {1} and isinstance(item.get(1), dict):
                    item_ctx = "measurement"
                # Detect issue-entry (has key 0 -> str, key 2 -> dict)
                if 0 in keys and isinstance(item.get(0), str) and 2 in keys and isinstance(item.get(2), dict):
                    item_ctx = "issue"
                # Detect entity (has key 0 -> str, key 2 -> list)
                if 0 in keys and isinstance(item.get(0), str) and 2 in keys and isinstance(item.get(2), list):
                    item_ctx = "entity"
                # Detect fw-identifier (has key 0 -> dict with version info, or key 1 -> list of digests)
                if 0 in keys and isinstance(item.get(0), dict) and 1 in keys and isinstance(item.get(1), list):
                    if isinstance(item[0].get(0, None), str):
                        item_ctx = "fw-identifier"
            items.append(corim_to_json_serializable(item, item_ctx))
        return items

    if hasattr(obj, "isoformat"):
        return obj.isoformat()

    return obj


def generate_keys(seed_string=DEFAULT_TEST_KEY_SEED):
    """Generate deterministic ECDSA P-384 key pair from a seed string.

    The seed is hashed with SHA-384 to produce a 384-bit integer which is
    used as the P-384 private scalar.
    The same seed always produces the same key pair.
    """
    print(f"Deriving deterministic ECDSA P-384 test key pair from seed...")
    seed_hash = hashlib.sha384(seed_string.encode()).digest()  # 48 bytes
    seed_int = int.from_bytes(seed_hash, "big")

    private_key = derive_private_key(seed_int, SECP384R1())

    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(PRIV_KEY_FILE, "wb") as f:
        f.write(priv_pem)
    with open(PUB_KEY_FILE, "wb") as f:
        f.write(pub_pem)

    # Generate self-signed X.509 certificate
    subject = issuer = x509.Name([
        NameAttribute(NameOID.COMMON_NAME, "Caliptra SAFE Report Test Signer"),
        NameAttribute(NameOID.ORGANIZATION_NAME, "CHIPS Alliance"),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA384())
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    with open(CERT_FILE, "wb") as f:
        f.write(cert_der)

    # Use the certificate's SKI as the COSE_Sign1 kid so verifiers
    # can look up the signing certificate by matching SKI == kid.
    ski = cert.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value.digest

    print(f"  Private key:  {PRIV_KEY_FILE}")
    print(f"  Public key:   {PUB_KEY_FILE}")
    print(f"  Certificate:  {CERT_FILE}")
    print(f"  SKI (kid):    {ski.hex()}")
    return ski


def load_json_report(path):
    """Load a Caliptra JSON short-form report."""
    with open(path, "r") as f:
        return json.load(f)


def generate_corim_for_component(name, json_report, private_key, public_key, kid):
    """Generate unsigned & signed CoRIM for a single Caliptra component."""
    device = json_report["device"]
    audit = json_report["audit"]
    framework_ver = json_report.get("review_framework_version", "1.1")

    tag = name.lower()  # fmc, runtime, rom
    output_cbor = f"caliptra_{tag}_corim_unsigned.cbor"
    output_json = f"caliptra_{tag}_corim_unsigned.json"
    output_signed = f"safe_endorsement_corim_caliptra_{tag}.cbor"

    print(f"\n{'='*60}")
    print(f"  {name}  ({device.get('category', '')})")
    print(f"{'='*60}")

    report = ShortFormReport(framework_ver=framework_ver)

    report.add_device(
        device.get("vendor", ""),
        device.get("product", ""),
        device.get("category", ""),
        device.get("repo_tag", ""),
        device.get("fw_version", ""),
        device.get("fw_hash_sha2_384", ""),
        device.get("fw_hash_sha2_512", ""),
        class_id=device.get("class_id"),
    )

    scope = audit.get("scope_number", 1)
    if isinstance(scope, str):
        scope = int(scope) if scope else 1

    report.add_audit(
        audit["srp"],
        audit.get("methodology", ""),
        audit["completion_date"],
        audit.get("report_version", "1.0"),
        scope,
        audit.get("cvss_version", "3.1"),
    )

    for issue in audit.get("issues", []):
        report.add_issue(
            issue["title"],
            issue["cvss_score"],
            issue["cvss_vector"],
            issue.get("cwe", ""),
            issue.get("description", ""),
            cve=issue.get("cve") or None,
        )

    # Generate unsigned CoRIM
    print("--- Generating CoRIM ---")
    corim_dict = report.get_report_as_corim_dict()
    corim_cbor = report.get_report_as_corim_cbor()
    print(f"  CBOR payload: {len(corim_cbor)} bytes")

    with open(output_cbor, "wb") as f:
        f.write(corim_cbor)
    print(f"  Saved: {output_cbor}")

    corim_json = corim_to_json_serializable(corim_dict, context="corim")
    with open(output_json, "w") as f:
        json.dump(corim_json, f, indent=4)
    print(f"  Saved: {output_json}")

    # Sign as COSE_Sign1 (tag 18) via OcpReportLib
    print("--- Signing (COSE_Sign1) ---")
    report.sign_corim_report_pem(private_key, SIGN_ALGO, kid)
    signed_corim = report.get_signed_corim_report()
    print(f"  Signed size: {len(signed_corim)} bytes")

    with open(output_signed, "wb") as f:
        f.write(signed_corim)
    print(f"  Saved: {output_signed}")

    # Verify
    print("--- Verifying ---")
    try:
        report.verify_signed_corim_report(
            signed_corim, public_key, kid, algo=COSE_ALG)
        print("  Verification: SUCCESS")
    except Exception as e:
        print(f"  Verification FAILED: {e}")

    return [output_cbor, output_json, output_signed]


def main():
    parser = argparse.ArgumentParser(
        description="Generate signed CoRIMs from Caliptra JSON reports.")
    parser.add_argument(
        "--reports-dir",
        default=DEFAULT_REPORTS_DIR,
        help="Directory containing the OCP_SAFE_-_caliptra_-_*.json files",
    )
    args = parser.parse_args()
    reports_dir = os.path.normpath(args.reports_dir)

    print("=== Caliptra CoRIM Report Generation ===")
    print(f"Reports directory: {reports_dir}")

    ski = generate_keys()

    # Load keys
    with open(PRIV_KEY_FILE, "rb") as f:
        private_key = f.read()
    with open(PUB_KEY_FILE, "rb") as f:
        public_key = f.read()

    # Process each Caliptra component
    all_files = []
    for name, filename in REPORT_FILES.items():
        report_path = os.path.join(reports_dir, filename)
        if not os.path.exists(report_path):
            print(f"\nWARNING: Report not found, skipping {name}: {report_path}")
            continue
        json_report = load_json_report(report_path)
        files = generate_corim_for_component(name, json_report, private_key, public_key, ski)
        all_files.extend(files)

    # Summary
    print(f"\n{'='*60}")
    print("  Summary")
    print(f"{'='*60}")
    for path in all_files + [PUB_KEY_FILE, CERT_FILE]:
        if os.path.exists(path):
            size = os.path.getsize(path)
            print(f"  {path}: {size} bytes")


if __name__ == "__main__":
    main()
