#!/usr/bin/env bash
# Generate a signed endorsement CoRIM from Caliptra JSON short-form reports.
#
# Usage:
#   ./gen_endorsement_corim.sh [reports-dir]
#
# If no reports-dir is given, defaults to the Caliptra reports in this repo.
# The script sets up a Python 3.12 venv (if not already present), installs
# dependencies, runs generate_caliptra_corim_report.py, and copies the
# signed CoRIM and certificate into <reports-dir>.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/.venv"
PYTHON=python3.12
DEFAULT_REPORTS_DIR="$SCRIPT_DIR/../Reports/CHIPS_Alliance/2023/Caliptra"

if [[ $# -ge 1 ]]; then
    REPORTS_DIR="$(cd "$1" && pwd)"
else
    echo "==> No reports-dir specified, using default: $DEFAULT_REPORTS_DIR"
    REPORTS_DIR="$(cd "$DEFAULT_REPORTS_DIR" && pwd)"
fi

# ── 1. Set up virtual environment ──────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    echo "==> Creating Python 3.12 virtual environment..."
    "$PYTHON" -m venv "$VENV_DIR"
fi

echo "==> Installing dependencies..."
"$VENV_DIR/bin/pip" install --quiet -r "$SCRIPT_DIR/requirements.txt"

# ── 2. Generate signed endorsement CoRIM ───────────────────────────────────
# Remove any stale signed CoRIMs so we only copy freshly-generated ones.
echo "==> Running generate_caliptra_corim_report.py..."
cd "$SCRIPT_DIR"
rm -f safe_endorsement_corim_caliptra_*.cbor
"$VENV_DIR/bin/python" generate_caliptra_corim_report.py --reports-dir "$REPORTS_DIR"

# ── 3. Copy artifacts into reports directory ───────────────────────────────
echo ""
echo "==> Copying artifacts to $REPORTS_DIR ..."
for f in "$SCRIPT_DIR"/safe_endorsement_corim_caliptra_*.cbor \
         "$SCRIPT_DIR/testkey_p384_cert.der" \
         "$SCRIPT_DIR/testkey_ecdsa_p384.pub"; do
    if [[ -f "$f" ]]; then
        cp "$f" "$REPORTS_DIR/"
        echo "    $(basename "$f") -> $REPORTS_DIR/"
    fi
done

echo ""
echo "==> Done."
