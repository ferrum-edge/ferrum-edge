#!/usr/bin/env bash
# Regenerate vendor/VENDOR_INTEGRITY.sha256 after an INTENTIONAL refresh of a
# vendored, patched crate under vendor/**.
#
# This is the only supported way to update the manifest: it runs the exact same
# hashing the drift guard uses (tests/integration/vendor_integrity_tests.rs), so
# the manifest and the guard can never disagree.
#
# Only run this together with a documented patch change (docs/upstream-*-patches/)
# and review the resulting diff before committing. See docs/dependency-policy.md.
#
# Usage: scripts/update_vendor_integrity.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Regenerating vendor/VENDOR_INTEGRITY.sha256 via the integration drift test..."
UPDATE_VENDOR_INTEGRITY=1 cargo test --test integration_tests vendor_integrity -- --nocapture

echo ""
echo "Done. Review the diff to vendor/VENDOR_INTEGRITY.sha256 and commit it alongside"
echo "the vendored-crate change and its docs/upstream-*-patches/ update."
