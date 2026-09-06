#!/usr/bin/env python3
"""Validate unit CI logs and report selection proof and phase measurements.

Counts are floors from main run 34018271780, not caps on new coverage. ACME
also requires every named regression so replacement tests cannot mask deletion.
Cargo commands are literal workflow steps. This helper never executes a process.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


PHASES = (
    "default-build", "default-lib", "default-unit",
    "acme-build", "acme-outbound", "acme-dns", "acme-renewal",
)
MINIMUM_PASSED = {
    "default-lib": 5880,
    "default-unit": 18239,
    "acme-outbound": 20,
    "acme-dns": 2,
    "acme-renewal": 16,
}
RESULT = re.compile(
    r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
    r"(\d+) measured; (\d+) filtered out; finished in ([0-9.]+)s$",
    re.MULTILINE,
)

# Complete ACME inventory from the pre-move successful baseline.
REQUIRED_TESTS: dict[str, set[str]] = {
    "acme-outbound": {
        "tls::acme::client::tests::challenge_notify_plan_covers_every_remote_status",
        "tls::acme::client::tests::completion_plan_is_remote_state_aware_and_finalizes_at_most_once",
        "tls::acme::client::tests::credential_directory_mismatch_and_legacy_urls_fail_closed",
        "tls::acme::client::tests::custom_client_body_is_checked_again_after_collection",
        "tls::acme::client::tests::declared_oversized_response_body_is_rejected_before_collection",
        "tls::acme::client::tests::excessive_complete_dns_answer_is_rejected_without_truncation",
        "tls::acme::client::tests::excessive_dns_answer_is_fully_policy_screened_before_size_rejection",
        "tls::acme::client::tests::https_and_redirect_invariants_fail_closed",
        "tls::acme::client::tests::normalize_order_domains_trims_lowercases_and_deduplicates",
        "tls::acme::client::tests::private_directory_and_order_resource_urls_never_reach_transport",
        "tls::acme::client::tests::private_directory_new_nonce_and_new_order_are_rejected_in_response",
        "tls::acme::client::tests::private_dns_answer_is_rejected_before_connect",
        "tls::acme::client::tests::private_order_authorization_challenge_finalize_and_certificate_fields_are_rejected",
        "tls::acme::client::tests::public_multi_address_answer_preserves_every_approved_candidate",
        "tls::acme::client::tests::renewal_completion_uses_credential_and_persisted_order_boundary",
        "tls::acme::client::tests::renewal_preparation_uses_the_same_credential_boundary",
        "tls::acme::client::tests::same_origin_absolute_endpoints_are_allowed",
        "tls::acme::client::tests::shared_connection_deadline_covers_fresh_dns_resolution",
        "tls::acme::client::tests::streamed_oversized_response_body_is_stopped_at_hyper_limit",
        "tls::acme::client::tests::unusable_finalization_material_fails_before_any_network_call",
    },
    "acme-dns": {
        "a_dns01_hook_cannot_complete_after_the_renewal_claim_is_lost",
        "dropping_a_dns01_hook_future_terminates_the_child",
    },
    "acme-renewal": {
        "tls::acme_renewal_resume_tests::a_claim_lost_during_resumed_work_cancels_completion_and_cleanup",
        "tls::acme_renewal_resume_tests::a_live_claim_denies_a_second_renewer_before_any_plan_is_made",
        "tls::acme_renewal_resume_tests::a_matching_published_order_url_suppresses_resume",
        "tls::acme_renewal_resume_tests::a_resumed_dns01_order_without_a_hook_is_skipped_without_side_effects",
        "tls::acme_renewal_resume_tests::a_resumed_order_with_ambiguous_challenges_fails_before_any_side_effect",
        "tls::acme_renewal_resume_tests::a_resumed_order_with_corrupt_finalization_material_fails_closed",
        "tls::acme_renewal_resume_tests::a_resumed_order_without_finalization_material_fails_before_any_side_effect",
        "tls::acme_renewal_resume_tests::ambiguous_or_missing_challenge_families_fail_closed",
        "tls::acme_renewal_resume_tests::an_order_without_a_url_is_resumed_rather_than_skipped",
        "tls::acme_renewal_resume_tests::every_active_order_status_is_resumed_after_takeover",
        "tls::acme_renewal_resume_tests::expired_claim_takeover_resumes_a_persisted_dns01_order",
        "tls::acme_renewal_resume_tests::expired_claim_takeover_resumes_a_persisted_http01_order",
        "tls::acme_renewal_resume_tests::expired_claim_takeover_resumes_a_persisted_tls_alpn01_order",
        "tls::acme_renewal_resume_tests::finalization_material_survives_store_reopen_and_takeover",
        "tls::acme_renewal_resume_tests::terminal_and_absent_orders_plan_a_new_order",
        "tls::acme_renewal_resume_tests::weak_or_missing_completion_evidence_still_resumes",
    },
}


def validate_output(phase: str, output: str) -> str:
    """Require a real successful run; Cargo's zero-match success is not proof."""
    if phase.endswith("-build"):
        return "precompile (no tests executed)"
    results = RESULT.findall(output)
    if len(results) != 1:
        raise ValueError(f"{phase}: expected exactly one successful libtest summary")
    passed, failed, ignored, measured, filtered = map(int, results[0][:5])
    if passed < MINIMUM_PASSED[phase] or failed or measured:
        raise ValueError(f"{phase}: missing required passing test count")
    # Default inline tests intentionally leave existing live/opt-in tests ignored;
    # the separate unchanged kTLS step supplies its required live-kernel proof.
    if phase != "default-lib" and ignored:
        raise ValueError(f"{phase}: required selection contains ignored tests")
    if phase in {"default-lib", "default-unit", "acme-dns"} and filtered:
        raise ValueError(f"{phase}: complete target must not filter tests")
    passed_names = set(re.findall(r"^test (\S+) \.\.\. ok$", output, re.MULTILINE))
    missing = REQUIRED_TESTS.get(phase, set()) - passed_names
    if missing:
        raise ValueError(f"{phase}: required tests did not pass: {', '.join(sorted(missing))}")
    return (
        f"{passed} passed, {ignored} ignored, {filtered} filtered; "
        f"libtest execution {results[0][5]}s"
    )


def validate_usage(phase: str, usage: str) -> str:
    """Require complete GNU time telemetry and a successful child exit."""
    match = re.fullmatch(
        r"wall_seconds=([0-9]+(?:\.[0-9]+)?) max_child_rss_kib=([0-9]+) exit_status=0\n?",
        usage,
    )
    if match is None:
        raise ValueError(f"{phase}: missing/invalid timing or unsuccessful command")
    return f"Wall time (including Cargo): {match[1]}s; maximum child RSS: {match[2]} KiB"


def report(phase: str) -> None:
    root = Path(os.environ["RUNNER_TEMP"]) / "unit-ci"
    # Read both files even for precompile phases; missing logs/telemetry are
    # errors. The workflow's pipefail also rejects Cargo AND tee failures
    # before this helper runs, independently of any apparent passing output.
    usage = validate_usage(phase, (root / f"{phase}.time").read_text(encoding="utf-8"))
    proof = validate_output(phase, (root / f"{phase}.log").read_text(encoding="utf-8"))
    result = f"### Unit CI: {phase}\n\n- {proof}\n- {usage}\n"
    print(result, flush=True)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write(result + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=PHASES)
    args = parser.parse_args()
    try:
        report(args.phase)
        return 0
    except (OSError, ValueError, KeyError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
