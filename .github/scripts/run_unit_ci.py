#!/usr/bin/env python3
"""Run the existing unit CI commands with selection proof and phase measurements.

Counts are floors from main run 34018271780, not caps on new coverage. ACME
also requires every named regression so replacement tests cannot mask deletion.
Only CI executes Cargo; importing this module never runs a command.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path


COMMANDS = {
    "default-build": "cargo test --lib --test unit_tests --no-run",
    "default-lib": "cargo test --lib",
    "default-unit": "cargo test --test unit_tests",
    "acme-build": "cargo test --features acme --lib --test acme_dns01_tests --no-run",
    "acme-outbound": "cargo test --features acme --lib tls::acme::client::tests",
    "acme-dns": "cargo test --features acme --test acme_dns01_tests",
    "acme-renewal": "cargo test --features acme --lib tls::acme_renewal_resume_tests",
}
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


def sample_memory(stop: threading.Event, peaks: dict[str, int], errors: list[str]) -> None:
    """Sample whole-runner usage, including concurrent Cargo children, in KiB."""
    while True:
        try:
            fields = dict(re.findall(r"^(\w+):\s+(\d+) kB$", Path("/proc/meminfo").read_text(), re.M))
            ram = int(fields["MemTotal"]) - int(fields["MemAvailable"])
            swap = int(fields["SwapTotal"]) - int(fields["SwapFree"])
            peaks["ram"] = max(peaks["ram"], ram)
            peaks["swap"] = max(peaks["swap"], swap)
        except (OSError, KeyError, ValueError) as error:
            errors.append(f"memory sampling unavailable: {error}")
            return
        if stop.wait(1):
            return


def run(phase: str, command: list[str]) -> int:
    if command != COMMANDS[phase].split():
        raise ValueError(f"{phase}: command must be exactly {COMMANDS[phase]}")
    root = Path(os.environ["RUNNER_TEMP"]) / "unit-ci"
    root.mkdir(parents=True, exist_ok=True)
    usage_path = root / f"{phase}.time"
    output_path = root / f"{phase}.log"
    stop = threading.Event()
    peaks = {"ram": 0, "swap": 0}
    errors: list[str] = []
    sampler = threading.Thread(target=sample_memory, args=(stop, peaks, errors), daemon=True)
    started = time.monotonic()
    sampler.start()
    status = 1
    proof = "FAILED before test proof"
    try:
        # GNU time reports the maximum child RSS, not aggregate process-tree
        # memory; the independent runner sample supplies RAM and swap peaks.
        with output_path.open("w", encoding="utf-8") as log:
            with subprocess.Popen(
                ["/usr/bin/time", "-f", "max_child_rss_kib=%M swap_outs=%W", "-o", str(usage_path), *command],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            ) as process:
                assert process.stdout is not None
                for line in process.stdout:
                    print(line, end="", flush=True)
                    log.write(line)
                status = process.wait()
        if status == 0:
            proof = validate_output(phase, output_path.read_text(encoding="utf-8"))
        else:
            proof = f"FAILED: Cargo exit {status}"
    except (OSError, ValueError) as error:
        proof = f"FAILED: {error}"
        status = 1
    finally:
        stop.set()
        sampler.join()
        elapsed = time.monotonic() - started
        usage = usage_path.read_text().strip() if usage_path.exists() else "child RSS unavailable"
        memory = (
            f"sampled runner peak RAM: {peaks['ram']} KiB; "
            f"swap: {peaks['swap']} KiB (1s samples)"
            if not errors else "; ".join(errors)
        )
        report = (
            f"### Unit CI: {phase}\n\n"
            f"- {proof}\n"
            f"- Wall time (including Cargo): {elapsed:.2f}s; {usage}\n"
            f"- {memory}\n"
        )
        print(report, flush=True)
        if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
            with Path(summary).open("a", encoding="utf-8") as stream:
                stream.write(report + "\n")
    # Keep the actual Cargo failure code; telemetry never turns failure green.
    return status if status >= 0 else 128 - status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=COMMANDS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return run(args.phase, command)
    except (OSError, ValueError, KeyError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
