import argparse
import datetime
import json
import pathlib
import sys

PASS = "pass"
FAIL = "fail"
INCOMPLETE_STATUSES = {"error", "infra_error", "missing", "skipped", "unknown"}
STATUS_ICONS = {
    PASS: "✅",
    FAIL: "❌",
    "error": "⚠️",
    "infra_error": "⚠️",
    "missing": "—",
    "skipped": "⏭️",
    "unknown": "⚠️",
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Aggregate bpfcompat gadget reports into a release comparison."
    )
    parser.add_argument("--reports-dir", required=True, type=pathlib.Path)
    parser.add_argument("--matrix-json", required=True)
    parser.add_argument("--markdown-output", required=True, type=pathlib.Path)
    parser.add_argument("--json-output", required=True, type=pathlib.Path)
    parser.add_argument(
        "--expected-no-ebpf-gadget",
        action="append",
        default=[],
        help="Gadget expected to publish no extractable eBPF layer; repeatable.",
    )
    parser.add_argument("--fail-on-regression", action="store_true")
    parser.add_argument("--fail-on-unexpected-missing", action="store_true")
    parser.add_argument("--fail-on-identical-artifacts", action="store_true")
    return parser.parse_args()


def read_json(path):
    with path.open(encoding="utf-8") as input_file:
        return json.load(input_file)


def normalize_status(status):
    normalized = str(status or "unknown").lower()
    if normalized in STATUS_ICONS:
        return normalized
    return "unknown"


def missing_result(classification_code="NO_REPORT", expected_missing=False):
    return {
        "status": "missing",
        "classification_code": classification_code,
        "required": None,
        "expected_missing": expected_missing,
    }


def load_expected_matrix(matrix_json):
    matrix = json.loads(matrix_json)
    entries = matrix.get("include", [])
    if not entries:
        raise ValueError("the expected matrix has no include entries")

    gadgets = []
    versions = {}
    for entry in entries:
        gadget = entry["gadget"]
        version = entry["version"]
        if gadget not in gadgets:
            gadgets.append(gadget)
        versions.setdefault(gadget, {})[version] = entry

    for gadget in gadgets:
        missing_versions = {"baseline", "current"} - versions[gadget].keys()
        if missing_versions:
            missing = ", ".join(sorted(missing_versions))
            raise ValueError(f"{gadget} is missing matrix versions: {missing}")

    return gadgets, versions


def load_reports(reports_dir):
    reports = {}
    profiles = []
    profile_requirements = {}

    for metadata_path in sorted(reports_dir.rglob("metadata.json")):
        metadata = read_json(metadata_path)
        key = (metadata["gadget"], metadata["version"])
        if key in reports:
            raise ValueError(f"duplicate metadata for {key[0]} ({key[1]})")

        report_path = metadata_path.with_name("compatibility.json")
        targets = {}
        artifact = None
        if report_path.exists():
            report = read_json(report_path)
            artifact = report.get("artifact")
            for target in report.get("targets", []):
                profile = target.get("profile_id")
                if not profile:
                    continue
                if profile not in profiles:
                    profiles.append(profile)
                required = target.get("required")
                if required is not None and not isinstance(required, bool):
                    raise ValueError(f"{profile} has a non-boolean required value")
                known_required = profile_requirements.get(profile)
                if (
                    known_required is not None
                    and required is not None
                    and known_required != required
                ):
                    raise ValueError(f"{profile} has inconsistent required values")
                if required is not None:
                    profile_requirements[profile] = required
                targets[profile] = {
                    "status": normalize_status(target.get("status")),
                    "classification_code": target.get("classification_code") or "",
                    "required": required,
                    "expected_missing": False,
                }

        reports[key] = {
            "metadata": metadata,
            "artifact": artifact,
            "targets": targets,
        }

    return reports, profiles, profile_requirements


def classify_change(baseline, current):
    baseline_status = baseline["status"]
    current_status = current["status"]

    if baseline_status in INCOMPLETE_STATUSES or current_status in INCOMPLETE_STATUSES:
        return "incomplete"
    if baseline_status == PASS and current_status == FAIL:
        return "regression"
    if baseline_status == FAIL and current_status == PASS:
        return "improvement"
    if baseline_status == FAIL and current_status == FAIL:
        return "existing_limitation"
    if baseline_status == PASS and current_status == PASS:
        return "passing"
    return "incomplete"


def missing_report_result(expected, gadget, expected_no_ebpf_gadgets):
    if expected.get("ref_exists", True) is False:
        return missing_result("REFERENCE_NOT_FOUND", expected_missing=True)
    if gadget in expected_no_ebpf_gadgets:
        return missing_result("NO_EBPF_LAYER", expected_missing=True)
    return missing_result()


def report_artifact(report):
    if not report or not isinstance(report["artifact"], dict):
        return None
    sha256 = report["artifact"].get("sha256")
    if not isinstance(sha256, str) or not sha256:
        return None
    return report["artifact"]


def has_results(report):
    # A report contributes per-kernel results as long as it carries targets.
    # This is deliberately independent of the artifact SHA-256: bpfcompat can
    # emit load/attach results without (or before) recording an artifact hash,
    # and coupling the two would silently drop real pass/fail data — masking a
    # regression as "incomplete". The hash is only used for artifact/image
    # comparison, never to decide whether results exist.
    return bool(report) and bool(report.get("targets"))


def result_for(
    reports,
    versions,
    expected_no_ebpf_gadgets,
    gadget,
    version,
    profile,
):
    report = reports.get((gadget, version))
    if not has_results(report):
        return missing_report_result(
            versions[gadget][version],
            gadget,
            expected_no_ebpf_gadgets,
        )
    return report["targets"].get(
        profile,
        missing_result("MISSING_PROFILE_RESULT"),
    )


def empty_counts():
    return {
        "regressions": 0,
        "improvements": 0,
        "existing_limitations": 0,
        "passing": 0,
        "incomplete": 0,
    }


def requirement_name(required):
    if required is True:
        return "required"
    if required is False:
        return "optional"
    return "unknown"


def build_summary(matrix_json, reports_dir, expected_no_ebpf_gadgets=None):
    expected_no_ebpf_gadgets = set(expected_no_ebpf_gadgets or [])
    gadgets, versions = load_expected_matrix(matrix_json)
    reports, profiles, profile_requirements = load_reports(reports_dir)

    artifacts = []
    for gadget in gadgets:
        for version in ("baseline", "current"):
            expected = versions[gadget][version]
            report = reports.get((gadget, version))
            metadata = report["metadata"] if report else {}
            artifact = report_artifact(report)
            ref_exists = metadata.get(
                "ref_exists",
                expected.get("ref_exists", True),
            )
            report_available = has_results(report)
            expected_missing = False
            missing_reason = ""
            if not report_available:
                missing = missing_report_result(
                    expected,
                    gadget,
                    expected_no_ebpf_gadgets,
                )
                expected_missing = missing["expected_missing"]
                missing_reason = missing["classification_code"]
            artifacts.append(
                {
                    "gadget": gadget,
                    "version": version,
                    "tag": metadata.get("tag", expected["tag"]),
                    "ref": metadata.get("ref", expected.get("ref", "")),
                    "action_outcome": metadata.get("action_outcome", "missing"),
                    "ref_exists": ref_exists,
                    "manifest_digest": metadata.get(
                        "manifest_digest",
                        expected.get("manifest_digest"),
                    ),
                    "report_available": report_available,
                    "expected_missing": expected_missing,
                    "missing_reason": missing_reason,
                    "artifact": artifact,
                }
            )

    results = []
    counts = empty_counts()
    by_requirement = {
        "required": empty_counts(),
        "optional": empty_counts(),
        "unknown": empty_counts(),
    }
    count_keys = {
        "regression": "regressions",
        "improvement": "improvements",
        "existing_limitation": "existing_limitations",
        "passing": "passing",
        "incomplete": "incomplete",
    }

    for profile in profiles:
        for gadget in gadgets:
            baseline = result_for(
                reports,
                versions,
                expected_no_ebpf_gadgets,
                gadget,
                "baseline",
                profile,
            )
            current = result_for(
                reports,
                versions,
                expected_no_ebpf_gadgets,
                gadget,
                "current",
                profile,
            )
            change = classify_change(baseline, current)
            required = profile_requirements.get(profile)
            requirement = requirement_name(required)
            counts[count_keys[change]] += 1
            by_requirement[requirement][count_keys[change]] += 1
            results.append(
                {
                    "gadget": gadget,
                    "profile": profile,
                    "required": required,
                    "baseline": baseline,
                    "current": current,
                    "change": change,
                }
            )

    first_gadget = gadgets[0]
    baseline_tag = versions[first_gadget]["baseline"]["tag"]
    current_tag = versions[first_gadget]["current"]["tag"]
    report_completeness = {
        "available": sum(1 for artifact in artifacts if artifact["report_available"]),
        "expected_missing": sum(
            1
            for artifact in artifacts
            if not artifact["report_available"] and artifact["expected_missing"]
        ),
        "unexpected_missing": sum(
            1
            for artifact in artifacts
            if not artifact["report_available"] and not artifact["expected_missing"]
        ),
    }
    comparable_pairs = 0
    identical_pairs = 0
    changed_pairs = 0
    image_comparable_pairs = 0
    same_image_pairs = 0
    artifacts_by_key = {
        (artifact["gadget"], artifact["version"]): artifact for artifact in artifacts
    }
    for gadget in gadgets:
        baseline_entry = artifacts_by_key[(gadget, "baseline")]
        current_entry = artifacts_by_key[(gadget, "current")]
        baseline_artifact = baseline_entry["artifact"]
        current_artifact = current_entry["artifact"]
        if baseline_artifact and current_artifact:
            comparable_pairs += 1
            if baseline_artifact.get("sha256") == current_artifact.get("sha256"):
                identical_pairs += 1
            else:
                changed_pairs += 1
        # "Release vs itself" is a mismatch of published images, so detect it
        # from the OCI manifest digests (resolved in the generator), not from
        # eBPF-hash equality: in a quiet week the eBPF object can be byte-for-
        # byte identical while the images legitimately differ, and gating on
        # the eBPF hash would false-fail that healthy state.
        baseline_digest = baseline_entry["manifest_digest"]
        current_digest = current_entry["manifest_digest"]
        if baseline_digest and current_digest:
            image_comparable_pairs += 1
            if baseline_digest == current_digest:
                same_image_pairs += 1

    return {
        "schema_version": "ig.gadget-kernel-compatibility-summary.v2",
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "baseline_tag": baseline_tag,
        "current_tag": current_tag,
        "gadgets": gadgets,
        "profiles": profiles,
        "profile_requirements": profile_requirements,
        "artifacts": artifacts,
        "summary": counts,
        "summary_by_requirement": by_requirement,
        "report_completeness": report_completeness,
        "artifact_comparison": {
            "comparable_pairs": comparable_pairs,
            "identical_pairs": identical_pairs,
            "changed_pairs": changed_pairs,
            "all_comparable_pairs_identical": (
                comparable_pairs > 0 and identical_pairs == comparable_pairs
            ),
        },
        "image_comparison": {
            "comparable_pairs": image_comparable_pairs,
            "same_image_pairs": same_image_pairs,
            "all_comparable_pairs_same_image": (
                image_comparable_pairs > 0
                and same_image_pairs == image_comparable_pairs
            ),
        },
        "results": results,
    }


def markdown_escape(value):
    return str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def classification_text(baseline, current):
    baseline_code = baseline.get("classification_code") or ""
    current_code = current.get("classification_code") or ""
    if baseline["status"] == FAIL and current["status"] == FAIL:
        if baseline_code == current_code:
            return current_code
        if baseline_code and current_code:
            return f"{baseline_code} → {current_code}"
    if current["status"] != PASS and current_code:
        return current_code
    if baseline["status"] != PASS and baseline_code:
        return baseline_code
    if current["status"] != PASS:
        return current["status"].upper()
    if baseline["status"] != PASS:
        return baseline["status"].upper()
    return ""


def render_cell(result):
    baseline = result["baseline"]
    current = result["current"]
    value = f"{STATUS_ICONS[baseline['status']]} → {STATUS_ICONS[current['status']]}"
    classification = classification_text(baseline, current)
    if classification:
        value += f" ({markdown_escape(classification)})"
    if result["change"] == "regression":
        return f"**{value}**"
    return value


def render_markdown(summary):
    counts = summary["summary"]
    required_counts = summary["summary_by_requirement"]["required"]
    optional_counts = summary["summary_by_requirement"]["optional"]
    completeness = summary["report_completeness"]
    artifact_comparison = summary["artifact_comparison"]
    image_comparison = summary["image_comparison"]
    lines = [
        "# Gadget kernel compatibility",
        "",
        (
            f"Baseline: `{markdown_escape(summary['baseline_tag'])}` · "
            f"Current: `{markdown_escape(summary['current_tag'])}`"
        ),
        "",
        (
            f"Regressions: **{counts['regressions']}** · "
            f"Required regressions: **{required_counts['regressions']}** · "
            f"Optional regressions: **{optional_counts['regressions']}**"
        ),
        "",
        (
            f"Improvements: **{counts['improvements']}** · "
            f"Existing limitations: **{counts['existing_limitations']}** · "
            f"Passing: **{counts['passing']}** · "
            f"Incomplete: **{counts['incomplete']}**"
        ),
        "",
        (
            f"Reports: **{completeness['available']}** available · "
            f"**{completeness['expected_missing']}** expected missing · "
            f"**{completeness['unexpected_missing']}** unexpected missing"
        ),
        "",
        (
            f"Comparable artifact pairs: "
            f"**{artifact_comparison['comparable_pairs']}** · "
            f"Changed: **{artifact_comparison['changed_pairs']}** · "
            f"Identical eBPF: **{artifact_comparison['identical_pairs']}** · "
            f"Same published image: "
            f"**{image_comparison['same_image_pairs']}**/"
            f"**{image_comparison['comparable_pairs']}**"
        ),
        "",
        (
            "Each cell is `baseline → current`; bold cells are regressions. "
            "✅ pass · ❌ incompatible · ⚠️ infrastructure error · "
            "⏭️ skipped · — missing report"
        ),
        "",
    ]

    gate = summary.get("gate")
    if gate:
        lines.append(f"Gate: **{'PASS' if gate['passed'] else 'FAIL'}**")
        lines.append("")
        for error in gate["errors"]:
            lines.append(f"- {markdown_escape(error)}")
        if gate["errors"]:
            lines.append("")

    if not summary["profiles"]:
        lines.extend(
            [
                "No kernel-profile results were available.",
                "",
            ]
        )
        return "\n".join(lines)

    by_key = {
        (result["profile"], result["gadget"]): result for result in summary["results"]
    }
    gadgets = summary["gadgets"]
    lines.append(
        "| Kernel profile | "
        + " | ".join(markdown_escape(gadget) for gadget in gadgets)
        + " |"
    )
    lines.append("| --- | " + " | ".join("---" for _ in gadgets) + " |")
    for profile in summary["profiles"]:
        cells = [render_cell(by_key[(profile, gadget)]) for gadget in gadgets]
        requirement = requirement_name(summary["profile_requirements"].get(profile))
        profile_label = f"{profile} ({requirement})"
        lines.append(
            f"| {markdown_escape(profile_label)} | " + " | ".join(cells) + " |"
        )
    lines.append("")
    return "\n".join(lines)


def write_output(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def evaluate_gates(
    summary,
    fail_on_regression=False,
    fail_on_unexpected_missing=False,
    fail_on_identical_artifacts=False,
):
    errors = []
    if fail_on_regression and summary["summary"]["regressions"]:
        errors.append(
            f"{summary['summary']['regressions']} compatibility regressions found"
        )

    unexpected_missing = summary["report_completeness"]["unexpected_missing"]
    if fail_on_unexpected_missing and unexpected_missing:
        missing = [
            f"{artifact['gadget']}:{artifact['version']}"
            for artifact in summary["artifacts"]
            if not artifact["report_available"] and not artifact["expected_missing"]
        ]
        errors.append(
            f"{unexpected_missing} unexpected missing reports: " + ", ".join(missing)
        )

    missing_profile_results = [
        f"{result['gadget']}:{result['profile']}:{version}"
        for result in summary["results"]
        for version in ("baseline", "current")
        if result[version]["classification_code"] == "MISSING_PROFILE_RESULT"
    ]
    if fail_on_unexpected_missing and missing_profile_results:
        errors.append(
            f"{len(missing_profile_results)} unexpected missing profile results: "
            + ", ".join(missing_profile_results)
        )

    image_comparison = summary["image_comparison"]
    all_same_image = image_comparison["all_comparable_pairs_same_image"]
    if fail_on_identical_artifacts and all_same_image:
        errors.append(
            "all "
            f"{image_comparison['comparable_pairs']} comparable gadget pairs "
            "resolve to the same published image (identical manifest digests); "
            "baseline and current likely point at the same release"
        )
    return errors


def main():
    args = parse_args()
    try:
        summary = build_summary(
            args.matrix_json,
            args.reports_dir,
            args.expected_no_ebpf_gadget,
        )
    except (KeyError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1

    gate_errors = evaluate_gates(
        summary,
        fail_on_regression=args.fail_on_regression,
        fail_on_unexpected_missing=args.fail_on_unexpected_missing,
        fail_on_identical_artifacts=args.fail_on_identical_artifacts,
    )
    summary["gate"] = {
        "passed": not gate_errors,
        "errors": gate_errors,
    }
    write_output(args.markdown_output, render_markdown(summary))
    write_output(
        args.json_output,
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )
    for error in gate_errors:
        print(f"error: {error}", file=sys.stderr)
    return 1 if gate_errors else 0


if __name__ == "__main__":
    sys.exit(main())
