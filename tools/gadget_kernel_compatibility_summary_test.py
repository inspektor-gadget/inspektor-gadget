import json
import pathlib
import tempfile
import unittest

from tools import gadget_kernel_compatibility_summary as summary


class GadgetKernelCompatibilitySummaryTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.reports_dir = pathlib.Path(self.temporary_directory.name)
        self.matrix = {
            "include": [
                {
                    "gadget": gadget,
                    "version": version,
                    "tag": "v1.0.0" if version == "baseline" else "main",
                    "ref_exists": True,
                }
                for gadget in ("trace_exec", "trace_open")
                for version in ("baseline", "current")
            ]
        }

    def tearDown(self):
        self.temporary_directory.cleanup()

    def write_report(
        self,
        gadget,
        version,
        targets,
        sha256=None,
        manifest_digest=None,
        include_artifact=True,
    ):
        report_dir = self.reports_dir / f"{gadget}-{version}"
        report_dir.mkdir()
        metadata = {
            "gadget": gadget,
            "version": version,
            "action_outcome": "success",
            "ref_exists": True,
        }
        if manifest_digest is not None:
            metadata["manifest_digest"] = manifest_digest
        (report_dir / "metadata.json").write_text(
            json.dumps(metadata),
            encoding="utf-8",
        )
        # include_artifact=False models a report that carries real per-kernel
        # results but no recorded artifact SHA-256 (the F1 regression case).
        artifact = (
            {"sha256": sha256 or f"{gadget}-{version}-sha256"}
            if include_artifact
            else {}
        )
        (report_dir / "compatibility.json").write_text(
            json.dumps(
                {
                    "artifact": artifact,
                    "targets": targets,
                }
            ),
            encoding="utf-8",
        )

    def test_builds_regression_table_and_counts_changes(self):
        self.write_report(
            "trace_exec",
            "baseline",
            [
                {
                    "profile_id": "kernel-a",
                    "status": "pass",
                    "required": True,
                },
                {
                    "profile_id": "kernel-b",
                    "status": "fail",
                    "classification_code": "MISSING_BTF",
                    "required": True,
                },
                {
                    "profile_id": "kernel-c",
                    "status": "fail",
                    "classification_code": "UNSUPPORTED_MAP_TYPE",
                    "required": False,
                },
                {
                    "profile_id": "kernel-d",
                    "status": "pass",
                    "required": True,
                },
            ],
        )
        self.write_report(
            "trace_exec",
            "current",
            [
                {
                    "profile_id": "kernel-a",
                    "status": "fail",
                    "classification_code": "UNSUPPORTED_HELPER",
                    "required": True,
                },
                {
                    "profile_id": "kernel-b",
                    "status": "fail",
                    "classification_code": "MISSING_BTF",
                    "required": True,
                },
                {
                    "profile_id": "kernel-c",
                    "status": "pass",
                    "required": False,
                },
                {
                    "profile_id": "kernel-d",
                    "status": "infra_error",
                    "required": True,
                },
            ],
        )

        result = summary.build_summary(json.dumps(self.matrix), self.reports_dir)
        markdown = summary.render_markdown(result)

        self.assertEqual(result["summary"]["regressions"], 1)
        self.assertEqual(result["summary"]["improvements"], 1)
        self.assertEqual(result["summary"]["existing_limitations"], 1)
        self.assertEqual(result["summary"]["incomplete"], 5)
        self.assertEqual(
            result["summary_by_requirement"]["required"]["regressions"],
            1,
        )
        self.assertEqual(
            result["summary_by_requirement"]["optional"]["improvements"],
            1,
        )
        self.assertEqual(result["report_completeness"]["available"], 2)
        self.assertEqual(
            result["report_completeness"]["unexpected_missing"],
            2,
        )
        self.assertEqual(result["artifact_comparison"]["changed_pairs"], 1)
        self.assertEqual(len(result["artifacts"]), 4)
        self.assertEqual(result["artifacts"][0]["action_outcome"], "success")
        self.assertIn("**✅ → ❌ (UNSUPPORTED_HELPER)**", markdown)
        self.assertIn("❌ → ❌ (MISSING_BTF)", markdown)
        self.assertIn("❌ → ✅ (UNSUPPORTED_MAP_TYPE)", markdown)
        self.assertIn("✅ → ⚠️ (INFRA_ERROR)", markdown)
        self.assertIn("— → — (NO_REPORT)", markdown)
        self.assertIn("kernel-a (required)", markdown)

        errors = summary.evaluate_gates(
            result,
            fail_on_regression=True,
            fail_on_unexpected_missing=True,
            fail_on_identical_artifacts=True,
        )
        self.assertEqual(len(errors), 2)
        self.assertIn("1 compatibility regressions found", errors)
        self.assertIn("2 unexpected missing reports", errors[1])

    def test_expected_missing_and_identical_artifact_gates(self):
        matrix = {
            "include": [
                {
                    "gadget": gadget,
                    "version": version,
                    "tag": "v1.0.0" if version == "baseline" else "main",
                    "ref_exists": not (
                        gadget == "new_gadget" and version == "baseline"
                    ),
                }
                for gadget in ("trace_exec", "new_gadget", "bpfstats")
                for version in ("baseline", "current")
            ]
        }
        targets = [
            {
                "profile_id": "kernel-a",
                "status": "pass",
                "required": True,
            }
        ]
        self.write_report(
            "trace_exec",
            "baseline",
            targets,
            sha256="same-sha256",
            manifest_digest="sha256:same-image",
        )
        self.write_report(
            "trace_exec",
            "current",
            targets,
            sha256="same-sha256",
            manifest_digest="sha256:same-image",
        )
        self.write_report("new_gadget", "current", targets)

        result = summary.build_summary(
            json.dumps(matrix),
            self.reports_dir,
            expected_no_ebpf_gadgets=["bpfstats"],
        )
        markdown = summary.render_markdown(result)

        self.assertEqual(result["report_completeness"]["available"], 3)
        self.assertEqual(result["report_completeness"]["expected_missing"], 3)
        self.assertEqual(result["report_completeness"]["unexpected_missing"], 0)
        # baseline and current resolve to the same OCI manifest digest ->
        # release-vs-itself, which is what the gate must catch.
        self.assertTrue(result["image_comparison"]["all_comparable_pairs_same_image"])
        self.assertEqual(
            result["artifacts"][2]["missing_reason"],
            "REFERENCE_NOT_FOUND",
        )
        self.assertEqual(
            result["artifacts"][4]["missing_reason"],
            "NO_EBPF_LAYER",
        )
        self.assertIn("— → ✅ (REFERENCE_NOT_FOUND)", markdown)
        self.assertIn("— → — (NO_EBPF_LAYER)", markdown)
        errors = summary.evaluate_gates(
            result,
            fail_on_regression=True,
            fail_on_unexpected_missing=True,
            fail_on_identical_artifacts=True,
        )
        self.assertEqual(len(errors), 1)
        self.assertIn("same published image", errors[0])

    def test_missing_profile_result_fails_completeness_gate(self):
        matrix = {
            "include": [
                {
                    "gadget": "trace_exec",
                    "version": version,
                    "tag": "v1.0.0" if version == "baseline" else "main",
                    "ref_exists": True,
                }
                for version in ("baseline", "current")
            ]
        }
        baseline_targets = [
            {"profile_id": "kernel-a", "status": "pass", "required": True},
            {"profile_id": "kernel-b", "status": "pass", "required": True},
        ]
        current_targets = [
            {"profile_id": "kernel-a", "status": "pass", "required": True},
        ]
        self.write_report("trace_exec", "baseline", baseline_targets)
        self.write_report("trace_exec", "current", current_targets)

        result = summary.build_summary(json.dumps(matrix), self.reports_dir)
        errors = summary.evaluate_gates(
            result,
            fail_on_unexpected_missing=True,
        )

        self.assertEqual(len(errors), 1)
        self.assertIn("1 unexpected missing profile results", errors[0])
        self.assertIn("trace_exec:kernel-b:current", errors[0])

    def test_regression_is_detected_without_an_artifact_hash(self):
        # F1: a report with real per-kernel results but no artifact SHA-256
        # must still yield its pass/fail data; the ✅ -> ❌ regression cannot be
        # silently downgraded to "incomplete".
        self.write_report(
            "trace_exec",
            "baseline",
            [{"profile_id": "kernel-a", "status": "pass", "required": True}],
        )
        self.write_report(
            "trace_exec",
            "current",
            [
                {
                    "profile_id": "kernel-a",
                    "status": "fail",
                    "classification_code": "UNSUPPORTED_HELPER",
                    "required": True,
                }
            ],
            include_artifact=False,
        )
        matrix = {
            "include": [
                {
                    "gadget": "trace_exec",
                    "version": version,
                    "tag": "v1.0.0" if version == "baseline" else "main",
                    "ref_exists": True,
                }
                for version in ("baseline", "current")
            ]
        }

        result = summary.build_summary(json.dumps(matrix), self.reports_dir)

        cell = result["results"][0]
        self.assertEqual(cell["baseline"]["status"], "pass")
        self.assertEqual(cell["current"]["status"], "fail")
        self.assertEqual(cell["change"], "regression")
        self.assertEqual(result["summary"]["regressions"], 1)
        self.assertEqual(result["report_completeness"]["available"], 2)
        self.assertEqual(result["report_completeness"]["unexpected_missing"], 0)

        errors = summary.evaluate_gates(result, fail_on_regression=True)
        self.assertIn("1 compatibility regressions found", errors)

    def test_identical_ebpf_but_distinct_images_does_not_gate(self):
        # F2: in a quiet week the eBPF object can be byte-identical between the
        # release and current while the published images legitimately differ.
        # The identical-artifacts gate keys on manifest digests, not the eBPF
        # hash, so this healthy state must not fail the run.
        matrix = {
            "include": [
                {
                    "gadget": gadget,
                    "version": version,
                    "tag": "v1.0.0" if version == "baseline" else "main",
                    "ref_exists": True,
                }
                for gadget in ("trace_exec", "trace_open")
                for version in ("baseline", "current")
            ]
        }
        targets = [{"profile_id": "kernel-a", "status": "pass", "required": True}]
        for gadget in ("trace_exec", "trace_open"):
            self.write_report(
                gadget,
                "baseline",
                targets,
                sha256=f"{gadget}-unchanged",
                manifest_digest=f"sha256:{gadget}-release",
            )
            self.write_report(
                gadget,
                "current",
                targets,
                sha256=f"{gadget}-unchanged",
                manifest_digest=f"sha256:{gadget}-main",
            )

        result = summary.build_summary(json.dumps(matrix), self.reports_dir)

        # Every eBPF pair is identical (quiet week) ...
        self.assertTrue(result["artifact_comparison"]["all_comparable_pairs_identical"])
        # ... but the images differ, so the gate stays silent.
        self.assertFalse(result["image_comparison"]["all_comparable_pairs_same_image"])
        errors = summary.evaluate_gates(result, fail_on_identical_artifacts=True)
        self.assertEqual(errors, [])

    def test_rejects_a_matrix_without_both_versions(self):
        matrix = {
            "include": [
                {
                    "gadget": "trace_exec",
                    "version": "baseline",
                    "tag": "v1.0.0",
                }
            ]
        }

        with self.assertRaisesRegex(ValueError, "missing matrix versions: current"):
            summary.build_summary(json.dumps(matrix), self.reports_dir)


if __name__ == "__main__":
    unittest.main()
