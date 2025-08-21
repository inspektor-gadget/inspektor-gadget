---
title: Reporting security issues
sidebar_position: 120
description: >
  Instructions to report security issues found in Inspektor Gadget
---

As Inspektor Gadget maintainers, we take security seriously.
If you discover a security issue, please bring it to our attention right away.

## Reporting a Vulnerability

You have two possibilities:
1. Using the GitHub feature "Report a security vulnerability" when opening an issue.
It will then create a non-public issue specific to security.
2. Sending a mail to security@inspektor-gadget.io.
If you do not know which information you need to fill out when using the first option, then the second option is the way to go.

In all cases, we ask that you do not open a public issue.

## Vulnerability Exploitability eXchange (VEX)

VEX (Vulnerability Exploitability eXchange) is a standard for communicating the
exploitability of known vulnerabilities in software projects.

Inspektor Gadget publishes VEX documents to provide a clear, machine-readable
assessment of our software's relationship to known vulnerabilities (CVEs). VEX
helps users and security tools to:
- Suppress false positives for vulnerabilities that do not affect our project.
- Understand why a specific vulnerability is or is not exploitable in our code.

Our VEX documents follow the [OpenVEX specification](https://openvex.dev/).

The VEX statements are not exhaustive due to resource constraints. As of today,
we don't have a commitment to publish VEX statements for all known
vulnerabilities. When we check if a vulnerability applies to Inspektor Gadget,
we use VEX statements as the primary method to record and communicate our
findings. This ensures our results are shared in an open way.

Inspektor Gadget does not provide Long-Term Support (LTS) releases. This means
that only the latest release receives security updates and maintenance, and
older versions may not be updated or supported. When writing VEX statements, we
focus our effort on the latest release. Other previous versions might be
considered based on user demand. For example, v0.41.0 may be considered because
it is the last release with [builtin
gadgets](gadgets/switching_to_image_based_gadgets.mdx), which some users may
still rely on.

All VEX documents are published in the following locations:

- In the .vex directory of this repository, at
  [https://github.com/inspektor-gadget/inspektor-gadget/tree/main/.vex](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/.vex).
  This helps discovery by tools such as [VEX
  Hub](https://github.com/aquasecurity/vexhub?tab=readme-ov-file#discovery-of-vex-documents)
- Assets attached to their [corresponding official GitHub
  Releases](https://github.com/inspektor-gadget/inspektor-gadget/releases). For
  each release (e.g., v0.42.0), you will find a corresponding vex.json file
  available for download alongside the source code and other release artifacts.

### How to Create or Update VEX Documents

To add a VEX document when none exists for a specific version yet, use the
[vexctl command](https://github.com/openvex/vexctl):

```bash
VER=v0.41.0
vexctl create --file .vex/$VER.vex.json \
--product "pkg:github/inspektor-gadget/inspektor-gadget@$VER" \
--vuln "CVE-2025-54388" \
--status "not_affected" \
--justification "vulnerable_code_not_in_execute_path" \
--id "https://github.com/inspektor-gadget/inspektor-gadget/releases/download/$VER/$VER.vex.json" \
--author "Inspektor Gadget Security Team <security@inspektor-gadget.io>"
```

The [possible
statuses](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-labels)
and [possible
justifications](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md#status-justifications)
are listed in the [OpenVEX
Specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).

When a VEX document already exists for a specific version, use `vexctl add`
instead of `vexctl create`. For example:

```bash
VER=v0.41.0
vexctl add --in-place .vex/$VER.vex.json \
--product "pkg:github/inspektor-gadget/inspektor-gadget@$VER" \
--vuln "CVE-2099-12345" \
--status "not_affected" \
--justification "vulnerable_code_not_in_execute_path"
```
