# Contributing to RVI-Sentinel

Thank you for helping improve RVI-Sentinel. Contributions should preserve the project's defensive, evidence-oriented purpose: authorized iPhone/iPad capture, analysis of supplied PCAP or PCAPNG files, and cautious comparison against a persistent baseline.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before opening an issue

1. Search existing issues for the same behavior or request.
2. Use the appropriate issue form.
3. For a vulnerability, use the private process in [SECURITY.md](SECURITY.md) instead of a public issue.
4. Remove sensitive material before submitting anything to GitHub.

Never upload packet captures, generated reports, baseline files, endpoint or hostname inventories, device serial numbers or UDIDs, credentials, tokens, precise private-network details, or unsanitized absolute paths. Reproduce problems with the deterministic fixtures or a minimal synthetic capture whenever possible.

## Development setup

Clone the repository and create the optional GUI environment:

```bash
git clone https://github.com/hideouts-io/RVI-Sentinel.git
cd RVI-Sentinel
python3 -m venv venv
venv/bin/python -m pip install -r requirements-gui.txt
```

The analyzer requires `tshark`. Live capture has additional platform-specific prerequisites documented in the [README](README.md). You do not need an iPhone, `rvictl`, or `rvi0` to run the deterministic analyzer tests.

## Making changes

- Keep changes focused and avoid unrelated rewrites.
- Prefer small, pure functions and explicit typed data models.
- Raise clear, specific errors instead of hiding failures.
- Keep code comments in English.
- Preserve the separation between capture, analysis, enrichment, and interpretation.
- Treat `NEW` as newly observed relative to a baseline, not as a malicious verdict.
- Keep GeoIP lookup local-only. Document and justify any proposed outbound network behavior before implementation.
- Preserve upstream attribution and do not vendor `gh2o/rvi_capture` into this repository.
- Do not commit PCAP/PCAPNG files, generated exports, local baselines, `.mmdb` databases, virtual environments, or machine-specific paths.
- Use synthetic, documentation-only data for screenshots and examples.

## Validation

Run the checks relevant to your change. For a complete analyzer and GUI change, run:

```bash
python3 -m py_compile analyze.py gui.py gui_models.py enrich_endpoints.py finding_enrichment.py
python3 tests/test_analyzer.py
venv/bin/python -m tests.test_gui_models
venv/bin/python -m tests.test_finding_enrichment
QT_QPA_PLATFORM=offscreen venv/bin/python -m tests.test_gui_integration
./scripts/run_gui.sh --smoke-test
git diff --check
```

Platform-specific capture changes should also be exercised on the affected operating system and owned or explicitly authorized hardware. State clearly when a platform or live-device path was not tested.

## Pull requests

A useful pull request:

- explains the problem and the chosen solution;
- links any related issue;
- stays within the authorized defensive scope;
- identifies the platforms and components affected;
- lists exact validation commands and results;
- documents security, privacy, network, or dependency changes;
- uses sanitized or synthetic evidence only;
- updates the README when user-facing behavior changes; and
- keeps third-party provenance and licensing accurate.

Contributions are submitted under the repository's [MIT License](LICENSE). Do not include code or assets that you do not have the right to contribute.
