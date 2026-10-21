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
venv/bin/python -m py_compile analyze.py analyze_preview.py analyze_reviewed.py analyze_captured.py analysis_baseline.py analysis_observations.py packet_models.py pcapng_process.py saved_capture.py captured_dns.py dns_sessions.py dns_view.py capture_models.py capture_devices.py capture_session.py capture_receipt.py capture_stats.py capture_mobile.py gui.py gui_shell.py gui_icons.py gui_models.py packet_timeline.py packet_view.py packet_sessions.py session_view.py report_loader.py enrich_endpoints.py local_endpoint_enrichment.py finding_enrichment.py
python3 tests/test_analyzer.py
venv/bin/python -m tests.test_capture_models
venv/bin/python -m tests.test_gui_models
venv/bin/python -m tests.test_finding_enrichment
venv/bin/python -m tests.test_saved_capture
venv/bin/python -m tests.test_pcapng_process
venv/bin/python -m tests.test_capture_stats
venv/bin/python -m tests.test_capture_receipts
QT_QPA_PLATFORM=offscreen venv/bin/python -m tests.test_gui_integration
QT_QPA_PLATFORM=offscreen venv/bin/python -X faulthandler -m tests.test_gui_shell
venv/bin/python -m tests.test_packet_timeline
QT_QPA_PLATFORM=offscreen venv/bin/python -X faulthandler -m tests.test_packet_view
QT_QPA_PLATFORM=offscreen venv/bin/python -X faulthandler -m tests.test_packet_gui_integration
venv/bin/python -m tests.test_packet_sessions
QT_QPA_PLATFORM=offscreen venv/bin/python -X faulthandler -m tests.test_session_view
QT_QPA_PLATFORM=offscreen venv/bin/python -X faulthandler -m tests.test_session_gui_integration
venv/bin/python -m tests.test_captured_dns
venv/bin/python -m tests.test_dns_sessions
QT_QPA_PLATFORM=offscreen venv/bin/python -X faulthandler -m tests.test_dns_view
QT_QPA_PLATFORM=offscreen venv/bin/python -X faulthandler -m tests.test_dns_gui_integration
./scripts/run_gui.sh --smoke-test
git diff --check
```

Platform-specific capture changes should also be exercised on the affected operating system and owned or explicitly authorized hardware. State clearly when a platform or live-device path was not tested.

The saved-file integration suite requires real TShark on PATH and fails if it is missing. It generates valid PCAP/PCAPNG bytes in temporary directories, uses reserved addresses and names, and performs no live capture or public PTR lookup. It replaces source directories during real decoding to verify pinned original input across packet, structured DNS and streaming artifact passes, and denies baseline growth before it could replace readable history. The artifact suite includes a real 200,001-frame streaming reduction and corrupt-tail cases. Receipt lifecycle tests execute the generated native shell against task-owned synthetic recorders and exercise controlled device/tool connector boundaries. They do not invoke actual tcpdump, rvictl, administrator authorization, or a physical device. Deterministic fake-decoder checks remain useful for process/report/baseline contracts; they do not establish real decoding.

The packet GUI suite also exercises generated real-decoder reports, literal inspector presentation, metadata conflicts, stable selection, paged queries, cancellation, stale report generations, FIFO/link races, and application Quit while owned workers are active. Its 50k/100k query measurements use a generated repeated-metadata corpus and report process high-water RSS and event-loop gaps. On macOS, run the same suite with `QT_QPA_PLATFORM=cocoa` to exercise shown native widgets; offscreen results alone do not establish native scrolling or hardware capture.

The shell suite uses a real saved synthetic PCAPNG report to verify sidebar and result navigation, preserved evidence context, and unchanged capture/baseline/export bytes even when a reviewed baseline update is available. It checks complete controls, readable tables and inspectors, and actual 900×680 and 1180×820 windows. Run `QT_QPA_PLATFORM=cocoa venv/bin/python -X faulthandler -m tests.test_gui_shell` for shown native macOS validation.

The session suites verify exact bidirectional grouping, every scope boundary and exclusion reason, original record membership, complete frame partitioning, byte/time summaries, combined filters, bounded pages, capture-bound return navigation and owned-worker shutdown. Real TShark decodes small generated classic PCAP and Apple-metadata PCAPNG fixtures. Separate 50k/100k-frame Qt measurements use diverse synthetic records with 25k/50k sessions and varied regular/effective process and interface labels; they report RSS and event-loop gaps without claiming full-capacity responsiveness. Run the widget and session GUI suites with `QT_QPA_PLATFORM=cocoa` for native macOS evidence, including table/inspector layout and application Quit.

The DNS suites decode generated saved PCAP/PCAPNG with real TShark, round-trip structured evidence, and exercise query links, message/answer boundaries, CNAME chains, A/AAAA replacement rules, TTL expiry, NXDOMAIN/NODATA, extended response codes, exact client/interface/session scope, cancellation and explicit resource failures. Qt checks navigate between candidates, original query/response/superseding packets, matched member frames and scoped sessions; they verify return state, same-digest report replacement, literal inspectors and owned-worker shutdown while capture, baseline and exports remain unchanged. Run `tests.test_dns_view` and `tests.test_dns_gui_integration` with `QT_QPA_PLATFORM=cocoa` for shown native macOS widgets. These small synthetic integrations do not establish physical-device metadata, DNS authenticity, application name use or DNS-heavy full-capacity performance.

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
