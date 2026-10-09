# RVI-Sentinel Python repository instructions

- Preserve the separation between capture, analysis, local enrichment, and interpretation. Keep the separate Swift repository outside this repository's scope.
- Keep changes uncommitted until the user authorizes a commit; commit, push, PR creation, merge, release, deployment, and live capture each require authorization covering that operation.
- Keep the `Python and native smoke` PR check emitted for every PR. CONTRIBUTING.md and `.github/workflows/ci.yml` own the deterministic analyzer, model, offscreen GUI, syntax, and native launcher checks.
- Preserve the existing Python and C/C++ CodeQL coverage. Confirm successful analysis for both languages at the reviewed revision; test fixtures do not establish live-device capture behavior.
- Hosted CI must not invoke rvictl, create rvi interfaces, capture live traffic, request administrator authorization, or connect a physical device.
- Keep packet captures, device identifiers, private baselines, reports, endpoint inventories, and GeoIP databases outside Git and published artifacts. Use the existing synthetic validation data.
