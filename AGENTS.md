# RVI-Sentinel Python repository instructions

- Preserve the separation between capture, analysis, local enrichment, and interpretation. Keep the separate Swift repository outside this repository's scope.
- Keep changes reviewable and preserve unrelated staged, unstaged, and untracked work. This project has the standing delivery authorization recorded below; merge, force-push, release, deployment, publication, settings changes, permission changes, and live capture remain separately restricted.
- Keep the `Python and native smoke` PR check emitted for every PR. CONTRIBUTING.md and `.github/workflows/ci.yml` own the deterministic analyzer, model, offscreen GUI, syntax, and native launcher checks.
- Preserve the existing Python and C/C++ CodeQL coverage. Confirm successful analysis for both languages at the reviewed revision; test fixtures do not establish live-device capture behavior.
- Hosted CI must not invoke rvictl, create rvi interfaces, capture live traffic, request administrator authorization, or connect a physical device.
- Keep packet captures, device identifiers, private baselines, reports, endpoint inventories, and GeoIP databases outside Git and published artifacts. Use the existing synthetic validation data.

## Project working defaults

These instructions apply only to this project and its canonical repository. Read `WORKSPACE.md`, this `AGENTS.md`, any applicable `AGENTS.override.md` files, the actual TODO list, project documentation, and the latest project checkpoint before making changes. Always verify the canonical checkout, Git root, current branch, HEAD, remote, upstream, attached worktrees, open pull requests, and staged, unstaged, and untracked files. Preserve all unrelated work.

The user grants standing authorization for the normal Git and GitHub delivery steps for work implemented and verified in this project. This authorization permits:

- Staging only reviewed files or hunks belonging to the current task.
- Creating and using a `codex/` feature branch when appropriate.
- Creating focused commits with clear, conventional messages.
- Pushing the task branch to the verified GitHub repository.
- Creating a new pull request when review or CI is the safest delivery path.
- Updating an existing pull request when the work clearly belongs to it.
- Marking a draft pull request ready after implementation and required checks are complete.
- Pushing follow-up fixes needed to make a pull request's required CI checks pass.
- Choosing between committing and pushing to the existing authorized task branch or opening/updating a pull request based on the repository's current branch, protection rules, scope, and review needs.

Use a pull request by default for source, application behavior, packaging, workflow, dependency, security-sensitive, or substantial multi-file changes. A direct push is acceptable only when it follows the repository's established practice, targets the correct non-protected task branch, and does not bypass required review or branch protection.

Before every commit or push:

1. Confirm the canonical repository, branch, remote URL, upstream, HEAD, and outgoing diff.
2. Preserve unrelated staged, unstaged, and untracked work.
3. Stage explicit files or reviewed hunks; never use `git add .`, `git add -A`, or `git commit -a` in a dirty canonical checkout.
4. Inspect the complete staged diff.
5. Check that no credentials, private evidence, device identifiers, personal data, local absolute paths, backups, logs, downloaded indicators, build caches, or private test artifacts would enter Git history.
6. Run applicable tests, linting, documentation checks, packaging checks, and native UI checks.
7. Review the final diff for regressions, security issues, scope drift, generated-file mistakes, and unrelated changes.
8. Fetch and inspect the verified remote before integrating upstream changes. Do not use a blind pull.
9. Push only the intended branch and verify that the remote revision matches the expected commit.
10. Inspect the resulting GitHub checks and fix failures without weakening tests, assertions, security controls, or required gates.

If the canonical checkout contains overlapping or conflicting user work, preserve it and use the existing suitable review worktree or create a focused worktree from the correct committed base. Do not reset, clean, stash, discard, overwrite, or silently include unrelated changes.

This standing authorization does not cover merging a pull request, force-pushing or rewriting published history, deleting remote branches, creating tags or GitHub releases, publishing release artifacts, deploying an application, approving protected environments or publication jobs, changing branch protection, repository visibility, permissions, secrets, Actions settings, or other repository settings, installing or broadening GitHub App access, or sending unrelated external messages or review responses. Ask for separate authorization before those operations. A successful pull request and passing CI do not authorize a merge, release, deployment, or publication.

Do not start adapters, dependencies, installers, packaging, or CI work while an actionable TODO remains.

Maintain durable project continuity during active work. At the beginning of a work session, load the latest project memory and checkpoint. At least once every hour while actively working, and again before ending or pausing, save a concise checkpoint containing the current objective and scope; canonical checkout and worktree; branch, HEAD, remote branch, pull-request URL and number; relevant staged, unstaged, and untracked state; intentionally changed files; completed and remaining TODO items; implementation decisions and reasons; tests, builds, CI runs, and native checks with exact status; application bundle path and native-window evidence when applicable; investigated failures and approaches not to repeat; blockers; and the next safe action. Use the existing project checkpoint or continuity location instead of creating duplicate planning documents. Do not store credentials, secrets, signing material, device identifiers, raw backups, private logs, downloaded threat intelligence, personal information, or large command output in memory. Do not create empty or repetitive hourly entries when no project state changed.

Continue autonomously through implementation, verification, commit, push, pull-request creation or update, and CI repair under this standing authorization. At completion, report what changed and why; commit hashes and pushed branch; pull-request URL and review state when applicable; tests, builds, and CI outcomes; remaining macOS TODOs and concrete blockers; exact path and visible state of the updated app when applicable; and whether any publication-sensitive step still needs authorization. Preserve the restrictions above for merging, releasing, deploying, settings changes, force pushes, and device operations.
