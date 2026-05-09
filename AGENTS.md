# OTscope — Codex Agent Guide

This file is for Codex and other AGENTS.md-aware AI coding agents. `CLAUDE.md` is specific to Claude Code and may intentionally differ; do not edit `CLAUDE.md` unless the user explicitly asks.

---

## Project Overview

This repo contains **OTscope**, an offline OT/ICS packet-capture analysis tool.

Primary file: `otscope/src/otscope.py` — an intentionally single-file Python application (~7,700 lines).

Supporting docs:
- `otscope/README.md` — quick-start and feature overview
- `otscope/docs/OTscope_User_Guide.md` — full operator manual and version history
- `otscope/requirements.txt` — Python dependencies
- `otscope/LICENSE.txt` — source-available proprietary license

---

## Architecture — Read Before Editing

- **Single-file design is intentional. Do not split `otscope.py` into modules or packages.**
- The file is structured in clear sections (top to bottom):
  - Constants and globals
  - Dataclasses (`ProcessedPcap`, `DeviceRecord`, `ConnectionSummary`, `Finding`, `SessionState`)
  - tshark interface (`run_tshark`, `iter_tshark_rows`)
  - Main analyzer class `OTPcapAnalyzer` (~300 methods)
  - Protocol checkers (`_run_streaming_protocol_checks`, `run_optional_checks`)
  - Report builders (Word `.docx`, JSON, CSV, SVG)
  - UI (interactive menus, ANSI colors, progress ETAs)
  - Utilities (IP classification, OUI lookup, risk scoring)
- Session state is serialized to `.otpa_session` JSON files.
- Output artifacts go in `otscope/output/` (gitignored — never commit these).

---

## License & Attribution — Critical

`otscope/LICENSE.txt` is a **source-available proprietary license**. When editing the code:

- **Preserve all authorship attribution:**
  - `__author__` and `__copyright__` constants near the top of the file
  - Startup banner (printed at tool launch)
  - `.docx` core property fields (`author`, `last_modified_by`, `comments`)
  - JSON report fields `tool_author` and `tool_copyright`
- **Do not remove or alter** `_OUI_TABLE_BUILD_SIG` or the comment block immediately above `_run_streaming_protocol_checks`.
- **Do not add any code** that connects to the internet, exfiltrates data, or resolves hostnames unless it is explicitly behind the existing `OFFLINE_LOCK` / `OFFLINE_MODE` guard.

Violating these rules could constitute license infringement. When in doubt, leave attribution code untouched.

---

## Versioning

- Single version constant near line 61: `VERSION = "x.y.z"`
- **Keep `VERSION` in `otscope.py` in sync with the version header in `otscope/docs/OTscope_User_Guide.md`.**
- When bumping the version, also add an entry to the Version History section of the User Guide (newest at top).

---

## Running the Tool

```bash
# Requires Python 3.8+ and tshark 4.6.4+
pip install -r otscope/requirements.txt

# Check version
python3 otscope/src/otscope.py --version

# Non-interactive scan (no prompts, auto-generates report)
python3 otscope/src/otscope.py --scan /path/to/pcaps/

# Interactive mode
python3 otscope/src/otscope.py

# Hard-lock all outbound network calls
python3 otscope/src/otscope.py --offline
```

---

## Git Workflow

- Branching model: feature branch → PR → `main`
- **Always target `main` when creating PRs.**
- Always branch from the latest `main`:
  ```bash
  git checkout main && git pull && git checkout -b <your-branch>
  ```
- Never commit pcap files or generated output artifacts — they are gitignored.
- If GitHub CLI or GitHub API commands fail from Codex with a proxy error to `127.0.0.1:9`, clear inherited proxy variables for that command and retry:
  ```powershell
  $env:HTTP_PROXY=''; $env:HTTPS_PROXY=''; $env:ALL_PROXY=''; $env:GIT_HTTP_PROXY=''; $env:GIT_HTTPS_PROXY=''; gh auth status
  ```

---

## Obsidian Vault

An Obsidian vault lives at `notes/` in the repo root (gitignored — never commit it).

**Always keep the vault up to date when completing a task:**

- `notes/OTscope/Dev Log.md` — add an entry (newest at top) summarizing what changed and why.
- `notes/OTscope/Feature Backlog.md` — check off completed items; add new ideas surfaced during the work.
- `notes/OTscope/Architecture Decisions.md` — add an entry if a meaningful design decision was made.

Update the vault as part of every task, before creating the PR commit.

---

## Multi-Tool Workflow (Codex + Claude Code)

This project is worked on by both **OpenAI Codex** (reads `AGENTS.md`) and **Claude Code** (reads `CLAUDE.md`). Treat the files as tool-specific guides; preserve their shared project facts, but do not force identical wording or update `CLAUDE.md` from Codex unless the user explicitly requests it.

### Handoff convention

When switching tools mid-task (e.g. hitting a token limit):

1. Commit all in-progress work with a `WIP:` prefix describing what's done and what's left:
   ```
   WIP: <what has been completed> — TODO: <what remains>
   ```
2. Push the branch to remote before switching tools.
3. The incoming tool reads the WIP commit message and branch state to understand where to resume.
4. When the task is fully complete, the final PR commit message should summarize the whole change clearly.

### On session start

Before writing any code, check:
1. `git log --oneline -5` — look for any `WIP:` commits that signal in-progress work.
2. `git status` — confirm the working tree is clean.
3. Read this file (`AGENTS.md`) and `CLAUDE.md` to confirm you understand the project conventions.

---

## Code Style

- No unnecessary comments — only add one when the **why** is non-obvious.
- No docstrings on internal helper functions unless the logic is genuinely surprising.
- No splitting the single file into modules.
- No adding error handling for scenarios that cannot happen.
- No new dependencies without explicit instruction — the dependency surface is intentionally minimal.
- Preserve existing ANSI color output patterns and progress-reporting conventions.
