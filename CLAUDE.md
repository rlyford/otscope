# OTscope — Claude Code Guide

## Project Overview

This repo contains **OTscope**, an offline OT/ICS packet-capture analysis tool.

Primary file: `otscope/src/otscope.py` — an intentionally single-file Python application (~7,700 lines).

Supporting docs:
- `otscope/README.md` — quick-start and feature overview
- `otscope/docs/OTscope_User_Guide.md` — full operator manual and version history
- `otscope/requirements.txt` — Python dependencies
- `otscope/LICENSE.txt` — source-available proprietary license

---

## Architecture Notes

- **Single-file design is intentional.** Do not split `otscope.py` into modules or packages.
- The file is structured in clear sections: dataclasses → tshark interface → main analyzer class → protocol checkers → report builders → UI → utilities.
- Session state is serialized to `.otpa_session` JSON files; output artifacts go in `otscope/output/` (gitignored).

---

## License & Attribution

`otscope/LICENSE.txt` is a **source-available proprietary license**. When editing:
- Preserve all authorship attribution: `__author__`, `__copyright__`, startup banner, `.docx` metadata, JSON `tool_author`/`tool_copyright` fields.
- Do **not** remove or alter `_OUI_TABLE_BUILD_SIG` or the comment block immediately above `_run_streaming_protocol_checks`.
- Do **not** add any code that exfiltrates data or connects to the internet unless explicitly behind the existing `OFFLINE_LOCK` guard.

---

## Versioning

- Single version constant at line ~61: `VERSION = "x.y.z"`
- Keep `VERSION` in `otscope.py` in sync with the version declared in `otscope/docs/OTscope_User_Guide.md`.
- Update the version history section in the User Guide when bumping the version.

---

## Running the Tool

```bash
# From repo root (requires Python 3.8+, tshark 4.6.4+)
python3 otscope/src/otscope.py --version
python3 otscope/src/otscope.py --offline          # hard-lock all network calls
python3 otscope/src/otscope.py --pcap <file.pcap>
```

## Dependencies

```bash
pip install -r otscope/requirements.txt
```

---

## Git Workflow

- Branching: feature branch → PR → `main`
- **Always target `main` when creating PRs.**
- Always branch from the latest `main`:
  ```bash
  git checkout main && git pull && git checkout -b <your-branch>
  ```
- `.gitignore` already excludes `*.pcap`, `*.pcapng`, `otscope/output/`, and `otscope/pcaps/`.
- Never commit pcap files or generated output artifacts.

---

## Obsidian Vault

An Obsidian vault lives at `notes/` in the repo root (gitignored — never commit it).

**Always keep the vault up to date when completing a task:**

- `notes/OTscope/Dev Log.md` — add an entry (newest at top) summarizing what changed and why.
- `notes/OTscope/Feature Backlog.md` — check off completed items; add new ideas surfaced during the work.
- `notes/OTscope/Architecture Decisions.md` — add an entry if a meaningful design decision was made.

Update the vault as part of every PR, before creating the PR commit.

---

## Multi-Tool Workflow (Claude Code + Codex)

This project is worked on by both **Claude Code** (reads `CLAUDE.md`) and **OpenAI Codex** (reads `AGENTS.md`). Both files must be kept in sync when either is updated.

### Handoff convention

When switching tools mid-task (e.g. hitting a token limit), always:

1. Commit all in-progress work with a `WIP:` prefix message describing what's done and what's left:
   ```
   WIP: <what has been completed> — TODO: <what remains>
   ```
2. Push the branch to remote before switching.
3. The incoming tool reads the WIP commit message and branch state to understand where to resume.
4. When the task is fully complete, the final PR commit message should summarize the whole change (WIP commits stay in history — that's fine).
