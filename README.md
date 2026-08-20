# Local & Open-Source Model Security Tracker (`lomst`)

Daily tracking and governance classification of local and open-source AI models,
implementing **Paradox Interactive — Governance of Local and Open-Source AI Models
v1.1**.

It does three things:

1. **Ingests** eleven sources daily — the seven you nominated, plus four that
   supply the per-model provenance, licence and CVE facts §7 actually requires.
2. **Classifies** model families against the five §7 criteria, producing an
   evidence-backed *recommendation* — never an approval.
3. **Gates usage** — answers "may I use model X on runtime Y for purpose Z with
   information of class W" by applying four independent §8 checks, each traceable
   to the section that requires it.

An MCP server exposes all of it to an AI assistant. A launchd job runs the ingest
daily.

---

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -e .

.venv/bin/lomst ingest          # fetch everything (~60-90s)
.venv/bin/lomst digest          # what changed and what it means
.venv/bin/lomst actions         # what needs a human, most urgent first
```

Ask the two questions that matter:

```bash
# Section 7: what does the evidence say about this family?
lomst assess qwen

# Section 8: may we actually do this?
lomst check llama internal_productivity --runtime ollama --info internal
lomst check mistral production_services --runtime vllm --solution "Billing summariser"
```

`lomst check` exits `0` when permitted, `3` when blocked. `lomst actions` exits
`2` when something is immediate, so a cron wrapper can alert on it.

---

## The design decision that shapes everything

**The classifier cannot approve anything.**

`lomst assess` gathers evidence and returns a recommended §6.3 outcome. Recording
an outcome is a separate act requiring a named authority:

```bash
lomst decide qwen approved_with_conditions \
  --authority "AI Governance" \
  --rationale "Apache-2.0, official publisher, safetensors weights" \
  --approved-use internal_productivity --condition C2 --condition C6
```

`--authority` is mandatory: Appendix A.5 and D.6 both require an approving
authority, and an unattributable approval is not auditable under §9.1. Over MCP,
decision-writing is **disabled by default** — the tool returns the exact command
for a human to run instead. Set `LOMST_ALLOW_DECISIONS=1` to change that, though
the default is the workflow §13 step 4 describes.

---

## Storage: why two places

| What | Where | Why |
|---|---|---|
| Observations, advisories, artefacts | `var/tracker.db` (SQLite, gitignored) | A rebuildable cache of what the world said. Good for change detection. |
| Approval decisions, registry entries | `registry/**.yaml` (git-tracked) | §9.1 requires historical decisions be retained auditably. Git gives reviewable diffs, authorship and timestamps that a database `UPDATE` would silently overwrite. |

**Commit `registry/` after any `lomst decide`.** The git history *is* the audit
record.

---

## Sources, and how much each is trusted

Trust tier controls whether a source can be *cited as evidence* or is only a
*lead*. §7.1 requires provenance evidence from reputable, preferably official
channels, so this distinction is enforced in code, not left to the reader.

| Source | Access | Tier |
|---|---|---|
| llm-stats.com | HTML (Next.js RSC payload) | community |
| Evertune AI Model Tracker | JSON (`models.evertune.ai`) | community |
| OWASP GenAI Security Project | WordPress REST | community |
| Awesome AI Security (5 repos) | GitHub API | community |
| Obot | WordPress REST | community |
| **Wilder AI via Artiverse.ca** | WordPress REST | **aggregator — leads only** |
| **RadarAI** | RSS | **aggregator — leads only** |
| Hugging Face Hub | JSON API | authoritative |
| OSV.dev | JSON API | authoritative |
| GitHub Security Advisories | JSON API | authoritative |
| Ollama library | HTML | authoritative |

Aggregator-tier material can raise a candidate worth investigating but is never
cited for a provenance, licensing or vulnerability conclusion.

### Two notes on your original list

- **Artiverse.ca** states that *"the majority of content published on
  Artiverse.ca is generated using artificial intelligence"* and asks readers to
  verify independently. It is ingested as you asked, but tiered `aggregator`.
- **"Wilder AI"** is not itself a model-security tracker. It surfaced via an
  Artiverse article about AI model tracking; the company at `wilder.ai` /
  `wilderai.com` sells text-mining and computer-vision products. The connector
  therefore tracks the Artiverse coverage, not a Wilder AI feed.

### Added sources, and why

Your seven cover news and tooling but carry no per-model facts. Without these,
§7.1–7.4 scoring would be guesswork:

- **Hugging Face** — publisher of record, licence tag, gated flag, and the file
  manifest. The manifest matters: pickle-format weights (`.bin`, `.pt`, `.ckpt`)
  execute arbitrary code on load, which §7.4 calls an insecure execution
  practice. `lomst` fails §7.2 for a family that ships *only* pickle weights.
- **OSV + GitHub Advisories** — CVEs land on the *inference stack*, not on model
  weights. At the time of writing: vLLM 24 critical / 23 high, Ollama 1 critical
  / 11 high, llama.cpp 2 critical.
- **Ollama library** — what is actually pullable onto a workstation.

`llm-stats.com/robots.txt` disallows `/api/`. That is honoured centrally in
`http.fetch`, which raises `RobotsDenied` rather than routing around it; the
public pages are parsed instead.

---

## MCP server

Register it with your client:

```json
{
  "mcpServers": {
    "lomst": {
      "command": "/absolute/path/to/repo/.venv/bin/lomst-mcp",
      "env": { "LOMST_HOME": "/absolute/path/to/repo" }
    }
  }
}
```

`LOMST_HOME` matters — the server starts with an arbitrary working directory.

13 tools, 11 of them read-only:

| Tool | Purpose |
|---|---|
| `check_usage` | **The gate.** Four §8 checks with per-check section citations. |
| `assess_family` | §7 evaluation with cited evidence and a recommendation. |
| `list_registry` / `get_registry_entry` | The §9 authoritative record. |
| `governance_actions` | Everything needing a human, by urgency. |
| `daily_digest` | What changed in the last run. |
| `get_advisories` | CVEs by runtime and severity (§7.4, §11.4). |
| `search_intelligence` | Full-text across all ingest, tier-labelled. |
| `list_observed_families` | Families in the wild vs. in the registry (§15.3). |
| `governance_vocabulary` | Outcomes, categories, C1–C9, lifecycle states. |
| `source_health` | Freshness; stale sources mean stale evidence. |
| `run_ingest` | Refresh now (writes cache only). |
| `record_decision` | Disabled by default; hands back a command. |

The server's `instructions` tell the assistant the rules it must not break —
notably that model approval never authorises a use on its own, and that
aggregator sources stay separate from evidence.

---

## Daily schedule

> **This repo's current location blocks scheduling.** See the next section.

```bash
./scripts/install-launchd.sh              # 08:15 local
./scripts/install-launchd.sh --hour 7     # 07:15
./scripts/install-launchd.sh --verify     # run it now, confirm it actually ran
./scripts/install-launchd.sh --status
./scripts/install-launchd.sh --uninstall
```

Logs land in `var/logs/YYYY-MM-DD.log`, pruned after 90 days. Immediate actions
raise a desktop notification, because §11.4 expects a critical advisory on an
approved runtime to prompt an assessment rather than sit in a log file.

launchd skips `StartCalendarInterval` runs while the machine is asleep — pick an
hour the Mac is usually awake.

### macOS privacy protection blocks unattended runs from `~/Documents`

This repo currently lives under `~/Documents`, which macOS TCC protects. A
launchd agent there fails with `Operation not permitted` on **every** run while
still appearing perfectly healthy in `launchctl list`.

Measured, not assumed — from a launchd agent, against a file under `~/Documents`:

| Operation | Result |
|---|---|
| `ls` (stat the path) | OK |
| `head` (read contents) | **DENIED** |
| exec `.venv/bin/python` | **DENIED** |

Because *content reads* are denied, relocating just the launcher script does not
help; the interpreter and the repo are both unreadable. `install-launchd.sh`
detects this and refuses to install rather than leave you with a job that never
runs. Three ways forward:

1. **Move the repo out of `~/Documents`** (recommended):
   ```bash
   mv ~/Documents/repositories/local-opensource-model-security-tracker ~/src/lomst
   cd ~/src/lomst
   rm -rf .venv && python3 -m venv .venv && .venv/bin/pip install -e .
   ./scripts/install-launchd.sh && ./scripts/install-launchd.sh --verify
   ```
   Verified working from `~/src`: the scheduled run completed all 11 sources.
2. **Grant Full Disk Access to `/bin/bash`** in System Settings → Privacy &
   Security. Broad, affects every shell script on the machine; not advised.
3. **Skip scheduling** and run `lomst ingest && lomst digest && lomst actions`
   yourself, or from a terminal-based cron you already trust.

`LOMST_FORCE_INSTALL=1` overrides the check if you want the plist anyway.

---

## What gets enforced

Rules implemented as code rather than prose, each with a test:

| § | Rule |
|---|---|
| 5, 10 | Model approval never implies runtime approval. An approved model on an unapproved runtime is blocked. |
| 6.2 | Family approval is not release approval. Unapproved versions are routed to expedited vs. full reassessment. |
| 6.2 | Third-party redistributions are independent artefacts. `deepseek-ai/DeepSeek-R1-Distill-Llama-70B` is a *DeepSeek* artefact and never affects Llama's record. |
| 6.3 | Only a named authority records an outcome. |
| 7.1 | Aggregator sources cannot be cited as evidence. |
| 7.2 | Pickle-only weight distribution fails distribution integrity. |
| 7.3 | Licences classified into permissive / copyleft / community / research-only / proprietary; community licences force Legal review (C2). |
| 7.4 | Advisories assessed against the family's *approved runtimes*. |
| 8.1 | Approval is per usage category. |
| 8.2 | Restricted uses never return a bare "allowed". |
| 8.3, 11.2 | Confidential, personal or customer information requires Sensitive Information Processing approval. |
| 8.5, C9 | At Internal Business Applications and above, an untested fallback blocks. Proportionate — prototypes need none. |
| 9.2 | Overdue reviews surface as immediate. |
| 9.3, E.5 | Retired families are blocked for new solutions. |
| 14.1, 14.3 | An exception with no expiry is treated as expired, not perpetual. |
| 4.2 | Origin country is recorded but **never** an input to any score. |

Two deliberate refusals to guess:

- **Absence of evidence is not a pass.** Missing data yields `unknown`, which
  pushes toward Deferred, not Approved.
- **Licence heterogeneity is surfaced, not collapsed.** Llama publishes a dozen
  licence strings across releases; a single family-level licence claim would be
  misleading, so the spread is reported and the assessed release is the approved
  one where known.

---

## Layout

```
config/sources.yaml          source definitions, tiers, robots notes
registry/families/*.yaml     governance decisions (git = audit record)
registry/runtimes/*.yaml     runtimes, governed independently (§5, §10)
src/lomst/
  governance/vocab.py        controlled vocabulary, every term traced to a §
  governance/licensing.py    §7.3 licence taxonomy
  governance/registry.py     Appendix B entries, validation, YAML round-trip
  governance/classify.py     §7 evaluation engine
  governance/usage.py        §8 usage gate
  governance/review.py       §6.2/8.5/9.2/9.3/11.4/14 lifecycle triggers
  sources/                   11 connectors
  extract.py                 family/runtime attribution
  ingest.py digest.py cli.py mcp_server.py
tests/                       81 tests
```

Seeded registry: `llama` (the Appendix B.1 worked example), `mistral`, and
runtimes `ollama` and `vllm`. `mistral` intentionally carries an **untested**
fallback so `lomst actions` demonstrates the §8.5 gap it exists to catch.

```bash
.venv/bin/python -m pytest -q       # 81 tests
lomst probe                          # verify every source still parses
```

`lomst probe` is the command to run when a digest looks thin — scrapers rot, and
the HTML connectors raise a descriptive error naming the source to re-verify.

---

## Known limits

- Family attribution is pattern-based. New families need an entry in
  `extract.py:FAMILY_PATTERNS`; unknown families still appear via
  `list_observed_families` so they are not invisible.
- `OFFICIAL_PUBLISHERS` in `classify.py` is hand-maintained. A family absent from
  it returns `unknown` provenance rather than a false pass.
- GitHub API is rate-limited to 60 req/h unauthenticated. Set `GITHUB_TOKEN` for
  5000/h.
- Severity for OSV records lacking a numeric CVSS score is bucketed coarsely from
  the vector's impact metrics, and recorded as unknown when neither is present.
- Appendix A/D document *generation* is not built (not selected in scope);
  `lomst assess --json` returns the same fields for whatever renders them.
