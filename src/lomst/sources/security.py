"""Security connectors: OSV, GitHub Security Advisories, awesome-list tracking.

These populate Section 7.4 (Security) and feed Section 11.4 (Vulnerability
management). Note the deliberate asymmetry: vulnerabilities are tracked against
*runtimes and libraries*, not model weights, because that is where CVEs actually
land. Section 5 already tells us to evaluate those components independently.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from ..config import SourceConfig
from ..extract import detect
from ..http import fetch, github_headers
from .base import Advisory, Observation, Result, iso_date, strip_html

# ------------------------------------------------------------------------- OSV

#: Map a tracked package back to a runtime key so advisories can be joined to
#: runtime registry entries.
PACKAGE_RUNTIME: dict[str, str] = {
    "vllm": "vllm",
    "llama-cpp-python": "llama_cpp",
    "github.com/ollama/ollama": "ollama",
    "transformers": "transformers",
    "onnxruntime": "onnxruntime",
    "torch": "transformers",
    "sentence-transformers": "transformers",
}


def _severity_from_cvss(vector: str | None, score: float | None = None) -> str | None:
    """Bucket a CVSS vector/score into GitHub-style severity words."""
    if score is None and vector:
        # OSV frequently gives the vector without a numeric score; derive a
        # coarse bucket from the impact metrics rather than pretend precision.
        high_impact = sum(1 for m in ("C:H", "I:H", "A:H") if m in vector)
        if "AV:N" in vector and high_impact >= 2:
            return "critical" if high_impact == 3 else "high"
        if high_impact >= 1:
            return "moderate"
        return "low"
    if score is None:
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "moderate"
    return "low"


class OsvConnector:
    """OSV.dev batch vulnerability lookup for inference-stack packages."""

    name = "osv"

    def fetch(self, cfg: SourceConfig) -> Result:
        url = cfg.url or "https://api.osv.dev/v1/query"
        packages: list[dict[str, str]] = cfg.options.get("packages") or []

        advisories: list[Advisory] = []
        for pkg in packages:
            eco, pname = pkg.get("ecosystem"), pkg.get("name")
            if not eco or not pname:
                continue
            resp = fetch(
                url,
                method="POST",
                json_body={"package": {"name": pname, "ecosystem": eco}},
                check_robots=False,  # documented public API, no robots policy
            )
            for vuln in resp.json().get("vulns", []):
                advisories.append(self._to_advisory(vuln, eco, pname))

        observations = [
            Observation(
                external_id="osv:summary",
                kind="vuln_summary",
                title=f"OSV: {len(advisories)} advisories across {len(packages)} packages",
                url="https://osv.dev",
                summary=", ".join(f"{p.get('name')}" for p in packages),
                payload={"package_count": len(packages), "advisory_count": len(advisories)},
            )
        ]
        return Result(observations=observations, advisories=advisories)

    def _to_advisory(self, vuln: dict[str, Any], eco: str, pname: str) -> Advisory:
        sev_entries = vuln.get("severity") or []
        vector = next((s.get("score") for s in sev_entries if s.get("type", "").startswith("CVSS")), None)
        # database_specific.severity is present on GHSA-sourced records.
        stated = (vuln.get("database_specific") or {}).get("severity")
        severity = (stated or "").lower() or _severity_from_cvss(vector)

        return Advisory(
            advisory_id=vuln["id"],
            aliases=vuln.get("aliases") or [],
            ecosystem=eco,
            package=pname,
            severity=severity,
            cvss=vector,
            summary=strip_html(vuln.get("summary") or vuln.get("details"), 400),
            url=f"https://osv.dev/vulnerability/{vuln['id']}",
            published_at=iso_date(vuln.get("published")),
            modified_at=iso_date(vuln.get("modified")),
            withdrawn_at=iso_date(vuln.get("withdrawn")),
            payload={"runtime_key": PACKAGE_RUNTIME.get(pname)},
        )


# ------------------------------------------------------------------------ GHSA


class GhsaConnector:
    """GitHub Security Advisories - global feed filtered to relevant ecosystems.

    Catches advisories affecting AI tooling we may not yet track by package name,
    which the per-package OSV queries by construction cannot surface.
    """

    name = "ghsa"

    #: Only advisories whose text touches the local-AI stack are kept; the raw
    #: pip/npm/go feeds are far too broad to be actionable.
    RELEVANCE = re.compile(
        r"\b(llm|llama|ollama|vllm|gguf|safetensors|transformers|langchain|"
        r"llama[\s._-]?index|onnx|pytorch|torch|diffusers|mlflow|"
        r"model[\s-]?(?:load|serial|deserial)|pickle|inference|embedding|"
        r"comfyui|gradio|triton|tokenizer|sglang|text-generation)\b",
        re.I,
    )

    def fetch(self, cfg: SourceConfig) -> Result:
        url = cfg.url or "https://api.github.com/advisories"
        ecosystems = cfg.options.get("ecosystems") or ["pip"]
        severities = cfg.options.get("severities") or ["high", "critical"]
        per_page = int(cfg.options.get("per_page", 100))

        advisories: list[Advisory] = []
        skipped = 0
        for eco in ecosystems:
            for sev in severities:
                resp = fetch(
                    url,
                    params={
                        "ecosystem": eco,
                        "severity": sev,
                        "per_page": per_page,
                        "sort": "published",
                        "direction": "desc",
                    },
                    headers=github_headers(),
                    check_robots=False,
                )
                for adv in resp.json():
                    text = " ".join(
                        str(x) for x in (adv.get("summary"), adv.get("description")) if x
                    )
                    pkgs = [
                        (v.get("package") or {}).get("name")
                        for v in (adv.get("vulnerabilities") or [])
                    ]
                    haystack = text + " " + " ".join(p for p in pkgs if p)
                    if not self.RELEVANCE.search(haystack):
                        skipped += 1
                        continue
                    advisories.append(
                        Advisory(
                            advisory_id=adv["ghsa_id"],
                            aliases=[adv["cve_id"]] if adv.get("cve_id") else [],
                            ecosystem=eco,
                            package=next((p for p in pkgs if p), None),
                            severity=(adv.get("severity") or sev).lower(),
                            cvss=(adv.get("cvss") or {}).get("vector_string"),
                            summary=strip_html(adv.get("summary"), 400),
                            url=adv.get("html_url"),
                            published_at=iso_date(adv.get("published_at")),
                            modified_at=iso_date(adv.get("updated_at")),
                            withdrawn_at=iso_date(adv.get("withdrawn_at")),
                            payload={
                                "runtime_key": next(
                                    (PACKAGE_RUNTIME[p] for p in pkgs if p in PACKAGE_RUNTIME),
                                    None,
                                ),
                                "packages": [p for p in pkgs if p],
                            },
                        )
                    )

        observations = [
            Observation(
                external_id="ghsa:summary",
                kind="vuln_summary",
                title=f"GitHub advisories: {len(advisories)} relevant to the local-AI stack",
                url="https://github.com/advisories",
                summary=f"{skipped} advisories filtered out as unrelated to local AI tooling.",
                payload={"kept": len(advisories), "filtered": skipped},
            )
        ]
        return Result(observations=observations, advisories=advisories)


# ---------------------------------------------------------------- awesome lists

_LIST_ENTRY_RE = re.compile(r"^\s*[-*]\s*\[([^\]]{2,120})\]\(([^)]+)\)\s*[-–—:]?\s*(.*)$", re.M)


class GithubAwesomeConnector:
    """Track curated 'Awesome AI Security' lists.

    The requested source name is ambiguous - several well-known repositories
    share it - so the config names them explicitly and each is attributed
    separately rather than silently collapsing them into one source.
    """

    name = "github_awesome"

    def fetch(self, cfg: SourceConfig) -> Result:
        repos: list[str] = cfg.options.get("repos") or []
        observations: list[Observation] = []

        for repo in repos:
            meta = fetch(
                f"https://api.github.com/repos/{repo}",
                headers=github_headers(),
                check_robots=False,
            ).json()

            observations.append(
                Observation(
                    external_id=f"gh:{repo}",
                    kind="curated_list",
                    title=f"{repo}: {meta.get('stargazers_count')}★",
                    url=meta.get("html_url"),
                    summary=strip_html(meta.get("description")),
                    published_at=iso_date(meta.get("pushed_at")),
                    payload={
                        "stars": meta.get("stargazers_count"),
                        "license": ((meta.get("license") or {}) or {}).get("spdx_id"),
                        "archived": meta.get("archived"),
                        "pushed_at": iso_date(meta.get("pushed_at")),
                    },
                )
            )

            # README entries become individually addressable tool observations so
            # a newly listed tool shows up in the daily digest.
            try:
                readme = fetch(
                    f"https://api.github.com/repos/{repo}/readme",
                    headers=github_headers(),
                    check_robots=False,
                ).json()
                content = base64.b64decode(readme.get("content", "")).decode("utf-8", "replace")
            except Exception:
                continue

            for label, link, desc in _LIST_ENTRY_RE.findall(content):
                if not link.startswith("http"):
                    continue
                hits = detect(label, desc)
                observations.append(
                    Observation(
                        external_id=f"gh:{repo}#{link}",
                        kind="security_tool",
                        title=label.strip(),
                        url=link,
                        summary=strip_html(desc, 300) or None,
                        payload={
                            "list_repo": repo,
                            "families": list(hits.families),
                            "runtimes": list(hits.runtimes),
                        },
                    )
                )

        return Result(observations=observations)


# -------------------------------------------------------------------- CISA KEV


class KevConnector:
    """CISA Known Exploited Vulnerabilities catalogue.

    The strongest signal in Section 11.4. An advisory says a flaw exists; a KEV
    entry says it is *being exploited right now*, which is what should move an
    organisation from "assess" to "patch or suspend". Section 11.4 lets the
    organisation suspend or withdraw approval on severity, and nothing outranks
    confirmed exploitation.

    The catalogue is all of CISA's 1600+ entries across every vendor, so it is
    filtered to the AI and ML stack. The filter is deliberately generous: a
    false positive costs a human ten seconds, a false negative hides an actively
    exploited RCE in the inference stack.
    """

    name = "kev"

    #: Deliberately AI/ML-specific. Two earlier mistakes are corrected here:
    #:
    #: 1. Generic infrastructure (Redis, Elasticsearch, MinIO, Airflow) was
    #:    included as "the ML stack". Those are ordinary IT components whose
    #:    patching is not what Section 7.4 governs, and they dominated the
    #:    results.
    #: 2. The match ran over shortDescription too, so a Cisco IOS XR advisory
    #:    matched "Redis" purely because its prose mentioned one. A KEV entry is
    #:    about the *affected product*, so only vendor and product are matched.
    #:
    #: Precision matters more than recall here: a spurious "actively exploited
    #: critical" would erode trust in the whole action list.
    AI_STACK = re.compile(
        r"\b(ollama|vllm|sglang|llama[\s._-]?cpp|llamaindex|llama[\s-]?index|"
        r"mlflow|kubeflow|litellm|langchain|langflow|flowise|"
        r"pytorch|torchserve|tensorflow|tensorboard|onnx|triton|"
        r"jupyter|jupyterhub|jupyterlab|huggingface|hugging\s?face|"
        r"gradio|comfyui|automatic1111|open[\s-]?webui|anythingllm|"
        r"sagemaker|vertex\s?ai|bentoml|seldon|kserve|clearml|"
        r"deepspeed|nemo|tritonserver|text[\s-]generation[\s-]inference)\b"
        r"|^ray$|\bray[\s-]project\b|\bnvidia\b",
        re.I,
    )

    def fetch(self, cfg: SourceConfig) -> Result:
        url = cfg.url or (
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        )
        doc = fetch(url, check_robots=False).json()
        entries = doc.get("vulnerabilities") or []

        advisories: list[Advisory] = []
        for v in entries:
            # Vendor and product only - never the description (see AI_STACK).
            haystack = f"{v.get('vendorProject') or ''} {v.get('product') or ''}".strip()
            if not self.AI_STACK.search(haystack):
                continue
            product = f"{v.get('vendorProject','')}/{v.get('product','')}".strip("/")
            advisories.append(
                Advisory(
                    advisory_id=f"KEV-{v['cveID']}",
                    aliases=[v["cveID"]],
                    ecosystem="cisa-kev",
                    package=product or None,
                    # Actively exploited outranks any CVSS bucket.
                    severity="critical",
                    summary=(
                        f"ACTIVELY EXPLOITED. {v.get('vulnerabilityName','')}: "
                        f"{strip_html(v.get('shortDescription'), 300) or ''} "
                        f"Required action: {v.get('requiredAction','')}"
                    ).strip(),
                    url=f"https://nvd.nist.gov/vuln/detail/{v['cveID']}",
                    published_at=iso_date(v.get("dateAdded")),
                    modified_at=iso_date(v.get("dateAdded")),
                    payload={
                        "runtime_key": PACKAGE_RUNTIME.get((v.get("product") or "").lower()),
                        "actively_exploited": True,
                        "due_date": v.get("dueDate"),
                        "ransomware_use": v.get("knownRansomwareCampaignUse"),
                        "required_action": v.get("requiredAction"),
                        "cwes": v.get("cwes") or [],
                    },
                )
            )

        observations = [
            Observation(
                external_id="kev:summary",
                kind="vuln_summary",
                title=f"CISA KEV: {len(advisories)} actively exploited flaws in the AI/ML stack",
                url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                summary=(
                    f"Catalogue {doc.get('catalogVersion')} holds {doc.get('count')} entries; "
                    f"{len(advisories)} touch AI or ML infrastructure. These are confirmed "
                    f"exploited in the wild, which Section 11.4 treats as the top of the "
                    f"severity scale."
                ),
                payload={
                    "catalog_version": doc.get("catalogVersion"),
                    "total": doc.get("count"),
                    "ai_stack": len(advisories),
                },
            )
        ]
        return Result(observations=observations, advisories=advisories)
