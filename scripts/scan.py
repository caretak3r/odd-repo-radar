#!/usr/bin/env python3
"""Odd Repo Radar — high-signal detector for PixelLeak-class / AI-agent public dumps.

Prefers quality over quantity: admission-style descriptions, commit footprints,
media-heavy personal dumps — not empty gitshot-images shells.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
HITS_PATH = ROOT / "docs" / "data" / "hits.json"
MAX_HITS = 60
LOOKBACK_DAYS = 180
BOILERPLATE = {
    "readme", "readme.md", "readme.txt", "license", "license.md", "license.txt",
    ".gitignore", ".gitattributes", "codeowners", ".github",
}

# ---------------------------------------------------------------------------
# Search queries — high-signal first (admission / private-PR hosting language)
# ---------------------------------------------------------------------------
REPO_QUERIES: list[tuple[str, str, str]] = [
    # Explicit private-repo → public screenshot dump admissions
    ('"Public screenshots for private" in:description', "private-repo PR screenshots admission", "asset-dump"),
    ('"Screenshots linked from" (PR OR "pull request") in:description', "screenshots linked from private PR", "asset-dump"),
    ('"PR screenshot assets for" in:description', "PR screenshot assets for named repo", "asset-dump"),
    ('"for private-repo PR" OR "for private repo PR" in:description', "for private-repo PR", "asset-dump"),
    ('"private TheFeedFactory" OR "private repo)" screenshot in:description', "private repo screenshot dump", "asset-dump"),
    # Camo / anonymous-resolvable (GitHub image proxy workaround)
    ('"camo-renderable" in:description', "camo-renderable image host", "asset-dump"),
    ('"anonymous-resolvable" OR "Anonymously-resolvable" in:description', "anonymous-resolvable image host", "asset-dump"),
    ('"anonymous image embeds" in:description', "anonymous image embeds", "asset-dump"),
    # Temporary / ephemeral public hosting admissions
    ('"Temporary public hosting for PR" in:description', "temporary public PR hosting", "asset-dump"),
    ('"Ephemeral PR screenshot" in:description', "ephemeral PR screenshot host", "asset-dump"),
    ('"Temporary public host for PR" in:description', "temporary public host for PR", "asset-dump"),
    ('"safe to delete after" (merge OR review) (screenshot OR PR OR media) in:description', "safe-to-delete PR media", "asset-dump"),
    ('"Public evidence host" OR "Public evidence hosting" in:description created:>{since}', "public evidence hosting", "agent-assets"),
    ('"agent-factory" (screenshot OR evidence OR PR) in:description created:>{since}', "agent-factory evidence", "agent-assets"),
    ('"agent-uploaded" in:description created:>{since}', "agent-uploaded assets", "agent-assets"),
    ('"from cloud agents" in:description created:>{since}', "cloud-agent PR assets", "agent-assets"),
    # Media dump naming with recent create
    ('pr-screenshots in:name created:>{since}', "pr-screenshots name", "asset-dump"),
    ('pr-assets in:name created:>{since}', "pr-assets name", "asset-dump"),
    ('"pr-evidence" in:name created:>{since}', "pr-evidence name", "asset-dump"),
]

# Commit-message footprints (agent reasoning about public screenshot hosts)
COMMIT_QUERIES: list[str] = [
    '"host PR screenshots" OR "screenshots now live in" public',
    '"Created public repo" screenshot',
    '"public repo for" (screenshot OR screenshots OR "PR assets")',
    '"workaround" screenshot (PR OR "pull request") public',
    '"orphan branch" screenshot OR "pr-assets orphan"',
]

# Code / skill footprints that teach the leak pattern
CODE_QUERIES: list[str] = [
    '"attach a screenshot to a GitHub" (issue OR PR)',
    '"no API" screenshot (PR OR "pull request") (host OR upload OR public)',
    '"raw.githubusercontent.com never renders" OR "cannot render images from a private"',
]

DENY_NAME = (
    "html2canvas", "pageres", "screenshot-to-code", "pix2code", "flameshot",
    "pr-agent", "playwright", "oss-pr-tracker", "pr-screenshot-reviewer",
    "open-agents", "weaviate/docs", "awesome-", "hacktoberfest",
    "gitshot-images",  # mass empty templates — excluded as a class (see quality gate)
)

DENY_DESC = re.compile(
    r"(read-only cli|privacy policy|github app cho|synthetic end-to-end fixture|"
    r"internal developer platform|preview environments|hacktoberfest|"
    r"screenshot.?to.?code|powerful yet simple to use screenshot)",
    re.I,
)

# Strong admission / PixelLeak language in description
ADMISSION = re.compile(
    r"(private[- ]repo|private .+ repo|camo-renderable|anonymous-?resolvable|"
    r"temporary public (host|hosting)|ephemeral (pr|public)|"
    r"safe to delete after|screenshots linked from|"
    r"public screenshots for private|pr screenshot assets for|"
    r"agent-uploaded|agent-factory|cloud agents|"
    r"public evidence host|anonymous image embeds|"
    r"no api for pr|image proxy|for pr descriptions)",
    re.I,
)

IMAGE_EXT = re.compile(r"\.(png|jpe?g|webp|gif|mp4|webm|mov)$", re.I)


def run(cmd: list[str], timeout: int = 60) -> str | None:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE, timeout=timeout)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        err = getattr(e, "stderr", "") or ""
        if err:
            print(f"[warn] {' '.join(cmd[:4])}…: {str(err)[:180]}", file=sys.stderr)
        return None


def gh_json(cmd: list[str], default: Any = None) -> Any:
    out = run(cmd)
    if out is None:
        return default
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return default


def search_repos(query: str, limit: int = 25) -> list[dict]:
    return gh_json(
        [
            "gh", "search", "repos", query,
            "--limit", str(limit),
            "--json", "fullName,url,description,createdAt,stargazersCount,updatedAt",
        ],
        [],
    ) or []


def search_commits(query: str, limit: int = 20) -> list[dict]:
    return gh_json(
        [
            "gh", "search", "commits", query,
            "--limit", str(limit),
            "--json", "repository,commit,url",
        ],
        [],
    ) or []


def search_code(query: str, limit: int = 10) -> list[dict]:
    # gh search code returns text; use REST for JSON
    q = quote(query)
    data = gh_json(
        ["gh", "api", f"search/code?q={q}&per_page={limit}"],
        {"items": []},
    ) or {"items": []}
    return data.get("items") or []


def repo_meta(full_name: str) -> dict | None:
    return gh_json(
        [
            "gh", "api", f"repos/{full_name}",
            "--jq",
            "{size,pushed_at,created_at,default_branch,stargazers_count,description,html_url,updated_at}",
        ],
        None,
    )


def repo_root_names(full_name: str) -> list[str]:
    data = gh_json(["gh", "api", f"repos/{full_name}/contents"], [])
    if not isinstance(data, list):
        return []
    return [x.get("name", "") for x in data if isinstance(x, dict)]


def repo_releases(full_name: str) -> list[dict]:
    data = gh_json(
        [
            "gh", "api", f"repos/{full_name}/releases?per_page=5",
            "--jq",
            "[.[]|{tag:.tag_name,n:(.assets|length),bytes:(.assets|map(.size)|add),"
            "images:(.assets|map(select(.content_type|test(\"image|video|octet\")))|length)}]",
        ],
        [],
    )
    return data if isinstance(data, list) else []


def commit_count_hint(full_name: str) -> int:
    """Best-effort: length of first page of commits."""
    data = gh_json(["gh", "api", f"repos/{full_name}/commits?per_page=5"], [])
    return len(data) if isinstance(data, list) else 0


def classify(name: str, desc: str, matched: str, default_sev: str) -> tuple[str, str]:
    n = name.lower()
    d = (desc or "").lower()
    short = n.split("/")[-1]
    reason = (desc or "").strip() or matched
    sev = default_sev

    if "gitshot-images" in short or "managed by gitshot" in d:
        sev = "gitshot-host"
    elif short in ("gitshot",) or (short.startswith("gitshot") and "cli" in d):
        sev = "tool" if any(k in d for k in ("cli", "upload", "agent-first")) else "gitshot-related"
    elif any(k in d for k in ("agent-factory", "agent-uploaded", "cloud agents", "coding agent")):
        sev = "agent-assets"
    elif ADMISSION.search(desc or "") or any(
        x in short for x in ("pr-assets", "pr-screenshots", "pr-evidence", "pr-media")
    ):
        sev = "asset-dump"
    return sev, reason


def name_denied(full_name: str) -> bool:
    low = full_name.lower()
    return any(s in low for s in DENY_NAME)


def quality_probe(full_name: str, desc: str, sev: str) -> tuple[bool, str, dict]:
    """Return (keep, quality_reason, enrichment).

    EXCLUDE:
      - missing/404 repos
      - gitshot-images / gitshot-host shells with README-only tree (even if _gitshot
        release has assets — those are mass-produced CDN shells, not useful radar hits)
      - size 0 + boilerplate-only + no image release assets (truly empty)
      - deny-list descriptions

    KEEP when any strong signal:
      - non-boilerplate tree files (esp. images/media)
      - repo size > 5 (KB units)
      - admission-language description AND (tree content OR size>0 OR release images)
      - non-gitshot-host with _gitshot/release image assets (actual binaries)
      - commits > 1 with size > 0
    """
    if DENY_DESC.search(desc or ""):
        return False, "deny-desc", {}

    short = full_name.split("/")[-1].lower()
    meta = repo_meta(full_name)
    if not meta:
        return False, "meta-unavailable", {}

    size = int(meta.get("size") or 0)
    names = repo_root_names(full_name)
    non_boiler = [
        n for n in names
        if n and n.lower().rstrip("/") not in BOILERPLATE and not n.startswith(".")
    ]
    image_files = [n for n in non_boiler if IMAGE_EXT.search(n)]
    releases = repo_releases(full_name)
    rel_images = sum(int(r.get("images") or r.get("n") or 0) for r in releases)
    rel_bytes = sum(int(r.get("bytes") or 0) for r in releases)
    gitshot_rel = [r for r in releases if (r.get("tag") or "") == "_gitshot" or "_gitshot" in (r.get("tag") or "")]
    gitshot_assets = sum(int(r.get("n") or 0) for r in gitshot_rel)
    commits = commit_count_hint(full_name)
    admission = bool(ADMISSION.search(desc or ""))

    enrichment = {
        "size_kb": size,
        "root_files": names[:20],
        "non_boilerplate": non_boiler[:15],
        "image_files_root": image_files[:10],
        "release_image_assets": rel_images,
        "release_bytes": rel_bytes,
        "gitshot_release_assets": gitshot_assets,
        "commit_page_count": commits,
        "admission": admission,
    }

    # Hard exclude: mass gitshot-images CDN shells (README-only tree)
    if ("gitshot-images" in short or sev == "gitshot-host") and not non_boiler and size <= 1:
        return False, "empty-gitshot-shell", enrichment

    # Truly empty
    if not non_boiler and size <= 1 and rel_images == 0 and gitshot_assets == 0:
        return False, "empty-repo", enrichment

    # Strong keep signals
    if image_files:
        return True, f"tree-images:{len(image_files)}", enrichment
    if non_boiler and (admission or size > 5 or any(
        x in short for x in ("pr-assets", "pr-screenshots", "pr-evidence", "pr-media", "evidence")
    )):
        return True, f"tree-content:{','.join(non_boiler[:4])}", enrichment
    if size > 50:
        return True, f"size-kb:{size}", enrichment
    if admission and (size > 0 or rel_images > 0 or non_boiler):
        return True, "admission+content", enrichment
    if sev != "gitshot-host" and (rel_images >= 1 or gitshot_assets >= 1) and rel_bytes >= 5_000:
        return True, f"release-assets:{rel_images or gitshot_assets}", enrichment
    if commits > 1 and size > 5:
        return True, f"commits:{commits},size:{size}", enrichment
    if admission and rel_bytes >= 20_000:
        return True, "admission+release-bytes", enrichment

    return False, "low-signal", enrichment


def load_existing() -> dict:
    if HITS_PATH.exists():
        with open(HITS_PATH) as f:
            return json.load(f)
    return {"hits": [], "generated_at": None, "count": 0}


def main() -> int:
    since = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%d")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    candidates: dict[str, dict] = {}

    # --- Repo search ---
    for q_tmpl, matched, default_sev in REPO_QUERIES:
        query = q_tmpl.format(since=since)
        print(f"[scan:repos] {query}")
        for item in search_repos(query):
            name = item.get("fullName") or ""
            if not name or name_denied(name):
                continue
            desc = item.get("description") or ""
            if DENY_DESC.search(desc):
                continue
            # Drop ancient famous tools
            created = item.get("createdAt") or ""
            if created < "2025-01-01" and not ADMISSION.search(desc):
                continue
            stars = item.get("stargazersCount") or 0
            if stars >= 200 and not ADMISSION.search(desc):
                continue
            sev, reason = classify(name, desc, matched, default_sev)
            prev = candidates.get(name)
            if prev:
                if matched not in prev["matched"]:
                    prev["matched"].append(matched)
                continue
            candidates[name] = {
                "name": name,
                "url": item.get("url") or f"https://github.com/{name}",
                "description": desc,
                "created_at": created,
                "stars": stars,
                "reason": reason,
                "matched": [matched],
                "severity": sev,
                "first_seen": now,
                "source": "repo-search",
            }

    # --- Commit footprints → parent repos (and mention of asset repos in messages) ---
    for cq in COMMIT_QUERIES:
        print(f"[scan:commits] {cq}")
        for item in search_commits(cq):
            repo = (item.get("repository") or {}).get("fullName")
            msg = ((item.get("commit") or {}).get("message") or "")
            if not repo or name_denied(repo):
                continue
            # Prefer extracting referenced asset-repo names from commit messages
            extra_names = re.findall(
                r"\b([A-Za-z0-9_.-]+/(?:[A-Za-z0-9_.-]*(?:pr-assets|pr-screenshots|pr-evidence|assets|screenshots)[A-Za-z0-9_.-]*))\b",
                msg,
            )
            targets = list(dict.fromkeys([repo] + extra_names))
            for name in targets:
                if name_denied(name):
                    continue
                if name in candidates:
                    if cq not in candidates[name]["matched"]:
                        candidates[name]["matched"].append(f"commit:{cq[:40]}")
                    continue
                # Fetch description for new refs
                meta = repo_meta(name) or {}
                desc = meta.get("description") or ""
                sev, reason = classify(name, desc, f"commit footprint: {msg[:80]}", "asset-dump")
                candidates[name] = {
                    "name": name,
                    "url": meta.get("html_url") or f"https://github.com/{name}",
                    "description": desc,
                    "created_at": meta.get("created_at"),
                    "stars": meta.get("stargazers_count") or 0,
                    "reason": reason if desc else f"Commit footprint: {msg.splitlines()[0][:120]}",
                    "matched": [f"commit:{cq[:50]}"],
                    "severity": sev,
                    "first_seen": now,
                    "source": "commit-search",
                    "commit_excerpt": msg[:240],
                }
            time.sleep(0.2)  # be gentle on secondary lookups

    # --- Code / skill footprints ---
    for cq in CODE_QUERIES:
        print(f"[scan:code] {cq}")
        for item in search_code(cq):
            repo_obj = item.get("repository") or {}
            name = repo_obj.get("full_name") or ""
            if not name or name_denied(name):
                continue
            path = item.get("path") or ""
            if name in candidates:
                candidates[name]["matched"].append(f"code:{path[:40]}")
                continue
            meta = repo_meta(name) or {}
            desc = meta.get("description") or ""
            # Skills that teach the pattern are tools, not dumps — keep as tool if clear
            sev = "tool" if re.search(r"skill|agents?\.md|plugin", path, re.I) else "asset-dump"
            candidates[name] = {
                "name": name,
                "url": meta.get("html_url") or f"https://github.com/{name}",
                "description": desc,
                "created_at": meta.get("created_at"),
                "stars": meta.get("stargazers_count") or 0,
                "reason": f"Code/skill footprint ({path}): teaches or references public screenshot hosting",
                "matched": [f"code:{cq[:40]}"],
                "severity": sev,
                "first_seen": now,
                "source": "code-search",
            }
            time.sleep(0.15)

    print(f"[quality] probing {len(candidates)} candidates…")
    kept: list[dict] = []
    excluded = {"empty-gitshot-shell": 0, "empty-repo": 0, "low-signal": 0, "other": 0, "no-admission": 0}
    name_ok = re.compile(
        r"(pr-assets|pr-screenshots|pr-evidence|pr-media|evidence|screenshot|"
        r"pr-\\d+|qa-media|agent-evidence|factory-evidence)",
        re.I,
    )
    for name, hit in candidates.items():
        ok, qreason, enrich = quality_probe(name, hit.get("description") or "", hit.get("severity") or "")
        if not ok:
            bucket = qreason if qreason in excluded else "other"
            excluded[bucket] = excluded.get(bucket, 0) + 1
            print(f"  - drop {name} [{qreason}]")
            continue
        desc = hit.get("description") or ""
        reason = hit.get("reason") or ""
        blob = f"{name} {desc} {reason}"
        short = name.split("/")[-1]
        admission = bool(ADMISSION.search(blob))
        named = bool(name_ok.search(short))
        # Prefer admission-language or clear dump naming; drop loose commit/code noise
        if not admission and not named:
            excluded["no-admission"] += 1
            print(f"  - drop {name} [no-admission]")
            continue
        if hit.get("source") == "commit-search" and not admission and not named:
            excluded["no-admission"] += 1
            print(f"  - drop {name} [commit-noise]")
            continue
        hit["quality"] = qreason
        hit["enrichment"] = enrich
        if admission and desc:
            hit["reason"] = desc
        kept.append(hit)
        print(f"  + keep {name} [{hit['severity']}] ({qreason})")
        time.sleep(0.05)

    # Score: admissions and media dumps first
    def score(h: dict) -> tuple:
        en = h.get("enrichment") or {}
        return (
            1 if en.get("admission") else 0,
            1 if h.get("source") == "commit-search" else 0,
            int(en.get("image_files_root") and len(en["image_files_root"]) or 0),
            int(en.get("size_kb") or 0),
            h.get("created_at") or "",
        )

    kept.sort(key=score, reverse=True)
    if len(kept) > MAX_HITS:
        kept = kept[:MAX_HITS]
    # Display order: newest first
    kept.sort(key=lambda h: h.get("created_at") or "", reverse=True)

    # Spot-check invariant
    assert not any(h["name"] == "doziben/gitshot-images" for h in kept), "doziben must be excluded"

    payload = {
        "generated_at": now,
        "scan_id": f"scan-{now[:10]}",
        "source": "github-actions" if os.environ.get("GITHUB_ACTIONS") else "local",
        "count": len(kept),
        "excluded_summary": excluded,
        "candidates_considered": len(candidates),
        "hits": kept,
    }

    old = load_existing()

    def norm(p: dict) -> str:
        return json.dumps(
            [{"name": h["name"], "severity": h.get("severity"), "quality": h.get("quality")} for h in p.get("hits", [])],
            sort_keys=True,
        )

    changed = norm(payload) != norm(old)
    HITS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(HITS_PATH, "w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    print(f"[done] candidates={len(candidates)} kept={len(kept)} excluded={excluded} changed={changed}")
    (ROOT / ".scan-changed").write_text("1" if changed or len(kept) != old.get("count") else "0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
