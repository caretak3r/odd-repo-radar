#!/usr/bin/env python3
"""Odd Repo Radar scanner — searches GitHub for PixelLeak-class anomalous public repos."""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HITS_PATH = ROOT / "docs" / "data" / "hits.json"
MAX_HITS = 150
LOOKBACK_DAYS = 120

# High-signal query patterns only.
QUERIES = [
    ('gitshot-images in:name', 'gitshot-images in:name', 'gitshot-host'),
    ('"Managed by gitshot" in:description', 'Managed by gitshot', 'gitshot-host'),
    ('"Image hosting for gitshot" in:description', 'Image hosting for gitshot', 'gitshot-host'),
    ('"Image hosting for GitHub issues" in:description', 'Image hosting for GitHub issues', 'gitshot-host'),
    ('gitshot in:name created:>{since}', 'gitshot in:name', 'gitshot-related'),
    ('pr-assets in:name created:>{since}', 'pr-assets in:name', 'asset-dump'),
    ('pr-screenshots in:name created:>{since}', 'pr-screenshots in:name', 'asset-dump'),
    ('pr-evidence in:name created:>{since}', 'pr-evidence in:name', 'asset-dump'),
    ('"PR screenshots" in:description created:>{since}', 'PR screenshots', 'asset-dump'),
    ('"PR screenshot" in:description created:>{since}', 'PR screenshot', 'asset-dump'),
    ('"PR evidence" in:description created:>{since}', 'PR evidence', 'asset-dump'),
    ('"temporary PR screenshot" in:description created:>{since}', 'temporary PR screenshot', 'asset-dump'),
    ('"temporary PR image" in:description created:>{since}', 'temporary PR image', 'asset-dump'),
    ('"temporary PR assets" in:description created:>{since}', 'temporary PR assets', 'asset-dump'),
    ('"Ephemeral PR screenshot" in:description created:>{since}', 'Ephemeral PR screenshot', 'asset-dump'),
    ('"Public hosting for PR" in:description', 'Public hosting for PR', 'asset-dump'),
    ('"Public assets (PR" in:description', 'Public assets (PR', 'asset-dump'),
    ('"agent-uploaded" in:description created:>{since}', 'agent-uploaded', 'agent-assets'),
    ('"from cloud agents" in:description created:>{since}', 'from cloud agents', 'agent-assets'),
    ('"Agent-generated review" in:description created:>{since}', 'Agent-generated review', 'agent-assets'),
    ('"PR screenshot assets (agent" in:description', 'PR screenshot assets agent', 'agent-assets'),
]

DENY_NAME_SUBSTRINGS = (
    "oss-pr-tracker",
    "pr-screenshot-reviewer",
    "behavior-review-demo",
    "open-assets",
    "proof-of-assets",
    "moonbirds",
    "protocol-assets",
    "html2canvas",
    "pageres",
    "playwright",
    "screenshot-to-code",
    "screenfetch",
    "webkit2png",
    "open-agents",
    "agent-orchestrator",
    "weaviate/docs",
    "deploy-action",
    "memprivacy",
    "pipecat-cloud",
)

# Require at least one of these signals in name OR description for non-gitshot hits
REQUIRE_SIGNAL = re.compile(
    r"(gitshot|pr-assets|pr-screenshots|pr-evidence|pr-media|pr-attachments|"
    r"pr screenshot|pr evidence|temporary pr (image|screenshot|asset)|"
    r"ephemeral pr screenshot|temp pr evidence|"
    r"managed by gitshot|image hosting for (gitshot|github)|"
    r"agent-uploaded|from cloud agents|"
    r"agent-generated review|public hosting for pr|public assets \(pr|"
    r"screenshot assets|review images and pr|screenshots for|"
    r"proof assets \(screenshots\)|screenshots and artifacts)",
    re.I,
)


def run_gh_search(query: str, limit: int = 40) -> list[dict]:
    cmd = [
        "gh", "search", "repos", query,
        "--limit", str(limit),
        "--json", "fullName,url,description,createdAt,stargazersCount,updatedAt",
    ]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"[warn] search failed for {query!r}: {e.stderr[:240]}", file=sys.stderr)
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return []


def classify(name: str, desc: str, matched: str, default_sev: str) -> tuple[str, str]:
    n = (name or "").lower()
    d = (desc or "").lower()
    short = n.split("/")[-1] if "/" in n else n
    reason = (desc or "").strip() or matched
    sev = default_sev

    if (
        "gitshot-images" in short
        or "managed by gitshot" in d
        or "image hosting for gitshot" in d
        or ("image hosting for github" in d and "gitshot" in d)
    ):
        sev = "gitshot-host"
        reason = desc.strip() or "gitshot-managed public image host"
    elif short in ("gitshot",) or short.startswith("gitshot"):
        if any(k in d for k in ("cli", "upload", "agent-first", "zero-config")):
            sev = "tool"
        else:
            sev = "gitshot-related"
    elif "agent" in d and any(k in d for k in ("pr", "screenshot", "review image")):
        sev = "agent-assets"
    elif any(
        x in short
        for x in (
            "pr-assets",
            "pr-screenshots",
            "pr-evidence",
            "pr-media",
            "pr-attachments",
            "pr-shots",
        )
    ) or any(
        p in d
        for p in (
            "pr screenshot",
            "pr evidence",
            "temporary pr",
            "ephemeral pr",
            "temp pr",
            "public assets (pr",
            "public hosting for pr",
        )
    ):
        sev = "asset-dump"

    return sev, reason


def is_noise(item: dict) -> bool:
    name = (item.get("fullName") or "")
    desc = item.get("description") or ""
    low = name.lower()
    if any(s in low for s in DENY_NAME_SUBSTRINGS):
        return True
    created = item.get("createdAt") or ""
    if created < "2025-01-01":
        short = low.split("/")[-1]
        if not re.search(r"(gitshot|pr-assets|pr-screenshots|pr-evidence)", short):
            return True
    # Must match PixelLeak-class signal
    if not REQUIRE_SIGNAL.search(f"{name} {desc}"):
        return True
    # Drop high-star general tools accidentally caught
    stars = item.get("stargazersCount") or 0
    short = low.split("/")[-1]
    if stars >= 100 and not re.search(r"(gitshot|pr-assets|pr-screenshots)", short):
        # keep notable tooling like gitshot itself / gh-attach
        d = desc.lower()
        if not any(k in d for k in ("gitshot", "pr screenshot", "upload images to github")):
            return True
    return False


def load_existing() -> dict:
    if HITS_PATH.exists():
        with open(HITS_PATH) as f:
            return json.load(f)
    return {"hits": [], "generated_at": None, "count": 0}


def main() -> int:
    since = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).strftime("%Y-%m-%d")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    existing = load_existing()
    # Start fresh merge from existing but drop noise that no longer passes filters
    by_name: dict[str, dict] = {}
    for h in existing.get("hits", []):
        fake = {
            "fullName": h["name"],
            "description": h.get("description"),
            "createdAt": h.get("created_at"),
            "stargazersCount": h.get("stars", 0),
        }
        if not is_noise(fake):
            by_name[h["name"]] = h

    new_count = 0
    for q_tmpl, matched, default_sev in QUERIES:
        query = q_tmpl.format(since=since)
        print(f"[scan] {query}")
        for item in run_gh_search(query):
            if is_noise(item):
                continue
            name = item["fullName"]
            desc = item.get("description") or ""
            sev, reason = classify(name, desc, matched, default_sev)
            if name in by_name:
                prev = by_name[name]
                prev["stars"] = item.get("stargazersCount", prev.get("stars", 0))
                if desc:
                    prev["description"] = desc
                prev["severity"] = sev
                prev["reason"] = reason
                if matched not in (prev.get("matched") or []):
                    prev.setdefault("matched", []).append(matched)
                continue
            hit = {
                "name": name,
                "url": item.get("url") or f"https://github.com/{name}",
                "description": desc,
                "created_at": item.get("createdAt"),
                "stars": item.get("stargazersCount", 0),
                "reason": reason,
                "matched": [matched],
                "severity": sev,
                "first_seen": now,
            }
            by_name[name] = hit
            new_count += 1
            print(f"  + {name} [{sev}]")

    hits = sorted(by_name.values(), key=lambda h: h.get("created_at") or "", reverse=True)
    if len(hits) > MAX_HITS:
        hits = hits[:MAX_HITS]

    payload = {
        "generated_at": now,
        "scan_id": f"scan-{now[:10]}",
        "source": "github-actions" if os.environ.get("GITHUB_ACTIONS") else "local",
        "count": len(hits),
        "new_this_run": new_count,
        "hits": hits,
    }

    def normalize(p: dict) -> str:
        slim = {
            "count": p.get("count"),
            "hits": [
                {
                    "name": h["name"],
                    "url": h.get("url"),
                    "description": h.get("description"),
                    "created_at": h.get("created_at"),
                    "stars": h.get("stars"),
                    "reason": h.get("reason"),
                    "matched": h.get("matched"),
                    "severity": h.get("severity"),
                    "first_seen": h.get("first_seen"),
                }
                for h in p.get("hits", [])
            ],
        }
        return json.dumps(slim, sort_keys=True)

    old = load_existing()
    changed = normalize(payload) != normalize(old) or new_count > 0

    HITS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(HITS_PATH, "w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    print(f"[done] total={len(hits)} new={new_count} changed={changed}")
    marker = ROOT / ".scan-changed"
    marker.write_text("1" if (changed or new_count > 0) else "0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
