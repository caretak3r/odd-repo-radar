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
MAX_HITS = 200  # retain cap in committed file
LOOKBACK_DAYS = 90

# High-signal query patterns. Keep narrow to avoid Search API noise/rate limits.
QUERIES = [
    ('gitshot in:name created:>{since}', 'gitshot in:name', 'gitshot-related'),
    ('gitshot in:description created:>{since}', 'gitshot in:description', 'gitshot-related'),
    ('"Managed by gitshot" in:description', 'Managed by gitshot', 'gitshot-host'),
    ('"Image hosting for gitshot" in:description', 'Image hosting for gitshot', 'gitshot-host'),
    ('gitshot-images in:name', 'gitshot-images in:name', 'gitshot-host'),
    ('pr-assets in:name created:>{since}', 'pr-assets in:name', 'asset-dump'),
    ('"PR screenshots" in:description created:>{since}', 'PR screenshots', 'asset-dump'),
    ('"PR screenshot" in:description created:>{since}', 'PR screenshot', 'asset-dump'),
    ('"PR evidence" in:description created:>{since}', 'PR evidence', 'asset-dump'),
    ('"temporary PR" in:description created:>{since}', 'temporary PR', 'asset-dump'),
    ('"Ephemeral PR" in:description created:>{since}', 'Ephemeral PR', 'asset-dump'),
    ('"agent-uploaded" in:description created:>{since}', 'agent-uploaded', 'agent-assets'),
    ('"cloud agents" in:description created:>{since}', 'cloud agents', 'agent-assets'),
    ('"Agent-generated" PR in:description created:>{since}', 'Agent-generated PR', 'agent-assets'),
    ('"Public hosting for PR" in:description', 'Public hosting for PR', 'asset-dump'),
]


# Noise denylist — known unrelated projects matching loose tokens
DENY_NAME_SUBSTRINGS = (
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
)

DENY_OLD_YEARS = True  # drop pre-2025 unless severity is tool/gitshot-host with explicit match


def run_gh_search(query: str, limit: int = 30) -> list[dict]:
    cmd = [
        "gh",
        "search",
        "repos",
        query,
        "--limit",
        str(limit),
        "--json",
        "fullName,url,description,createdAt,stargazersCount,updatedAt",
    ]
    try:
        out = subprocess.check_output(cmd, text=True, stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as e:
        print(f"[warn] search failed for {query!r}: {e.stderr[:200]}", file=sys.stderr)
        return []
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return []


def classify(name: str, desc: str, matched: str, default_sev: str) -> tuple[str, str]:
    n = (name or "").lower()
    d = (desc or "").lower()
    reason = matched
    sev = default_sev

    if "gitshot-images" in n or "managed by gitshot" in d or "image hosting for gitshot" in d:
        sev = "gitshot-host"
        reason = "gitshot-managed public image host"
    elif "agent" in d and ("pr" in d or "review" in d or "screenshot" in d):
        sev = "agent-assets"
        reason = desc.strip() or matched
    elif any(x in n for x in ("pr-assets", "pr-screenshots", "pr-evidence", "pr-media", "pr-attachments")):
        sev = "asset-dump"
        reason = desc.strip() or matched
    elif "gitshot" in n:
        sev = "gitshot-related"
        if "cli" in d or "upload" in d or "agent" in d:
            sev = "tool"
            reason = desc.strip() or "gitshot tool"
    elif any(
        p in d
        for p in (
            "pr screenshot",
            "pr evidence",
            "temporary pr",
            "ephemeral pr",
            "public assets (pr",
            "public hosting for pr",
        )
    ):
        sev = "asset-dump"
        reason = desc.strip() or matched

    return sev, reason or matched


def is_noise(item: dict) -> bool:
    name = (item.get("fullName") or "").lower()
    if any(s in name for s in DENY_NAME_SUBSTRINGS):
        return True
    created = item.get("createdAt") or ""
    # Keep older only if name is clearly gitshot-images / pr-* pattern from heuristics
    if DENY_OLD_YEARS and created < "2025-01-01":
        short = name.split("/")[-1] if "/" in name else name
        if not re.search(r"(gitshot|pr-assets|pr-screenshots|pr-evidence|pr-media)", short):
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
    by_name: dict[str, dict] = {h["name"]: h for h in existing.get("hits", [])}

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
                # refresh stars / description but keep first_seen
                prev = by_name[name]
                prev["stars"] = item.get("stargazersCount", prev.get("stars", 0))
                if desc:
                    prev["description"] = desc
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

    old_raw = HITS_PATH.read_text() if HITS_PATH.exists() else ""
    # Compare without generated_at / scan_id / new_this_run for idempotency
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

    old = existing
    changed = normalize(payload) != normalize(old) or new_count > 0

    HITS_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Always bump generated_at so dashboard shows last scan time even if no new hits
    # but Action only commits when changed OR when FORCE_COMMIT=1
    with open(HITS_PATH, "w") as f:
        json.dump(payload, f, indent=2)
        f.write("\n")

    print(f"[done] total={len(hits)} new={new_count} changed={changed}")
    # Exit 0 always; write a marker for the workflow
    marker = ROOT / ".scan-changed"
    marker.write_text("1" if (changed or new_count > 0) else "0")
    # Also update generated_at commit if at least the timestamp should refresh weekly —
    # for hourly runs, only commit on real changes to avoid spam.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
