# Odd Repo Radar

Near-real-time radar for **odd / anomalous public GitHub repos** — the kind that showed up in [PixelLeak](https://www.glow.io/blogs/how-ai-agents-exposed-developer-screenshots-from-leading-tech-companies): personal accounts dumping screenshot assets so AI coding agents can attach images to private PR workflows.

**Live dashboard:** https://caretak3r.github.io/odd-repo-radar/ (also https://silent.engineer/odd-repo-radar/ via custom domain)

## What this is

Not a feed of every new repo. A **high-signal** watchlist for patterns like:

- `gitshot` / `gitshot-images` / “Managed by gitshot”
- `pr-assets`, `pr-screenshots`, `pr-evidence`, ephemeral/temporary PR image hosts
- Agent-uploaded review images and cloud-agent PR asset dumps
- Forks/tools that publish review screenshots to public GitHub

## PixelLeak (seed finding)

AI coding agents leaked **13,000+** internal screenshots from **343** organizations onto public GitHub. Agents often couldn’t attach images to private PRs via CLI, so they created or reused **public** repos as image hosts. Roughly **⅓** used `gitshot` (images under a `_gitshot` tag).

Sources:

- [Glow.io writeup](https://www.glow.io/blogs/how-ai-agents-exposed-developer-screenshots-from-leading-tech-companies)
- [The Hacker News](https://thehackernews.com/2026/09/ai-coding-agents-exposed-13000-internal.html)
- [IntCyberDigest tweet](https://x.com/IntCyberDigest/status/2104987762864558330)

This repo stores **metadata and public links only** — never leaked screenshot contents or PII.

## How updates work

1. GitHub Action [`.github/workflows/scan.yml`](.github/workflows/scan.yml) runs **hourly** (`cron: '14 * * * *'`) and on `workflow_dispatch`.
2. [`scripts/scan.py`](scripts/scan.py) queries the GitHub Search API (`gh search repos`) with narrow heuristics.
3. New unique hits merge into [`docs/data/hits.json`](docs/data/hits.json).
4. The Action commits only when there are material changes (quiet / idempotent).
5. GitHub Pages serves [`docs/`](docs/) — the dashboard reads the JSON client-side.

## Site structure

```
docs/
  index.html          # dashboard
  assets/style.css
  assets/app.js
  data/hits.json      # live / scanned hits
  data/findings.json  # PixelLeak seed narrative
```

## Contribute heuristics

Open a PR that:

1. Adds a query + severity mapping in `scripts/scan.py` (`QUERIES` / `classify`).
2. Documents the pattern in `docs/index.html` (Heuristics section) and this README.
3. Keeps filters **high-signal** — prefer precision over recall.

## Local scan

```bash
# requires authenticated gh CLI
python3 scripts/scan.py
```

## Disclaimer

**Defensive research / awareness only.** Do not use this project to exploit, scrape, or redistribute leaked content. If you encounter sensitive material in a public repo, report it to the owner, GitHub, or the affected organization — do not mirror it here.

## License

MIT — see [LICENSE](LICENSE).
