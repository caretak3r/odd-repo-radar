(function () {
  const hitsBody = document.getElementById("hits-body");
  const hitCount = document.getElementById("hit-count");
  const lastScan = document.getElementById("last-scan");
  const statHits = document.getElementById("stat-hits");
  const filterQ = document.getElementById("filter-q");
  const filterSev = document.getElementById("filter-sev");
  const findingBrief = document.getElementById("finding-brief");

  let allHits = [];

  function fmtDate(iso) {
    if (!iso) return "—";
    try {
      const d = new Date(iso);
      return d.toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
        timeZone: "America/New_York",
      });
    } catch {
      return iso.slice(0, 10);
    }
  }

  function fmtScan(iso) {
    if (!iso) return "scan: —";
    try {
      const d = new Date(iso);
      return (
        "scan: " +
        d.toLocaleString("en-US", {
          month: "short",
          day: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          timeZone: "America/New_York",
          timeZoneName: "short",
        })
      );
    } catch {
      return "scan: " + iso;
    }
  }

  function renderHits(list) {
    if (!list.length) {
      hitsBody.innerHTML =
        '<tr><td colspan="5" class="loading">No hits match filters.</td></tr>';
      return;
    }
    hitsBody.innerHTML = list
      .map((h) => {
        const sev = h.severity || "asset-dump";
        const desc = h.description
          ? `<span class="desc">${escapeHtml(h.description)}</span>`
          : "";
        return `<tr>
          <td>
            <a href="${escapeAttr(h.url)}" target="_blank" rel="noopener">${escapeHtml(h.name)}</a>
            ${desc}
          </td>
          <td>${fmtDate(h.created_at)}</td>
          <td>${h.stars ?? 0}</td>
          <td><span class="sev sev-${escapeAttr(sev)}">${escapeHtml(sev)}</span></td>
          <td class="reason">${escapeHtml(h.reason || (h.matched || []).join(", "))}</td>
        </tr>`;
      })
      .join("");
  }

  function applyFilters() {
    const q = (filterQ.value || "").toLowerCase().trim();
    const sev = filterSev.value;
    const filtered = allHits.filter((h) => {
      if (sev && h.severity !== sev) return false;
      if (!q) return true;
      const hay = [h.name, h.description, h.reason, ...(h.matched || [])]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
    renderHits(filtered);
  }

  function escapeHtml(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }
  function escapeAttr(s) {
    return escapeHtml(s).replace(/'/g, "&#39;");
  }

  function renderFinding(data) {
    const f = (data.findings || [])[0];
    if (!f) {
      findingBrief.innerHTML = "<p>No findings loaded.</p>";
      return;
    }
    const chips = Object.entries(f.impact || {})
      .map(
        ([k, v]) =>
          `<span class="chip">${escapeHtml(k)}: ${escapeHtml(String(v))}</span>`
      )
      .join("");
    const sources = (f.sources || [])
      .map(
        (s) =>
          `<li><a href="${escapeAttr(s.url)}" target="_blank" rel="noopener">${escapeHtml(s.label)}</a></li>`
      )
      .join("");
    findingBrief.innerHTML = `
      <h3 style="margin:0 0 0.4rem;color:#fff;font-size:0.95rem;">${escapeHtml(f.title)}</h3>
      <p>${escapeHtml(f.summary)}</p>
      <div class="impact">${chips}</div>
      <p><strong style="color:var(--muted);">Pattern:</strong> ${escapeHtml(f.pattern)}</p>
      <ul class="sources">${sources}</ul>
    `;
  }

  Promise.all([
    fetch("data/hits.json").then((r) => r.json()),
    fetch("data/findings.json").then((r) => r.json()),
  ])
    .then(([hitsData, findingsData]) => {
      allHits = (hitsData.hits || []).slice().sort((a, b) => {
        return String(b.created_at).localeCompare(String(a.created_at));
      });
      hitCount.textContent = `${allHits.length} hits`;
      statHits.textContent = String(allHits.length);
      lastScan.textContent = fmtScan(hitsData.generated_at);
      applyFilters();
      renderFinding(findingsData);
    })
    .catch((err) => {
      hitsBody.innerHTML = `<tr><td colspan="5" class="loading">Failed to load data: ${escapeHtml(err.message)}</td></tr>`;
      findingBrief.innerHTML = `<p class="loading">Failed to load findings.</p>`;
    });

  filterQ.addEventListener("input", applyFilters);
  filterSev.addEventListener("change", applyFilters);
})();
