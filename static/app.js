function copyPoC(btn) {
  const code = btn.previousElementSibling.innerText;
  navigator.clipboard.writeText(code);
  const originalHTML = btn.innerHTML;
  btn.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>';
  setTimeout(() => {
    btn.innerHTML = originalHTML;
  }, 2000);
}

function _destroyGraph(container) {
  if (!container) return;
  if (container._graphResizeHandler) {
    window.removeEventListener("resize", container._graphResizeHandler);
    container._graphResizeHandler = null;
  }
  if (container._graphTimers && Array.isArray(container._graphTimers)) {
    container._graphTimers.forEach((id) => clearInterval(id));
  }
  container._graphTimers = [];
  if (container._cyInstance) {
    try {
      container._cyInstance.destroy();
    } catch (e) {
      /* ignore */
    }
    container._cyInstance = null;
  }
  container.innerHTML = "";
}

function _textOf(issue) {
  const n = (issue.name || "").toLowerCase();
  const im = (issue.impact || "").toLowerCase();
  const cat = (issue.category || "").toLowerCase();
  return { n, im, cat, rawName: issue.name || "", rawImpact: issue.impact || "" };
}

function _findIssue(issues, keywords) {
  return issues.some((i) => {
    const t = _textOf(i);
    return keywords.some((k) => t.n.includes(k) || t.im.includes(k) || t.cat.includes(k));
  });
}

function _truncate(s, max) {
  if (!s) return "";
  const t = String(s).trim();
  return t.length <= max ? t : t.slice(0, max - 1) + "…";
}

/**
 * Parse backend "Exploit Chain" issues (impact often uses "A → B → C").
 */
function _stepsFromExploitIssue(issue, chainIdx) {
  const raw = (issue.impact || issue.name || "").trim();
  let parts = raw
    .split(/\s*(?:\u2192|->|=>|—>)\s*/)
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0 && issue.name) parts = [issue.name];

  const types = ["entry", "escalation", "impact"];
  if (parts.length >= 3) {
    return parts.slice(0, 3).map((label, i) => ({
      id: `ec_${chainIdx}_${i}`,
      label: _truncate(label, 48),
      type: types[i],
    }));
  }
  if (parts.length === 2) {
    return [
      { id: `ec_${chainIdx}_0`, label: _truncate(parts[0], 48), type: "entry" },
      { id: `ec_${chainIdx}_1`, label: "Attack progression", type: "escalation" },
      { id: `ec_${chainIdx}_2`, label: _truncate(parts[1], 48), type: "impact" },
    ];
  }
  if (parts.length === 1) {
    return [
      { id: `ec_${chainIdx}_0`, label: "Initial exposure", type: "entry" },
      { id: `ec_${chainIdx}_1`, label: _truncate(parts[0], 48), type: "escalation" },
      { id: `ec_${chainIdx}_2`, label: "Business / user impact", type: "impact" },
    ];
  }
  return null;
}

function _chainKey(chain) {
  return chain.map((n) => n.label).join("|");
}

function buildAttackChains(issues) {
  const chains = [];
  const seen = new Set();
  const push = (chain) => {
    const k = _chainKey(chain);
    if (seen.has(k)) return;
    seen.add(k);
    chains.push(chain);
  };

  let ecIdx = 0;
  issues.forEach((issue) => {
    if ((issue.category || "") === "Exploit Chain") {
      const steps = _stepsFromExploitIssue(issue, ecIdx++);
      if (steps) push(steps);
    }
  });

  const hasXSS = _findIssue(issues, [
    "xss",
    "cross-site",
    "client-side code injection",
    "reflected",
    "injection",
  ]);
  const hasCookie = _findIssue(issues, [
    "httponly",
    "session",
    "cookie",
    "insecure account",
    "account session",
  ]);
  if (hasXSS && (hasCookie || _findIssue(issues, ["hijack", "takeover", "session theft"]))) {
    push([
      { id: "xss_e", label: "Untrusted input reaches the page", type: "entry" },
      { id: "xss_m", label: "Script runs in the victim browser", type: "escalation" },
      { id: "xss_i", label: "Session or sensitive actions abused", type: "impact" },
    ]);
  }

  const hasTransport = _findIssue(issues, [
    "unencrypted",
    "mitm",
    "hsts",
    "transport",
    "http",
    "cleartext",
  ]);
  if (hasTransport) {
    push([
      { id: "tr_e", label: "Traffic readable on the network", type: "entry" },
      { id: "tr_m", label: "Tokens or cookies exposed", type: "escalation" },
      { id: "tr_i", label: "Account or data theft", type: "impact" },
    ]);
  }

  const hasRedirect = _findIssue(issues, ["open redirect", "url redirection", "redirect"]);
  if (hasRedirect) {
    push([
      { id: "rd_e", label: "Trusted link with attacker-controlled target", type: "entry" },
      { id: "rd_m", label: "User sent to a malicious site", type: "escalation" },
      { id: "rd_i", label: "Phishing / credential loss", type: "impact" },
    ]);
  }

  const hasExposure = _findIssue(issues, [
    "exposure",
    "sensitive file",
    "sensitive data source",
    "config",
    "backup",
    ".env",
  ]);
  if (hasExposure) {
    push([
      { id: "ex_e", label: "Secrets or config reachable over HTTP", type: "entry" },
      { id: "ex_m", label: "Extra attack surface revealed", type: "escalation" },
      { id: "ex_i", label: "Lateral movement or full compromise", type: "impact" },
    ]);
  }

  if (chains.length === 0 && issues.some((i) => (i.severity || "").toUpperCase() === "HIGH")) {
    push([
      { id: "gen_e", label: "High-severity weakness present", type: "entry" },
      { id: "gen_m", label: "Attacker probes or chains with other bugs", type: "escalation" },
      { id: "gen_i", label: "Data or availability at risk", type: "impact" },
    ]);
  }

  return chains;
}

function buildGraphSummary(chains, meta, isFree) {
  const risk = (meta.risk || "Unknown").toString();
  const score = meta.score != null ? String(meta.score) : "";
  const parts = [];

  if (meta.scanFailed) {
    return "Scan could not complete; chains are not available for this target.";
  }

  if (chains.length === 0) {
    parts.push(
      "No multi-step story was inferred from the current signals (or only low-confidence items were present)."
    );
    if (meta.hasIssues === false) {
      parts.push("Overall this target looked comparatively clean in our automated pass.");
    } else {
      parts.push(
        "You may still have important single issues below — not every risk forms a neat three-step chain."
      );
    }
    if (score) parts.push(`Score ${score}/100 · overall risk label: ${risk}.`);
    return parts.join(" ");
  }

  parts.push(
    `Showing ${chains.length} chain${chains.length > 1 ? "s" : ""}: how separate weaknesses combine into a worse outcome.`
  );
  parts.push(`Score ${score || "—"}/100 · ${risk} risk — use the list below for exact fixes.`);

  if (isFree) {
    parts.push("Upgrade to see full PoCs and every finding in this report.");
  }

  return parts.join(" ");
}

function buildCytoscapeElements(chains, isFree) {
  const elements = [];
  chains.forEach((chain, chainIdx) => {
    chain.forEach((node, nodeIdx) => {
      elements.push({
        data: {
          id: `${node.id}_${chainIdx}`,
          label: node.label,
          type: node.type,
          chain: chainIdx,
        },
      });
      if (nodeIdx > 0) {
        const prev = chain[nodeIdx - 1];
        const lastStep = nodeIdx === chain.length - 1;
        const locked = isFree && lastStep;
        elements.push({
          data: {
            id: `e_${node.id}_${chainIdx}`,
            source: `${prev.id}_${chainIdx}`,
            target: `${node.id}_${chainIdx}`,
            type: locked ? "locked-edge" : "chain-edge",
          },
        });
      }
    });
  });
  return elements;
}

function applyPresetLayout(elements, chains, width, height) {
  const padX = 90;
  const padY = 70;
  const usableW = Math.max(width - padX * 2, 280);
  const rowH = Math.min(130, Math.max(100, (height - padY * 2) / Math.max(chains.length, 1)));

  chains.forEach((chain, cIdx) => {
    const y = padY + cIdx * rowH + rowH / 2;
    const len = chain.length;
    const span = usableW;
    const step = len > 1 ? span / (len - 1) : 0;
    const startX = padX + (usableW - (len - 1) * step) / 2;
    chain.forEach((node, nIdx) => {
      const id = `${node.id}_${cIdx}`;
      const pos = { x: startX + nIdx * step, y };
      elements.forEach((el) => {
        if (el.data && !el.data.source && el.data.id === id) {
          el.position = pos;
        }
      });
    });
  });
}

function renderGraph(issues, isFree, meta) {
  meta = meta || {};
  const container = document.getElementById("graph");
  const summaryEl = document.getElementById("graph-summary");

  if (!container) return;

  _destroyGraph(container);

  const setSummary = (text) => {
    if (summaryEl) summaryEl.textContent = text || "";
  };

  const chains = buildAttackChains(issues || []);

  if (chains.length === 0) {
    setSummary(buildGraphSummary(chains, meta, isFree));
    container.innerHTML = `
      <div class="flex flex-col items-center justify-center h-full min-h-[280px] text-center px-8 py-12">
        <div class="w-14 h-14 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center mb-5">
          <i class="fa-solid fa-shield-halved text-emerald-500 text-2xl"></i>
        </div>
        <p class="text-sm font-bold text-gray-800 dark:text-gray-200 mb-2 max-w-md">No chained attack path drawn</p>
        <p class="text-xs text-gray-600 dark:text-gray-400 max-w-md leading-relaxed">
          We only draw a story when the scanner can connect signals into entry → escalation → impact.
          Check the inventory below for individual findings.
        </p>
      </div>
    `;
    return;
  }

  setSummary(buildGraphSummary(chains, meta, isFree));

  const elements = buildCytoscapeElements(chains, isFree);
  const w = container.clientWidth || 640;
  const h = Math.max(container.clientHeight || 400, 380);
  applyPresetLayout(elements, chains, w, h);

  if (typeof cytoscape === "undefined") {
    container.innerHTML =
      '<p class="text-center text-amber-600 text-sm p-8">Graph library failed to load. Refresh the page.</p>';
    return;
  }

  const cy = cytoscape({
    container,
    elements,
    style: [
      {
        selector: "node",
        style: {
          label: "data(label)",
          color: "#e2e8f0",
          "font-family": "Outfit, JetBrains Mono, system-ui, sans-serif",
          "font-size": "11px",
          "font-weight": "700",
          "text-wrap": "wrap",
          "text-max-width": "120px",
          "text-valign": "center",
          "text-halign": "center",
          "text-outline-width": 2,
          "text-outline-color": "#020617",
          "background-color": "#0f172a",
          "border-width": 3,
          "border-color": "#475569",
          width: 56,
          height: 56,
          "shadow-blur": 12,
          "shadow-color": "#000",
          "shadow-opacity": 0.5,
        },
      },
      {
        selector: 'node[type="entry"]',
        style: {
          "background-color": "#4f46e5",
          "border-color": "#818cf8",
          shape: "ellipse",
          "border-width": 4,
          "shadow-color": "#6366f1",
        },
      },
      {
        selector: 'node[type="escalation"]',
        style: {
          "background-color": "#d97706",
          "border-color": "#fbbf24",
          shape: "round-rectangle",
          "border-width": 4,
          width: 72,
          height: 52,
          "shadow-color": "#f59e0b",
        },
      },
      {
        selector: 'node[type="impact"]',
        style: {
          "background-color": "#b91c1c",
          "border-color": "#f87171",
          shape: "hexagon",
          width: 76,
          height: 76,
          "font-size": "10px",
          "shadow-color": "#ef4444",
          "shadow-blur": 24,
        },
      },
      {
        selector: "edge",
        style: {
          width: 3,
          "line-color": "#64748b",
          "target-arrow-color": "#64748b",
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          "arrow-scale": 1.1,
          opacity: 0.85,
        },
      },
      {
        selector: 'edge[type="chain-edge"]',
        style: {
          "line-color": "#818cf8",
          "target-arrow-color": "#a5b4fc",
          "line-style": "solid",
        },
      },
      {
        selector: 'edge[type="locked-edge"]',
        style: {
          "line-style": "dashed",
          "line-color": "#475569",
          "target-arrow-color": "#64748b",
          opacity: 0.45,
        },
      },
    ],
    layout: {
      name: "preset",
      fit: true,
      padding: 24,
      animate: false,
    },
    userZoomingEnabled: true,
    userPanningEnabled: true,
    boxSelectionEnabled: false,
    minZoom: 0.35,
    maxZoom: 1.75,
  });

  cy.fit(undefined, 36);
  container._cyInstance = cy;

  const timers = [];
  let dashOffset = 0;
  const dashTimer = setInterval(() => {
    dashOffset += 1.5;
    cy.edges('[type="chain-edge"]').style({
      "line-style": "dashed",
      "line-dash-pattern": [8, 6],
      "line-dash-offset": -dashOffset,
    });
  }, 80);
  timers.push(dashTimer);
  container._graphTimers = timers;

  const onResize = () => {
    if (!container._cyInstance) return;
    cy.resize();
    cy.fit(undefined, 36);
  };
  window.addEventListener("resize", onResize);
  container._graphResizeHandler = onResize;
}
