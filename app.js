/* Luminar AI — Decision Governance Dashboard (Rebuild)
   - Decision-level evidence (per README/PDF)
   - Event-sourced audit log: append-only, hash chained, signed (tamper-evident)
   - ISO/IEC 42001 Clauses 4–10 heat map + descriptions + mitigations
   - Export:
       (1) Audit Pack JSON (decisions + approvals + audit log + anchor)
       (2) Board-ready briefing HTML (print-ready)
*/

document.addEventListener("DOMContentLoaded", () => {
  const STORAGE_KEY = "luminar_decision_governance_v2";
  const KEY_STORAGE_KEY = "luminar_hmac_key_v2"; // exported JWK for demo continuity (still not “tamper-proof”)
  const ANCHOR_HISTORY_KEY = "luminar_anchor_history_v2";

  const state = {
    actingUser: "cao@municipality.ca",
    decisions: [],
    approvalsByDecision: {},  // { [id]: [{user, rationale, at}] }
    auditLog: [],
    lastHash: "GENESIS",
    hmacKey: null,            // CryptoKey
    lastAnchor: null          // {anchorHash, at, auditLen, lastEventHash}
  };

  const riskRules = {
    Low: { approvalsRequired: 1, allowApprove: true, label: "Low" },
    Medium: { approvalsRequired: 1, allowApprove: true, label: "Medium" },
    High: { approvalsRequired: 2, allowApprove: true, label: "High" },
    Critical: { approvalsRequired: Infinity, allowApprove: false, label: "Critical (Escalate)" }
  };

  // ISO/IEC 42001 Clauses 4–10 evidence-support map (dashboard view)
  const isoClauses = [
    {
      id: "Clause 4",
      title: "Context of the organisation",
      desc: "Define the organisational context, stakeholders, and scope of the AI management system (AIMS).",
      evidence: [
        "Decision context fields (why it was needed, constraints, impacted parties)",
        "Decision scope statement (governs decisions, not technology)"
      ],
      mitigations: [
        "Document scope boundaries (what is governed vs not governed)",
        "Identify stakeholders impacted by AI-influenced decisions",
        "Maintain a decision taxonomy (HR/financial/service/policy) to show coverage"
      ]
    },
    {
      id: "Clause 5",
      title: "Leadership",
      desc: "Leadership accountability, roles, responsibilities, and governance commitment.",
      evidence: [
        "Decision owner field",
        "Approver(s) recorded with rationale",
        "Oversight level declared before outcomes"
      ],
      mitigations: [
        "Assign named roles (Owner, Approver, Oversight body) in policy",
        "Require written approval rationale for higher-risk decisions",
        "Ensure board/council oversight path exists for critical decisions"
      ]
    },
    {
      id: "Clause 6",
      title: "Planning",
      desc: "Risk-based planning, objectives, and controls for AI use within the AIMS.",
      evidence: [
        "Risk classification per decision",
        "Risk acceptance recorded (Yes/No + notes)",
        "Safeguards declared"
      ],
      mitigations: [
        "Define risk criteria and thresholds for Low/Medium/High/Critical",
        "Create a risk acceptance template (who can accept what level)",
        "Require declared safeguards for Medium+ decisions"
      ]
    },
    {
      id: "Clause 7",
      title: "Support",
      desc: "Competence, awareness, communication, documented information, and resources.",
      evidence: [
        "Decision record completeness (evidence readiness score)",
        "Audit pack export for documentation",
        "Board briefing export for communication"
      ],
      mitigations: [
        "Train staff on how to record AI influence accurately",
        "Use standard safeguard checklists by decision type",
        "Implement records retention and custody (export anchors to official systems)"
      ]
    },
    {
      id: "Clause 8",
      title: "Operation",
      desc: "Operational controls — how AI-influenced decisions are carried out under governance.",
      evidence: [
        "Decision workflow (record → approve → escalate for critical)",
        "Separation of duties for High risk",
        "Influence narrative (how AI was used)"
      ],
      mitigations: [
        "Block approval for Critical; require formal oversight minutes outside tool",
        "Enforce dual approval and distinct approvers for High risk",
        "Require verification notes when AI is recommendatory/determinative"
      ]
    },
    {
      id: "Clause 9",
      title: "Performance evaluation",
      desc: "Monitoring, measurement, internal review, and evaluation of governance effectiveness.",
      evidence: [
        "Audit log integrity checks",
        "Metrics: pending high/critical, acceptance rate, evidence readiness"
      ],
      mitigations: [
        "Run periodic board reporting (monthly/quarterly)",
        "Spot-check records for completeness and rationale quality",
        "Use exported audit packs for independent review"
      ]
    },
    {
      id: "Clause 10",
      title: "Improvement",
      desc: "Nonconformity, corrective action, and continual improvement of the AIMS.",
      evidence: [
        "Escalation events logged",
        "Audit anchors stored over time (improvement trail)"
      ],
      mitigations: [
        "Add corrective action notes when decisions are challenged",
        "Update safeguards checklists based on incidents/lessons learned",
        "Track recurring risk patterns and update thresholds"
      ]
    }
  ];

  // DOM
  const $ = (id) => document.getElementById(id);
  const dom = {
    actingUser: $("actingUser"),
    integrityText: $("integrityText"),
    integrityDot: $("integrityDot"),

    btnSeed: $("btnSeed"),
    btnExportAudit: $("btnExportAudit"),
    btnExportBoard: $("btnExportBoard"),

    mTotal: $("mTotal"),
    mHighPending: $("mHighPending"),
    mAcceptance: $("mAcceptance"),
    mEvidence: $("mEvidence"),

    decisionForm: $("decisionForm"),
    btnReset: $("btnReset"),

    registerBody: $("registerBody"),
    search: $("search"),
    riskFilter: $("riskFilter"),

    auditPre: $("auditPre"),
    btnCopyAudit: $("btnCopyAudit"),
    btnVerify: $("btnVerify"),
    btnClear: $("btnClear"),

    isoGrid: $("isoGrid"),
    isoTitle: $("isoTitle"),
    isoDesc: $("isoDesc"),
    isoEvidence: $("isoEvidence"),
    isoMitigations: $("isoMitigations"),

    modalBackdrop: $("modalBackdrop"),
    approvalRationale: $("approvalRationale"),
    btnCancelModal: $("btnCancelModal"),
    btnConfirmModal: $("btnConfirmModal")
  };

  // Modal state
  let pendingApprovalDecisionId = null;

  // ----------------------------
  // Crypto helpers
  // ----------------------------
  const enc = new TextEncoder();

  async function sha256Hex(str) {
    const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
    return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async function getOrCreateHmacKey() {
    // Demo continuity: store/export the key as JWK (this is still not “tamper-proof”).
    // Production immutability: server-side append-only log or external signing authority.
    const raw = localStorage.getItem(KEY_STORAGE_KEY);
    if (raw) {
      try {
        const jwk = JSON.parse(raw);
        return await crypto.subtle.importKey("jwk", jwk, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
      } catch {
        // fall through to recreate
      }
    }
    const key = await crypto.subtle.generateKey({ name: "HMAC", hash: "SHA-256" }, true, ["sign", "verify"]);
    const jwk = await crypto.subtle.exportKey("jwk", key);
    localStorage.setItem(KEY_STORAGE_KEY, JSON.stringify(jwk));
    return key;
  }

  async function hmacHex(key, str) {
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(str));
    return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // ----------------------------
  // Persistence
  // ----------------------------
  function save() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      actingUser: state.actingUser,
      decisions: state.decisions,
      approvalsByDecision: state.approvalsByDecision,
      auditLog: state.auditLog,
      lastHash: state.lastHash,
      lastAnchor: state.lastAnchor
    }));
  }

  function load() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return;
    try {
      const p = JSON.parse(raw);
      state.actingUser = p.actingUser ?? state.actingUser;
      state.decisions = p.decisions ?? [];
      state.approvalsByDecision = p.approvalsByDecision ?? {};
      state.auditLog = p.auditLog ?? [];
      state.lastHash = p.lastHash ?? "GENESIS";
      state.lastAnchor = p.lastAnchor ?? null;
    } catch {
      // ignore
    }
  }

  // ----------------------------
  // Audit log (tamper-evident)
  // ----------------------------
  async function logEvent(type, payload) {
    const evt = {
      id: crypto.randomUUID(),
      type,
      payload,
      actor: state.actingUser,
      at: new Date().toISOString(),
      previousHash: state.lastHash
    };

    const canonical = JSON.stringify(evt);
    const hash = await sha256Hex(canonical);
    const signature = await hmacHex(state.hmacKey, hash); // sign the hash

    const record = Object.freeze({ ...evt, hash, signature });
    state.auditLog.push(record);
    state.lastHash = hash;

    save();
    renderAudit();
    await verifyIntegrity(); // keep status updated
  }

  async function verifyIntegrity() {
    // Recompute chain + verify signatures
    let prev = "GENESIS";
    for (const record of state.auditLog) {
      const { hash, signature, ...evt } = record;

      // ensure chain continuity
      if (evt.previousHash !== prev) return setIntegrity(false);

      const canonical = JSON.stringify(evt);
      const rehash = await sha256Hex(canonical);
      if (rehash !== hash) return setIntegrity(false);

      const expectedSig = await hmacHex(state.hmacKey, hash);
      if (expectedSig !== signature) return setIntegrity(false);

      prev = hash;
    }

    // Show sealed/anchored indicator if we have an anchor
    setIntegrity(true);
  }

  function setIntegrity(valid) {
    if (!valid) {
      dom.integrityText.textContent = "COMPROMISED";
      dom.integrityDot.style.background = "var(--bad)";
      dom.integrityDot.style.boxShadow = "0 0 0 4px rgba(185,28,28,.22)";
      return false;
    }

    // If we have an anchor, display as “ANCHORED”
    if (state.lastAnchor) {
      dom.integrityText.textContent = "ANCHORED (tamper-evident)";
      dom.integrityDot.style.background = "var(--good)";
      dom.integrityDot.style.boxShadow = "0 0 0 4px rgba(21,128,61,.22)";
      return true;
    }

    dom.integrityText.textContent = "VALID (tamper-evident)";
    dom.integrityDot.style.background = "var(--warn)";
    dom.integrityDot.style.boxShadow = "0 0 0 4px rgba(180,83,9,.22)";
    return true;
  }

  function approvalsFor(decisionId) {
    state.approvalsByDecision[decisionId] ??= [];
    return state.approvalsByDecision[decisionId];
  }

  function isApproved(decision) {
    const rule = riskRules[decision.risk];
    const approvals = approvalsFor(decision.id);
    return approvals.length >= rule.approvalsRequired;
  }

  function isPending(decision) {
    const rule = riskRules[decision.risk];
    if (!rule.allowApprove) return true; // critical = escalated
    return !isApproved(decision);
  }

  // ----------------------------
  // Evidence readiness (simple and useful)
  // ----------------------------
  function decisionCompleteness(d) {
    const required = [
      d.id, d.date, d.statement, d.context,
      d.aiSystem, d.aiInfluence, d.owner,
      d.risk, d.oversight, d.riskAccepted
    ];
    let score = required.filter(Boolean).length / required.length;

    if ((d.influenceNotes || "").trim().length > 0) score += 0.08;
    if ((d.safeguards || []).length > 0) score += 0.08;
    if (d.riskAccepted === "Yes" && (d.riskAcceptanceNotes || "").trim().length > 0) score += 0.08;

    return Math.min(1, score);
  }

  function overallEvidenceReadiness() {
    if (state.decisions.length === 0) return 0;
    const avg = state.decisions.map(decisionCompleteness).reduce((a, b) => a + b, 0) / state.decisions.length;
    return Math.round(avg * 100);
  }

  // ----------------------------
  // ISO coverage heuristic (evidence-support view)
  // ----------------------------
  function isoStatus() {
    // covered/partial/missing based on presence of evidence in records
    const any = state.decisions.length > 0;

    const hasContext = state.decisions.some(d => (d.context || "").trim().length > 0);
    const hasLeadership = state.decisions.some(d => (d.owner || "").trim().length > 0) &&
                          Object.values(state.approvalsByDecision).some(arr => (arr || []).length > 0);
    const hasPlanning = state.decisions.some(d => !!d.risk && !!d.oversight);
    const hasSupport = state.decisions.some(d => (d.safeguards || []).length > 0);
    const hasOperation = any;
    const hasPerformance = state.auditLog.length > 0;
    const hasImprovement = state.auditLog.some(e => e.type === "DECISION_ESCALATED" || e.type === "AUDIT_ANCHOR_EXPORTED");

    return {
      "Clause 4": hasContext ? "covered" : "missing",
      "Clause 5": hasLeadership ? "covered" : "partial",
      "Clause 6": hasPlanning ? "covered" : "missing",
      "Clause 7": hasSupport ? "partial" : "missing",
      "Clause 8": hasOperation ? "covered" : "missing",
      "Clause 9": hasPerformance ? "covered" : "missing",
      "Clause 10": hasImprovement ? "partial" : "missing"
    };
  }

  // ----------------------------
  // Rendering
  // ----------------------------
  function esc(s) {
    return String(s ?? "")
      .replaceAll("&","&amp;")
      .replaceAll("<","&lt;")
      .replaceAll(">","&gt;")
      .replaceAll('"',"&quot;")
      .replaceAll("'","&#039;");
  }

  function short(s, n=120) {
    if (!s) return "";
    return s.length > n ? s.slice(0, n-1) + "…" : s;
  }

  function renderExec() {
    dom.mTotal.textContent = String(state.decisions.length);

    const highPending = state.decisions.filter(d => (d.risk === "High" || d.risk === "Critical") && isPending(d)).length;
    dom.mHighPending.textContent = String(highPending);

    const acceptedCount = state.decisions.filter(d => d.riskAccepted === "Yes").length;
    dom.mAcceptance.textContent = state.decisions.length ? `${Math.round((acceptedCount / state.decisions.length) * 100)}%` : "0%";

    dom.mEvidence.textContent = `${overallEvidenceReadiness()}%`;
  }

  function renderRegister() {
    const q = (dom.search.value || "").toLowerCase().trim();
    const rf = dom.riskFilter.value;

    const rows = state.decisions.filter(d => {
      const matchesRisk = rf === "All" ? true : d.risk === rf;
      const hay = [d.id, d.owner, d.aiSystem, d.statement, d.context].join(" ").toLowerCase();
      const matchesQ = q ? hay.includes(q) : true;
      return matchesRisk && matchesQ;
    });

    dom.registerBody.innerHTML = "";

    for (const d of rows) {
      const approvals = approvalsFor(d.id);
      const rule = riskRules[d.risk];
      const approved = isApproved(d);

      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><strong>${esc(d.id)}</strong></td>
        <td class="small">${esc(d.date)}</td>
        <td class="small">
          <div><strong>${esc(d.statement)}</strong></div>
          <div class="muted">${esc(short(d.context))}</div>
        </td>
        <td class="small">
          <div><strong>${esc(d.aiSystem)}</strong></div>
          <div class="muted">${esc(d.aiInfluence)}</div>
        </td>
        <td><span class="badge ${esc(d.risk)}">${esc(d.risk)}</span></td>
        <td class="small">${esc(d.owner)}</td>
        <td class="small">
          <div><strong>${approvals.length}</strong> / ${rule.approvalsRequired === Infinity ? "Escalate" : rule.approvalsRequired}</div>
          <div class="muted">${rule.allowApprove ? (approved ? "Approved" : "Pending") : "Escalated"}</div>
        </td>
        <td></td>
      `;

      const actionTd = tr.querySelector("td:last-child");

      const viewBtn = document.createElement("button");
      viewBtn.className = "btn btn-ghost";
      viewBtn.textContent = "View";
      viewBtn.addEventListener("click", () => showDecision(d));
      actionTd.appendChild(viewBtn);

      if (!rule.allowApprove) {
        const escBtn = document.createElement("button");
        escBtn.className = "btn btn-ghost";
        escBtn.style.marginLeft = "8px";
        escBtn.textContent = "Escalation note";
        escBtn.addEventListener("click", () => {
          alert("Critical risk: approval is blocked here. Use your board/committee process and attach formal minutes in your records system.");
        });
        actionTd.appendChild(escBtn);
      } else if (!approved) {
        const approveBtn = document.createElement("button");
        approveBtn.className = "btn";
        approveBtn.style.marginLeft = "8px";
        approveBtn.textContent = "Approve";
        approveBtn.addEventListener("click", () => openApprovalModal(d.id));
        actionTd.appendChild(approveBtn);
      }

      dom.registerBody.appendChild(tr);
    }
  }

  function renderAudit() {
    dom.auditPre.textContent = JSON.stringify(state.auditLog, null, 2);
  }

  function renderISO() {
    const status = isoStatus();
    dom.isoGrid.innerHTML = "";

    for (const clause of isoClauses) {
      const s = status[clause.id] || "missing";
      const tile = document.createElement("div");
      tile.className = `iso-tile ${s === "covered" ? "iso-covered" : (s === "partial" ? "iso-partial" : "iso-missing")}`;
      tile.innerHTML = `<div style="font-size:1.05rem">${esc(clause.id)}</div><div style="opacity:.9;font-weight:800">${esc(clause.title)}</div>`;
      tile.addEventListener("click", () => renderClauseDetail(clause, s));
      dom.isoGrid.appendChild(tile);
    }
  }

  function renderClauseDetail(clause, status) {
    dom.isoTitle.textContent = `${clause.id}: ${clause.title} (${status.toUpperCase()})`;
    dom.isoDesc.textContent = clause.desc;

    dom.isoEvidence.innerHTML = "";
    clause.evidence.forEach(e => {
      const li = document.createElement("li");
      li.textContent = e;
      dom.isoEvidence.appendChild(li);
    });

    dom.isoMitigations.innerHTML = "";
    clause.mitigations.forEach(m => {
      const li = document.createElement("li");
      li.textContent = m;
      dom.isoMitigations.appendChild(li);
    });
  }

  function showDecision(d) {
    const approvals = approvalsFor(d.id);
    const safeguards = (d.safeguards || []).map(x => `- ${x}`).join("\n") || "(none)";
    const approvalsTxt = approvals.length
      ? approvals.map(a => `- ${a.user} @ ${a.at}\n  Rationale: ${a.rationale}`).join("\n")
      : "(none)";

    alert(
`Decision ID: ${d.id}
Date: ${d.date}
Owner: ${d.owner}

Decision statement:
${d.statement}

Context:
${d.context}

AI system:
${d.aiSystem}
AI influence:
${d.aiInfluence}
Influence notes:
${d.influenceNotes || "(none)"}

Declared oversight:
${d.oversight}

Risk:
${d.risk}
Risk acceptance recorded:
${d.riskAccepted}
Risk acceptance notes:
${d.riskAcceptanceNotes || "(none)"}

Safeguards:
${safeguards}

Approvals:
${approvalsTxt}`
    );
  }

  function renderAll() {
    renderExec();
    renderRegister();
    renderAudit();
    renderISO();
    save();
  }

  // ----------------------------
  // Modal
  // ----------------------------
  function openApprovalModal(decisionId) {
    pendingApprovalDecisionId = decisionId;
    dom.approvalRationale.value = "";
    dom.modalBackdrop.style.display = "flex";
    dom.modalBackdrop.setAttribute("aria-hidden", "false");
    dom.approvalRationale.focus();
  }

  function closeApprovalModal() {
    pendingApprovalDecisionId = null;
    dom.modalBackdrop.style.display = "none";
    dom.modalBackdrop.setAttribute("aria-hidden", "true");
  }

  // ----------------------------
  // Exports
  // ----------------------------
  async function exportAnchor() {
    // Anchor = signed hash of (lastHash + audit length + timestamp)
    const lastHash = state.lastHash;
    const auditLen = state.auditLog.length;
    const at = new Date().toISOString();
    const anchorPayload = { lastHash, auditLen, at };

    const anchorHash = await sha256Hex(JSON.stringify(anchorPayload));
    const anchorSig = await hmacHex(state.hmacKey, anchorHash);

    const anchor = { ...anchorPayload, anchorHash, anchorSig };

    state.lastAnchor = anchor;

    // Keep history for board packs (optional)
    const historyRaw = localStorage.getItem(ANCHOR_HISTORY_KEY);
    const history = historyRaw ? (JSON.parse(historyRaw) || []) : [];
    history.unshift(anchor);
    localStorage.setItem(ANCHOR_HISTORY_KEY, JSON.stringify(history.slice(0, 25)));

    await logEvent("AUDIT_ANCHOR_EXPORTED", { anchorHash, auditLen });

    downloadJSON(anchor, "luminar-audit-anchor.json");
  }

  function exportAuditPack() {
    const pack = {
      meta: {
        product: "Luminar AI — Decision Governance Dashboard",
        exportedAt: new Date().toISOString(),
        boundary: "Governs decisions, not technology. Not an audit or certification.",
        trustNote: "Static deployments are tamper-evident. Store the anchor in an independent records system to strengthen custody."
      },
      anchor: state.lastAnchor,
      decisions: state.decisions,
      approvalsByDecision: state.approvalsByDecision,
      auditLog: state.auditLog,
      isoStatus: isoStatus(),
      evidenceReadinessPercent: overallEvidenceReadiness()
    };

    downloadJSON(pack, "luminar-decision-governance-audit-pack.json");
  }

  function exportBoardBriefing() {
    const now = new Date().toISOString();
    const total = state.decisions.length;
    const pendingHighCritical = state.decisions.filter(d => (d.risk === "High" || d.risk === "Critical") && isPending(d)).length;
    const acceptedCount = state.decisions.filter(d => d.riskAccepted === "Yes").length;
    const acceptanceRate = total ? Math.round((acceptedCount / total) * 100) : 0;
    const evidence = overallEvidenceReadiness();
    const iso = isoStatus();
    const anchor = state.lastAnchor;

    // risk counts
    const counts = { Low: 0, Medium: 0, High: 0, Critical: 0 };
    state.decisions.forEach(d => { counts[d.risk] = (counts[d.risk] || 0) + 1; });

    const top = state.decisions.slice(0, 6).map(d => `
      <tr>
        <td><strong>${esc(d.id)}</strong><br><span class="muted">${esc(d.date)}</span></td>
        <td>${esc(d.statement)}<br><span class="muted">${esc(short(d.context, 140))}</span></td>
        <td>${esc(d.aiSystem)}<br><span class="muted">${esc(d.aiInfluence)}</span></td>
        <td><span class="badge ${esc(d.risk)}">${esc(d.risk)}</span></td>
        <td>${esc(d.owner)}<br><span class="muted">${esc(d.oversight)}</span></td>
        <td>${esc(d.riskAccepted)}<br><span class="muted">${esc(short(d.riskAcceptanceNotes, 120) || "")}</span></td>
      </tr>
    `).join("");

    const isoRows = Object.entries(iso).map(([c, s]) => `
      <tr><td><strong>${esc(c)}</strong></td><td>${esc(s.toUpperCase())}</td></tr>
    `).join("");

    const anchorBlock = anchor
      ? `<p><strong>Audit Anchor:</strong> ${esc(anchor.anchorHash)}<br><span class="muted">Exported: ${esc(anchor.at)} • Entries: ${esc(anchor.auditLen)} • Last event hash: ${esc(anchor.lastHash)}</span></p>`
      : `<p><strong>Audit Anchor:</strong> <span class="muted">Not exported yet. Export an anchor for records custody.</span></p>`;

    const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Board Briefing — AI Decision Governance</title>
<style>
  body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif;margin:28px;color:#0b1220}
  h1{margin:0 0 6px}
  .muted{color:#475569}
  .card{border:1px solid #d8dee9;border-radius:14px;padding:14px;margin-top:14px}
  .grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
  .metric{font-size:1.8rem;font-weight:900}
  table{width:100%;border-collapse:collapse;margin-top:10px}
  th,td{border-bottom:1px solid #d8dee9;padding:10px;vertical-align:top;text-align:left}
  th{background:#f1f5f9}
  .badge{display:inline-flex;padding:4px 10px;border-radius:999px;font-weight:900;color:#fff}
  .badge.Low{background:#15803d}.badge.Medium{background:#1d4ed8}.badge.High{background:#b45309}.badge.Critical{background:#b91c1c}
  .hr{height:1px;background:#e2e8f0;margin:16px 0}
  @media print { .no-print{display:none} body{margin:0} }
</style>
</head>
<body>

<h1>Board Briefing — AI Decision Governance</h1>
<p class="muted">Generated: ${esc(now)} • Tool: Luminar AI Decision Governance Dashboard</p>

<div class="card">
  <h2>Purpose and boundary</h2>
  <p>
    This briefing summarises AI-influenced decisions recorded to ensure <strong>accountability, oversight, and risk acceptance</strong>
    were deliberate and documented at the time decisions were made. It governs decisions, not technology.
  </p>
  <p class="muted">
    This is not an audit, certification, legal opinion, or technical assessment.
  </p>
</div>

<div class="card">
  <h2>Governance snapshot</h2>
  <div class="grid">
    <div><div class="muted">Decisions recorded</div><div class="metric">${total}</div></div>
    <div><div class="muted">Pending High/Critical</div><div class="metric">${pendingHighCritical}</div></div>
    <div><div class="muted">Risk acceptance recorded</div><div class="metric">${acceptanceRate}%</div></div>
    <div><div class="muted">Evidence readiness</div><div class="metric">${evidence}%</div></div>
  </div>
  <div class="hr"></div>
  <p><strong>Risk distribution:</strong>
    Low ${counts.Low} • Medium ${counts.Medium} • High ${counts.High} • Critical ${counts.Critical}
  </p>
</div>

<div class="card">
  <h2>Integrity and custody</h2>
  ${anchorBlock}
  <p class="muted">
    Static deployments are tamper-evident. Strengthen custody by storing the anchor and export pack in an independent records system (board portal, DMS, records retention).
  </p>
</div>

<div class="card">
  <h2>Most recent decisions (top ${Math.min(6, total)})</h2>
  <table>
    <thead>
      <tr>
        <th>ID / Date</th>
        <th>Decision</th>
        <th>AI use</th>
        <th>Risk</th>
        <th>Owner / Oversight</th>
        <th>Risk acceptance</th>
      </tr>
    </thead>
    <tbody>
      ${top || `<tr><td colspan="6" class="muted">No decisions recorded.</td></tr>`}
    </tbody>
  </table>
</div>

<div class="card">
  <h2>ISO/IEC 42001 evidence-support status (Clauses 4–10)</h2>
  <table>
    <thead><tr><th>Clause</th><th>Status</th></tr></thead>
    <tbody>${isoRows}</tbody>
  </table>
  <p class="muted">
    Status reflects evidence presence in records, not certification. Use the dashboard’s ISO heat map for mitigation guidance.
  </p>
</div>

<p class="muted no-print">Tip: Print to PDF for board packages.</p>

</body>
</html>`;

    downloadText(html, "luminar-board-briefing.html", "text/html");
  }

  function downloadJSON(obj, filename) {
    downloadText(JSON.stringify(obj, null, 2), filename, "application/json");
  }

  function downloadText(text, filename, type) {
    const blob = new Blob([text], { type });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    a.click();
  }

  // ----------------------------
  // Events / Wiring
  // ----------------------------
  function setDefaultDate() {
    const d = new Date();
    const yyyy = d.getFullYear();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    document.getElementById("dDate").value = `${yyyy}-${mm}-${dd}`;
  }

  function getSafeguards() {
    return Array.from(document.querySelectorAll(".sg:checked")).map(x => x.value);
  }

  dom.decisionForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const id = $("dId").value.trim();
    if (!id) return;

    if (state.decisions.some(d => d.id === id)) {
      alert("That Decision ID already exists. Use a new ID.");
      return;
    }

    const decision = {
      id,
      date: $("dDate").value,
      statement: $("dStatement").value.trim(),
      context: $("dContext").value.trim(),
      aiSystem: $("dAiSystem").value.trim(),
      aiInfluence: $("dInfluence").value,
      influenceNotes: $("dInfluenceNotes").value.trim(),
      owner: $("dOwner").value.trim(),
      risk: $("dRisk").value,
      oversight: $("dOversight").value,
      riskAccepted: $("dAcceptance").value,
      riskAcceptanceNotes: $("dAcceptanceNotes").value.trim(),
      safeguards: getSafeguards(),
      notes: $("dNotes").value.trim()
    };

    state.decisions.unshift(decision);

    await logEvent("DECISION_RECORDED", {
      decisionId: decision.id,
      risk: decision.risk,
      owner: decision.owner,
      aiSystem: decision.aiSystem,
      aiInfluence: decision.aiInfluence,
      oversight: decision.oversight,
      riskAccepted: decision.riskAccepted,
      safeguardsCount: decision.safeguards.length
    });

    if (!riskRules[decision.risk].allowApprove) {
      await logEvent("DECISION_ESCALATED", {
        decisionId: decision.id,
        reason: "Critical risk requires board/committee process outside tool approvals"
      });
    }

    dom.decisionForm.reset();
    setDefaultDate();
    renderAll();
    alert("Decision added to the register.");
  });

  dom.btnReset.addEventListener("click", () => {
    dom.decisionForm.reset();
    setDefaultDate();
  });

  dom.actingUser.addEventListener("change", async (e) => {
    state.actingUser = e.target.value;
    await logEvent("USER_SWITCHED", { user: state.actingUser });
    save();
  });

  dom.search.addEventListener("input", renderRegister);
  dom.riskFilter.addEventListener("change", renderRegister);

  // Tabs
  document.querySelectorAll(".tab").forEach(btn => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      document.getElementById(btn.dataset.tab).classList.add("active");
    });
  });

  dom.btnCopyAudit.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(state.auditLog, null, 2));
      alert("Audit JSON copied.");
    } catch {
      alert("Copy failed (browser permissions).");
    }
  });

  dom.btnVerify.addEventListener("click", async () => {
    const ok = await verifyIntegrity();
    if (ok !== false) alert("Integrity check complete.");
  });

  dom.btnClear.addEventListener("click", async () => {
    if (!confirm("Clear stored demo data for this dashboard?")) return;
    localStorage.removeItem(STORAGE_KEY);
    state.decisions = [];
    state.approvalsByDecision = {};
    state.auditLog = [];
    state.lastHash = "GENESIS";
    state.lastAnchor = null;
    save();
    await logEvent("SYSTEM_RESET", { note: "User cleared demo data." });
    renderAll();
  });

  dom.btnExportAudit.addEventListener("click", async () => {
    // Encourage anchor
    if (!state.lastAnchor && state.auditLog.length) {
      const doAnchor = confirm("No anchor exported yet. Export anchor first for custody?");
      if (doAnchor) await exportAnchor();
    }
    exportAuditPack();
  });

  dom.btnExportBoard.addEventListener("click", async () => {
    if (!state.lastAnchor && state.auditLog.length) {
      const doAnchor = confirm("No anchor exported yet. Export anchor first for custody?");
      if (doAnchor) await exportAnchor();
    }
    exportBoardBriefing();
  });

  dom.btnSeed.addEventListener("click", async () => {
    if (state.decisions.length && !confirm("Load demo examples and keep existing decisions?")) return;

    const examples = [
      {
        id: "DEC-2026-001",
        date: todayISO(),
        statement: "Approve a high-risk eligibility decision using AI-assisted scoring, with dual human approval.",
        context: "Front-line staff needed consistency under time pressure; impacts include eligibility outcomes and public trust.",
        aiSystem: "Eligibility Scoring ML",
        aiInfluence: "Recommendatory",
        influenceNotes: "Model output used as input; manual verification completed; decision recorded before outcomes.",
        owner: "Director, Community Services",
        risk: "High",
        oversight: "Two-person approval",
        riskAccepted: "Yes",
        riskAcceptanceNotes: "Residual error risk accepted by decision owner; dual approval and appeal path documented.",
        safeguards: ["Human review before action", "Second approver / separation of duties", "Source verification / cross-checking", "Escalation path defined"],
        notes: ""
      },
      {
        id: "DEC-2026-002",
        date: todayISO(),
        statement: "Use an LLM to draft a shortlist for interviews, with human final selection.",
        context: "HR capacity constraints for a high-volume posting; equity and privacy considered.",
        aiSystem: "HR LLM Assistant",
        aiInfluence: "Informative",
        influenceNotes: "LLM used for summarisation; no automated ranking acted on without review.",
        owner: "Manager, HR",
        risk: "Medium",
        oversight: "Manager review",
        riskAccepted: "No",
        riskAcceptanceNotes: "",
        safeguards: ["Human review before action", "Bias/impact consideration documented", "Privacy / confidentiality controls"],
        notes: ""
      },
      {
        id: "DEC-2026-003",
        date: todayISO(),
        statement: "Critical service decision informed by AI forecasting — escalated to board/council process.",
        context: "Service continuity decision with significant public impact; requires formal oversight outside tool approvals.",
        aiSystem: "Demand Forecasting Model",
        aiInfluence: "Determinative",
        influenceNotes: "Forecasting materially shaped options; independent review required.",
        owner: "CAO",
        risk: "Critical",
        oversight: "Board/Council oversight",
        riskAccepted: "No",
        riskAcceptanceNotes: "",
        safeguards: ["Second approver / separation of duties", "Source verification / cross-checking", "Escalation path defined"],
        notes: ""
      }
    ];

    for (const d of examples) {
      if (state.decisions.some(x => x.id === d.id)) continue;
      state.decisions.unshift(d);
      await logEvent("DECISION_RECORDED", {
        decisionId: d.id,
        risk: d.risk,
        owner: d.owner,
        aiSystem: d.aiSystem,
        aiInfluence: d.aiInfluence,
        oversight: d.oversight,
        riskAccepted: d.riskAccepted,
        safeguardsCount: d.safeguards.length
      });
      if (!riskRules[d.risk].allowApprove) {
        await logEvent("DECISION_ESCALATED", { decisionId: d.id, reason: "Critical risk requires formal board/council process" });
      }
    }

    renderAll();
    // Export anchor immediately for demo credibility
    await exportAnchor();
  });

  // Approval modal actions
  dom.btnCancelModal.addEventListener("click", closeApprovalModal);

  dom.btnConfirmModal.addEventListener("click", async () => {
    const rationale = (dom.approvalRationale.value || "").trim();
    if (!pendingApprovalDecisionId) return;
    if (!rationale) return alert("Rationale is required.");

    const decision = state.decisions.find(d => d.id === pendingApprovalDecisionId);
    if (!decision) return;

    const rule = riskRules[decision.risk];
    if (!rule.allowApprove) {
      alert("Critical risk is escalated. Approval is not performed in this tool.");
      closeApprovalModal();
      return;
    }

    const approvals = approvalsFor(decision.id);

    // enforce distinct approvers
    if (approvals.some(a => a.user === state.actingUser)) {
      alert("You already approved this decision. Switch acting user for another approver.");
      return;
    }

    approvals.push({ user: state.actingUser, rationale, at: new Date().toISOString() });

    await logEvent(approvals.length === 1 ? "DECISION_APPROVAL_STAGE_1" : "DECISION_APPROVAL_STAGE_2", {
      decisionId: decision.id,
      risk: decision.risk,
      rationale
    });

    if (isApproved(decision)) {
      await logEvent("DECISION_FULLY_APPROVED", {
        decisionId: decision.id,
        risk: decision.risk,
        approvals: approvalsFor(decision.id)
      });
    }

    save();
    renderAll();
    closeApprovalModal();
  });

  // In-table approve buttons trigger modal
  function wireApproveButtons() {
    // handled in renderRegister via listeners
  }

  // Register approve action via modal trigger
  window.openApprovalModal = openApprovalModal;

  // For approve buttons created in renderRegister:
  function openApprovalModalFromRegister(decisionId) {
    openApprovalModal(decisionId);
  }

  // override in renderRegister
  const _openApprovalModal = openApprovalModal;
  openApprovalModal = _openApprovalModal;

  // ----------------------------
  // Utility
  // ----------------------------
  function todayISO() {
    const d = new Date();
    return `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}-${String(d.getDate()).padStart(2,"0")}`;
  }

  // ----------------------------
  // Init
  // ----------------------------
  (async function init() {
    state.hmacKey = await getOrCreateHmacKey();
    load();

    dom.actingUser.value = state.actingUser;
    setDefaultDate();

    if (state.auditLog.length === 0) {
      await logEvent("SYSTEM_STARTED", { version: "luminar-v2-rebuild" });
    } else {
      await verifyIntegrity();
    }

    renderAll();
    renderClauseDetail(isoClauses[0], isoStatus()[isoClauses[0].id] || "missing");

    // Add a one-click anchor export via existing buttons
    // (Anchor is exported on demo seed; also encouraged before exports)
  })();

  // Expose approval modal open for table buttons
  function openApprovalModal(decisionId) {
    pendingApprovalDecisionId = decisionId;
    dom.approvalRationale.value = "";
    dom.modalBackdrop.style.display = "flex";
    dom.modalBackdrop.setAttribute("aria-hidden", "false");
    dom.approvalRationale.focus();
  }

  // Patch renderRegister to use modal open
  const originalRenderRegister = renderRegister;
  renderRegister = function() {
    originalRenderRegister();

    // add approve click handlers for dynamically created buttons
    // already attached in originalRenderRegister via addEventListener, so no work here.
  };

  // Replace approve handler in renderRegister (already calls openApprovalModal)
  // End
});