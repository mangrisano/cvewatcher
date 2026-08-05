(function () {
    const TOKEN_KEY = "cvewatcher_token";
    const EMAIL_KEY = "cvewatcher_email";
    const THEME_KEY = "cvewatcher_theme";

    const $ = (id) => document.getElementById(id);
    const token = () => localStorage.getItem(TOKEN_KEY);
    const authHeaders = () => ({ Authorization: "Bearer " + token() });

    const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
    const SEV_CLASS = {
        CRITICAL: "sev-critical",
        HIGH: "sev-high",
        MEDIUM: "sev-medium",
        LOW: "sev-low",
        UNKNOWN: "sev-unknown",
    };
    const SEV_VAR = {
        CRITICAL: "--sev-critical",
        HIGH: "--sev-high",
        MEDIUM: "--sev-medium",
        LOW: "--sev-low",
        UNKNOWN: "--text-muted",
    };
    const STATUS_LABELS = {
        open: "Open",
        acknowledged: "Acknowledged",
        fixed: "Fixed",
        false_positive: "False positive",
        accepted_risk: "Accepted risk",
    };
    const SUPPRESSED = new Set(["fixed", "false_positive", "accepted_risk"]);
    const EDIT_SVG =
        '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg>';
    const TRASH_SVG =
        '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg>';

    function esc(s) {
        return String(s).replace(
            /[&<>"']/g,
            (c) =>
                ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
        );
    }

    // --- Theme -------------------------------------------------------------
    function applyTheme(theme) {
        document.documentElement.setAttribute("data-theme", theme);
        document
            .querySelectorAll("#themeSegment [data-theme-set]")
            .forEach((b) => b.classList.toggle("is-active", b.dataset.themeSet === theme));
    }
    function setTheme(theme) {
        localStorage.setItem(THEME_KEY, theme);
        applyTheme(theme);
    }

    // --- Auth --------------------------------------------------------------
    async function login(event) {
        event.preventDefault();
        $("loginError").classList.add("hidden");
        const email = $("loginEmail").value;
        const password = $("loginPassword").value;
        try {
            const res = await fetch("/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password }),
            });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.detail || "Login failed");
            }
            const data = await res.json();
            localStorage.setItem(TOKEN_KEY, data.access_token);
            localStorage.setItem(EMAIL_KEY, data.user ? data.user.email : email);
            enterApp();
        } catch (err) {
            $("loginError").textContent = err.message;
            $("loginError").classList.remove("hidden");
        }
        return false;
    }

    async function logout() {
        try {
            await fetch("/auth/logout", { method: "POST", headers: authHeaders() });
        } catch (_) {
            /* ignore */
        }
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(EMAIL_KEY);
        $("appView").classList.add("hidden");
        $("loginView").classList.remove("hidden");
    }

    function enterApp() {
        $("loginView").classList.add("hidden");
        $("appView").classList.remove("hidden");
        const email = localStorage.getItem(EMAIL_KEY) || "";
        $("userEmail").textContent = email;
        $("userEmailFull").textContent = email;
        $("userAvatar").textContent = initials(email);
        showSection("overview");
    }

    function initials(email) {
        const name = (email.split("@")[0] || "?").replace(/[^a-zA-Z]/g, "");
        return (name.charAt(0) || "?").toUpperCase();
    }

    function toggleUserMenu(event) {
        event.stopPropagation();
        $("userMenu").classList.toggle("hidden");
    }

    // --- Section routing ---------------------------------------------------
    function showSection(name) {
        document
            .querySelectorAll(".nav__item")
            .forEach((n) => n.classList.toggle("is-active", n.dataset.section === name));
        document
            .querySelectorAll(".section")
            .forEach((s) => s.classList.add("hidden"));
        $("section-" + name).classList.remove("hidden");
        $("sectionTitle").textContent = name.charAt(0).toUpperCase() + name.slice(1);
        if (name === "overview") loadOverview();
        else if (name === "assets") loadAssets();
        else if (name === "findings") loadFindings();
    }

    // --- Overview ----------------------------------------------------------
    async function loadOverview() {
        $("overviewLoading").classList.remove("hidden");
        $("overviewGrid").classList.add("hidden");
        let summary = { total: 0, kev: 0, by_severity: {}, by_status: {} };
        let assetsCount = 0;
        try {
            const [sRes, aRes] = await Promise.all([
                fetch("/findings?include_suppressed=false", { headers: authHeaders() }),
                fetch("/assets/", { headers: authHeaders() }),
            ]);
            if (sRes.status === 401 || aRes.status === 401) {
                logout();
                return;
            }
            if (sRes.ok) summary = await sRes.json();
            if (aRes.ok) assetsCount = (await aRes.json()).length;
        } catch (_) {
            /* best effort */
        }
        renderOverview(summary, assetsCount);
        $("overviewLoading").classList.add("hidden");
        $("overviewGrid").classList.remove("hidden");
    }

    function renderOverview(summary, assetsCount) {
        const bySev = summary.by_severity || {};
        const byStatus = summary.by_status || {};
        $("statFindings").textContent = summary.total || 0;
        $("statKev").textContent = summary.kev || 0;
        $("statCritHigh").textContent = (bySev.CRITICAL || 0) + (bySev.HIGH || 0);
        $("statAssets").textContent = assetsCount;

        const sevTotal = Object.values(bySev).reduce((a, b) => a + b, 0) || 1;
        $("sevBars").innerHTML =
            SEV_ORDER.filter((k) => bySev[k])
                .map((k) => {
                    const pct = Math.round((bySev[k] / sevTotal) * 100);
                    return `<div class="bar-row">
                        <span class="bar-row__label"><span class="badge-sev ${SEV_CLASS[k]}">${k}</span></span>
                        <span class="bar"><span class="bar__fill" style="width:${pct}%;background:var(${SEV_VAR[k]})"></span></span>
                        <span class="bar-row__count">${bySev[k]}</span>
                    </div>`;
                })
                .join("") || '<span class="muted">No findings</span>';

        $("statusChips").innerHTML =
            Object.entries(byStatus)
                .map(([k, v]) => `<span class="chip">${k}: ${v}</span>`)
                .join("") || '<span class="muted">No findings</span>';
    }

    // --- Assets ------------------------------------------------------------
    let assets = [];

    async function loadAssets() {
        $("assetsLoading").classList.remove("hidden");
        $("assetsTableWrap").classList.add("hidden");
        $("assetsEmpty").classList.add("hidden");
        const res = await fetch("/assets/", { headers: authHeaders() });
        if (res.status === 401) {
            logout();
            return;
        }
        assets = res.ok ? await res.json() : [];
        $("assetsLoading").classList.add("hidden");
        renderAssets();
    }

    function renderAssets() {
        const body = $("assetsBody");
        if (!assets.length) {
            $("assetsEmpty").classList.remove("hidden");
            $("assetsTableWrap").classList.add("hidden");
            return;
        }
        const q = ($("assetFilter").value || "").toLowerCase();
        const list = assets.filter(
            (a) =>
                !q ||
                (a.name || "").toLowerCase().includes(q) ||
                (a.version || "").toLowerCase().includes(q)
        );
        $("assetsEmpty").classList.add("hidden");
        $("assetsTableWrap").classList.remove("hidden");
        body.innerHTML = list
            .map((a) => {
                const eco = a.ecosystem
                    ? `<span class="pill pill--eco">${esc(a.ecosystem)}</span>`
                    : '<span class="dash">\u2014</span>';
                const match = a.cpe
                    ? `<span class="pill pill--cpe" title="${esc(a.cpe)}">CPE</span>`
                    : '<span class="pill pill--cpe">keyword</span>';
                return `<tr>
                    <td class="mono">${esc(a.name)}</td>
                    <td>${a.version ? esc(a.version) : '<span class="dash">\u2014</span>'}</td>
                    <td>${eco}</td>
                    <td>${match}</td>
                    <td class="cell-summary">${a.description ? esc(a.description) : '<span class="dash">\u2014</span>'}</td>
                    <td><div class="row-actions">
                        <button class="icon-btn" data-edit="${esc(a.id)}" title="Edit">${EDIT_SVG}</button>
                        <button class="icon-btn icon-btn--danger" data-del="${esc(a.id)}" title="Delete">${TRASH_SVG}</button>
                    </div></td>
                </tr>`;
            })
            .join("");
        body.querySelectorAll("[data-edit]").forEach((b) => {
            b.onclick = () => openAssetModal(b.dataset.edit);
        });
        body.querySelectorAll("[data-del]").forEach((b) => {
            b.onclick = () => deleteAsset(b.dataset.del);
        });
    }

    function openAssetModal(id) {
        $("assetModalError").classList.add("hidden");
        const editing = assets.find((a) => a.id === id);
        $("assetModalTitle").textContent = editing ? "Edit asset" : "Add asset";
        $("assetId").value = editing ? editing.id : "";
        $("assetName").value = editing ? editing.name || "" : "";
        $("assetVersion").value = editing ? editing.version || "" : "";
        $("assetEcosystem").value = editing ? editing.ecosystem || "" : "";
        $("assetCpe").value = editing ? editing.cpe || "" : "";
        $("assetDescription").value = editing ? editing.description || "" : "";
        $("assetModal").classList.remove("hidden");
    }

    function closeAssetModal() {
        $("assetModal").classList.add("hidden");
    }

    async function submitAsset(event) {
        event.preventDefault();
        $("assetModalError").classList.add("hidden");
        const id = $("assetId").value;
        const payload = {
            name: $("assetName").value,
            version: $("assetVersion").value || null,
            cpe: $("assetCpe").value || null,
            ecosystem: $("assetEcosystem").value || null,
            description: $("assetDescription").value || null,
        };
        const res = await fetch(id ? "/assets/" + id : "/assets/", {
            method: id ? "PATCH" : "POST",
            headers: { ...authHeaders(), "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        if (res.status === 401) {
            logout();
            return false;
        }
        if (!res.ok) {
            const d = await res.json().catch(() => ({}));
            $("assetModalError").textContent = d.detail || "Could not save asset";
            $("assetModalError").classList.remove("hidden");
            return false;
        }
        closeAssetModal();
        loadAssets();
        return false;
    }

    async function deleteAsset(id) {
        if (!confirm("Delete this asset?")) return;
        const res = await fetch("/assets/" + id, {
            method: "DELETE",
            headers: authHeaders(),
        });
        if (res.status === 401) {
            logout();
            return;
        }
        loadAssets();
    }

    // --- Findings ----------------------------------------------------------
    let findings = [];

    async function loadFindings() {
        $("findingsLoading").classList.remove("hidden");
        $("findingsTableWrap").classList.add("hidden");
        $("findingsEmpty").classList.add("hidden");
        const inc = $("findSuppressed").checked;
        const res = await fetch("/findings?include_suppressed=" + inc, {
            headers: authHeaders(),
        });
        if (res.status === 401) {
            logout();
            return;
        }
        const data = res.ok ? await res.json() : { findings: [] };
        findings = data.findings || [];
        $("findingsLoading").classList.add("hidden");
        renderFindings();
    }

    function renderFindings() {
        const sev = $("findSeverity").value;
        const st = $("findStatus").value;
        const incSup = $("findSuppressed").checked;
        const list = findings.filter((f) => {
            const status = f.status || "open";
            if (!incSup && SUPPRESSED.has(status)) return false;
            if (sev && (f.severity || "UNKNOWN").toUpperCase() !== sev) return false;
            if (st && status !== st) return false;
            return true;
        });
        const body = $("findingsBody");
        if (!list.length) {
            $("findingsEmpty").classList.remove("hidden");
            $("findingsTableWrap").classList.add("hidden");
            return;
        }
        $("findingsEmpty").classList.add("hidden");
        $("findingsTableWrap").classList.remove("hidden");
        body.innerHTML = list
            .map((f) => {
                const sevU = (f.severity || "UNKNOWN").toUpperCase();
                const cve = f.cve_url
                    ? `<a href="${esc(f.cve_url)}" target="_blank" rel="noopener">${esc(f.cve_id)}</a>`
                    : esc(f.cve_id);
                const asset =
                    esc(f.asset_name || "\u2014") +
                    (f.asset_version ? ` <span class="muted">v${esc(f.asset_version)}</span>` : "");
                return `<tr>
                    <td class="mono">${cve}</td>
                    <td>${asset}</td>
                    <td><span class="badge-sev ${SEV_CLASS[sevU] || "sev-unknown"}">${sevU}</span></td>
                    <td>${f.score != null ? esc(f.score) : '<span class="dash">\u2014</span>'}</td>
                    <td>${f.kev ? '<span class="kev-badge">KEV</span>' : '<span class="dash">\u2014</span>'}</td>
                    <td>${f.epss != null ? epssText(f.epss) : '<span class="dash">\u2014</span>'}</td>
                    <td>${statusSelect(f)}</td>
                    <td class="cell-summary" title="${esc(f.summary || "")}">${esc(f.summary || "")}</td>
                </tr>`;
            })
            .join("");
        body.querySelectorAll("select.status-select").forEach((sel) => {
            sel.onchange = () =>
                changeFindingStatus(sel.dataset.asset, sel.dataset.cve, sel);
        });
    }

    function statusSelect(f) {
        const cur = f.status || "open";
        const opts = Object.entries(STATUS_LABELS)
            .map(([v, l]) => `<option value="${v}" ${v === cur ? "selected" : ""}>${l}</option>`)
            .join("");
        const cls = SUPPRESSED.has(cur) ? " is-suppressed" : "";
        return `<select class="status-select${cls}" data-asset="${esc(f.asset_id)}" data-cve="${esc(f.cve_id)}">${opts}</select>`;
    }

    async function changeFindingStatus(assetId, cveId, sel) {
        if (!assetId) return;
        const status = sel.value;
        sel.disabled = true;
        const res = await fetch(
            "/assets/" + assetId + "/vulnerabilities/" + encodeURIComponent(cveId),
            {
                method: "PATCH",
                headers: { ...authHeaders(), "Content-Type": "application/json" },
                body: JSON.stringify({ status }),
            }
        );
        sel.disabled = false;
        if (res.status === 401) {
            logout();
            return;
        }
        if (!res.ok) return;
        const f = findings.find(
            (x) => String(x.asset_id) === String(assetId) && x.cve_id === cveId
        );
        if (f) f.status = status;
        renderFindings();
    }

    function epssText(epss) {
        const pct = (epss * 100).toFixed(1) + "%";
        return epss >= 0.5 ? `<span class="epss-strong">${pct}</span>` : pct;
    }

    async function exportFindings(format) {
        const inc = $("findSuppressed").checked;
        const res = await fetch(
            "/findings/export?format=" + format + "&include_suppressed=" + inc,
            { headers: authHeaders() }
        );
        if (res.status === 401) {
            logout();
            return;
        }
        if (!res.ok) {
            alert("Export failed.");
            return;
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "findings." + format;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
    }

    // --- Init --------------------------------------------------------------
    applyTheme(localStorage.getItem(THEME_KEY) || "dark");
    document.querySelectorAll(".nav__item").forEach((item) => {
        item.addEventListener("click", () => showSection(item.dataset.section));
    });
    document.querySelectorAll("#themeSegment [data-theme-set]").forEach((b) => {
        b.addEventListener("click", () => setTheme(b.dataset.themeSet));
    });
    document.addEventListener("click", (e) => {
        const menu = $("userMenu");
        if (
            menu &&
            !menu.classList.contains("hidden") &&
            !e.target.closest(".usermenu")
        ) {
            menu.classList.add("hidden");
        }
    });
    if (token()) enterApp();

    window.app = {
        login,
        logout,
        toggleUserMenu,
        showSection,
        renderAssets,
        openAssetModal,
        closeAssetModal,
        submitAsset,
        renderFindings,
        loadFindings,
        exportFindings,
    };
})();
