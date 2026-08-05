(function () {
    const TOKEN_KEY = "cvewatcher_token";
    const REFRESH_KEY = "cvewatcher_refresh_token";
    const EMAIL_KEY = "cvewatcher_email";
    const THEME_KEY = "cvewatcher_theme";

    const $ = (id) => document.getElementById(id);
    const token = () => localStorage.getItem(TOKEN_KEY);
    const refreshToken = () => localStorage.getItem(REFRESH_KEY);
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
    const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
    const SECTION_TITLES = {
        overview: "Overview",
        assets: "Assets",
        findings: "Vulnerabilities",
    };
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
    let authMode = "login";
    let refreshPromise = null;

    // Exchanges the refresh token for a new access token. Concurrent 401s
    // share a single in-flight request instead of racing separate refreshes.
    function refreshAccessToken() {
        const rt = refreshToken();
        if (!rt) return Promise.resolve(false);
        if (!refreshPromise) {
            refreshPromise = fetch("/auth/refresh", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ refresh_token: rt }),
            })
                .then(async (res) => {
                    if (!res.ok) return false;
                    const data = await res.json();
                    localStorage.setItem(TOKEN_KEY, data.access_token);
                    return true;
                })
                .catch(() => false)
                .finally(() => {
                    refreshPromise = null;
                });
        }
        return refreshPromise;
    }

    // fetch() wrapper that attaches the access token and, on a 401, tries a
    // silent refresh + one retry before giving up and logging the user out.
    async function apiFetch(url, options = {}) {
        const withAuth = () => ({
            ...options,
            headers: { ...(options.headers || {}), ...authHeaders() },
        });
        let res = await fetch(url, withAuth());
        if (res.status === 401) {
            const refreshed = await refreshAccessToken();
            res = refreshed ? await fetch(url, withAuth()) : res;
            if (res.status === 401) logout();
        }
        return res;
    }

    function setAuthMode(mode) {
        authMode = mode;
        const register = mode === "register";
        $("usernameField").classList.toggle("hidden", !register);
        $("regUsername").required = register;
        $("authSubtitle").textContent = register
            ? "Create your CVE Watcher account"
            : "Sign in to your security dashboard";
        $("authSubmit").textContent = register ? "Create account" : "Sign in";
        $("authToggleText").textContent = register
            ? "Already have an account?"
            : "Don't have an account?";
        $("authToggleLink").textContent = register ? "Sign in" : "Create one";
        $("loginError").classList.add("hidden");
        $("regUsername").value = "";
        $("loginEmail").value = "";
        $("loginPassword").value = "";
    }

    function toggleAuthMode(event) {
        event.preventDefault();
        setAuthMode(authMode === "login" ? "register" : "login");
        return false;
    }

    async function doLogin(email, password) {
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
        localStorage.setItem(REFRESH_KEY, data.refresh_token);
        localStorage.setItem(EMAIL_KEY, data.user ? data.user.email : email);
        enterApp();
    }

    async function submitAuth(event) {
        event.preventDefault();
        $("loginError").classList.add("hidden");
        const email = $("loginEmail").value;
        const password = $("loginPassword").value;
        try {
            if (authMode === "register") {
                const username = $("regUsername").value;
                const res = await fetch("/auth/register", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username, email, password }),
                });
                if (!res.ok) {
                    const data = await res.json().catch(() => ({}));
                    throw new Error(data.detail || "Registration failed");
                }
            }
            await doLogin(email, password);
        } catch (err) {
            $("loginError").textContent = err.message;
            $("loginError").classList.remove("hidden");
        }
        return false;
    }

    async function logout() {
        try {
            await fetch("/auth/logout", {
                method: "POST",
                headers: { ...authHeaders(), "Content-Type": "application/json" },
                body: JSON.stringify({ refresh_token: refreshToken() || "" }),
            });
        } catch (_) {
            /* ignore */
        }
        localStorage.removeItem(TOKEN_KEY);
        localStorage.removeItem(REFRESH_KEY);
        localStorage.removeItem(EMAIL_KEY);
        setAuthMode("login");
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
        $("sectionTitle").textContent = SECTION_TITLES[name] || name;
        if (name === "overview") loadOverview();
        else if (name === "assets") loadAssets();
        else if (name === "findings") loadFindings();
    }

    // --- Overview ----------------------------------------------------------
    async function loadOverview(force = false) {
        const btn = $("overviewRefresh");
        if (btn) btn.classList.add("is-busy");
        $("overviewLoading").classList.remove("hidden");
        $("overviewGrid").classList.add("hidden");
        let summary = { total: 0, kev: 0, by_severity: {}, by_status: {} };
        let assetsCount = 0;
        try {
            const [sRes, aRes] = await Promise.all([
                apiFetch(
                    "/findings?include_suppressed=false" + (force ? "&refresh=true" : "")
                ),
                apiFetch("/assets/"),
            ]);
            if (sRes.ok) summary = await sRes.json();
            if (aRes.ok) assetsCount = (await aRes.json()).length;
        } catch (_) {
            /* best effort */
        } finally {
            if (btn) btn.classList.remove("is-busy");
        }
        renderOverview(summary, assetsCount);
        $("overviewLoading").classList.add("hidden");
        $("overviewGrid").classList.remove("hidden");
    }

    function refreshOverview() {
        loadOverview(true);
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
                .join("") || '<span class="muted">No vulnerabilities</span>';

        $("statusChips").innerHTML =
            Object.entries(byStatus)
                .map(([k, v]) => `<span class="chip">${k}: ${v}</span>`)
                .join("") || '<span class="muted">No vulnerabilities</span>';
    }

    // --- Assets ------------------------------------------------------------
    let assets = [];

    async function loadAssets() {
        $("assetsLoading").classList.remove("hidden");
        $("assetsTableWrap").classList.add("hidden");
        $("assetsEmpty").classList.add("hidden");
        const res = await apiFetch("/assets/");
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
        const res = await apiFetch(id ? "/assets/" + id : "/assets/", {
            method: id ? "PATCH" : "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
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
        await apiFetch("/assets/" + id, { method: "DELETE" });
        loadAssets();
    }

    // --- Findings ----------------------------------------------------------
    let findings = [];

    async function loadFindings(force = false) {
        const btn = $("findRefresh");
        if (btn) btn.classList.add("is-busy");
        $("findingsLoading").classList.remove("hidden");
        $("findingsTableWrap").classList.add("hidden");
        $("findingsEmpty").classList.add("hidden");
        const inc = $("findSuppressed").checked;
        const url =
            "/findings?include_suppressed=" + inc + (force ? "&refresh=true" : "");
        let res;
        try {
            res = await apiFetch(url);
        } finally {
            if (btn) btn.classList.remove("is-busy");
        }
        const data = res.ok ? await res.json() : { findings: [] };
        findings = data.findings || [];
        $("findingsLoading").classList.add("hidden");
        renderFindings();
    }

    function refreshFindings() {
        loadFindings(true);
    }

    const findSort = { key: null, dir: "desc" };

    function findSortValue(f, key) {
        switch (key) {
            case "severity":
                return SEV_RANK[(f.severity || "UNKNOWN").toUpperCase()] ?? -1;
            case "score":
                return f.score ?? -1;
            case "epss":
                return f.epss ?? -1;
            case "kev":
                return f.kev ? 1 : 0;
            case "cve_id":
                return (f.cve_id || "").toLowerCase();
            case "asset_name":
                return (f.asset_name || "").toLowerCase();
            case "status":
                return f.status || "open";
            default:
                return 0;
        }
    }

    function sortFindingsBy(key) {
        if (findSort.key === key) {
            findSort.dir = findSort.dir === "asc" ? "desc" : "asc";
        } else {
            findSort.key = key;
            findSort.dir = ["cve_id", "asset_name", "status"].includes(key)
                ? "asc"
                : "desc";
        }
        renderFindings();
    }

    function updateSortIndicators() {
        document.querySelectorAll("#section-findings th[data-sort]").forEach((th) => {
            const arrow = th.querySelector(".th-arrow");
            if (!arrow) return;
            arrow.textContent =
                th.dataset.sort === findSort.key
                    ? findSort.dir === "asc"
                        ? " \u2191"
                        : " \u2193"
                    : "";
        });
    }

    function renderFindings() {
        const sev = $("findSeverity").value;
        const st = $("findStatus").value;
        const q = ($("findSearch").value || "").trim().toLowerCase();
        const incSup = $("findSuppressed").checked;
        let list = findings.filter((f) => {
            const status = f.status || "open";
            if (!incSup && SUPPRESSED.has(status)) return false;
            if (sev && (f.severity || "UNKNOWN").toUpperCase() !== sev) return false;
            if (st && status !== st) return false;
            if (
                q &&
                !((f.cve_id || "") + " " + (f.asset_name || "")).toLowerCase().includes(q)
            )
                return false;
            return true;
        });
        if (findSort.key) {
            const dir = findSort.dir === "asc" ? 1 : -1;
            list = list.slice().sort((a, b) => {
                const va = findSortValue(a, findSort.key);
                const vb = findSortValue(b, findSort.key);
                if (va < vb) return -dir;
                if (va > vb) return dir;
                return 0;
            });
        }
        updateSortIndicators();
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
        const res = await apiFetch(
            "/assets/" + assetId + "/vulnerabilities/" + encodeURIComponent(cveId),
            {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ status }),
            }
        );
        sel.disabled = false;
        if (!res.ok) return;
        const f = findings.find(
            (x) => String(x.asset_id) === String(assetId) && x.cve_id === cveId
        );
        if (f) f.status = status;
        renderFindings();
    }

    function epssText(epss) {
        const pct = (epss * 100).toFixed(1) + "%";
        const cls = epss >= 0.5 ? "epss-strong" : "";
        return `<span class="${cls}">${pct}</span>`;
    }

    async function exportFindings(format) {
        const inc = $("findSuppressed").checked;
        const res = await apiFetch(
            "/findings/export?format=" + format + "&include_suppressed=" + inc
        );
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

    // --- Registration availability -----------------------------------------
    async function checkRegistration() {
        try {
            const res = await fetch("/auth/registration-status");
            if (res.ok && !(await res.json()).open) {
                const toggle = document.querySelector(".auth-toggle");
                if (toggle) toggle.classList.add("hidden");
            }
        } catch (_) {
            /* leave the toggle visible on error */
        }
    }

    // --- Init --------------------------------------------------------------
    applyTheme(localStorage.getItem(THEME_KEY) || "dark");
    checkRegistration();
    document.querySelectorAll(".nav__item").forEach((item) => {
        item.addEventListener("click", () => showSection(item.dataset.section));
    });
    document.querySelectorAll("#themeSegment [data-theme-set]").forEach((b) => {
        b.addEventListener("click", () => setTheme(b.dataset.themeSet));
    });
    document.querySelectorAll("#section-findings th[data-sort]").forEach((th) => {
        th.addEventListener("click", () => sortFindingsBy(th.dataset.sort));
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
        submitAuth,
        toggleAuthMode,
        logout,
        toggleUserMenu,
        showSection,
        renderAssets,
        openAssetModal,
        closeAssetModal,
        submitAsset,
        renderFindings,
        loadFindings,
        refreshFindings,
        refreshOverview,
        exportFindings,
    };
})();
