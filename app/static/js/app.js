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

    function errorText(data, fallback) {
        // FastAPI validation errors carry a list of {msg} objects.
        if (Array.isArray(data.detail)) {
            return data.detail.map((d) => d.msg.replace(/^Value error, /, "")).join("; ");
        }
        return data.detail || fallback;
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
                    // Another tab may have rotated the token first: its new pair
                    // is already in localStorage, so the caller can just retry.
                    if (!res.ok) return refreshToken() !== rt;
                    const data = await res.json();
                    localStorage.setItem(TOKEN_KEY, data.access_token);
                    localStorage.setItem(REFRESH_KEY, data.refresh_token);
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
        $("resendVerifyLink").classList.add("hidden");
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
            const err = new Error(errorText(data, "Login failed"));
            // 403 = right password, but the sign-up is still waiting for confirmation.
            err.unverified = res.status === 403;
            throw err;
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
        $("loginNotice").classList.add("hidden");
        $("resendVerifyLink").classList.add("hidden");
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
                const data = await res.json().catch(() => ({}));
                if (!res.ok) {
                    throw new Error(errorText(data, "Registration failed"));
                }
                if (data.verification_required) {
                    setAuthMode("login");
                    $("loginEmail").value = email;
                    showCardMessage(
                        "loginNotice",
                        "Account created. Open the link we emailed you to activate it, then sign in.",
                        true
                    );
                    return false;
                }
            }
            await doLogin(email, password);
        } catch (err) {
            $("loginError").textContent = err.message;
            $("loginError").classList.remove("hidden");
            $("resendVerifyLink").classList.toggle("hidden", !err.unverified);
        }
        return false;
    }

    async function resendVerification(event) {
        event.preventDefault();
        $("resendVerifyLink").classList.add("hidden");
        $("loginError").classList.add("hidden");
        try {
            const res = await fetch("/auth/resend-verification", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: $("loginEmail").value }),
            });
            const data = await res.json().catch(() => ({}));
            showCardMessage(
                res.ok ? "loginNotice" : "loginError",
                res.ok ? data.message : errorText(data, "Could not send the link"),
                res.ok
            );
            if (!res.ok) $("loginError").className = "alert alert--error";
        } catch (_) {
            /* the error box stays hidden; the user can try again */
        }
    }

    // A confirmation link opens the dashboard with #verify=<token>.
    async function openVerifyLink() {
        const match = location.hash.match(/^#verify=([A-Za-z0-9_-]+)$/);
        if (!match) return false;
        history.replaceState(null, "", location.pathname + location.search);
        showAuthCard("loginForm");
        const res = await fetch("/auth/verify-email", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ token: match[1] }),
        }).catch(() => null);
        const data = res ? await res.json().catch(() => ({})) : {};
        if (res && res.ok) {
            showCardMessage("loginNotice", data.message, true);
        } else {
            $("loginError").textContent = errorText(data, "Could not confirm the email");
            $("loginError").classList.remove("hidden");
        }
        return true;
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
        try {
            const url = "/findings?include_suppressed=false&limit=0";
            let res = await apiFetch(url + (force ? "&refresh=true" : ""));
            // Over the scan quota: still show the stored numbers.
            if (res.status === 429) res = await apiFetch(url);
            if (res.ok) summary = await res.json();
        } catch (_) {
            /* best effort */
        } finally {
            if (btn) btn.classList.remove("is-busy");
        }
        renderOverview(summary);
        $("overviewLoading").classList.add("hidden");
        $("overviewGrid").classList.remove("hidden");
    }

    function refreshOverview() {
        loadOverview(true);
    }

    function renderOverview(summary) {
        const bySev = summary.by_severity || {};
        const byStatus = summary.by_status || {};
        $("statFindings").textContent = summary.total || 0;
        $("statKev").textContent = summary.kev || 0;
        $("statCritHigh").textContent = (bySev.CRITICAL || 0) + (bySev.HIGH || 0);
        $("statAssets").textContent = summary.total_assets || 0;

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
                .map(([k, v]) => `<span class="chip">${esc(k)}: ${esc(v)}</span>`)
                .join("") || '<span class="muted">No vulnerabilities</span>';
    }

    // --- Assets ------------------------------------------------------------
    let assets = [];
    const ASSET_PAGE = 100;
    const MAX_SBOM_BYTES = 5 * 1024 * 1024;

    // The API returns at most 100 assets per request.
    async function fetchAllAssets() {
        const all = [];
        for (let offset = 0; ; offset += ASSET_PAGE) {
            const res = await apiFetch(`/assets/?limit=${ASSET_PAGE}&offset=${offset}`);
            if (!res.ok) return all;
            const page = await res.json();
            all.push(...page);
            if (page.length < ASSET_PAGE) return all;
        }
    }

    async function loadAssets() {
        $("assetsLoading").classList.remove("hidden");
        $("assetsTableWrap").classList.add("hidden");
        $("assetsEmpty").classList.add("hidden");
        assets = await fetchAllAssets();
        $("assetsLoading").classList.add("hidden");
        renderAssets();
    }

    function showSbomResult(ok, text) {
        const box = $("sbomResult");
        box.className = "section-note " + (ok ? "alert--ok" : "alert--error");
        box.textContent = text;
    }

    async function importSbom(event) {
        const file = event.target.files[0];
        event.target.value = "";
        if (!file) return;
        if (file.size > MAX_SBOM_BYTES) {
            showSbomResult(false, "The SBOM is larger than 5 MB.");
            return;
        }
        const btn = $("sbomImportBtn");
        btn.classList.add("is-busy");
        try {
            const res = await apiFetch("/assets/import-sbom", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: await file.text(),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showSbomResult(false, errorText(data, "Import failed"));
                return;
            }
            const skipped = [
                [data.skipped_existing.length, "already present"],
                [data.skipped_invalid.length, "with a name or version too long"],
                [data.unsupported.length, "without a supported package URL"],
            ]
                .filter(([n]) => n)
                .map(([n, why]) => `${n} ${why}`);
            showSbomResult(
                true,
                `Created ${data.created} asset(s)` +
                (data.project ? ` from ${data.project}` : "") +
                "." +
                (skipped.length ? ` Skipped: ${skipped.join(", ")}.` : "") +
                (data.created ? " Use Rescan under Vulnerabilities to check them." : "")
            );
            loadAssets();
        } finally {
            btn.classList.remove("is-busy");
        }
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
            $("assetModalError").textContent = errorText(d, "Could not save asset");
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
    // The server filters, sorts and pages: the browser holds one page only.
    const FIND_PAGE = 50;
    const findState = { offset: 0, matched: 0, sort: null, order: "desc" };
    let findSearchTimer = null;

    function findingsQuery(refresh) {
        const params = new URLSearchParams({
            include_suppressed: $("findSuppressed").checked,
            limit: FIND_PAGE,
            offset: findState.offset,
        });
        const q = ($("findSearch").value || "").trim();
        if (q) params.set("q", q);
        if ($("findSeverity").value) params.set("severity", $("findSeverity").value);
        if ($("findStatus").value) params.set("status", $("findStatus").value);
        if (findState.sort) {
            params.set("sort", findState.sort);
            params.set("order", findState.order);
        }
        if (refresh) params.set("refresh", "true");
        return "/findings?" + params;
    }

    async function loadFindings(refresh = false) {
        const btn = $("findRefresh");
        if (refresh && btn) btn.classList.add("is-busy");
        $("findingsLoading").textContent = refresh
            ? "Scanning your assets\u2026 this can take a while."
            : "Loading vulnerabilities\u2026";
        $("findingsLoading").classList.remove("hidden");
        let data = { findings: [], matched: 0 };
        let notice = "";
        try {
            let res = await apiFetch(findingsQuery(refresh));
            if (res.status === 429) {
                notice = "Scan limit reached, showing the last results. Try again later.";
                res = await apiFetch(findingsQuery(false));
            }
            if (res.ok) data = await res.json();
        } finally {
            if (btn) btn.classList.remove("is-busy");
        }
        $("findingsLoading").classList.add("hidden");
        findState.matched = data.matched || 0;
        renderScanInfo(data, notice);
        renderFindings(data.findings || []);
    }

    function refreshFindings() {
        loadFindings(true);
    }

    // Filters change what matches: start again from the first page.
    function reloadFindings() {
        findState.offset = 0;
        loadFindings();
    }

    function searchFindings() {
        clearTimeout(findSearchTimer);
        findSearchTimer = setTimeout(reloadFindings, 300);
    }

    function pageFindings(step) {
        const next = findState.offset + step * FIND_PAGE;
        if (next < 0 || next >= findState.matched) return;
        findState.offset = next;
        loadFindings();
    }

    function sortFindingsBy(key) {
        if (findState.sort === key) {
            findState.order = findState.order === "asc" ? "desc" : "asc";
        } else {
            findState.sort = key;
            findState.order = ["cve_id", "asset_name", "status"].includes(key)
                ? "asc"
                : "desc";
        }
        reloadFindings();
    }

    function updateSortIndicators() {
        document.querySelectorAll("#section-findings th[data-sort]").forEach((th) => {
            const arrow = th.querySelector(".th-arrow");
            if (!arrow) return;
            arrow.textContent =
                th.dataset.sort === findState.sort
                    ? findState.order === "asc"
                        ? " \u2191"
                        : " \u2193"
                    : "";
        });
    }

    function renderScanInfo(data, notice) {
        const parts = notice ? [notice] : [];
        if (data.last_scan) {
            parts.push("Last scan: " + new Date(data.last_scan).toLocaleString());
        }
        if (data.unscanned_assets) {
            parts.push(
                `${data.unscanned_assets} asset(s) not scanned yet \u2014 use Rescan to check them.`
            );
        }
        $("findScanInfo").textContent = parts.join(" \u00b7 ");
        $("findScanInfo").classList.toggle("hidden", !parts.length);
    }

    function renderPager(shown) {
        const pager = $("findPager");
        pager.classList.toggle("hidden", findState.matched <= FIND_PAGE);
        const from = shown ? findState.offset + 1 : 0;
        $("findRange").textContent = `${from}\u2013${findState.offset + shown} of ${findState.matched}`;
        $("findPrev").disabled = findState.offset === 0;
        $("findNext").disabled = findState.offset + FIND_PAGE >= findState.matched;
    }

    function renderFindings(list) {
        updateSortIndicators();
        renderPager(list.length);
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
                    <td><span class="badge-sev ${SEV_CLASS[sevU] || "sev-unknown"}">${esc(sevU)}</span></td>
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
        // The new status may move the row out of the current filters.
        loadFindings();
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

    // --- Notifications -----------------------------------------------------
    const CHANNELS = ["slack", "teams", "discord"];
    const clearedChannels = new Set();

    function showNotifMessage(text, ok) {
        const box = $("notifMsg");
        box.className = ok ? "alert--ok" : "alert--error";
        box.textContent = text;
    }

    function renderChannel(channel, configured) {
        $(`notif_${channel}_state`).textContent = configured
            ? "(configured — enter new values to replace it)"
            : "(not set)";
        $(`notif_${channel}_clear`).classList.toggle("hidden", !configured);
    }

    function fillNotifications(settings) {
        $("notifMinSeverity").value = settings.min_severity;
        $("notifAlwaysKev").checked = settings.always_kev;
        $("notifEscalations").checked = settings.escalations;
        $("notifEmailInfo").textContent = settings.email_available
            ? `Alerts are always emailed to ${settings.email}.`
            : "Email is not configured on this server: add a chat channel to get alerts.";
        clearedChannels.clear();
        CHANNELS.forEach((c) => {
            $(`notif_${c}`).value = "";
            renderChannel(c, settings[`${c}_configured`]);
        });
        $("notif_telegram_token").value = "";
        $("notif_telegram_chat").value = "";
        renderChannel("telegram", settings.telegram_configured);
    }

    async function openNotifications() {
        $("userMenu").classList.add("hidden");
        $("notifMsg").className = "hidden";
        const res = await apiFetch("/user/notifications");
        if (!res.ok) return;
        fillNotifications(await res.json());
        $("notifModal").classList.remove("hidden");
    }

    function closeNotifications() {
        $("notifModal").classList.add("hidden");
    }

    function clearChannel(channel) {
        clearedChannels.add(channel);
        if (channel === "telegram") {
            $("notif_telegram_token").value = "";
            $("notif_telegram_chat").value = "";
        } else {
            $(`notif_${channel}`).value = "";
        }
        renderChannel(channel, false);
    }

    async function saveNotifications(event) {
        event.preventDefault();
        const payload = {
            min_severity: $("notifMinSeverity").value,
            always_kev: $("notifAlwaysKev").checked,
            escalations: $("notifEscalations").checked,
        };
        CHANNELS.forEach((c) => {
            const url = $(`notif_${c}`).value.trim();
            if (url) payload[`${c}_webhook_url`] = url;
            else if (clearedChannels.has(c)) payload[`${c}_webhook_url`] = "";
        });
        const token = $("notif_telegram_token").value.trim();
        const chat = $("notif_telegram_chat").value.trim();
        if (token || chat) {
            payload.telegram_bot_token = token;
            payload.telegram_chat_id = chat;
        } else if (clearedChannels.has("telegram")) {
            payload.telegram_bot_token = "";
            payload.telegram_chat_id = "";
        }
        const res = await apiFetch("/user/notifications", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            showNotifMessage(errorText(data, "Could not save settings"), false);
            return false;
        }
        fillNotifications(data);
        showNotifMessage("Settings saved.", true);
        return false;
    }

    async function testNotifications() {
        const res = await apiFetch("/user/notifications/test", { method: "POST" });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
            showNotifMessage(errorText(data, "Test failed"), false);
            return;
        }
        const results = Object.entries(data.results || {});
        const failed = results.filter(([, ok]) => !ok).map(([name]) => name);
        showNotifMessage(
            failed.length
                ? `Test not delivered to: ${failed.join(", ")}.`
                : `Test sent to: ${results.map(([name]) => name).join(", ")}.`,
            !failed.length
        );
    }

    // --- Change password ---------------------------------------------------
    function showPwdMessage(text, ok) {
        const box = $("pwdMsg");
        box.className = ok ? "alert--ok" : "alert--error";
        box.textContent = text;
    }

    function openPassword() {
        $("userMenu").classList.add("hidden");
        $("pwdForm").reset();
        $("pwdUsername").value = $("userEmailFull").textContent;
        $("pwdMsg").className = "hidden";
        $("pwdSubmit").disabled = false;
        $("pwdModal").classList.remove("hidden");
        $("pwdCurrent").focus();
    }

    function closePassword() {
        $("pwdForm").reset();
        $("pwdModal").classList.add("hidden");
    }

    async function changePassword(event) {
        event.preventDefault();
        if ($("pwdNew").value !== $("pwdConfirm").value) {
            showPwdMessage("The new passwords do not match.", false);
            return;
        }
        $("pwdSubmit").disabled = true;
        try {
            const res = await apiFetch("/user/password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    current_password: $("pwdCurrent").value,
                    new_password: $("pwdNew").value,
                }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showPwdMessage(errorText(data, "Could not change the password"), false);
                return;
            }
            // The old tokens are now invalid: keep this session on the new pair.
            localStorage.setItem(TOKEN_KEY, data.access_token);
            localStorage.setItem(REFRESH_KEY, data.refresh_token);
            $("pwdForm").reset();
            showPwdMessage("Password changed. Every other session was signed out.", true);
        } finally {
            $("pwdSubmit").disabled = false;
        }
    }

    // --- Forgot / reset password -------------------------------------------
    let resetToken = null;

    function showAuthCard(id) {
        ["loginForm", "forgotForm", "resetForm"].forEach((f) =>
            $(f).classList.toggle("hidden", f !== id)
        );
    }

    function showCardMessage(id, text, ok) {
        const box = $(id);
        box.className = ok ? "alert--ok" : "alert--error";
        box.textContent = text;
    }

    function openForgot(event) {
        event.preventDefault();
        $("forgotForm").reset();
        $("forgotMsg").className = "hidden";
        $("forgotEmail").value = $("loginEmail").value;
        showAuthCard("forgotForm");
        $("forgotEmail").focus();
    }

    function backToLogin(event) {
        event.preventDefault();
        resetToken = null;
        showAuthCard("loginForm");
    }

    async function submitForgot(event) {
        event.preventDefault();
        $("forgotSubmit").disabled = true;
        try {
            const res = await fetch("/auth/forgot-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: $("forgotEmail").value }),
            });
            const data = await res.json().catch(() => ({}));
            showCardMessage(
                "forgotMsg",
                res.ok ? data.message : errorText(data, "Could not send the reset link"),
                res.ok
            );
        } catch (_) {
            showCardMessage("forgotMsg", "Could not send the reset link", false);
        } finally {
            $("forgotSubmit").disabled = false;
        }
    }

    async function submitReset(event) {
        event.preventDefault();
        if ($("resetPassword").value !== $("resetConfirm").value) {
            showCardMessage("resetMsg", "The passwords do not match.", false);
            return;
        }
        $("resetSubmit").disabled = true;
        try {
            const res = await fetch("/auth/reset-password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    token: resetToken,
                    new_password: $("resetPassword").value,
                }),
            });
            const data = await res.json().catch(() => ({}));
            if (!res.ok) {
                showCardMessage("resetMsg", errorText(data, "Could not reset the password"), false);
                return;
            }
            resetToken = null;
            $("resetForm").reset();
            setAuthMode("login");
            showAuthCard("loginForm");
            showCardMessage("loginNotice", data.message, true);
        } catch (_) {
            showCardMessage("resetMsg", "Could not reset the password", false);
        } finally {
            $("resetSubmit").disabled = false;
        }
    }

    // A reset link opens the dashboard with #reset=<token>.
    function openResetLink() {
        const match = location.hash.match(/^#reset=([A-Za-z0-9_-]+)$/);
        if (!match) return false;
        resetToken = match[1];
        history.replaceState(null, "", location.pathname + location.search);
        $("resetMsg").className = "hidden";
        showAuthCard("resetForm");
        return true;
    }

    // --- Registration availability -----------------------------------------
    async function checkRegistration() {
        try {
            const res = await fetch("/auth/registration-status");
            if (!res.ok) return;
            const status = await res.json();
            if (!status.open) {
                const toggle = document.querySelector(".auth-toggle");
                if (toggle) toggle.classList.add("hidden");
            }
            $("forgotLink").classList.toggle("hidden", !status.password_reset);
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

    // Bound here, not inline in the HTML, so the CSP can forbid inline scripts.
    const on = (id, type, handler) => $(id).addEventListener(type, handler);
    on("loginForm", "submit", submitAuth);
    on("authToggleLink", "click", toggleAuthMode);
    on("userMenuBtn", "click", toggleUserMenu);
    on("logoutBtn", "click", () => logout());
    on("overviewRefresh", "click", refreshOverview);
    on("assetFilter", "input", renderAssets);
    on("assetAddBtn", "click", () => openAssetModal());
    on("sbomImportBtn", "click", () => $("sbomFile").click());
    on("sbomFile", "change", importSbom);
    on("findSearch", "input", searchFindings);
    on("findSeverity", "change", reloadFindings);
    on("findStatus", "change", reloadFindings);
    on("findSuppressed", "change", reloadFindings);
    on("findRefresh", "click", refreshFindings);
    on("findPrev", "click", () => pageFindings(-1));
    on("findNext", "click", () => pageFindings(1));
    on("exportCsv", "click", () => exportFindings("csv"));
    on("exportJson", "click", () => exportFindings("json"));
    on("assetModalClose", "click", closeAssetModal);
    on("assetCancel", "click", closeAssetModal);
    on("assetForm", "submit", submitAsset);
    on("notifBtn", "click", openNotifications);
    on("notifClose", "click", closeNotifications);
    on("notifCancel", "click", closeNotifications);
    on("notifForm", "submit", saveNotifications);
    on("notifTest", "click", testNotifications);
    CHANNELS.forEach((c) => on(`notif_${c}_clear`, "click", () => clearChannel(c)));
    on("notif_telegram_clear", "click", () => clearChannel("telegram"));
    on("pwdBtn", "click", openPassword);
    on("pwdClose", "click", closePassword);
    on("pwdCancel", "click", closePassword);
    on("pwdForm", "submit", changePassword);
    on("forgotLink", "click", openForgot);
    on("forgotBack", "click", backToLogin);
    on("forgotForm", "submit", submitForgot);
    on("resetBack", "click", backToLogin);
    on("resetForm", "submit", submitReset);
    on("resendVerifyLink", "click", resendVerification);

    if (!openResetLink()) {
        openVerifyLink().then((opened) => {
            if (!opened && token()) enterApp();
        });
    }
})();
