from fastapi import APIRouter
from fastapi.responses import HTMLResponse

router = APIRouter()


@router.get("/dashboard", response_class=HTMLResponse, tags=["dashboard"])
async def dashboard_page() -> HTMLResponse:
    """Minimal single-page dashboard to manage assets and view their CVEs."""
    return HTMLResponse(content=_DASHBOARD_HTML)


_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVE Watcher - Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
</head>
<body class="bg-gray-50 text-gray-800">
    <nav class="bg-white shadow">
        <div class="container mx-auto px-6 py-3 flex justify-between items-center">
            <div class="flex items-center">
                <i class="fas fa-shield-alt text-blue-600 text-2xl mr-3"></i>
                <span class="text-xl font-bold">CVE Watcher</span>
                <span class="ml-2 text-sm text-gray-400">Dashboard</span>
            </div>
            <div id="userBox" class="hidden items-center space-x-4">
                <span id="userEmail" class="text-sm text-gray-600"></span>
                <button onclick="logout()" class="text-sm bg-gray-200 px-3 py-1 rounded hover:bg-gray-300">
                    <i class="fas fa-sign-out-alt mr-1"></i>Logout
                </button>
            </div>
        </div>
    </nav>

    <main class="container mx-auto px-6 py-8 max-w-5xl">

        <!-- Login view -->
        <section id="loginView" class="max-w-md mx-auto bg-white rounded-lg shadow p-8">
            <h2 class="text-2xl font-bold mb-6 text-center">Sign in</h2>
            <div id="loginError" class="hidden bg-red-100 text-red-700 text-sm rounded px-4 py-2 mb-4"></div>
            <form onsubmit="login(event)" class="space-y-4">
                <div>
                    <label class="block text-sm font-medium mb-1">Email</label>
                    <input id="loginEmail" type="email" required
                        class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">Password</label>
                    <input id="loginPassword" type="password" required
                        class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <button type="submit"
                    class="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700">
                    Sign in
                </button>
            </form>
        </section>

        <!-- App view -->
        <section id="appView" class="hidden space-y-8">

            <!-- Add asset -->
            <div class="bg-white rounded-lg shadow p-6">
                <h2 class="text-lg font-bold mb-4"><i class="fas fa-plus-circle text-blue-600 mr-2"></i>Add asset</h2>
                <div id="assetError" class="hidden bg-red-100 text-red-700 text-sm rounded px-4 py-2 mb-4"></div>
                <form onsubmit="createAsset(event)" class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <input id="assetName" placeholder="Name (e.g. nginx)" required
                        class="border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <input id="assetVersion" placeholder="Version (e.g. 1.24.0)"
                        class="border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <input id="assetCpe" placeholder="CPE (optional)"
                        class="border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <input id="assetDescription" placeholder="Description (optional)"
                        class="border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                    <div class="md:col-span-2">
                        <button type="submit" class="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700">
                            Add asset
                        </button>
                    </div>
                </form>
            </div>

            <!-- Asset list -->
            <div class="bg-white rounded-lg shadow p-6">
                <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                    <h2 class="text-lg font-bold"><i class="fas fa-server text-blue-600 mr-2"></i>Your assets</h2>
                    <div class="flex items-center gap-2 text-sm">
                        <div class="relative">
                            <i class="fas fa-search absolute left-2 top-2.5 text-gray-400 text-xs"></i>
                            <input id="filterName" oninput="renderAssets()" placeholder="Filter by name"
                                class="border rounded pl-7 pr-3 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        </div>
                        <input id="filterVersion" oninput="renderAssets()" placeholder="Filter by version"
                            class="border rounded px-3 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500">
                        <button onclick="clearAssetFilters()" class="text-gray-500 hover:text-gray-700" title="Clear filters">
                            <i class="fas fa-times-circle"></i>
                        </button>
                    </div>
                </div>
                <div id="assetsEmpty" class="hidden text-gray-400 text-sm">No assets yet. Add one above.</div>
                <div id="assetsNoMatch" class="hidden text-gray-400 text-sm">No assets match the current filters.</div>
                <div class="overflow-x-auto">
                    <table id="assetsTable" class="hidden w-full text-sm">
                        <thead>
                            <tr class="text-left text-gray-500 border-b">
                                <th class="py-2 pr-4">Name</th>
                                <th class="py-2 pr-4">Version</th>
                                <th class="py-2 pr-4">Description</th>
                                <th class="py-2 pr-4"></th>
                            </tr>
                        </thead>
                        <tbody id="assetsBody"></tbody>
                    </table>
                </div>
            </div>

            <!-- Vulnerabilities -->
            <div id="vulnCard" class="hidden bg-white rounded-lg shadow p-6">
                <div class="flex flex-wrap items-center justify-between gap-3 mb-4">
                    <h2 class="text-lg font-bold">
                        <i class="fas fa-bug text-red-600 mr-2"></i>
                        Vulnerabilities for <span id="vulnAssetName" class="text-blue-600"></span>
                    </h2>
                    <div class="flex items-center gap-4 text-sm">
                        <div class="flex items-center">
                            <label for="vulnSeverity" class="mr-2 text-gray-500">Severity</label>
                            <select id="vulnSeverity" onchange="reloadVulnerabilities()"
                                class="border rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="" selected>All</option>
                                <option value="CRITICAL">Critical</option>
                                <option value="HIGH">High</option>
                                <option value="MEDIUM">Medium</option>
                                <option value="LOW">Low</option>
                            </select>
                        </div>
                        <div class="flex items-center">
                            <label for="vulnDays" class="mr-2 text-gray-500">Period</label>
                            <select id="vulnDays" onchange="reloadVulnerabilities()"
                                class="border rounded px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500">
                                <option value="" selected>All</option>
                                <option value="30">Last 30 days</option>
                                <option value="90">Last 90 days</option>
                                <option value="365">Last 365 days</option>
                            </select>
                        </div>
                    </div>
                </div>
                <div id="vulnLoading" class="hidden text-gray-400 text-sm">Loading...</div>
                <div id="vulnError" class="hidden bg-amber-100 text-amber-800 text-sm rounded px-4 py-2">
                    <i class="fas fa-triangle-exclamation mr-1"></i>
                    <span id="vulnErrorMsg"></span>
                </div>
                <div id="vulnEmpty" class="hidden text-green-600 text-sm">No known vulnerabilities in the selected window.</div>
                <div class="overflow-x-auto">
                    <table id="vulnTable" class="hidden w-full text-sm">
                        <thead>
                            <tr class="text-left text-gray-500 border-b">
                                <th class="py-2 pr-4">CVE ID</th>
                                <th class="py-2 pr-4">Severity</th>
                                <th class="py-2 pr-4">Score</th>
                                <th class="py-2 pr-4">Summary</th>
                            </tr>
                        </thead>
                        <tbody id="vulnBody"></tbody>
                    </table>
                </div>
            </div>
        </section>
    </main>

    <!-- Edit asset modal -->
    <div id="editModal" class="hidden fixed inset-0 bg-black/40 flex items-center justify-center p-4 z-50">
        <div class="bg-white rounded-lg shadow-lg w-full max-w-md p-6">
            <div class="flex items-center justify-between mb-4">
                <h2 class="text-lg font-bold"><i class="fas fa-pen text-blue-600 mr-2"></i>Edit asset</h2>
                <button onclick="closeEditModal()" class="text-gray-400 hover:text-gray-600">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div id="editError" class="hidden bg-red-100 text-red-700 text-sm rounded px-4 py-2 mb-4"></div>
            <form onsubmit="submitEditAsset(event)" class="space-y-4">
                <input type="hidden" id="editAssetId">
                <div>
                    <label class="block text-sm font-medium mb-1">Name</label>
                    <input id="editName" required
                        class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">Version</label>
                    <input id="editVersion"
                        class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">CPE</label>
                    <input id="editCpe"
                        class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1">Description</label>
                    <input id="editDescription"
                        class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                </div>
                <div class="flex justify-end gap-2 pt-2">
                    <button type="button" onclick="closeEditModal()"
                        class="px-4 py-2 rounded bg-gray-200 hover:bg-gray-300">Cancel</button>
                    <button type="submit"
                        class="px-4 py-2 rounded bg-blue-600 text-white hover:bg-blue-700">Save changes</button>
                </div>
            </form>
        </div>
    </div>

    <script>
        const TOKEN_KEY = "cvewatcher_token";
        const EMAIL_KEY = "cvewatcher_email";
        let currentAsset = null;
        let allAssets = [];

        function token() { return localStorage.getItem(TOKEN_KEY); }
        function authHeaders() { return { "Authorization": "Bearer " + token() }; }

        function showError(id, msg) {
            const el = document.getElementById(id);
            el.textContent = msg;
            el.classList.remove("hidden");
        }
        function hideError(id) { document.getElementById(id).classList.add("hidden"); }

        async function login(event) {
            event.preventDefault();
            hideError("loginError");
            const email = document.getElementById("loginEmail").value;
            const password = document.getElementById("loginPassword").value;
            try {
                const res = await fetch("/auth/login", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ email, password })
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
                showError("loginError", err.message);
            }
        }

        async function logout() {
            try {
                await fetch("/auth/logout", { method: "POST", headers: authHeaders() });
            } catch (_) { /* ignore */ }
            localStorage.removeItem(TOKEN_KEY);
            localStorage.removeItem(EMAIL_KEY);
            document.getElementById("appView").classList.add("hidden");
            document.getElementById("userBox").classList.add("hidden");
            document.getElementById("loginView").classList.remove("hidden");
        }

        function enterApp() {
            document.getElementById("loginView").classList.add("hidden");
            document.getElementById("appView").classList.remove("hidden");
            const userBox = document.getElementById("userBox");
            userBox.classList.remove("hidden");
            userBox.classList.add("flex");
            document.getElementById("userEmail").textContent = localStorage.getItem(EMAIL_KEY) || "";
            loadAssets();
        }

        async function loadAssets() {
            const res = await fetch("/assets/", { headers: authHeaders() });
            if (res.status === 401) { logout(); return; }
            allAssets = await res.json();
            renderAssets();
        }

        function clearAssetFilters() {
            document.getElementById("filterName").value = "";
            document.getElementById("filterVersion").value = "";
            renderAssets();
        }

        function renderAssets() {
            const body = document.getElementById("assetsBody");
            const table = document.getElementById("assetsTable");
            const empty = document.getElementById("assetsEmpty");
            const noMatch = document.getElementById("assetsNoMatch");
            body.innerHTML = "";
            empty.classList.add("hidden");
            noMatch.classList.add("hidden");
            table.classList.add("hidden");

            if (!allAssets.length) {
                empty.classList.remove("hidden");
                return;
            }

            const nameQ = document.getElementById("filterName").value.trim().toLowerCase();
            const versionQ = document.getElementById("filterVersion").value.trim().toLowerCase();
            const assets = allAssets.filter(a =>
                (!nameQ || (a.name || "").toLowerCase().includes(nameQ)) &&
                (!versionQ || (a.version || "").toLowerCase().includes(versionQ))
            );

            if (!assets.length) {
                noMatch.classList.remove("hidden");
                return;
            }

            table.classList.remove("hidden");
            for (const a of assets) {
                const tr = document.createElement("tr");
                tr.className = "border-b hover:bg-gray-50";
                tr.innerHTML = `
                    <td class="py-2 pr-4 font-medium">${escapeHtml(a.name)}</td>
                    <td class="py-2 pr-4">${escapeHtml(a.version || "-")}</td>
                    <td class="py-2 pr-4 text-gray-500">${escapeHtml(a.description || "")}</td>
                    <td class="py-2 pr-4 text-right whitespace-nowrap">
                        <button class="text-blue-600 hover:underline mr-3">
                            <i class="fas fa-bug mr-1"></i>CVEs
                        </button>
                        <button class="text-gray-600 hover:underline mr-3">
                            <i class="fas fa-pen mr-1"></i>Edit
                        </button>
                        <button class="text-red-500 hover:underline">
                            <i class="fas fa-trash"></i>
                        </button>
                    </td>`;
                const [cveBtn, editBtn, delBtn] = tr.querySelectorAll("button");
                cveBtn.onclick = () => loadVulnerabilities(a.id, a.name);
                editBtn.onclick = () => openEditAsset(a.id);
                delBtn.onclick = () => deleteAsset(a.id);
                body.appendChild(tr);
            }
        }

        function openEditAsset(id) {
            const a = allAssets.find(x => x.id === id);
            if (!a) return;
            hideError("editError");
            document.getElementById("editAssetId").value = a.id;
            document.getElementById("editName").value = a.name || "";
            document.getElementById("editVersion").value = a.version || "";
            document.getElementById("editCpe").value = a.cpe || "";
            document.getElementById("editDescription").value = a.description || "";
            document.getElementById("editModal").classList.remove("hidden");
        }

        function closeEditModal() {
            document.getElementById("editModal").classList.add("hidden");
        }

        async function submitEditAsset(event) {
            event.preventDefault();
            hideError("editError");
            const id = document.getElementById("editAssetId").value;
            const payload = {
                name: document.getElementById("editName").value,
                version: document.getElementById("editVersion").value || null,
                cpe: document.getElementById("editCpe").value || null,
                description: document.getElementById("editDescription").value || null
            };
            const res = await fetch("/assets/" + id, {
                method: "PATCH",
                headers: { ...authHeaders(), "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            if (res.status === 401) { logout(); return; }
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                showError("editError", data.detail || "Could not update asset");
                return;
            }
            closeEditModal();
            if (currentAsset && currentAsset.id === id) {
                currentAsset.name = payload.name;
                loadVulnerabilities(id, payload.name);
            }
            loadAssets();
        }

        async function createAsset(event) {
            event.preventDefault();
            hideError("assetError");
            const payload = {
                name: document.getElementById("assetName").value,
                version: document.getElementById("assetVersion").value || null,
                cpe: document.getElementById("assetCpe").value || null,
                description: document.getElementById("assetDescription").value || null
            };
            const res = await fetch("/assets/", {
                method: "POST",
                headers: { ...authHeaders(), "Content-Type": "application/json" },
                body: JSON.stringify(payload)
            });
            if (res.status === 401) { logout(); return; }
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                showError("assetError", data.detail || "Could not create asset");
                return;
            }
            event.target.reset();
            loadAssets();
        }

        async function deleteAsset(id) {
            if (!confirm("Delete this asset?")) return;
            const res = await fetch("/assets/" + id, { method: "DELETE", headers: authHeaders() });
            if (res.status === 401) { logout(); return; }
            document.getElementById("vulnCard").classList.add("hidden");
            loadAssets();
        }

        async function loadVulnerabilities(id, name) {
            currentAsset = { id, name };
            const card = document.getElementById("vulnCard");
            const table = document.getElementById("vulnTable");
            const empty = document.getElementById("vulnEmpty");
            const loading = document.getElementById("vulnLoading");
            const errorBox = document.getElementById("vulnError");
            const body = document.getElementById("vulnBody");
            document.getElementById("vulnAssetName").textContent = name;
            card.classList.remove("hidden");
            table.classList.add("hidden");
            empty.classList.add("hidden");
            errorBox.classList.add("hidden");
            loading.classList.remove("hidden");
            body.innerHTML = "";
            card.scrollIntoView({ behavior: "smooth" });

            const days = document.getElementById("vulnDays").value || "0";
            const severity = document.getElementById("vulnSeverity").value;
            let url = "/assets/" + id + "/vulnerabilities?days=" + days;
            if (severity) { url += "&severity=" + encodeURIComponent(severity); }
            const res = await fetch(url, { headers: authHeaders() });
            loading.classList.add("hidden");
            if (res.status === 401) { logout(); return; }
            if (res.status === 503) {
                const data = await res.json().catch(() => ({}));
                document.getElementById("vulnErrorMsg").textContent =
                    "Could not reach the NVD service. This is not a clean bill of health \u2014 please retry shortly.";
                errorBox.classList.remove("hidden");
                return;
            }
            if (!res.ok) {
                document.getElementById("vulnErrorMsg").textContent = "Error loading vulnerabilities.";
                errorBox.classList.remove("hidden");
                return;
            }
            const data = await res.json();
            const vulns = data.vulnerabilities || [];
            if (!vulns.length) {
                empty.textContent = "No known vulnerabilities in the selected window.";
                empty.classList.remove("hidden");
                return;
            }
            table.classList.remove("hidden");
            for (const v of vulns) {
                const sev = (v.severity || "UNKNOWN").toUpperCase();
                const tr = document.createElement("tr");
                tr.className = "border-b align-top";
                const cveId = v.cve_id || "-";
                const idCell = v.cve_url
                    ? `<a href="${escapeHtml(v.cve_url)}" target="_blank" rel="noopener" class="text-blue-600 hover:underline">${escapeHtml(cveId)}</a>`
                    : escapeHtml(cveId);
                tr.innerHTML = `
                    <td class="py-2 pr-4 font-mono">${idCell}</td>
                    <td class="py-2 pr-4">${severityBadge(sev)}</td>
                    <td class="py-2 pr-4">${v.score != null ? escapeHtml(v.score) : "-"}</td>
                    <td class="py-2 pr-4 text-gray-600">${escapeHtml(v.summary || "")}</td>`;
                body.appendChild(tr);
            }
        }

        function reloadVulnerabilities() {
            if (currentAsset) { loadVulnerabilities(currentAsset.id, currentAsset.name); }
        }

        function severityBadge(sev) {
            const colors = {
                CRITICAL: "bg-red-100 text-red-700",
                HIGH: "bg-orange-100 text-orange-700",
                MEDIUM: "bg-yellow-100 text-yellow-700",
                LOW: "bg-green-100 text-green-700"
            };
            const cls = colors[sev] || "bg-gray-100 text-gray-600";
            return `<span class="px-2 py-0.5 rounded text-xs font-semibold ${cls}">${escapeHtml(sev)}</span>`;
        }

        function escapeHtml(s) {
            return String(s).replace(/[&<>"']/g, c => ({
                "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
            }[c]));
        }

        // Auto-enter if a token is already stored.
        if (token()) { enterApp(); }
    </script>
</body>
</html>
"""
