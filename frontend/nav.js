// nav.js - Strict Role-Based Navigation & Session Synchronization
async function setupRoleNavigation(activePage) {
    try {
        const res = await fetch("/api/session");
        const data = await res.json();
        const user = (data && data.authenticated) ? data.user : null;
        const role = user ? (user.role || "user") : "user";

        const navLinks = document.getElementById("navLinks");
        const userBadge = document.getElementById("userBadge");
        const authBtn = document.getElementById("authBtn");
        const logo = document.querySelector(".logo");

        // Route logo click to role home
        if (logo) {
            if (role === "admin") {
                logo.href = "/admin";
            } else if (role === "analyst") {
                logo.href = "/analyst";
            } else if (user) {
                logo.href = "/dashboard";
            } else {
                logo.href = "/login";
            }
        }

        if (userBadge) {
            if (user) {
                const roleTitle = role === "admin" ? "Administrator" : (role === "analyst" ? "Security Analyst" : "Employee");
                userBadge.textContent = `👤 ${user.username} (${roleTitle})`;
                userBadge.className = `badge-pill ${role === "admin" ? "phishing" : (role === "analyst" ? "suspicious" : "neutral")}`;
            } else {
                userBadge.textContent = "Guest";
                userBadge.className = "badge-pill neutral";
            }
        }

        if (authBtn) {
            if (user) {
                authBtn.textContent = "Sign Out";
                authBtn.href = "#";
                authBtn.onclick = async (e) => {
                    e.preventDefault();
                    await fetch("/api/auth/logout", { method: "POST" });
                    window.location.href = "/login";
                };
            } else {
                authBtn.textContent = "Sign In";
                authBtn.href = "/login";
            }
        }

        if (navLinks) {
            let links = [];

            if (role === "admin") {
                // Admin: Full company administration & security oversight
                links = [
                    { name: "Admin Dashboard", url: "/admin", key: "admin" },
                    { name: "Manage Users", url: "/users", key: "users" },
                    { name: "Analyst Queue", url: "/analyst", key: "analyst" },
                    { name: "Detection Analytics", url: "/analytics", key: "analytics" },
                    { name: "Scan History", url: "/history", key: "history" },
                    { name: "Blocklist Rules", url: "/indicators", key: "indicators" },
                    { name: "Scan Tool", url: "/analyze", key: "analyze" },
                ];
            } else if (role === "analyst") {
                // Security Analyst: Threat triage, review, analytics, threat rules & scanner
                links = [
                    { name: "Analyst Queue", url: "/analyst", key: "analyst" },
                    { name: "Review Incident", url: "/review", key: "review" },
                    { name: "Detection Analytics", url: "/analytics", key: "analytics" },
                    { name: "All Scans", url: "/history", key: "history" },
                    { name: "Threat Rules", url: "/indicators", key: "indicators" },
                    { name: "Scanner Tool", url: "/analyze", key: "analyze" },
                ];
            } else {
                // Standard Employee / User: ONLY their dashboard, scanner, and personal scan history!
                // NEVER see analytics, analyst dashboards, or admin console.
                links = [
                    { name: "Dashboard", url: "/dashboard", key: "dashboard" },
                    { name: "Scan Message / URL", url: "/analyze", key: "analyze" },
                    { name: "My Scan History", url: "/history", key: "history" },
                ];
            }

            navLinks.innerHTML = links.map(l => `
                <a href="${l.url}" class="${l.key === activePage ? 'active' : ''}">${l.name}</a>
            `).join("");
        }

        return user;
    } catch (err) {
        console.error("Navigation load failed", err);
        return null;
    }
}
