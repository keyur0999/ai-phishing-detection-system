// ===============================
// MOBILE MENU
// ===============================

const menuButton = document.getElementById("menuButton");
const navLinks = document.getElementById("navLinks");

menuButton.addEventListener("click", () => {
    navLinks.classList.toggle("open");

    if (navLinks.classList.contains("open")) {
        menuButton.textContent = "✕";
    } else {
        menuButton.textContent = "☰";
    }
});


// ===============================
// CLOSE MOBILE MENU
// ===============================

const navigationLinks = document.querySelectorAll(".nav-links a");

navigationLinks.forEach((link) => {
    link.addEventListener("click", () => {
        navLinks.classList.remove("open");
        menuButton.textContent = "☰";
    });
});


// ===============================
// ACTIVE NAVIGATION
// ===============================

const sections = document.querySelectorAll("section");
const navItems = document.querySelectorAll(".nav-links a");

window.addEventListener("scroll", () => {

    let currentSection = "";

    sections.forEach((section) => {
        const sectionTop = section.offsetTop - 150;
        const sectionHeight = section.offsetHeight;

        if (
            window.scrollY >= sectionTop &&
            window.scrollY < sectionTop + sectionHeight
        ) {
            currentSection = section.getAttribute("id");
        }
    });

    navItems.forEach((item) => {
        item.classList.remove("active");

        const href = item.getAttribute("href");

        if (href === `#${currentSection}`) {
            item.classList.add("active");
        }
    });
});


// ===============================
// SCROLL ANIMATION
// ===============================

const animatedElements = document.querySelectorAll(
    ".detection-card, .feature-card, .step, .about-content, .about-visual"
);

const observer = new IntersectionObserver(
    (entries) => {

        entries.forEach((entry) => {

            if (entry.isIntersecting) {
                entry.target.classList.add("show");
            }

        });

    },
    {
        threshold: 0.15
    }
);

animatedElements.forEach((element) => {
    observer.observe(element);
});


// ===============================
// BUTTON CLICK EFFECT
// ===============================

const buttons = document.querySelectorAll(
    ".card-button, .primary-button, .secondary-button"
);

buttons.forEach((button) => {

    button.addEventListener("click", () => {

        button.style.transform = "scale(0.96)";

        setTimeout(() => {
            button.style.transform = "";
        }, 120);

    });

});


// ===============================
// INITIAL PAGE LOAD
// ===============================

window.addEventListener("load", () => {

    document.querySelectorAll(".hero-content").forEach((element) => {
        element.style.opacity = "1";
    });

});

// ==========================================
// PHISHGUARD AI - BACKEND & UI LOGIC
// ==========================================

const API_URL = (window.location.protocol.startsWith("http") && (window.location.port === "5000" || window.location.port === "5001"))
    ? ""
    : "http://127.0.0.1:5000";

// --- Tab Switching ---
const tabButtons = document.querySelectorAll(".scanner-tabs .tab-btn");
const tabContents = {
    url: document.getElementById("tabContentUrl"),
    email: document.getElementById("tabContentEmail"),
    qr: document.getElementById("tabContentQr"),
    history: document.getElementById("tabContentHistory"),
};

function switchTab(tabName) {
    tabButtons.forEach(btn => {
        if (btn.dataset.tab === tabName) {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });

    Object.keys(tabContents).forEach(key => {
        if (tabContents[key]) {
            if (key === tabName) {
                tabContents[key].classList.add("active");
            } else {
                tabContents[key].classList.remove("active");
            }
        }
    });

    if (tabName !== "qr") {
        stopQrCamera();
    }

    if (tabName === "history") {
        fetchHistoryAndStats();
    }
}

tabButtons.forEach(btn => {
    btn.addEventListener("click", () => {
        switchTab(btn.dataset.tab);
    });
});

// Detection card click to jump to scanner tab
document.getElementById("cardEmail")?.addEventListener("click", () => {
    switchTab("email");
    document.getElementById("scannerConsole")?.scrollIntoView({ behavior: "smooth" });
    document.getElementById("emailSubject")?.focus();
});

document.getElementById("cardUrl")?.addEventListener("click", () => {
    switchTab("url");
    document.getElementById("scannerConsole")?.scrollIntoView({ behavior: "smooth" });
    document.getElementById("urlInput")?.focus();
});

document.getElementById("cardQr")?.addEventListener("click", () => {
    switchTab("qr");
    document.getElementById("scannerConsole")?.scrollIntoView({ behavior: "smooth" });
});


// --- Sample Selector ---
window.setSample = function(type, val) {
    if (type === "url") {
        const input = document.getElementById("urlInput");
        if (input) input.value = val;
    } else if (type === "email_bad") {
        const sub = document.getElementById("emailSubject");
        const body = document.getElementById("emailBody");
        if (sub) sub.value = "URGENT ACTION REQUIRED: Account Suspended";
        if (body) body.value = "Dear Customer,\n\nWe detected suspicious activity on your account. Please click here immediately to confirm your password and verify your account: http://paypa1.com/login-verify\n\nFailure to act now will result in permanent suspension.";
    } else if (type === "email_good") {
        const sub = document.getElementById("emailSubject");
        const body = document.getElementById("emailBody");
        if (sub) sub.value = "Project Architecture Review - Tuesday 10 AM";
        if (body) body.value = "Hi Team,\n\nLet's review the system architecture and database schema in tomorrow's standup.\n\nBest regards,\nEngineering Team";
    } else if (type === "qr") {
        const input = document.getElementById("qrInput");
        if (input) input.value = val;
    }
};

// --- Backend Health Check ---
async function checkBackend() {
    const badge = document.getElementById("backendStatus");
    const badgeText = document.getElementById("backendStatusText");
    try {
        const response = await fetch(`${API_URL}/api/health`);
        const data = await response.json();
        if (data && data.success) {
            if (badge) {
                badge.classList.remove("offline");
                badge.classList.add("online");
            }
            if (badgeText) badgeText.textContent = "AI Engine: Connected";
            fetchHistoryAndStats();
            return true;
        }
    } catch (error) {
        if (badge) {
            badge.classList.remove("online");
            badge.classList.add("offline");
        }
        if (badgeText) badgeText.textContent = "Backend Offline (Port 5000)";
        console.warn("Backend connection failed:", error);
    }
    return false;
}

// Current active scan ID for reporting
let activeScanId = null;

// --- Display Scan Results ---
function displayResult(data, scanType) {
    const resultBox = document.getElementById("resultContainer");
    const scanIdTag = document.getElementById("resScanId");
    const verdictBadge = document.getElementById("resVerdictBadge");
    const scoreText = document.getElementById("resScoreText");
    const scoreBar = document.getElementById("resScoreBar");
    const reasonsList = document.getElementById("resReasonsList");

    if (!resultBox) return;
    resultBox.style.display = "block";

    // Track active scan id for reporting
    activeScanId = data.scan_id || null;

    // Reset report form
    const reportBox = document.getElementById("reportBox");
    const reportAlert = document.getElementById("reportAlert");
    const reportReason = document.getElementById("reportReason");
    const btnSubmitReport = document.getElementById("btnSubmitReport");
    if (reportBox) reportBox.style.display = "none";
    if (reportAlert) reportAlert.style.display = "none";
    if (reportReason) reportReason.value = "";
    if (btnSubmitReport) {
        btnSubmitReport.disabled = false;
        btnSubmitReport.textContent = "Submit Report 🚀";
    }

    if (scanIdTag) {
        scanIdTag.textContent = data.scan_id ? `Scan #${data.scan_id}` : `Live Analysis`;
    }

    const verdict = (data.verdict || "safe").toLowerCase();
    const score = typeof data.risk_score === "number" ? data.risk_score : 0;
    const reasons = data.reasons || [];

    if (verdictBadge) {
        verdictBadge.className = `verdict-badge ${verdict}`;
        if (verdict === "phishing") {
            verdictBadge.innerHTML = "🚨 PHISHING THREAT";
        } else if (verdict === "suspicious") {
            verdictBadge.innerHTML = "⚠️ SUSPICIOUS";
        } else {
            verdictBadge.innerHTML = "🛡 SAFE & SECURE";
        }
    }

    if (scoreText) scoreText.textContent = `${score} / 100`;
    if (scoreBar) {
        scoreBar.style.width = `${Math.max(score, 4)}%`;
        if (verdict === "phishing") {
            scoreBar.style.background = "#ef4444";
        } else if (verdict === "suspicious") {
            scoreBar.style.background = "#f59e0b";
        } else {
            scoreBar.style.background = "#22c55e";
        }
    }

    if (reasonsList) {
        reasonsList.innerHTML = "";
        if (reasons.length === 0) {
            const li = document.createElement("li");
            li.className = "clean-item";
            li.innerHTML = "<span>✓</span> No phishing patterns, typosquats, or malicious keywords detected.";
            reasonsList.appendChild(li);
        } else {
            reasons.forEach(r => {
                const li = document.createElement("li");
                li.className = "threat-item";
                li.innerHTML = `<span>⚠️</span> ${r}`;
                reasonsList.appendChild(li);
            });
        }
    }

    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// Preset reason selector
window.setReportReason = function(preset) {
    const input = document.getElementById("reportReason");
    if (input) {
        input.value = preset;
        input.focus();
    }
};

// Report button open / toggle
document.getElementById("btnOpenReport")?.addEventListener("click", () => {
    const box = document.getElementById("reportBox");
    const reasonInput = document.getElementById("reportReason");
    const alertBox = document.getElementById("reportAlert");
    if (!box) return;

    if (box.style.display === "none" || !box.style.display) {
        box.style.display = "block";
        if (alertBox) alertBox.style.display = "none";
        if (reasonInput) reasonInput.focus();
        box.scrollIntoView({ behavior: "smooth", block: "nearest" });
    } else {
        box.style.display = "none";
    }
});

document.getElementById("btnCloseReport")?.addEventListener("click", () => {
    const box = document.getElementById("reportBox");
    if (box) box.style.display = "none";
});

document.getElementById("btnCancelReport")?.addEventListener("click", () => {
    const box = document.getElementById("reportBox");
    if (box) box.style.display = "none";
});

// Submit report
document.getElementById("btnSubmitReport")?.addEventListener("click", async () => {
    const reasonInput = document.getElementById("reportReason");
    const btn = document.getElementById("btnSubmitReport");
    const alertBox = document.getElementById("reportAlert");
    const reason = reasonInput?.value.trim();

    if (!reason) {
        if (alertBox) {
            alertBox.className = "report-alert error";
            alertBox.innerHTML = "<span>⚠️</span> Please enter a reason before submitting.";
            alertBox.style.display = "flex";
        }
        return;
    }

    btn.disabled = true;
    btn.textContent = "Submitting Report...";

    try {
        const response = await fetch(`${API_URL}/api/reports`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({
                scan_id: activeScanId,
                reason: reason
            })
        });

        const data = await response.json();
        if (data.success) {
            if (alertBox) {
                alertBox.className = "report-alert success";
                alertBox.innerHTML = `<span>✓</span> ${data.message || "Report submitted successfully! Thank you."}`;
                alertBox.style.display = "flex";
            }
            if (reasonInput) reasonInput.value = "";
            btn.textContent = "Report Submitted ✓";
            setTimeout(() => {
                const box = document.getElementById("reportBox");
                if (box) box.style.display = "none";
                btn.disabled = false;
                btn.textContent = "Submit Report 🚀";
                if (alertBox) alertBox.style.display = "none";
            }, 3000);
        } else {
            if (alertBox) {
                alertBox.className = "report-alert error";
                alertBox.innerHTML = `<span>⚠️</span> ${data.message || "Failed to submit report."}`;
                alertBox.style.display = "flex";
            }
            btn.disabled = false;
            btn.textContent = "Submit Report 🚀";
        }
    } catch (err) {
        console.error("Report submission failed:", err);
        if (alertBox) {
            alertBox.className = "report-alert error";
            alertBox.innerHTML = "<span>⚠️</span> Could not connect to report service.";
            alertBox.style.display = "flex";
        }
        btn.disabled = false;
        btn.textContent = "Submit Report 🚀";
    }
});

// ==========================================
// SCAN ACTIONS
// ==========================================

// 1. URL Scan
document.getElementById("submitUrlScan")?.addEventListener("click", async () => {
    const input = document.getElementById("urlInput");
    const btn = document.getElementById("submitUrlScan");
    const url = input?.value.trim();
    if (!url) {
        alert("Please enter a URL to analyze.");
        return;
    }

    btn.disabled = true;
    btn.textContent = "Scanning...";
    try {
        const response = await fetch(`${API_URL}/api/scan/url`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ url: url })
        });
        const data = await response.json();
        if (data.success) {
            displayResult(data, "url");
            fetchHistoryAndStats();
        } else {
            alert(data.message || "URL Scan error.");
        }
    } catch (err) {
        console.error(err);
        alert("Could not connect to Flask backend. Please make sure the server is running on http://127.0.0.1:5000");
    } finally {
        btn.disabled = false;
        btn.textContent = "Scan URL ⚡";
    }
});

// 2. Email Scan
document.getElementById("submitEmailScan")?.addEventListener("click", async () => {
    const subInput = document.getElementById("emailSubject");
    const bodyInput = document.getElementById("emailBody");
    const btn = document.getElementById("submitEmailScan");
    const subject = subInput?.value.trim() || "";
    const body = bodyInput?.value.trim() || "";

    if (!subject && !body) {
        alert("Please provide an email subject or body text to analyze.");
        return;
    }

    btn.disabled = true;
    btn.textContent = "Analyzing Email...";
    try {
        const response = await fetch(`${API_URL}/api/scan/email`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ subject: subject, body: body })
        });
        const data = await response.json();
        if (data.success) {
            displayResult(data, "email");
            fetchHistoryAndStats();
        } else {
            alert(data.message || "Email scan error.");
        }
    } catch (err) {
        console.error(err);
        alert("Could not connect to Flask backend. Please ensure app.py is running.");
    } finally {
        btn.disabled = false;
        btn.textContent = "Scan Email ⚡";
    }
});

// ==========================================
// QR CODE CAMERA & IMAGE SCANNING
// ==========================================

let html5QrCode = null;
let isCameraRunning = false;

// 1. QR Mode Switching (Camera vs Upload vs Manual)
const qrModeButtons = document.querySelectorAll(".qr-mode-btn");
const qrCameraPanel = document.getElementById("qrCameraPanel");
const qrFilePanel = document.getElementById("qrFilePanel");

function setQrMode(mode) {
    qrModeButtons.forEach(btn => {
        if (btn.dataset.qrmode === mode) {
            btn.classList.add("active");
        } else {
            btn.classList.remove("active");
        }
    });

    if (mode === "camera") {
        if (qrCameraPanel) qrCameraPanel.style.display = "block";
        if (qrFilePanel) qrFilePanel.style.display = "none";
    } else if (mode === "file") {
        if (qrCameraPanel) qrCameraPanel.style.display = "none";
        if (qrFilePanel) qrFilePanel.style.display = "block";
        stopQrCamera();
    } else {
        // Manual mode
        if (qrCameraPanel) qrCameraPanel.style.display = "none";
        if (qrFilePanel) qrFilePanel.style.display = "none";
        stopQrCamera();
        document.getElementById("qrInput")?.focus();
    }
}

qrModeButtons.forEach(btn => {
    btn.addEventListener("click", () => {
        setQrMode(btn.dataset.qrmode);
    });
});

// 2. Camera Controls
async function startQrCamera() {
    if (typeof Html5Qrcode === "undefined") {
        alert("QR Scanner library is still initializing. Please wait a moment.");
        return;
    }

    const placeholder = document.getElementById("qrCameraPlaceholder");
    const reader = document.getElementById("qrReader");
    const controls = document.getElementById("qrCameraControls");
    const select = document.getElementById("qrCameraSelect");
    const statusHint = document.getElementById("qrScanStatus");

    try {
        if (!html5QrCode) {
            html5QrCode = new Html5Qrcode("qrReader");
        }

        const devices = await Html5Qrcode.getCameras();
        if (!devices || devices.length === 0) {
            alert("No cameras detected on this device.");
            return;
        }

        if (select && select.options.length === 0) {
            select.innerHTML = devices.map((d, i) => `<option value="${d.id}">${d.label || `Camera ${i + 1}`}</option>`).join("");
            select.addEventListener("change", async () => {
                if (isCameraRunning) {
                    await stopQrCamera();
                    await startQrCamera();
                }
            });
        }

        const selectedCameraId = select?.value || devices[0].id;

        if (placeholder) placeholder.style.display = "none";
        if (reader) reader.style.display = "block";
        if (controls) controls.style.display = "flex";
        if (statusHint) statusHint.innerHTML = "<span>📷</span> Scanning active! Hold QR code in front of camera.";

        await html5QrCode.start(
            selectedCameraId,
            {
                fps: 10,
                qrbox: { width: 250, height: 250 }
            },
            (decodedText) => {
                onQrCodeDecoded(decodedText);
            },
            () => {
                // scanning frame
            }
        );

        isCameraRunning = true;

    } catch (err) {
        console.error("Camera startup error:", err);
        alert("Unable to access camera. Please check browser permissions and allow camera access.");
        stopQrCamera();
    }
}

async function stopQrCamera() {
    if (html5QrCode && isCameraRunning) {
        try {
            await html5QrCode.stop();
        } catch (e) {
            console.warn(e);
        }
        isCameraRunning = false;
    }

    const placeholder = document.getElementById("qrCameraPlaceholder");
    const reader = document.getElementById("qrReader");
    const controls = document.getElementById("qrCameraControls");
    const statusHint = document.getElementById("qrScanStatus");

    if (placeholder) placeholder.style.display = "block";
    if (reader) reader.style.display = "none";
    if (controls) controls.style.display = "none";
    if (statusHint) statusHint.innerHTML = "<span>💡</span> Point your camera at a QR code to automatically detect and scan.";
}

function onQrCodeDecoded(decodedText) {
    const input = document.getElementById("qrInput");
    const statusHint = document.getElementById("qrScanStatus");

    if (input) input.value = decodedText;
    if (statusHint) {
        statusHint.innerHTML = `<span>✅</span> <strong>QR Code Detected:</strong> <span style="color:#38bdf8;">${decodedText}</span>`;
    }

    // Auto-trigger security scan
    const submitBtn = document.getElementById("submitQrScan");
    if (submitBtn) {
        submitBtn.click();
    }
}

document.getElementById("btnStartQrCamera")?.addEventListener("click", startQrCamera);
document.getElementById("btnStopQrCamera")?.addEventListener("click", stopQrCamera);

// 3. QR Image File Upload & Dropzone
const qrFileInput = document.getElementById("qrFileInput");
const qrDropZone = document.getElementById("qrDropZone");
const btnBrowseQrFile = document.getElementById("btnBrowseQrFile");
const qrFilePreview = document.getElementById("qrFilePreview");
const qrFilePreviewContainer = document.getElementById("qrFilePreviewContainer");

btnBrowseQrFile?.addEventListener("click", (e) => {
    e.stopPropagation();
    qrFileInput?.click();
});

qrDropZone?.addEventListener("click", () => {
    qrFileInput?.click();
});

qrDropZone?.addEventListener("dragover", (e) => {
    e.preventDefault();
    qrDropZone.classList.add("dragover");
});

qrDropZone?.addEventListener("dragleave", () => {
    qrDropZone.classList.remove("dragover");
});

qrDropZone?.addEventListener("drop", (e) => {
    e.preventDefault();
    qrDropZone.classList.remove("dragover");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
        handleQrFile(e.dataTransfer.files[0]);
    }
});

qrFileInput?.addEventListener("change", (e) => {
    if (e.target.files && e.target.files.length > 0) {
        handleQrFile(e.target.files[0]);
    }
});

async function handleQrFile(file) {
    if (!file || !file.type.startsWith("image/")) {
        alert("Please select a valid image file (PNG, JPG, WebP).");
        return;
    }

    if (qrFilePreview && qrFilePreviewContainer) {
        qrFilePreview.src = URL.createObjectURL(file);
        qrFilePreviewContainer.style.display = "block";
    }

    try {
        if (!html5QrCode) {
            html5QrCode = new Html5Qrcode("qrReader");
        }
        const decodedText = await html5QrCode.scanFile(file, true);
        onQrCodeDecoded(decodedText);
    } catch (err) {
        console.error("QR file decode failed:", err);
        alert("No clear QR code could be detected in this image. Please try another image or paste the URL directly.");
    }
}

// 4. QR Submit Scan Action
document.getElementById("submitQrScan")?.addEventListener("click", async () => {
    const input = document.getElementById("qrInput");
    const btn = document.getElementById("submitQrScan");
    const url = input?.value.trim();
    if (!url) {
        alert("Please provide a QR decoded URL or content to analyze.");
        return;
    }

    btn.disabled = true;
    btn.textContent = "Analyzing QR Link...";
    try {
        const response = await fetch(`${API_URL}/api/scan/qr`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ url: url })
        });
        const data = await response.json();
        if (data.success) {
            displayResult(data, "qr");
            fetchHistoryAndStats();
        } else {
            alert(data.message || "QR scan error.");
        }
    } catch (err) {
        console.error(err);
        alert("Could not connect to Flask backend.");
    } finally {
        btn.disabled = false;
        btn.textContent = "Scan QR Target ⚡";
    }
});


// --- Fetch History & Statistics ---
async function fetchHistoryAndStats() {
    try {
        // Fetch stats
        const statsRes = await fetch(`${API_URL}/api/stats`);
        const statsData = await statsRes.json();
        if (statsData.success && statsData.stats) {
            const s = statsData.stats;
            const totalEl = document.getElementById("statTotalScans");
            const phishEl = document.getElementById("statPhishing");
            const suspEl = document.getElementById("statSuspicious");
            const safeEl = document.getElementById("statSafe");

            if (totalEl) totalEl.textContent = s.total_scans || 0;
            if (phishEl) phishEl.textContent = (s.by_verdict && s.by_verdict.phishing) || 0;
            if (suspEl) suspEl.textContent = (s.by_verdict && s.by_verdict.suspicious) || 0;
            if (safeEl) safeEl.textContent = (s.by_verdict && s.by_verdict.safe) || 0;
        }

        // Fetch history
        const histRes = await fetch(`${API_URL}/api/history?limit=15`);
        const histData = await histRes.json();
        const tbody = document.getElementById("historyTableBody");
        if (histData.success && tbody && histData.history) {
            if (histData.history.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#64748b; padding:20px;">No scans recorded yet. Run a scan above!</td></tr>`;
            } else {
                tbody.innerHTML = histData.history.map(item => {
                    const cleanInput = (item.input_data || "").length > 40
                        ? (item.input_data.substring(0, 40) + "...")
                        : item.input_data;
                    const dateStr = item.created_at || "Recent";
                    return `
                        <tr>
                            <td>#${item.id}</td>
                            <td><span style="text-transform: uppercase; font-size: 11px; font-weight:700;">${item.scan_type}</span></td>
                            <td title="${item.input_data}">${cleanInput}</td>
                            <td><span class="table-badge ${item.verdict}">${item.verdict}</span></td>
                            <td style="font-weight:700;">${item.risk_score}%</td>
                            <td style="color:#64748b; font-size:11px;">${dateStr}</td>
                        </tr>
                    `;
                }).join("");
            }
        }
    } catch (e) {
        console.warn("Could not load stats/history:", e);
    }
}

// --- User Authentication State ---
async function checkAuthState() {
    const navLoginBtn = document.getElementById("navLoginBtn");
    const navUserBadge = document.getElementById("navUserBadge");
    const navUsername = document.getElementById("navUsername");

    try {
        const res = await fetch(`${API_URL}/api/auth/me`, { credentials: "include" });
        const data = await res.json();
        if (data.authenticated && data.user) {
            localStorage.setItem("phishguard_user", JSON.stringify(data.user));
            if (navLoginBtn) navLoginBtn.style.display = "none";
            if (navUserBadge) navUserBadge.style.display = "flex";
            if (navUsername) navUsername.textContent = `👤 ${data.user.username}`;
            return data.user;
        } else {
            localStorage.removeItem("phishguard_user");
            if (navLoginBtn) navLoginBtn.style.display = "inline-flex";
            if (navUserBadge) navUserBadge.style.display = "none";
        }
    } catch (err) {
        const cached = localStorage.getItem("phishguard_user");
        if (cached) {
            try {
                const user = JSON.parse(cached);
                if (navLoginBtn) navLoginBtn.style.display = "none";
                if (navUserBadge) navUserBadge.style.display = "flex";
                if (navUsername) navUsername.textContent = `👤 ${user.username}`;
                return user;
            } catch (e) {}
        }
    }
    return null;
}

// Logout action
document.getElementById("navLogoutBtn")?.addEventListener("click", async () => {
    try {
        await fetch(`${API_URL}/api/auth/logout`, { method: "POST", credentials: "include" });
    } catch (e) {
        console.warn(e);
    }
    localStorage.removeItem("phishguard_user");
    window.location.reload();
});

// --- Update Pending Reports Counter Badge ---
async function updatePendingReportsBadge() {
    const badge = document.getElementById("navReportsPendingBadge");
    if (!badge) return;
    try {
        const res = await fetch(`${API_URL}/api/reports`);
        const data = await res.json();
        if (data.success && Array.isArray(data.reports)) {
            const pendingCount = data.reports.filter(r => (r.status || "").toLowerCase() === "pending").length;
            if (pendingCount > 0) {
                badge.textContent = pendingCount;
                badge.style.display = "inline-flex";
            } else {
                badge.style.display = "none";
            }
        }
    } catch (e) {
        // silent
    }
}

// Initial check on DOM load
document.addEventListener("DOMContentLoaded", () => {
    checkBackend();
    checkAuthState();
    updatePendingReportsBadge();
});



