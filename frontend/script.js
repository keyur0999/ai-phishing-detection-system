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
// PHISHGUARD AI - BACKEND CONNECTION
// ==========================================

const API_URL = "http://127.0.0.1:5000";


// ==========================================
// CHECK BACKEND CONNECTION
// ==========================================

async function checkBackend() {
    try {
        const response = await fetch(`${API_URL}/api/health`);
        const data = await response.json();

        console.log("Backend status:", data);

    } catch (error) {
        console.error("Backend is not connected:", error);
    }
}


// ==========================================
// URL SCAN
// ==========================================

async function scanURL(url) {
    try {
        const response = await fetch(`${API_URL}/api/scan/url`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        const data = await response.json();

        console.log("URL Scan Result:", data);

        return data;

    } catch (error) {
        console.error("URL scan failed:", error);

        return {
            success: false,
            message: "Unable to connect to backend."
        };
    }
}


// ==========================================
// EMAIL SCAN
// ==========================================

async function scanEmail(subject, body) {
    try {
        const response = await fetch(`${API_URL}/api/scan/email`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                subject: subject,
                body: body
            })
        });

        const data = await response.json();

        console.log("Email Scan Result:", data);

        return data;

    } catch (error) {
        console.error("Email scan failed:", error);

        return {
            success: false,
            message: "Unable to connect to backend."
        };
    }
}


// ==========================================
// QR SCAN
// ==========================================

async function scanQR(url) {
    try {
        const response = await fetch(`${API_URL}/api/scan/qr`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                url: url
            })
        });

        const data = await response.json();

        console.log("QR Scan Result:", data);

        return data;

    } catch (error) {
        console.error("QR scan failed:", error);

        return {
            success: false,
            message: "Unable to connect to backend."
        };
    }
}


// ==========================================
// TEST BACKEND WHEN PAGE LOADS
// ==========================================

document.addEventListener("DOMContentLoaded", () => {
    checkBackend();
});
