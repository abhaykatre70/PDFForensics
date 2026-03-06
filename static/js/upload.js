/**
 * upload.js — Drag-and-drop upload form logic
 */

(function () {
    "use strict";

    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("file-input");
    const analyzeBtn = document.getElementById("analyze-btn");
    const fileInfo = document.getElementById("drop-file-info");
    const fileNameEl = document.getElementById("file-name-display");
    const fileSizeEl = document.getElementById("file-size-display");
    const uploadForm = document.getElementById("upload-form");
    const btnText = document.querySelector(".btn-text");
    const btnLoading = document.querySelector(".btn-loading");

    if (!dropZone) return;

    // ── Drag events ──────────────────────────────────────────
    ["dragenter", "dragover"].forEach(evt => {
        dropZone.addEventListener(evt, e => {
            e.preventDefault();
            dropZone.classList.add("drag-over");
        });
    });

    ["dragleave", "dragend"].forEach(evt => {
        dropZone.addEventListener(evt, () => {
            dropZone.classList.remove("drag-over");
        });
    });

    dropZone.addEventListener("drop", e => {
        e.preventDefault();
        dropZone.classList.remove("drag-over");
        const file = e.dataTransfer?.files?.[0];
        if (file) setFile(file);
    });

    // ── Click on drop zone (not on buttons) ──────────────────
    dropZone.addEventListener("click", e => {
        if (e.target === dropZone ||
            e.target.classList.contains("drop-text") ||
            e.target.classList.contains("drop-hint") ||
            e.target.tagName === "STRONG") {
            fileInput.click();
        }
    });

    // ── File input change ─────────────────────────────────────
    fileInput.addEventListener("change", () => {
        const file = fileInput.files?.[0];
        if (file) setFile(file);
    });

    function setFile(file) {
        const maxMB = window.APP_MAX_UPLOAD_MB || 1024;
        const maxBytes = maxMB * 1024 * 1024;

        // Validate file extension / MIME type first
        if (!file.name.toLowerCase().endsWith(".pdf") &&
            file.type !== "application/pdf") {
            showError("Only PDF files are accepted.");
            return;
        }

        // On Vercel (serverless), the hard payload limit is ~4.5 MB.
        // Show a friendly warning instead of letting the server return a raw 413.
        // When running locally or via Docker, allow up to the server-configured maximum.
        if (window.APP_ON_VERCEL) {
            const VERCEL_MAX = 4.4 * 1024 * 1024; // 4.4 MB safe Vercel limit
            if (file.size > VERCEL_MAX) {
                showError(
                    `File is too large (${formatBytes(file.size)}) for Vercel deployment. ` +
                    `Max allowed on Vercel is 4.4 MB. ` +
                    `Run the app locally or via Docker to analyse larger files.`
                );
                return;
            }
        } else {
            // Local / Docker: respect the server-configured MAX_UPLOAD_MB
            if (file.size > maxBytes) {
                showError(`File is too large (${formatBytes(file.size)}). Maximum allowed is ${maxMB} MB.`);
                return;
            }
        }

        // Populate display
        fileNameEl.textContent = file.name;
        fileSizeEl.textContent = formatBytes(file.size);
        fileInfo.style.display = "flex";
        analyzeBtn.disabled = false;

        // Transfer to real input if dropped
        if (file !== fileInput.files?.[0]) {
            const dt = new DataTransfer();
            dt.items.add(file);
            fileInput.files = dt.files;
        }
    }

    // ── Form submit ───────────────────────────────────────────
    if (uploadForm) {
        uploadForm.addEventListener("submit", e => {
            if (!fileInput.files?.length) {
                e.preventDefault();
                showError("Please select a PDF file.");
                return;
            }
            // Show loading state
            if (btnText) btnText.style.display = "none";
            if (btnLoading) btnLoading.style.display = "flex";
            analyzeBtn.disabled = true;
        });
    }

    // ── Clear file selection ──────────────────────────────────
    window.clearFile = function () {
        fileInput.value = "";
        fileInfo.style.display = "none";
        analyzeBtn.disabled = true;
    };

    // ── Helpers ───────────────────────────────────────────────
    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / 1048576).toFixed(1) + " MB";
    }

    function showError(msg) {
        const existing = document.querySelector(".flash-error");
        if (existing) existing.remove();
        const flash = document.createElement("div");
        flash.className = "flash flash-error";
        flash.innerHTML = `<span>${msg}</span><button class="flash-close" onclick="this.parentElement.remove()">✕</button>`;
        const container = document.querySelector(".flash-container") || (() => {
            const c = document.createElement("div");
            c.className = "flash-container";
            document.body.appendChild(c);
            return c;
        })();
        container.appendChild(flash);
        setTimeout(() => flash.remove(), 5000);
    }
})();
