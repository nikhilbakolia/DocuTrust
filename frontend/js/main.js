/* main.js - shared helpers + site header/footer (used by every page). */

const NAV_ITEMS = [
  ["index.html", "Dashboard"],
  ["keys.html", "Keys"],
  ["sign.html", "Sign"],
  ["verify.html", "Verify"],
  ["history.html", "History"],
  ["learn.html", "Learn"],
  ["about.html", "About"],
];

/** Escape text before inserting into HTML (user-controlled values like file names!). */
function esc(value) {
  return String(value ?? "").replace(/[&<>"']/g, (c) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
  ));
}

/** Call the backend. Throws an Error with a friendly message on failure. */
async function apiRequest(path, options = {}) {
  let response;
  try {
    response = await fetch(path, {
      headers: { "Content-Type": "application/json" },
      ...options,
    });
  } catch (err) {
    throw new Error("Cannot reach the server. Is the backend running (uvicorn main:app --port 8000)?");
  }
  let data = null;
  try { data = await response.json(); } catch (_) { /* non-JSON response */ }
  if (!response.ok) {
    const detail = data && typeof data.detail === "string" ? data.detail : "Request failed (" + response.status + ").";
    throw new Error(detail);
  }
  return data;
}

/** Read a File as base64 (no "data:" prefix). */
function readFileAsBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",")[1] || "");
    reader.onerror = () => reject(new Error("Could not read the selected file."));
    reader.readAsDataURL(file);
  });
}

function readFileAsText(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(new Error("Could not read the selected file."));
    reader.readAsText(file);
  });
}

/** Trigger a browser download of text content. */
function downloadText(filename, text, mime = "text/plain") {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function formatDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return isNaN(d) ? esc(iso) : d.toLocaleString();
}

function shortFp(fp) {
  const head = String(fp || "").slice(0, 16).toUpperCase();
  return head.match(/.{1,2}/g)?.join(":") || "-";
}

function showAlert(container, message, type = "error") {
  container.innerHTML = '<div class="alert ' + type + '" role="alert">' + esc(message) + "</div>";
}

function setLoading(button, loading) {
  button.disabled = loading;
  button.classList.toggle("loading", loading);
}

function safeFileName(name) {
  return String(name || "file").replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 80);
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const old = button.textContent;
    button.textContent = "Copied!";
    setTimeout(() => (button.textContent = old), 1500);
  } catch (_) {
    button.textContent = "Copy failed";
  }
}

function buildChrome() {
  const page = location.pathname.split("/").pop() || "index.html";
  const header = document.getElementById("site-header");
  if (header) {
    const links = NAV_ITEMS.map(([href, label]) =>
      '<a href="' + href + '"' + (href === page ? ' aria-current="page"' : "") + ">" + label + "</a>").join("");
    header.className = "site-header";
    header.innerHTML =
      '<nav class="nav" aria-label="Main">' +
      '<a class="brand" href="index.html"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M8.5 12.5l2.5 2.5 4.5-5"/></svg>SignVerify</a>' +
      '<button class="nav-toggle" aria-expanded="false" aria-controls="nav-links">Menu</button>' +
      '<div class="nav-links" id="nav-links">' + links + "</div></nav>";
    const toggle = header.querySelector(".nav-toggle");
    const menu = header.querySelector(".nav-links");
    toggle.addEventListener("click", () => {
      const open = menu.classList.toggle("open");
      toggle.setAttribute("aria-expanded", String(open));
    });
  }
  const footer = document.getElementById("site-footer");
  if (footer) {
    footer.innerHTML = "Educational project: Digital Signature &amp; Document Verification System. " +
      "Not a legal e-signature service. Never use real confidential documents or real private keys here.";
  }
}

document.addEventListener("DOMContentLoaded", buildChrome);
