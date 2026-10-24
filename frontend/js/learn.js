/* learn.js - live SHA-256 demo (runs fully in the browser; nothing is sent anywhere) */
const input = document.getElementById("hash-input");
const output = document.getElementById("hash-output");
let previous = "";

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function update() {
  if (!(window.crypto && crypto.subtle)) {
    output.textContent = "Your browser does not support this demo here (open the site via http://127.0.0.1:8000).";
    return;
  }
  const h = await sha256Hex(input.value);
  // highlight characters that changed compared with the previous hash
  output.innerHTML = h.split("").map((ch, i) =>
    previous && previous[i] !== ch ? '<mark style="background:var(--accent-strong);color:#fff;border-radius:3px">' + ch + "</mark>" : ch).join("");
  previous = h;
}
input.addEventListener("input", update);
update();
