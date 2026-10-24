/* verify.js - verify a document against a signature package and a public key */
const form = document.getElementById("verify-form");
const alertBox = document.getElementById("alert");
const resultBox = document.getElementById("result");
const btn = document.getElementById("verify-btn");
const keySelect = document.getElementById("key-select");
const pubText = document.getElementById("public-key");

async function loadKeys() {
  try {
    const keys = await apiRequest("/api/keys");
    keySelect.innerHTML = '<option value="">- choose a registered signer -</option>' +
      keys.map((k) => '<option value="' + k.id + '">' + esc(k.owner_name) + " (" + shortFp(k.fingerprint) + ")</option>").join("");
  } catch (err) { /* dropdown stays empty; user can paste a PEM */ }
}

document.getElementById("pub-file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (f) { pubText.value = await readFileAsText(f); }
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  alertBox.innerHTML = "";
  resultBox.innerHTML = "";
  const doc = document.getElementById("doc-file").files[0];
  const sigFile = document.getElementById("sig-file").files[0];
  if (!doc) { showAlert(alertBox, "Please choose the document to verify."); return; }
  if (!sigFile) { showAlert(alertBox, "Please choose the signature file (.sig.json)."); return; }
  if (doc.size > 5 * 1024 * 1024) { showAlert(alertBox, "File is too large (limit is 5 MB)."); return; }
  if (!pubText.value.trim() && !keySelect.value) {
    showAlert(alertBox, "Choose a registered signer or provide a public key."); return;
  }
  let pkg;
  try { pkg = JSON.parse(await readFileAsText(sigFile)); }
  catch (_) { showAlert(alertBox, "The signature file is not valid JSON."); return; }

  setLoading(btn, true);
  try {
    const r = await apiRequest("/api/verify", {
      method: "POST",
      body: JSON.stringify({
        file_name: doc.name,
        file_b64: await readFileAsBase64(doc),
        signature_package: pkg,
        key_id: pubText.value.trim() ? null : Number(keySelect.value),
        public_key_pem: pubText.value.trim() || null,
      }),
    });
    const ok = r.status === "VALID";
    resultBox.innerHTML =
      '<div class="verdict ' + (ok ? "ok" : "bad") + '" role="status"><div class="big">' + (ok ? "&#10003; SIGNATURE VALID" : "&#10007; SIGNATURE INVALID") + "</div>" +
      "<p>" + esc(r.summary) + "</p></div>" +
      '<div class="card stack"><h2>What was checked</h2><ul class="checks">' +
      r.checks.map((c) =>
        '<li><span class="mark ' + (c.passed ? "ok" : "bad") + '" aria-hidden="true">' + (c.passed ? "&#10003;" : "&#10007;") +
        '</span><div><b>' + esc(c.name) + "</b> <span class=\"badge " + (c.passed ? "ok" : "bad") + '">' + (c.passed ? "PASS" : "FAIL") +
        '</span><div class="muted small">' + esc(c.detail) + "</div></div></li>").join("") +
      '</ul><dl class="kv"><dt>Signer</dt><dd>' + (r.signer_name ? esc(r.signer_name) : "Not in the registry") +
      "</dd><dt>Signed at (UTC)</dt><dd>" + esc(r.signed_at) + '</dd><dt>Hash of this file</dt><dd class="mono">' + esc(r.file_sha256) + "</dd></dl>" +
      '<p class="muted small">This is a cryptographic check. It proves the file is unchanged and the signature matches the key. It does not by itself prove who owns the key in real life.</p></div>';
    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  } catch (err) {
    showAlert(alertBox, err.message);
  } finally {
    setLoading(btn, false);
  }
});

loadKeys();
