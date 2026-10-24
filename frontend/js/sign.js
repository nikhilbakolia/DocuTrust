/* sign.js - sign a document with a private key */
const form = document.getElementById("sign-form");
const alertBox = document.getElementById("alert");
const resultBox = document.getElementById("result");
const btn = document.getElementById("sign-btn");
const keyText = document.getElementById("private-key");

document.getElementById("key-file").addEventListener("change", async (e) => {
  const f = e.target.files[0];
  if (f) { keyText.value = await readFileAsText(f); }
});

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  alertBox.innerHTML = "";
  resultBox.innerHTML = "";
  const file = document.getElementById("doc-file").files[0];
  if (!file) { showAlert(alertBox, "Please choose a document to sign."); return; }
  if (file.size > 5 * 1024 * 1024) { showAlert(alertBox, "File is too large (limit is 5 MB)."); return; }
  if (!keyText.value.trim()) { showAlert(alertBox, "Please provide your private key (upload the .pem file or paste it)."); return; }
  setLoading(btn, true);
  try {
    const out = await apiRequest("/api/sign", {
      method: "POST",
      body: JSON.stringify({
        file_name: file.name,
        file_b64: await readFileAsBase64(file),
        private_key_pem: keyText.value,
        passphrase: document.getElementById("passphrase").value || null,
      }),
    });
    const p = out.package;
    const who = out.registered ? esc(out.signer_name) : "Unregistered key";
    resultBox.innerHTML =
      '<div class="card stack"><h2>Document signed</h2>' +
      '<div class="alert success">The signature package is ready. Send it together with the document.</div>' +
      '<dl class="kv"><dt>Document</dt><dd>' + esc(p.file_name) + "</dd><dt>Signer</dt><dd>" + who +
      "</dd><dt>SHA-256</dt><dd class=\"mono\">" + esc(p.file_sha256) + "</dd><dt>Signed at (UTC)</dt><dd>" + esc(p.signed_at) +
      "</dd><dt>Algorithm</dt><dd>" + esc(p.algorithm) + "</dd></dl>" +
      '<div class="btn-row"><button class="btn" id="dl-sig">Download signature file (.sig.json)</button></div>' +
      '<details><summary>Show signature (base64)</summary><pre class="pem">' + esc(p.signature_b64) + "</pre></details></div>";
    document.getElementById("dl-sig").addEventListener("click", () =>
      downloadText(safeFileName(p.file_name) + ".sig.json", JSON.stringify(p, null, 2), "application/json"));
  } catch (err) {
    showAlert(alertBox, err.message);
  } finally {
    setLoading(btn, false);
  }
});
