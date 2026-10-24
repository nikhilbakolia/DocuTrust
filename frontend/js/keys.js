/* keys.js - generate key pairs + list registered public keys */
const form = document.getElementById("keygen-form");
const resultBox = document.getElementById("result");
const alertBox = document.getElementById("alert");
const btn = document.getElementById("gen-btn");
const keysBody = document.getElementById("keys-body");

async function loadKeys() {
  try {
    const keys = await apiRequest("/api/keys");
    keysBody.innerHTML = keys.length
      ? keys.map((k) =>
          "<tr><td>" + k.id + "</td><td>" + esc(k.owner_name) + '</td><td class="mono">' + shortFp(k.fingerprint) +
          "</td><td>" + formatDate(k.created_at) + '</td><td><button class="btn secondary dl-pub" data-id="' + k.id + '">Public key</button></td></tr>').join("")
      : '<tr><td colspan="5" class="muted">No keys registered yet.</td></tr>';
    keysBody.querySelectorAll(".dl-pub").forEach((b) => b.addEventListener("click", () => {
      const k = keys.find((x) => String(x.id) === b.dataset.id);
      downloadText(safeFileName(k.owner_name) + "_public_key.pem", k.public_key_pem);
    }));
  } catch (err) {
    keysBody.innerHTML = '<tr><td colspan="5" class="muted">' + esc(err.message) + "</td></tr>";
  }
}

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  alertBox.innerHTML = "";
  resultBox.innerHTML = "";
  const owner = document.getElementById("owner").value.trim();
  const pass = document.getElementById("passphrase").value;
  const pass2 = document.getElementById("passphrase2").value;
  if (pass !== pass2) { showAlert(alertBox, "The two passphrases do not match."); return; }
  setLoading(btn, true);
  try {
    const k = await apiRequest("/api/keys/generate", {
      method: "POST",
      body: JSON.stringify({ owner_name: owner, passphrase: pass || null }),
    });
    resultBox.innerHTML =
      '<div class="card stack"><h2>Key pair created for ' + esc(k.owner_name) + "</h2>" +
      '<div class="alert success">Download your <b>private key</b> now. The server does NOT keep it, so it cannot be recovered later.</div>' +
      '<dl class="kv"><dt>Key ID</dt><dd>' + k.key_id + "</dd><dt>Fingerprint</dt><dd class=\"mono\">" + esc(k.short_fingerprint) +
      "</dd><dt>Private key</dt><dd>" + (k.encrypted ? "Encrypted with your passphrase" : "NOT encrypted (no passphrase set)") + "</dd></dl>" +
      '<div class="btn-row"><button class="btn" id="dl-priv">Download private key (keep secret)</button>' +
      '<button class="btn secondary" id="dl-pub">Download public key</button></div>' +
      '<details><summary>Show public key (PEM)</summary><pre class="pem">' + esc(k.public_key_pem) + "</pre></details></div>";
    const base = safeFileName(k.owner_name);
    document.getElementById("dl-priv").addEventListener("click", () => downloadText(base + "_private_key.pem", k.private_key_pem));
    document.getElementById("dl-pub").addEventListener("click", () => downloadText(base + "_public_key.pem", k.public_key_pem));
    form.reset();
    loadKeys();
  } catch (err) {
    showAlert(alertBox, err.message);
  } finally {
    setLoading(btn, false);
  }
});

loadKeys();
