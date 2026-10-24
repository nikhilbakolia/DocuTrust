/* history.js - activity log + details dialog */
const body = document.getElementById("history-body");
const dialog = document.getElementById("detail-dialog");
const dialogBody = document.getElementById("detail-body");

function badge(result) {
  const cls = result === "INVALID" ? "bad" : result === "VALID" ? "ok" : "neutral";
  return '<span class="badge ' + cls + '">' + esc(result) + "</span>";
}

(async function load() {
  try {
    const items = await apiRequest("/api/history?limit=100");
    body.innerHTML = items.length
      ? items.map((r) =>
          "<tr><td>" + formatDate(r.created_at) + "</td><td>" + esc(r.action) + "</td><td>" + esc(r.file_name || "-") +
          "</td><td>" + badge(r.result) + '</td><td><button class="btn secondary view" data-id="' + r.id + '">View</button></td></tr>').join("")
      : '<tr><td colspan="5" class="muted">No activity yet.</td></tr>';
    body.querySelectorAll(".view").forEach((b) => b.addEventListener("click", async () => {
      try {
        const r = await apiRequest("/api/history/" + b.dataset.id);
        dialogBody.innerHTML =
          '<dl class="kv"><dt>ID</dt><dd>' + r.id + "</dd><dt>Time</dt><dd>" + formatDate(r.created_at) +
          "</dd><dt>Action</dt><dd>" + esc(r.action) + "</dd><dt>Result</dt><dd>" + badge(r.result) +
          "</dd><dt>File</dt><dd>" + esc(r.file_name || "-") + '</dd><dt>File SHA-256</dt><dd class="mono">' + esc(r.file_sha256 || "-") +
          '</dd><dt>Key fingerprint</dt><dd class="mono">' + esc(r.signer_fingerprint ? shortFp(r.signer_fingerprint) : "-") +
          "</dd><dt>Details</dt><dd>" + esc(r.detail) + "</dd></dl>";
        dialog.showModal();
      } catch (err) { alert(err.message); }
    }));
  } catch (err) {
    body.innerHTML = '<tr><td colspan="5" class="muted">' + esc(err.message) + "</td></tr>";
  }
})();

document.getElementById("close-dialog").addEventListener("click", () => dialog.close());
