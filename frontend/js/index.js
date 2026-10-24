/* index.js - dashboard */
(async function () {
  const statsBox = document.getElementById("stats");
  const recentBody = document.getElementById("recent-body");
  const status = document.getElementById("server-status");
  try {
    await apiRequest("/api/health");
    status.textContent = "Server online";
    status.className = "badge ok";
    const s = await apiRequest("/api/stats");
    const cards = [
      ["Registered keys", s.registered_keys, ""],
      ["Documents signed", s.documents_signed, ""],
      ["Verifications", s.verifications, ""],
      ["Valid results", s.valid_results, "ok"],
      ["Invalid results", s.invalid_results, "bad"],
    ];
    statsBox.innerHTML = cards.map(([label, num, cls]) =>
      '<div class="card stat ' + cls + '"><div class="num">' + num + '</div><div class="label">' + label + "</div></div>").join("");
    recentBody.innerHTML = s.recent.length
      ? s.recent.map((r) =>
          "<tr><td>" + formatDate(r.created_at) + "</td><td>" + esc(r.action) + "</td><td>" + esc(r.file_name || "-") +
          '</td><td><span class="badge ' + (r.result === "INVALID" ? "bad" : r.result === "VALID" ? "ok" : "neutral") + '">' + esc(r.result) + "</span></td></tr>").join("")
      : '<tr><td colspan="4" class="muted">No activity yet. Generate a key pair to get started.</td></tr>';
  } catch (err) {
    status.textContent = "Server offline";
    status.className = "badge bad";
    showAlert(statsBox, err.message);
    recentBody.innerHTML = '<tr><td colspan="4" class="muted">Unavailable</td></tr>';
  }
})();
