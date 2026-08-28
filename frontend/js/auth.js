const API_BASE = "http://127.0.0.1:8000";

function saveSession(token, username, role) {
  localStorage.setItem("token", token);
  localStorage.setItem("username", username);
  localStorage.setItem("role", role);
}

function getToken() { return localStorage.getItem("token"); }
function getUsername() { return localStorage.getItem("username"); }
function getRole() { return localStorage.getItem("role"); }

function logout() {
  localStorage.clear();
  window.location.href = "login.html";
}

// Redirect to login if not authenticated — call at the top of every protected page
function requireAuth() {
  if (!getToken()) window.location.href = "login.html";
}

// Wrapper so every API call automatically includes the JWT
async function apiFetch(path, options = {}) {
  options.headers = {
    ...(options.headers || {}),
    "Authorization": `Bearer ${getToken()}`
  };
  const res = await fetch(`${API_BASE}${path}`, options);
  if (res.status === 401) {
    logout(); // token expired/invalid — force re-login
  }
  return res;
}

// Renders the shared sidebar into <div id="nav-placeholder"></div>
function renderNav(activePage) {
  const role = getRole();
  const links = [
    { href: "dashboard.html", label: "Dashboard" },
    { href: "scans.html", label: "Scans" },
    { href: "rules.html", label: "Rules" },
    { href: "reports.html", label: "Reports" },
  ];
  if (role === "Admin" || role === "Auditor") {
    links.push({ href: "audit.html", label: "Audit Log" });
  }

  const linksHtml = links.map(l =>
    `<a href="${l.href}" class="${activePage === l.href ? 'active' : ''}">${l.label}</a>`
  ).join("");

  document.getElementById("nav-placeholder").innerHTML = `
    <nav class="sidebar">
      <h1>Compliance Engine</h1>
      <div class="role-badge">${getUsername()} <span class="role-tag">${role}</span></div>
      ${linksHtml}
      <a href="#" class="logout" onclick="logout()">Logout</a>
    </nav>
  `;
}