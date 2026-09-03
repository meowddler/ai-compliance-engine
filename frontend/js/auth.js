// Shared client-side auth and API helpers.
//
// NOTE ON TOKEN STORAGE: the JWT lives in localStorage, which is readable by
// any script running on the page. That is acceptable while the app is
// same-origin and XSS sinks are closed, but httpOnly cookies would be the
// stronger design. Recorded as a known limitation rather than silently ignored.

// Same origin as the page: the backend serves this frontend, so relative URLs
// work in every environment. A hardcoded host would break the moment the app
// is deployed anywhere other than localhost.
const API_BASE = "";

// Requests that hang forever leave the UI stuck with no feedback.
const REQUEST_TIMEOUT_MS = 90000;   // generous: AI calls can take ~60s

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
  window.location.replace("login.html");
}

// Call at the top of every protected page.
// Returns false when unauthenticated so the caller can stop; assigning
// window.location does NOT halt script execution, and letting the rest of the
// page run fires API calls with no token.
function requireAuth() {
  if (!getToken()) {
    window.location.replace("login.html");
    return false;
  }
  return true;
}

// Wrapper so every API call carries the JWT and cannot hang indefinitely.
async function apiFetch(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  options.headers = {
    ...(options.headers || {}),
    "Authorization": `Bearer ${getToken()}`
  };
  options.signal = controller.signal;

  try {
    const res = await fetch(`${API_BASE}${path}`, options);

    if (res.status === 401) {
      // Token expired or invalid. Redirect and stop the caller from acting on
      // a dead response — returning it would let page code carry on rendering
      // against a body that isn't there.
      logout();
      throw new Error("Session expired");
    }
    return res;
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("The request timed out. The server may be busy.");
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

// Renders the shared sidebar into <div id="nav-placeholder"></div>.
//
// Built with DOM nodes rather than an HTML string: the username and role come
// from storage and must never be parsed as markup. This is the same fix
// applied to the scans, rules, dashboard and audit tables.
//
// The role check here only decides what to SHOW. It is not a security control —
// the backend independently authorises every request, so editing the stored
// role in devtools reveals a link but grants no access.
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

  const nav = document.createElement("nav");
  nav.className = "sidebar";

  const title = document.createElement("h1");
  title.textContent = "Compliance Engine";
  nav.appendChild(title);

  const badge = document.createElement("div");
  badge.className = "role-badge";
  badge.textContent = getUsername() || "";
  const roleTag = document.createElement("span");
  roleTag.className = "role-tag";
  roleTag.textContent = role || "";
  badge.appendChild(roleTag);
  nav.appendChild(badge);

  links.forEach(l => {
    const a = document.createElement("a");
    a.href = l.href;
    a.textContent = l.label;
    if (activePage === l.href) a.className = "active";
    nav.appendChild(a);
  });

  const out = document.createElement("a");
  out.href = "#";
  out.className = "logout";
  out.textContent = "Logout";
  out.onclick = (e) => { e.preventDefault(); logout(); };
  nav.appendChild(out);

  const placeholder = document.getElementById("nav-placeholder");
  placeholder.innerHTML = "";      // safe: clearing, not injecting
  placeholder.appendChild(nav);
}