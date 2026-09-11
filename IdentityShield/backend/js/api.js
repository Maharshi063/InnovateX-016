// Automatically talks to Flask on port 5000 whether you open via Live Server (5500) or Flask (5000)
const API_BASE = (window.location.port === "5500" || window.location.port === "3000") 
  ? "http://127.0.0.1:5000/api" 
  : "/api";

async function request(endpoint, options = {}) {
  options.credentials = "include"; // Keeps you logged in by sending session cookies
  options.headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  const response = await fetch(`${API_BASE}${endpoint}`, options);
  const data = await response.json();
  
  if (!response.ok) {
    throw new Error(data.error || `Request failed with status ${response.status}`);
  }
  return data;
}

const api = {
  // Authentication
  login: (credentials) => request("/login", { method: "POST", body: JSON.stringify(credentials) }),
  register: (userData) => request("/register", { method: "POST", body: JSON.stringify(userData) }),
  logout: () => request("/logout", { method: "POST" }),
  getProfile: () => request("/profile"),

  // Data fetching
  getDashboard: () => request("/dashboard"),
  getAliases: () => request("/aliases"),
  getExposureEvents: () => request("/exposure"),
  getExposureDetail: (id) => request(`/exposure/${id}`),

  // Alias Actions
  createAlias: (data) => request("/aliases", { method: "POST", body: JSON.stringify(data) }),
  toggleAliasStatus: (id) => request(`/aliases/${id}`, { method: "PATCH", body: JSON.stringify({ action: "toggle_status" }) }),
  rotateAlias: (id) => request(`/aliases/${id}`, { method: "PATCH", body: JSON.stringify({ action: "rotate" }) }),

  // Exposure Simulation
  simulateExposure: (data) => request("/exposure/simulate", { method: "POST", body: JSON.stringify(data) })
};