const API_BASE = import.meta.env.VITE_API_URL || 'https://web-production-bdd26.up.railway.app';

class ApiClient {
  constructor() {
    this.base = API_BASE.replace(/\/+$/, '');
  }

  getToken() {
    return localStorage.getItem('gl_token');
  }

  async request(method, path, body = null) {
    const headers = { 'Content-Type': 'application/json' };
    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const opts = { method, headers };
    if (body) {
      opts.body = JSON.stringify(body);
    }

    const res = await fetch(`${this.base}${path}`, opts);

    if (res.status === 401) {
      localStorage.removeItem('gl_token');
      localStorage.removeItem('gl_email');
      window.dispatchEvent(new Event('gl:logout'));
      throw new Error('Session expired');
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(err.detail || err.message || `Request failed (${res.status})`);
    }

    return res.json();
  }

  get(path) {
    return this.request('GET', path);
  }

  post(path, body) {
    return this.request('POST', path, body);
  }

  // --- Auth ---
  login(email, password) {
    return this.post('/auth/login', { email, password });
  }

  // --- Dashboard ---
  getDashboard() {
    return this.get('/v1/dashboard');
  }

  // --- Models ---
  getModels() {
    return this.get('/v1/models');
  }

  // --- Ledger ---
  getLedger(page = 1, perPage = 50) {
    return this.get(`/ledger?page=${page}&per_page=${perPage}`);
  }

  verifyChain() {
    return this.get('/ledger/verify');
  }

  // --- Risk ---
  scoreRisk(payload) {
    return this.post('/risk-score', payload);
  }

  // --- Frameworks ---
  getFrameworks() {
    return this.get('/frameworks');
  }
}

const api = new ApiClient();
export default api;
