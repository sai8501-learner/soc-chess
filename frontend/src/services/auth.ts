import {
  API_BASE_URL,
  clearAccessToken,
  getAccessToken,
  setAccessToken,
} from './apiClient';

export interface AuthStatus {
  enabled: boolean;
  configured: boolean;
  bootstrap_required: boolean;
}

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  role: string;
}

interface AuthSession {
  access_token: string;
  token_type: string;
  user: AuthUser;
}

const authUrl = (path: string) => `${API_BASE_URL}${path}`;

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  try {
    const response = await fetch(authUrl(path), init);
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      let errMsg = `Request failed with status ${response.status}`;
      if (payload.detail) {
        if (typeof payload.detail === 'string') {
          errMsg = payload.detail;
        } else if (Array.isArray(payload.detail) && payload.detail.length > 0) {
          errMsg = payload.detail.map((e: any) => e.msg || JSON.stringify(e)).join(', ');
        } else {
          errMsg = JSON.stringify(payload.detail);
        }
      } else if (payload.message) {
        errMsg = payload.message;
      } else if (response.status === 500 || response.status === 503) {
        errMsg = 'Database connection error. Please ensure WampServer (MySQL :3306) and Backend are running.';
      }
      throw new Error(errMsg);
    }
    return response.json() as Promise<T>;
  } catch (err: any) {
    if (err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')) {
      throw new Error('Unable to reach backend server. Please verify backend is running on port 8001.');
    }
    throw err;
  }
}

function storeSession(session: AuthSession): AuthUser {
  setAccessToken(session.access_token);
  return session.user;
}

export const authApi = {
  getStatus: () => request<AuthStatus>('/api/auth/status'),

  login: async (username: string, password: string) => {
    const session = await request<AuthSession>('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    return storeSession(session);
  },

  bootstrap: async (username: string, email: string, password: string) => {
    const session = await request<AuthSession>('/api/auth/bootstrap', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    });
    return storeSession(session);
  },

  register: async (username: string, email: string, password: string) => {
    const session = await request<AuthSession>('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    });
    return storeSession(session);
  },

  getCurrentUser: () =>
    request<AuthUser>('/api/auth/me', {
      headers: { Authorization: `Bearer ${getAccessToken()}` },
    }),

  signOut: clearAccessToken,
};
