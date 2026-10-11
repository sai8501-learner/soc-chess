/**
 * SOC CHESS — Centralized API Client with Comprehensive Error Handling
 */

export interface ApiErrorDetails {
  status: number;
  statusText: string;
  message: string;
  endpoint: string;
  isNetworkError?: boolean;
}

export class ApiError extends Error {
  details: ApiErrorDetails;

  constructor(details: ApiErrorDetails) {
    super(details.message);
    this.name = 'ApiError';
    this.details = details;
  }
}

// Centralized API Base URL (defaults to empty string so requests use the Vite proxy / relative path)
export const API_BASE_URL: string = (
  (import.meta as any).env?.VITE_API_BASE_URL !== undefined
    ? (import.meta as any).env.VITE_API_BASE_URL
    : ''
).replace(/\/$/, '');

const ACCESS_TOKEN_STORAGE_KEY = 'soc-chess-access-token';

export const getAccessToken = (): string => localStorage.getItem(ACCESS_TOKEN_STORAGE_KEY) || '';

export const setAccessToken = (token: string): void => {
  localStorage.setItem(ACCESS_TOKEN_STORAGE_KEY, token);
};

export const clearAccessToken = (): void => {
  localStorage.removeItem(ACCESS_TOKEN_STORAGE_KEY);
};

export const apiUrl = (path: string): string => `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;

const withAuthHeaders = (headers: Record<string, string> = {}): Record<string, string> => {
  const token = getAccessToken();
  return token ? { ...headers, Authorization: `Bearer ${token}` } : headers;
};

async function handleResponse<T>(res: Response, endpoint: string): Promise<T> {
  if (!res.ok) {
    let errMsg = `HTTP ${res.status} (${res.statusText})`;
    try {
      const errorJson = await res.json();
      if (errorJson.detail) {
        errMsg = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
      } else if (errorJson.message) {
        errMsg = errorJson.message;
      }
    } catch {
      try {
        const text = await res.text();
        if (text) errMsg = text.slice(0, 300);
      } catch {}
    }

    if (res.status === 500 && (errMsg === 'HTTP 500 (Internal Server Error)' || errMsg.includes('ECONNREFUSED') || errMsg.includes('connect ECONNREFUSED'))) {
      errMsg = 'Backend server (Port 8001) is offline or unreachable. Please verify the backend is running.';
    }

    throw new ApiError({
      status: res.status,
      statusText: res.statusText,
      message: errMsg,
      endpoint
    });
  }

  try {
    return await res.json();
  } catch (err: any) {
    throw new ApiError({
      status: res.status,
      statusText: res.statusText,
      message: `Invalid JSON response from backend: ${err.message}`,
      endpoint
    });
  }
}

function handleFetchError(err: any, endpoint: string): never {
  if (err instanceof ApiError) {
    throw err;
  }

  const isConnRefused = err.message?.includes('Failed to fetch') ||
    err.message?.includes('NetworkError') ||
    err.name === 'TypeError';

  const displayTarget = API_BASE_URL || 'http://127.0.0.1:8001';
  const friendlyMsg = isConnRefused
    ? `BACKEND CONNECTION FAILED: Unable to reach ${displayTarget}. Check that the SOC Chess backend is running on port 8001.`
    : `Network error on ${endpoint}: ${err.message || 'Unknown network failure'}`;

  throw new ApiError({
    status: 0,
    statusText: 'Network / Connection Error',
    message: friendlyMsg,
    endpoint,
    isNetworkError: true
  });
}

export const apiClient = {
  get: async <T>(path: string, timeoutMs = 60000): Promise<T> => {
    const fullUrl = apiUrl(path);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(fullUrl, {
        method: 'GET',
        headers: withAuthHeaders({ 'Accept': 'application/json' }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return await handleResponse<T>(res, path);
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new ApiError({
          status: 408,
          statusText: 'Request Timeout',
          message: `Request timed out after ${timeoutMs / 1000}s on ${path}`,
          endpoint: path
        });
      }
      return handleFetchError(err, path);
    }
  },

  post: async <T>(path: string, body?: any, timeoutMs = 90000): Promise<T> => {
    const fullUrl = apiUrl(path);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(fullUrl, {
        method: 'POST',
        headers: withAuthHeaders({
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }),
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return await handleResponse<T>(res, path);
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new ApiError({
          status: 408,
          statusText: 'Request Timeout',
          message: `Request timed out after ${timeoutMs / 1000}s on ${path}`,
          endpoint: path
        });
      }
      return handleFetchError(err, path);
    }
  },

  patch: async <T>(path: string, body?: any, timeoutMs = 30000): Promise<T> => {
    const fullUrl = apiUrl(path);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(fullUrl, {
        method: 'PATCH',
        headers: withAuthHeaders({
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        }),
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return await handleResponse<T>(res, path);
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new ApiError({
          status: 408,
          statusText: 'Request Timeout',
          message: `Request timed out after ${timeoutMs / 1000}s on ${path}`,
          endpoint: path
        });
      }
      return handleFetchError(err, path);
    }
  },

  upload: async <T>(path: string, formData: FormData, timeoutMs = 60000): Promise<T> => {
    const fullUrl = apiUrl(path);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(fullUrl, {
        method: 'POST',
        headers: withAuthHeaders(),
        body: formData,
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return await handleResponse<T>(res, path);
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new ApiError({
          status: 408,
          statusText: 'Upload Timeout',
          message: `Upload request timed out after ${timeoutMs / 1000}s on ${path}`,
          endpoint: path
        });
      }
      return handleFetchError(err, path);
    }
  },

  delete: async <T>(path: string, timeoutMs = 30000): Promise<T> => {
    const fullUrl = apiUrl(path);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const res = await fetch(fullUrl, {
        method: 'DELETE',
        headers: withAuthHeaders({ 'Accept': 'application/json' }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      return await handleResponse<T>(res, path);
    } catch (err: any) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new ApiError({
          status: 408,
          statusText: 'Request Timeout',
          message: `Request timed out after ${timeoutMs / 1000}s on ${path}`,
          endpoint: path
        });
      }
      return handleFetchError(err, path);
    }
  },

  download: async (path: string, filename: string, timeoutMs = 60000): Promise<void> => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(apiUrl(path), {
        headers: withAuthHeaders({ 'Accept': 'application/octet-stream' }),
        signal: controller.signal,
      });
      if (!response.ok) {
        await handleResponse<never>(response, path);
      }
      const blob = await response.blob();
      const objectUrl = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.style.display = 'none';
      link.href = objectUrl;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      setTimeout(() => {
        if (link.parentNode) {
          link.parentNode.removeChild(link);
        }
        URL.revokeObjectURL(objectUrl);
      }, 1000);
    } finally {
      clearTimeout(timeoutId);
    }
  },
};
