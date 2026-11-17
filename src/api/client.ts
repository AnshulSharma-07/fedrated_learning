import { handleBrowserApiRequest } from '../browserEngine/handler';

const TOKEN_STORAGE_KEY = 'fl_ids_auth_token';

function isStaticBuild(): boolean {
  try {
    return (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_STATIC_MODE === 'true';
  } catch {
    return false;
  }
}

let detectedStaticHost = false;

export function getStoredToken(): string | null {
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setStoredToken(token: string | null): void {
  if (token) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  }
}

export async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> | undefined),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  if (isStaticBuild() || detectedStaticHost) {
    return handleBrowserApiRequest<T>(path, { ...options, headers });
  }

  try {
    const res = await fetch(path, {
      ...options,
      headers,
    });
    const contentType = res.headers.get('content-type') || '';
    if (!contentType.includes('application/json')) {
      // Static hosts (e.g., GitHub Pages without VITE_STATIC_MODE) return HTML 404/200 for /api/*
      detectedStaticHost = true;
      return handleBrowserApiRequest<T>(path, { ...options, headers });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const message = (data as { error?: string }).error || `Request failed (${res.status})`;
      throw new Error(message);
    }
    return data as T;
  } catch (err) {
    if (err instanceof TypeError) {
      // Network error reaching /api/* -> fallback to browser engine on static hosting
      detectedStaticHost = true;
      return handleBrowserApiRequest<T>(path, { ...options, headers });
    }
    throw err;
  }
}
