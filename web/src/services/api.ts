import axios from 'axios';

export function apiErrorMessage(error: unknown, fallback: string): string {
  if (axios.isAxiosError<{ error?: unknown }>(error)) {
    const detail = error.response?.data?.error;
    if (typeof detail === 'string' && detail.trim()) return detail;
  }
  return error instanceof Error && error.message ? error.message : fallback;
}

// Create the axios instance
const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

export default api;
