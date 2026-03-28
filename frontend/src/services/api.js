import axios from "axios";

const API = axios.create({
  baseURL: "http://127.0.0.1:8000",
});

export const AUTH_SESSION_KEY = "sentinel_auth_session";

const applyAuthHeader = (token) => {
  if (token) {
    API.defaults.headers.common.Authorization = `Bearer ${token}`;
    axios.defaults.headers.common.Authorization = `Bearer ${token}`;
  } else {
    delete API.defaults.headers.common.Authorization;
    delete axios.defaults.headers.common.Authorization;
  }
};

export const getAttackSummary = () => API.get("/attack-summary");
export const getAlerts = () => API.get("/alerts");

export const signupUser = (payload) => API.post("/auth/signup", payload);
export const loginUser = (payload) => API.post("/auth/login", payload);
export const logoutUser = () => API.post("/auth/logout");

export const saveAuthSession = (authData) => {
  localStorage.setItem(AUTH_SESSION_KEY, JSON.stringify(authData));
  applyAuthHeader(authData?.token);
};

export const getAuthSession = () => {
  try {
    const raw = localStorage.getItem(AUTH_SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    applyAuthHeader(parsed?.token);
    return parsed;
  } catch (error) {
    applyAuthHeader(null);
    return null;
  }
};

export const clearAuthSession = () => {
  localStorage.removeItem(AUTH_SESSION_KEY);
  applyAuthHeader(null);
};

export const parseApiError = (error, fallbackMessage) => {
  const message = error?.response?.data?.detail;
  if (typeof message === "string" && message.trim()) {
    return message;
  }
  return fallbackMessage;
};

const initialSession = getAuthSession();
if (initialSession?.token) {
  applyAuthHeader(initialSession.token);
}