import axios from 'axios'

const baseURL = import.meta.env.VITE_API_URL || 'http://localhost:5000'
const TOKEN_KEY = 'ts_jwt'

const api = axios.create({ baseURL })

export function getToken() {
  try {
    return localStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

export function setToken(token) {
  try {
    localStorage.setItem(TOKEN_KEY, token)
  } catch {}
}

export function clearToken() {
  try {
    localStorage.removeItem(TOKEN_KEY)
  } catch {}
}

api.interceptors.request.use((config) => {
  const token = getToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    const isLoginRequest = err.config?.url?.includes('/api/auth/login')
    if (err.response?.status === 401 && !isLoginRequest) {
      clearToken()
      window.location.reload()
    }
    return Promise.reject(err)
  }
)

export function core(path) {
  return `${baseURL}/api/core${path}`
}

export function ingest(path) {
  return `${baseURL}/api/ingest${path}`
}

export const WS_URL = `${baseURL.replace(/^http/, 'ws')}/ws`

export default api
