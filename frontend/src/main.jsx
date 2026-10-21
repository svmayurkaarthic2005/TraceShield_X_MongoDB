import React, { useEffect, useState } from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import LoginPage from './components/LoginPage'
import { getToken, clearToken } from './services/api'
import './index.css'

function Root() {
  const [authed, setAuthed] = useState(() => Boolean(getToken()))

  // api.js dispatches this when a request comes back 401 (e.g. expired JWT)
  useEffect(() => {
    const onUnauthorized = () => setAuthed(false)
    window.addEventListener('ts:unauthorized', onUnauthorized)
    return () => window.removeEventListener('ts:unauthorized', onUnauthorized)
  }, [])

  if (!authed) return <LoginPage onSuccess={() => setAuthed(true)} />
  return <App onLogout={() => { clearToken(); setAuthed(false) }} />
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
)
