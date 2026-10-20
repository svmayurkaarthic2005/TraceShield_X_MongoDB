import React, { useState } from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import LoginPage from './components/LoginPage'
import { getToken } from './services/api'
import './index.css'

function Root() {
  const [authed, setAuthed] = useState(() => Boolean(getToken()))
  if (!authed) return <LoginPage onSuccess={() => setAuthed(true)} />
  return <App onLogout={() => setAuthed(false)} />
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <Root />
  </React.StrictMode>
)
