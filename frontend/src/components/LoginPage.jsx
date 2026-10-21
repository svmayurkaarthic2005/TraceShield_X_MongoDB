import { useState } from 'react'
import api, { setToken } from '../services/api'

export default function LoginPage({ onSuccess }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError]       = useState(null)
  const [loading, setLoading]   = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError(null)
    try {
      const r = await api.post('/api/auth/login', { username, password })
      setToken(r.data.token)
      onSuccess()
    } catch (err) {
      const data = err.response?.data
      let msg = data?.error || 'Login failed — is the server running?'
      if (data?.retryAfterSeconds) {
        msg += ` (try again in ${Math.ceil(data.retryAfterSeconds / 60)} min)`
      }
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0A0E1A] p-4">
      <div className="w-full max-w-sm cyber-panel p-8 border-t-2 border-t-[#00F0FF]">
        <div className="flex items-center gap-3 mb-8 justify-center">
          <i className="ph ph-shield-checkered text-3xl text-[#00F0FF]" />
          <h1 className="text-2xl font-bold font-['Rajdhani'] uppercase tracking-widest text-white">
            Trace<span className="text-[#00F0FF]">Shield</span> X
          </h1>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-[10px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest block mb-1.5">
              Operator ID
            </label>
            <input
              className="cyber-input w-full"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoFocus
              required
            />
          </div>
          <div>
            <label className="text-[10px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest block mb-1.5">
              Passphrase
            </label>
            <input
              type="password"
              className="cyber-input w-full"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>

          {error && (
            <div className="text-[11px] text-[#FF003C] mono-text px-3 py-2 rounded border border-[#FF003C]/30 bg-[#FF003C]/10">
              {error}
            </div>
          )}

          <button type="submit" disabled={loading} className="cyber-btn w-full h-11 mt-2 border-[#00F0FF] text-[#00F0FF]">
            <i className={`ph ${loading ? 'ph-spinner animate-spin' : 'ph-lock-key'} text-lg`} />
            {loading ? 'Authenticating...' : 'Authenticate'}
          </button>
        </form>
      </div>
    </div>
  )
}
