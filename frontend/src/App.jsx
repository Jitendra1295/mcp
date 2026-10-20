import { useEffect, useState } from 'react'
import './App.css'

async function request(path, options = {}) {
  const response = await fetch(path, { ...options, credentials: 'same-origin', headers: { Accept: 'application/json', ...options.headers } })
  if (response.status === 204) return null
  const data = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(data?.error?.message || 'Something went wrong. Please try again.')
  return data
}

function Brand({ compact = false }) {
  return <div className={`brand ${compact ? 'brand-compact' : ''}`}><span className="brand-mark">S</span><span>mini sherlocq<span className="brand-dot">.</span></span></div>
}

function PasswordField({ value, onChange, name = 'password', autoComplete = 'current-password' }) {
  const [visible, setVisible] = useState(false)
  return <div className="password-wrap"><input id={name} name={name} type={visible ? 'text' : 'password'} value={value} onChange={onChange} autoComplete={autoComplete} required minLength={1} /><button type="button" className="show-password" onClick={() => setVisible(!visible)} aria-label={visible ? 'Hide password' : 'Show password'}>{visible ? 'Hide' : 'Show'}</button></div>
}

function Login({ onLogin, initialError = '' }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [csrf, setCsrf] = useState('')
  const [error, setError] = useState(initialError)
  const [loading, setLoading] = useState(false)
  const [serviceState, setServiceState] = useState('checking')

  async function checkSession() {
    try {
      const session = await request('/api/session')
      setCsrf(session.csrfToken)
      setServiceState('ready')
    } catch {
      setCsrf('')
      setServiceState('unavailable')
    }
  }

  useEffect(() => {
    let active = true
    request('/api/session').then((session) => {
      if (!active) return
      setCsrf(session.csrfToken)
      setServiceState('ready')
    }).catch(() => {
      if (!active) return
      setServiceState('unavailable')
    })
    return () => { active = false }
  }, [])

  async function submit(event) {
    event.preventDefault()
    setError('')
    setLoading(true)
    try {
      let csrfToken = csrf
      if (!csrfToken) {
        const session = await request('/api/session')
        csrfToken = session.csrfToken
        setCsrf(csrfToken)
        setServiceState('ready')
      }
      const result = await request('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
        body: JSON.stringify({ email, password }),
      })
      onLogin(result)
    } catch (e) {
      if (e instanceof TypeError) {
        setServiceState('unavailable')
        setError('We couldn’t connect just now. Please try again in a moment.')
      } else setError(e.message)
    } finally { setLoading(false) }
  }

  return <main className="auth-shell"><section className="login-card"><Brand /><div className="eyebrow">YOUR PRIVATE MCP WORKSPACE</div><h1>Welcome back</h1><p className="muted">Sign in to manage your Mini Sherlocq connection.</p>{serviceState === 'unavailable' && <div className="service-offline" role="status"><span className="offline-mark" aria-hidden="true">!</span><div><h2>Sign-in is temporarily unavailable</h2><p>We can’t connect right now. Please try again in a moment.</p><button type="button" className="retry-button" onClick={() => { setError(''); setServiceState('checking'); checkSession() }}>Try again</button></div></div>}{serviceState === 'checking' && <div className="service-checking-inline" role="status"><span className="spinner service-spinner" /> Checking sign-in service…</div>}<form onSubmit={submit} className="auth-form"><label htmlFor="email">Email address</label><input id="email" name="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" placeholder="you@example.com" required /><label htmlFor="password">Password</label><PasswordField value={password} onChange={(e) => setPassword(e.target.value)} /><div className="form-error" role="alert" aria-live="assertive">{error}</div><button className="primary-button" type="submit" disabled={loading} aria-busy={loading}>{loading ? <><span className="spinner" /> Signing in…</> : 'Sign in'}<span aria-hidden="true">→</span></button></form><div className="secure-note"><span className="lock-icon">◈</span> Your account is protected with secure sign-in</div></section><footer>MINI SHERLOCQ <span>•</span> PRIVATE MCP ACCESS</footer></main>
}

function Dashboard({ email, onLogout }) {
  const [csrf, setCsrf] = useState('')
  const [issuer, setIssuer] = useState(window.location.origin)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    request('/api/session').then((session) => setCsrf(session.csrfToken)).catch(() => {})
    request('/api/config').then((config) => setIssuer(config.issuer)).catch(() => {})
  }, [])

  async function logout() {
    try { await request('/api/logout', { method: 'POST', headers: { 'X-CSRF-Token': csrf } }) } finally { onLogout() }
  }

  async function copyUrl() {
    await navigator.clipboard.writeText(`${issuer}/mcp`)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1800)
  }

  return <main className="dashboard-shell"><header className="topbar"><Brand compact /><div className="topbar-right"><span className="user-chip"><span className="avatar">{(email || 'M').slice(0, 1).toUpperCase()}</span>{email}</span><button className="text-button" onClick={logout}>Sign out</button></div></header><section className="welcome"><div><div className="eyebrow">YOUR WORKSPACE</div><h1>Good to see you.</h1><p className="muted">Your Mini Sherlocq MCP server is ready to connect.</p></div><div className="welcome-spark">✳</div></section><section className="status-card"><div className="status-icon">⌘</div><div className="status-copy"><div className="status-heading">MCP endpoint <span className="live-pill"><i /> Protected</span></div><p>Your server requires OAuth sign-in before any tools can run.</p></div><div className="endpoint"><span>STREAMABLE HTTP</span><code>{issuer}/mcp</code><button onClick={copyUrl} className="copy-button">{copied ? 'Copied' : 'Copy URL'}</button></div></section><section className="connect-grid"><article className="connect-card"><div className="card-number">01 / CONNECT</div><h2>Bring Sherlocq to Claude</h2><p>Connect Claude to your remote MCP server. Claude will securely sign in with your Mini Sherlocq account before accessing tools.</p><a className="primary-button link-button" href="https://claude.ai/settings/connectors" target="_blank" rel="noreferrer">Open Claude connectors <span>↗</span></a><div className="small-note">You will review and approve access during Claude’s OAuth flow.</div></article><article className="instructions-card"><div className="card-number">02 / SET UP</div><h2>Three quick steps</h2><ol><li><b>1</b><span>In Claude, open <strong>Settings → Connectors</strong>.</span></li><li><b>2</b><span>Select <strong>Add custom connector</strong> and enter the server URL shown above.</span></li><li><b>3</b><span>Choose <strong>Sign in</strong>, log in here, and approve the requested access.</span></li></ol></article></section><section className="tool-strip"><div><span className="tool-spark">✳</span><div><strong>Two tools are available</strong><p>Check API health and ask questions through your MCP client.</p></div></div><span className="tool-name">check_app_health</span><span className="tool-name">ask_question</span></section><p className="privacy-line">Connection status is managed by Claude and is not visible to this dashboard. A successful sign-in here does not mean Claude has connected.</p><footer>MINI SHERLOCQ <span>•</span> PRIVATE MCP ACCESS</footer></main>
}

function OAuthInteraction() {
  const uid = decodeURIComponent(window.location.pathname.split('/').pop())
  const [details, setDetails] = useState(null)
  const [error, setError] = useState(new URLSearchParams(window.location.search).has('error') ? 'Email or password is incorrect.' : '')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')

  useEffect(() => { request(`/oauth/interaction/${encodeURIComponent(uid)}?format=json`).then(setDetails).catch((e) => setError(e.message)) }, [uid])

  if (!details && error) return <main className="auth-shell"><section className="login-card"><Brand /><div className="eyebrow">SECURE MCP SIGN-IN</div><h1>Sign-in link unavailable</h1><p className="muted">{error} Return to Claude and start connecting again.</p></section></main>
  if (!details) return <main className="auth-shell"><section className="login-card"><Brand /><p className="muted">Loading secure authorization…</p></section></main>

  const action = details.prompt === 'consent' && details.authenticated
    ? `/oauth/interaction/${encodeURIComponent(uid)}/consent`
    : `/oauth/interaction/${encodeURIComponent(uid)}/login`

  if (details.prompt === 'login' && details.authenticated) {
    return <main className="auth-shell"><section className="login-card"><Brand /><div className="eyebrow">SECURE MCP SIGN-IN</div><h1>Continue to approval</h1><p className="muted">Continue as <strong>{details.email}</strong> to review access for this OAuth client.</p><form method="post" action={`/oauth/interaction/${encodeURIComponent(uid)}/continue`}><input type="hidden" name="_csrf" value={details.csrfToken} /><button className="primary-button form-wide" type="submit">Continue as {details.email}<span>→</span></button></form><div className="secure-note">You will review the requested tools before access is granted.</div></section></main>
  }

  if (details.prompt === 'consent' && details.authenticated) {
    return <main className="auth-shell"><section className="login-card consent-card"><Brand /><div className="eyebrow">OAUTH PERMISSION</div><h1>Connect {details.clientName}?</h1><p className="muted">This MCP client is requesting permission to use your Mini Sherlocq tools.</p><div className="permission-box"><strong>Access requested</strong><ul>{details.scopes.filter((scope) => scope !== 'openid' && scope !== 'offline_access').map((scope) => <li key={scope}><span>✓</span> {scope === 'mcp' ? 'Use Mini Sherlocq MCP tools' : scope}</li>)}{details.scopes.includes('offline_access') && <li><span>✓</span> Keep access available with a refresh token</li>}</ul><div className="client-verified">OAuth client name (provided during registration): <b>{details.clientName}</b></div></div><form method="post" action={action}><input type="hidden" name="_csrf" value={details.csrfToken} /><div className="consent-actions"><button className="secondary-button" type="submit" name="decision" value="deny">Deny</button><button className="primary-button" type="submit" name="decision" value="approve">Approve access <span>→</span></button></div></form><div className="secure-note">You can disconnect this connector in Claude settings.</div></section></main>
  }

  return <main className="auth-shell"><section className="login-card"><Brand /><div className="eyebrow">SECURE MCP SIGN-IN</div><h1>Sign in to continue</h1><p className="muted">An OAuth client named <strong>{details.clientName}</strong> is requesting access to Mini Sherlocq. Client names are provided during registration and are not independently verified.</p><form method="post" action={action} className="auth-form"><input type="hidden" name="_csrf" value={details.csrfToken} /><label htmlFor="oauth-email">Email address</label><input id="oauth-email" name="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required /><label htmlFor="oauth-password">Password</label><PasswordField name="password" value={password} onChange={(e) => setPassword(e.target.value)} /><div className="form-error" role="alert">{error}</div><button className="primary-button" type="submit">Sign in and continue <span>→</span></button></form><div className="secure-note">Your password is never shared with Claude.</div></section></main>
}

export default function App() {
  const [user, setUser] = useState(null)
  const [checked, setChecked] = useState(false)
  const path = window.location.pathname
  const isInteraction = path.startsWith('/oauth/interaction/')

  useEffect(() => {
    if (isInteraction) return
    request('/api/session').then((session) => { setUser(session.authenticated ? session.email : null); setChecked(true) }).catch(() => setChecked(true))
  }, [isInteraction])

  if (isInteraction) return <OAuthInteraction />
  if (!checked) return <main className="auth-shell"><section className="login-card"><Brand /><p className="muted">Loading your workspace…</p></section></main>
  if (path === '/dashboard' && user) return <Dashboard email={user} onLogout={() => { setUser(null); window.history.replaceState({}, '', '/login') }} />
  if (path === '/dashboard' && !user) window.history.replaceState({}, '', '/login')
  return <Login onLogin={(result) => { setUser(result.email); window.history.replaceState({}, '', '/dashboard') }} />
}
