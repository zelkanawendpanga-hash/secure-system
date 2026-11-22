import { useEffect, useState } from 'react'
import axios from 'axios'
import './App.css'

function App() {
  const [token, setToken] = useState(localStorage.getItem('securenet_token') || '')
  const [user, setUser] = useState(null)
  const [credentials, setCredentials] = useState({ username: '', password: '', mfa_code: '' })
  const [registerData, setRegisterData] = useState({ username: '', email: '', password: '', passwordConfirm: '' })
  const [authMode, setAuthMode] = useState('login')
  const [message, setMessage] = useState({ recipient: '', content: '' })
  const [file, setFile] = useState(null)
  const [status, setStatus] = useState('')
  const [logs, setLogs] = useState([])

  const api = axios.create({
    baseURL: '',
    headers: token ? { Authorization: `Token ${token}` } : {},
  })

  useEffect(() => {
    if (!token) return
    api.get('/api/accounts/me/')
      .then((response) => setUser(response.data))
      .catch(logout)
  }, [token])

  function logout() {
    setToken('')
    setUser(null)
    localStorage.removeItem('securenet_token')
  }

  async function login(event) {
    event.preventDefault()
    setStatus('')
    try {
      const response = await api.post('/api/accounts/login/', credentials)
      localStorage.setItem('securenet_token', response.data.token)
      setToken(response.data.token)
      setUser(response.data.user)
    } catch (error) {
      setStatus(error.response?.data?.detail || 'Connexion impossible.')
    }

    async function register(event) {
      event.preventDefault()
      setStatus('')
      if (registerData.password !== registerData.passwordConfirm) {
        setStatus('Les mots de passe ne correspondent pas.')
        return
      }
      try {
        await api.post('/api/accounts/register/', {
          username: registerData.username,
          email: registerData.email,
          password: registerData.password,
        })
        setCredentials({ username: registerData.username, password: registerData.password, mfa_code: '' })
        setAuthMode('login')
        setStatus('Compte créé. Vous pouvez maintenant vous connecter.')
      } catch (error) {
        const data = error.response?.data
        if (data && typeof data === 'object') {
          setStatus(Object.values(data).flat().join(' '))
        } else {
          setStatus('Création du compte impossible.')
        }
      }
    }
  }

  async function sendMessage(event) {
    event.preventDefault()
    try {
      await api.post('/api/security/messages/', message)
      setStatus('Message chiffré envoyé.')
      setMessage({ recipient: '', content: '' })
    } catch (error) {
      setStatus(error.response?.data?.detail || 'Envoi impossible.')
    }
  }

  async function encryptFile(event) {
    event.preventDefault()
    if (!file) return
    const form = new FormData()
    form.append('file', file)
    try {
      const response = await api.post('/api/security/encrypt-file/', form)
      setStatus(`Fichier sécurisé : ${response.data.name}`)
      setFile(null)
    } catch (error) {
      setStatus(error.response?.data?.detail || 'Chiffrement impossible.')
    }
  }

  async function loadLogs() {
    try {
      const response = await api.get('/api/security/journal/')
      setLogs(response.data.results || response.data)
    } catch (error) {
      setStatus(error.response?.data?.detail || 'Accès au journal refusé.')
    }
  }

  if (!token) {
    return (
      <main className="auth-page">
        <section className="brand-panel">
          <div className="brand-mark">S</div>
          <h1>SecureNet</h1>
          <p>Protection des données et traçabilité des opérations sensibles.</p>
        </section>
        <section className="auth-card">
          <div className="auth-tabs">
            <button type="button" className={authMode === 'login' ? 'active' : ''} onClick={() => { setAuthMode('login'); setStatus('') }}>Connexion</button>
            <button type="button" className={authMode === 'register' ? 'active' : ''} onClick={() => { setAuthMode('register'); setStatus('') }}>Créer un compte</button>
          </div>
          {authMode === 'login' ? (
            <>
              <h2>Connexion sécurisée</h2>
              <form onSubmit={login}>
                <label>Identifiant<input value={credentials.username} onChange={(e) => setCredentials({ ...credentials, username: e.target.value })} required /></label>
                <label>Mot de passe<input type="password" value={credentials.password} onChange={(e) => setCredentials({ ...credentials, password: e.target.value })} required /></label>
                <label>Code MFA (si activé)<input inputMode="numeric" value={credentials.mfa_code} onChange={(e) => setCredentials({ ...credentials, mfa_code: e.target.value })} /></label>
                {status && <p className="status">{status}</p>}
                <button type="submit">Se connecter</button>
              </form>
            </>
          ) : (
            <>
              <h2>Créer un compte</h2>
              <form onSubmit={register}>
                <label>Identifiant<input value={registerData.username} onChange={(e) => setRegisterData({ ...registerData, username: e.target.value })} required /></label>
                <label>Adresse e-mail<input type="email" value={registerData.email} onChange={(e) => setRegisterData({ ...registerData, email: e.target.value })} required /></label>
                <label>Mot de passe<input type="password" minLength="8" value={registerData.password} onChange={(e) => setRegisterData({ ...registerData, password: e.target.value })} required /></label>
                <label>Confirmer le mot de passe<input type="password" minLength="8" value={registerData.passwordConfirm} onChange={(e) => setRegisterData({ ...registerData, passwordConfirm: e.target.value })} required /></label>
                {status && <p className="status error">{status}</p>}
                <button type="submit">Créer mon compte employé</button>
              </form>
            </>
          )}
        </section>
      </main>
    )
  }

  const canAudit = user?.role === 'admin' || user?.role === 'auditor'

  return (
    <main className="dashboard">
      <aside>
        <div className="brand-mark small">S</div>
        <h1>SecureNet</h1>
        <nav>
          <button className="active">Tableau de bord</button>
          <button onClick={() => document.getElementById('messages')?.scrollIntoView()}>Messages</button>
          <button onClick={() => document.getElementById('files')?.scrollIntoView()}>Fichiers</button>
          {canAudit && <button onClick={loadLogs}>Journal</button>}
        </nav>
        <button className="logout" onClick={logout}>Déconnexion</button>
      </aside>
      <section className="content">
        <header><div><p>Bienvenue</p><h2>{user?.username || 'Utilisateur'}</h2></div><span className="role">{user?.role}</span></header>
        {status && <p className="status">{status}</p>}
        <div className="cards">
          <article><span>Chiffrement</span><strong>AES-256-GCM</strong></article>
          <article><span>Contrôle d’accès</span><strong>RBAC</strong></article>
          <article><span>Traçabilité</span><strong>Journal chaîné</strong></article>
        </div>
        <div className="panels">
          <section id="messages">
            <h3>Envoyer un message</h3>
            <form onSubmit={sendMessage}>
              <label>ID du destinataire<input value={message.recipient} onChange={(e) => setMessage({ ...message, recipient: e.target.value })} required /></label>
              <label>Message<textarea value={message.content} onChange={(e) => setMessage({ ...message, content: e.target.value })} required /></label>
              <button type="submit">Chiffrer et envoyer</button>
            </form>
          </section>
          <section id="files">
            <h3>Fichier sensible</h3>
            <form onSubmit={encryptFile}>
              <label>Document<input type="file" onChange={(e) => setFile(e.target.files[0])} required /></label>
              <button type="submit">Chiffrer et stocker</button>
            </form>
          </section>
        </div>
        {canAudit && logs.length > 0 && (
          <section className="audit">
            <h3>Journal d’audit</h3>
            <div className="log-table">{logs.map((log) => <div key={log.id}><span>{log.timestamp}</span><strong>{log.action}</strong><span>{log.target}</span><em>{log.result}</em></div>)}</div>
          </section>
        )}
      </section>
    </main>
  )
}

export default App
