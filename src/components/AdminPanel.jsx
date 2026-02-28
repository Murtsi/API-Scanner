import { useEffect, useState } from 'react';
import { createManagedUser, listManagedUsers, setManagedUserDisabled } from '../lib/adminApi.js';

function formatDate(value) {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '—';
  return d.toLocaleString();
}

function isDisabled(user) {
  if (!user?.banned_until) return false;
  const d = new Date(user.banned_until);
  return d.getTime() > Date.now();
}

export default function AdminPanel() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('user');
  const [saving, setSaving] = useState(false);

  const loadUsers = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await listManagedUsers();
      setUsers(data);
    } catch (err) {
      setError(err.message || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUsers();
  }, []);

  const handleCreate = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError('');
    try {
      await createManagedUser({ email, password, role });
      setEmail('');
      setPassword('');
      setRole('user');
      await loadUsers();
    } catch (err) {
      setError(err.message || 'Failed to create user');
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (user) => {
    setError('');
    try {
      await setManagedUserDisabled({ userId: user.id, disabled: !isDisabled(user) });
      await loadUsers();
    } catch (err) {
      setError(err.message || 'Failed to update user');
    }
  };

  return (
    <div className="card admin-card">
      <div className="admin-head">
        <h2>Admin Panel</h2>
        <button type="button" className="btn-secondary" onClick={loadUsers} disabled={loading}>
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      <p className="muted small">Create user credentials and control who can sign in.</p>

      <form className="admin-form" onSubmit={handleCreate}>
        <input
          className="auth-input"
          type="email"
          placeholder="user@email.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          className="auth-input"
          type="text"
          placeholder="Temporary password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          minLength={8}
        />
        <select className="auth-input" value={role} onChange={(e) => setRole(e.target.value)}>
          <option value="user">User</option>
          <option value="admin">Admin</option>
        </select>
        <button type="submit" className="btn-primary" disabled={saving}>
          {saving ? 'Creating…' : 'Create User'}
        </button>
      </form>

      {error ? <div className="auth-error">{error}</div> : null}

      <div className="admin-users">
        {users.map((user) => {
          const disabled = isDisabled(user);
          const roleLabel = user.app_metadata?.role || 'user';

          return (
            <div key={user.id} className="admin-user-row">
              <div>
                <div className="admin-user-email">{user.email || '(no email)'}</div>
                <div className="muted small">
                  role: {roleLabel} · created: {formatDate(user.created_at)} · last login: {formatDate(user.last_sign_in_at)}
                </div>
              </div>
              <button
                type="button"
                className="btn-secondary"
                onClick={() => handleToggle(user)}
              >
                {disabled ? 'Enable' : 'Disable'}
              </button>
            </div>
          );
        })}

        {!loading && users.length === 0 ? (
          <p className="muted small">No users yet.</p>
        ) : null}
      </div>
    </div>
  );
}
