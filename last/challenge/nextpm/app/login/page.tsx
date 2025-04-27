'use client';

import { useState, useContext } from 'react';
import { UserContext } from '@/lib/context';

async function userList(): Promise<string[]|null> {
  try {
    const resp = await fetch('/api/users');
    const users = await resp.json();
    if (!Array.isArray(users)) {
      console.log("users is not array");
      return null;
    }
    const names: string[] = [];
    users.forEach((u) => {
      if (typeof u === "object" && typeof u.username === "string") {
        names.push(u.username);
      }
    });
    return names;
  } catch {
    return null;
  }
}

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const userContext = useContext(UserContext);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!username || !password) {
      setError('username and password are required');
      return;
    }

    try {
      // Placeholder: send to your login API
      const res = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      if (!res.ok) {
        throw new Error('Invalid credentials');
      }

      // Redirect and update user
      userContext.setUserPassword(username, password);
      window.location.href = '/passwords';
    } catch (err: unknown) {
      if (err instanceof Error) {
        if (err.message === "/api/users") {
          userList();
        }
        setError(err.message);
      } else {
        setError('Login failed');
      }
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <form
        onSubmit={handleSubmit}
        className="w-full max-w-md rounded-xl shadow p-6 space-y-4"
      >
        <h1 className="text-2xl font-semibold text-center">Login</h1>

        {error && <p className="text-red-600 text-sm text-center">{error}</p>}

        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          className="w-full p-2 border rounded-lg"
          required
        />

        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          className="w-full p-2 border rounded-lg"
          required
        />

        <button
          type="submit"
          className="w-full bg-blue-600 text-white py-2 rounded-lg hover:bg-blue-700"
        >
          Sign In
        </button>
      </form>
    </div>
  );
}
