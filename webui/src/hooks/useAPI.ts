import { useState, useEffect, useCallback } from 'react'

const BASE = ''

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(BASE + path, options)
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`${res.status}: ${text}`)
  }
  if (res.status === 204) return undefined as T
  return res.json() as Promise<T>
}

export function useAPI<T>(path: string, intervalMs = 0) {
  const [data,    setData]    = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState<string | null>(null)

  const fetch_ = useCallback(async () => {
    try {
      setLoading(true)
      const result = await apiFetch<T>(path)
      setData(result)
      setError(null)
    } catch (e) {
      setError(String(e))
    } finally {
      setLoading(false)
    }
  }, [path])

  useEffect(() => {
    fetch_()
    if (intervalMs > 0) {
      const id = setInterval(fetch_, intervalMs)
      return () => clearInterval(id)
    }
  }, [fetch_, intervalMs])

  return { data, loading, error, refresh: fetch_ }
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  return apiFetch<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export async function apiDelete(path: string): Promise<void> {
  const res = await fetch(BASE + path, { method: 'DELETE' })
  if (!res.ok && res.status !== 204) {
    const text = await res.text()
    throw new Error(`DELETE ${path}: ${res.status} ${text}`)
  }
}
