import { describe, it, expect, vi, beforeEach } from 'vitest'
import { Networks } from '@stellar/stellar-sdk'
import { authenticate, invalidateSep10Token } from '@/lib/stellar/sep10'
import { clearJwtCache, setJwtCacheCapacity, getCachedJwt, withDedupedAuth, getCachedJwtOrStale, setCachedJwt } from '@/lib/stellar/jwt-cache'
import * as sep1 from '@/lib/stellar/sep1'
import type { Sep10Auth } from '@/types'

const WEB_AUTH_ENDPOINT = 'https://cowrie.exchange/auth'
const ANCHOR = 'cowrie.exchange'
const PUBLIC_KEY = 'GABCDEFGHIJKLMNOPQRSTUVWXYZ012345678901234567890123456789'
const CHALLENGE_XDR = 'AAAAAQAAAAC...'
const SIGNED_XDR = 'AAAAAQAAAAD...'

const mockResolvedAnchor = (domain: string) => ({
  id: domain.split('.')[0] || 'anchor',
  name: domain,
  homeDomain: domain,
  corridors: [],
  assetCode: 'USDC',
  assetIssuer: 'G...',
  TRANSFER_SERVER_SEP0024: `https://${domain}/sep24`,
  WEB_AUTH_ENDPOINT: `https://${domain}/auth`,
  SIGNING_KEY: 'G...',
  capabilities: { sep10: true, sep24: true, sep38: false, sep12: false },
})

vi.mock('@stellar/freighter-api', () => ({
  signTransaction: vi.fn(),
}))

function makeJwt(expSeconds: number): string {
  const b64url = (s: string) =>
    btoa(s).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = b64url(JSON.stringify({ exp: expSeconds }))
  return `${header}.${payload}.signature`
}

async function getFreighter() {
  return await import('@stellar/freighter-api')
}

function stubChallengeAndJwt(jwt: string) {
  const fetchMock = vi.fn()
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({ transaction: CHALLENGE_XDR, network_passphrase: Networks.PUBLIC }),
    })
    .mockResolvedValueOnce({
      ok: true,
      json: async () => ({ token: jwt }),
    })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

beforeEach(async () => {
  vi.restoreAllMocks()
  clearJwtCache()
  setJwtCacheCapacity(32)

  const freighter = await getFreighter()
  vi.mocked(freighter.signTransaction).mockResolvedValue({
    signedTxXdr: SIGNED_XDR,
    signerAddress: PUBLIC_KEY,
  })
})

describe('SEP-10 JWT cache', () => {
  it('second call within validity returns cached token without invoking Freighter', async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600
    stubChallengeAndJwt(makeJwt(exp))

    const first = await authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY)

    const freighter = await getFreighter()
    vi.mocked(freighter.signTransaction).mockClear()
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('fetch should not be called on cache hit')
    }))

    const second = await authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY)

    expect(second.jwt).toBe(first.jwt)
    expect(second.expiresAt.getTime()).toBe(first.expiresAt.getTime())
    expect(freighter.signTransaction).not.toHaveBeenCalled()
  })

  it('expired cached token triggers a fresh sign flow', async () => {
    const shortExp = Math.floor(Date.now() / 1000) + 1
    stubChallengeAndJwt(makeJwt(shortExp))

    await authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY)

    // Advance past expiry
    vi.useFakeTimers()
    vi.setSystemTime(new Date((shortExp + 5) * 1000))

    const freighter = await getFreighter()
    vi.mocked(freighter.signTransaction).mockClear()

    const newExp = Math.floor(Date.now() / 1000) + 3600
    stubChallengeAndJwt(makeJwt(newExp))

    const fresh = await authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY)

    expect(freighter.signTransaction).toHaveBeenCalledTimes(1)
    expect(fresh.expiresAt.getTime()).toBe(newExp * 1000)

    vi.useRealTimers()
  })

  it('invalidateSep10Token forces re-authentication on next call', async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600
    stubChallengeAndJwt(makeJwt(exp))

    await authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY)
    expect(getCachedJwt(ANCHOR, PUBLIC_KEY)).toBeDefined()

    // Simulate downstream 401 response → invalidate
    invalidateSep10Token(ANCHOR, PUBLIC_KEY)
    expect(getCachedJwt(ANCHOR, PUBLIC_KEY)).toBeUndefined()

    const freighter = await getFreighter()
    vi.mocked(freighter.signTransaction).mockClear()
    stubChallengeAndJwt(makeJwt(exp))

    await authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY)
    expect(freighter.signTransaction).toHaveBeenCalledTimes(1)
  })

  it('LRU evicts the least-recently-used entry past capacity', async () => {
    setJwtCacheCapacity(2)
    const exp = Math.floor(Date.now() / 1000) + 3600

    stubChallengeAndJwt(makeJwt(exp))
    await authenticate(mockResolvedAnchor('a.example'), PUBLIC_KEY)

    stubChallengeAndJwt(makeJwt(exp))
    await authenticate(mockResolvedAnchor('b.example'), PUBLIC_KEY)

    // Touch 'a' so 'b' becomes the LRU
    expect(getCachedJwt('a.example', PUBLIC_KEY)).toBeDefined()

    stubChallengeAndJwt(makeJwt(exp))
    await authenticate(mockResolvedAnchor('c.example'), PUBLIC_KEY)

    expect(getCachedJwt('a.example', PUBLIC_KEY)).toBeDefined()
    expect(getCachedJwt('c.example', PUBLIC_KEY)).toBeDefined()
    expect(getCachedJwt('b.example', PUBLIC_KEY)).toBeUndefined()
  })

  it('concurrent authenticate calls are deduplicated', async () => {
    const exp = Math.floor(Date.now() / 1000) + 3600
    let callCount = 0

    const fetchMock = vi.fn()
      .mockImplementation(async () => {
        callCount++
        // Simulate network delay
        await new Promise(resolve => setTimeout(resolve, 50))
        return {
          ok: true,
          json: async () => ({ transaction: CHALLENGE_XDR, network_passphrase: Networks.PUBLIC }),
        }
      })
      .mockImplementation(async () => {
        callCount++
        return {
          ok: true,
          json: async () => ({ token: makeJwt(exp) }),
        }
      })
    vi.stubGlobal('fetch', fetchMock)

    // Launch concurrent requests
    const promises = [
      authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY),
      authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY),
      authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY),
    ]

    const results = await Promise.all(promises)

    // All should return the same JWT
    expect(results[0].jwt).toBe(results[1].jwt)
    expect(results[1].jwt).toBe(results[2].jwt)

    // Fetch should only be called once (deduplication)
    expect(callCount).toBe(2) // 1 for challenge, 1 for token exchange

    const freighter = await getFreighter()
    expect(freighter.signTransaction).toHaveBeenCalledTimes(1)
  })

  it('withDedupedAuth deduplicates concurrent requests', async () => {
    let fetchCount = 0
    const fetcher = vi.fn(async () => {
      fetchCount++
      await new Promise(resolve => setTimeout(resolve, 20))
      return {
        jwt: 'test.jwt',
        anchorDomain: ANCHOR,
        publicKey: PUBLIC_KEY,
        expiresAt: new Date(Date.now() + 3600000),
      } as Sep10Auth
    })

    const promises = [
      withDedupedAuth(ANCHOR, PUBLIC_KEY, fetcher),
      withDedupedAuth(ANCHOR, PUBLIC_KEY, fetcher),
      withDedupedAuth(ANCHOR, PUBLIC_KEY, fetcher),
    ]

    const results = await Promise.all(promises)

    // All should return the same result
    expect(results[0].jwt).toBe('test.jwt')
    expect(results[1].jwt).toBe('test.jwt')
    expect(results[2].jwt).toBe('test.jwt')

    // Fetcher should only be called once
    expect(fetchCount).toBe(1)
  })

  it('withDedupedAuth clears pending request on error', async () => {
    const fetcher = vi.fn(async () => {
      throw new Error('Network error')
    })

    // First request should fail
    await expect(withDedupedAuth(ANCHOR, PUBLIC_KEY, fetcher)).rejects.toThrow('Network error')

    // Second request should call fetcher again (not deduplicated)
    const successFetcher = vi.fn(async () => ({
      jwt: 'test.jwt',
      anchorDomain: ANCHOR,
      publicKey: PUBLIC_KEY,
      expiresAt: new Date(Date.now() + 3600000),
    } as Sep10Auth))

    const result = await withDedupedAuth(ANCHOR, PUBLIC_KEY, successFetcher)
    expect(result.jwt).toBe('test.jwt')
    expect(successFetcher).toHaveBeenCalledTimes(1)
  })

  it('getCachedJwtOrStale returns expired JWT for stale-while-revalidate', async () => {
    const expiredAuth: Sep10Auth = {
      jwt: 'expired.jwt',
      anchorDomain: ANCHOR,
      publicKey: PUBLIC_KEY,
      expiresAt: new Date(Date.now() - 1000), // Expired 1 second ago
    }

    setCachedJwt(expiredAuth)

    // getCachedJwt should return undefined for expired tokens
    expect(getCachedJwt(ANCHOR, PUBLIC_KEY)).toBeUndefined()

    // getCachedJwtOrStale should return the expired token
    const stale = getCachedJwtOrStale(ANCHOR, PUBLIC_KEY)
    expect(stale).toBeDefined()
    expect(stale?.jwt).toBe('expired.jwt')
    expect(stale?.expiresAt.getTime()).toBeLessThan(Date.now())
  })

  it('getCachedJwtOrStale returns undefined for missing cache entry', () => {
    expect(getCachedJwtOrStale(ANCHOR, PUBLIC_KEY)).toBeUndefined()
  })

  it('authenticate returns stale JWT immediately and revalidates in background', async () => {
    const expiredAuth: Sep10Auth = {
      jwt: 'expired.jwt',
      anchorDomain: ANCHOR,
      publicKey: PUBLIC_KEY,
      expiresAt: new Date(Date.now() - 1000), // Expired 1 second ago
    }

    setCachedJwt(expiredAuth)

    let backgroundFetchStarted = false
    const fetchMock = vi.fn()
      .mockImplementation(async () => {
        backgroundFetchStarted = true
        // Simulate network delay
        await new Promise(resolve => setTimeout(resolve, 100))
        return {
          ok: true,
          json: async () => ({ transaction: CHALLENGE_XDR, network_passphrase: Networks.PUBLIC }),
        }
      })
      .mockImplementation(async () => {
        return {
          ok: true,
          json: async () => ({ token: makeJwt(Math.floor(Date.now() / 1000) + 3600) }),
        }
      })
    vi.stubGlobal('fetch', fetchMock)

    // Authenticate should return stale JWT immediately
    const result = await authenticate(mockResolvedAnchor(ANCHOR), PUBLIC_KEY)

    // Should return the stale JWT immediately
    expect(result.jwt).toBe('expired.jwt')

    // Background fetch should have been triggered
    expect(backgroundFetchStarted).toBe(true)

    // Wait for background revalidation to complete
    await new Promise(resolve => setTimeout(resolve, 150))

    // Cache should now have fresh JWT
    const fresh = getCachedJwt(ANCHOR, PUBLIC_KEY)
    expect(fresh).toBeDefined()
    expect(fresh?.jwt).not.toBe('expired.jwt')
  })
})
