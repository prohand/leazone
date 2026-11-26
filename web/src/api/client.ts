import type { paths } from "./schema"

/*
 * Small typed fetch wrapper around the Leazone REST API.
 *
 * - Same-origin cookies (session cookie is HttpOnly, set by the server).
 * - Adds X-CSRF-Token (from GET /auth/session) on every non-GET request.
 * - Parses RFC 9457 problem+json errors into ApiError.
 * - On `urn:leazone:step-up-required`, asks the registered step-up handler
 *   (a global dialog) to re-verify the user, then retries the request once.
 * - On `urn:leazone:not-primary` / `urn:leazone:read-only` (config change on a
 *   cluster secondary, or while the config is frozen), tells the registered
 *   read-only handler (a toast with a link to the primary), then throws.
 */

export const API_BASE = "/api/v1"

export const ProblemType = {
  unauthenticated: "urn:leazone:unauthenticated",
  forbidden: "urn:leazone:forbidden",
  stepUpRequired: "urn:leazone:step-up-required",
  mfaRequired: "urn:leazone:mfa-required",
  rateLimited: "urn:leazone:rate-limited",
  validation: "urn:leazone:validation",
  notFound: "urn:leazone:not-found",
  conflict: "urn:leazone:conflict",
  csrf: "urn:leazone:csrf",
  notPrimary: "urn:leazone:not-primary",
  readOnly: "urn:leazone:read-only",
} as const

export class ApiError extends Error {
  readonly type: string
  readonly status: number
  readonly title?: string
  readonly detail?: string
  readonly retryAfter?: number
  readonly errors?: Record<string, string>
  /** UI address of the cluster primary (not-primary problems). */
  readonly primaryUrl?: string
  /** Set when a global handler already told the user (no second toast). */
  notified = false

  constructor(init: {
    type?: string
    status: number
    title?: string
    detail?: string
    retryAfter?: number
    errors?: Record<string, string>
    primaryUrl?: string
  }) {
    super(init.detail || init.title || `HTTP ${init.status}`)
    this.name = "ApiError"
    this.type = init.type || "about:blank"
    this.status = init.status
    this.title = init.title
    this.detail = init.detail
    this.retryAfter = init.retryAfter
    this.errors = init.errors
    this.primaryUrl = init.primaryUrl
  }

  is(type: string) {
    return this.type === type
  }
}

export function isApiError(err: unknown, type?: string): err is ApiError {
  return err instanceof ApiError && (type === undefined || err.type === type)
}

// ---- Global hooks set by the app (session cache, step-up dialog) ----

let csrfToken = ""
export function setCsrfToken(token: string | undefined) {
  csrfToken = token ?? ""
}

type StepUpHandler = () => Promise<boolean>
let stepUpHandler: StepUpHandler | null = null
export function setStepUpHandler(handler: StepUpHandler | null) {
  stepUpHandler = handler
}

type AuthLostHandler = (err: ApiError) => void
let authLostHandler: AuthLostHandler | null = null
/** Called when an authenticated call fails with 401 / mfa-required / csrf. */
export function setAuthLostHandler(handler: AuthLostHandler | null) {
  authLostHandler = handler
}

type ReadOnlyHandler = (err: ApiError) => void
let readOnlyHandler: ReadOnlyHandler | null = null
/** Called when a change is refused because this node is not writable (cluster). */
export function setReadOnlyHandler(handler: ReadOnlyHandler | null) {
  readOnlyHandler = handler
}

// ---- Typing helpers derived from the generated OpenAPI schema ----

type Method = "get" | "post" | "put" | "patch" | "delete"
type Path = keyof paths

type PathsWith<M extends Method> = {
  [P in Path]: paths[P][M] extends { responses: unknown } ? P : never
}[Path]

type Op<P extends Path, M extends Method> = paths[P][M]

type JsonOf<R> = R extends { content: { "application/json": infer T } }
  ? T
  : R extends { content: { "text/plain": infer T } }
    ? T
    : void

type ResponseOf<O> = O extends { responses: infer R }
  ? 200 extends keyof R
    ? JsonOf<R[200]>
    : 201 extends keyof R
      ? JsonOf<R[201]>
      : void
  : never

type BodyOf<O> = O extends { requestBody: { content: { "application/json": infer B } } }
  ? B
  : O extends { requestBody?: { content: { "application/json": infer B } } }
    ? B | undefined
    : undefined

type PathParamsOf<O> = O extends { parameters: { path: infer PP } } ? PP : undefined
type QueryOf<O> = O extends { parameters: { query?: infer Q } }
  ? [Q] extends [never]
    ? undefined
    : Q | undefined
  : undefined

type Options<O> = {
  params?: PathParamsOf<O>
  query?: QueryOf<O>
  body?: BodyOf<O>
  signal?: AbortSignal
  /** Internal: set on the retry after a successful step-up. */
  noStepUp?: boolean
}

export type ApiResponse<P extends Path, M extends Method> = ResponseOf<Op<P, M>>
export type ApiBody<P extends Path, M extends Method> = BodyOf<Op<P, M>>

function buildUrl(path: string, params?: object, query?: object) {
  let url = path.replace(/\{(\w+)\}/g, (_, key: string) => {
    const value = (params as Record<string, unknown> | undefined)?.[key]
    if (value === undefined || value === null) throw new Error(`missing path param ${key}`)
    return encodeURIComponent(String(value))
  })
  if (query) {
    const sp = new URLSearchParams()
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null || v === "") continue
      sp.set(k, String(v))
    }
    const qs = sp.toString()
    if (qs) url += `?${qs}`
  }
  return API_BASE + url
}

async function parseError(res: Response): Promise<ApiError> {
  let body: Record<string, unknown> = {}
  try {
    const text = await res.text()
    if (text) body = JSON.parse(text)
  } catch {
    // not JSON: keep empty body
  }
  let retryAfter = typeof body.retryAfter === "number" ? body.retryAfter : undefined
  if (retryAfter === undefined) {
    const h = res.headers.get("Retry-After")
    if (h && /^\d+$/.test(h)) retryAfter = Number(h)
  }
  return new ApiError({
    type: typeof body.type === "string" ? body.type : undefined,
    status: typeof body.status === "number" ? body.status : res.status,
    title: typeof body.title === "string" ? body.title : undefined,
    detail: typeof body.detail === "string" ? body.detail : undefined,
    retryAfter,
    errors:
      body.errors && typeof body.errors === "object"
        ? (body.errors as Record<string, string>)
        : undefined,
    primaryUrl: typeof body.primaryUrl === "string" && body.primaryUrl ? body.primaryUrl : undefined,
  })
}

// Paths that are part of the login / step-up flows: never trigger the
// "auth lost" handler or a step-up for them.
const AUTH_FLOW = /^\/auth\//

/** Sends the request; on error runs the global handlers (step-up + retry once, auth lost, read-only). */
async function send<P extends Path, M extends Method>(
  method: M,
  path: P,
  options: Options<Op<P, M>>,
  accept: string,
): Promise<Response> {
  const url = buildUrl(path, options.params as object | undefined, options.query as object | undefined)
  const headers: Record<string, string> = { Accept: accept }
  if (method !== "get" && csrfToken) headers["X-CSRF-Token"] = csrfToken
  let body: string | undefined
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json"
    body = JSON.stringify(options.body)
  }

  let res: Response
  try {
    res = await fetch(url, {
      method: method.toUpperCase(),
      headers,
      body,
      credentials: "same-origin",
      signal: options.signal,
    })
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e
    throw new ApiError({
      type: "urn:leazone:network",
      status: 0,
      detail: "Le serveur ne répond pas. Vérifiez la connexion.",
    })
  }

  if (!res.ok) {
    const err = await parseError(res)
    const inAuthFlow = AUTH_FLOW.test(path)

    if (err.is(ProblemType.stepUpRequired) && !options.noStepUp && stepUpHandler && !inAuthFlow) {
      const ok = await stepUpHandler()
      if (ok) return send(method, path, { ...options, noStepUp: true }, accept)
    }

    if (
      !inAuthFlow &&
      (err.is(ProblemType.unauthenticated) || err.is(ProblemType.mfaRequired) || err.is(ProblemType.csrf))
    ) {
      authLostHandler?.(err)
    }

    if ((err.is(ProblemType.notPrimary) || err.is(ProblemType.readOnly)) && readOnlyHandler) {
      readOnlyHandler(err)
      err.notified = true
    }
    throw err
  }
  return res
}

export async function request<P extends Path, M extends Method>(
  method: M,
  path: P,
  options: Options<Op<P, M>> = {},
): Promise<ApiResponse<P, M>> {
  const res = await send(method, path, options, "application/json, text/plain;q=0.9")
  if (res.status === 204) return undefined as ApiResponse<P, M>
  const text = await res.text()
  // Non-JSON bodies (e.g. a zone export in text/plain) are returned as a string.
  const ctype = res.headers.get("Content-Type") ?? ""
  if (ctype && !/[/+]json\b/i.test(ctype)) return text as ApiResponse<P, M>
  return (text ? JSON.parse(text) : undefined) as ApiResponse<P, M>
}

/** File name from a Content-Disposition header (filename* first), else undefined. */
export function dispositionFilename(header: string | null): string | undefined {
  if (!header) return undefined
  const star = /filename\*\s*=\s*(?:UTF-8|utf-8)''([^;]+)/.exec(header)
  if (star) {
    try {
      return decodeURIComponent(star[1].trim().replace(/^"|"$/g, ""))
    } catch {
      // fall through to the plain form
    }
  }
  const plain = /filename\s*=\s*("([^"]*)"|[^;]+)/.exec(header)
  const name = plain ? (plain[2] ?? plain[1]).trim() : ""
  // Never trust a path from the server: keep the last part only.
  return name ? name.split(/[\\/]/).pop() || undefined : undefined
}

/**
 * Downloads a file answer (backup, automatic backup...): same error handling
 * as `request` (step-up dialog then one retry), but returns the raw body and
 * the file name given by the server.
 */
export async function requestFile<P extends Path, M extends Method>(
  method: M,
  path: P,
  options: Options<Op<P, M>> = {},
): Promise<{ blob: Blob; filename?: string }> {
  const res = await send(method, path, options, "application/yaml, application/octet-stream, */*;q=0.8")
  const blob = await res.blob()
  return { blob, filename: dispositionFilename(res.headers.get("Content-Disposition")) }
}

export const api = {
  get: <P extends PathsWith<"get">>(path: P, options?: Options<Op<P, "get">>) =>
    request("get", path, options),
  post: <P extends PathsWith<"post">>(path: P, options?: Options<Op<P, "post">>) =>
    request("post", path, options),
  put: <P extends PathsWith<"put">>(path: P, options?: Options<Op<P, "put">>) =>
    request("put", path, options),
  patch: <P extends PathsWith<"patch">>(path: P, options?: Options<Op<P, "patch">>) =>
    request("patch", path, options),
  delete: <P extends PathsWith<"delete">>(path: P, options?: Options<Op<P, "delete">>) =>
    request("delete", path, options),
}
