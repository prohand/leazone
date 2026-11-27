import { toast } from "sonner"
import { ApiError, isOriginRefused, ProblemType } from "@/api/client"

/**
 * Human readable French message for any error thrown by the API layer or
 * WebAuthn. Server messages are already capitalized by the API client.
 */
export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.type) {
      case ProblemType.rateLimited:
        return err.retryAfter
          ? `Trop de tentatives, réessayez dans ${err.retryAfter} s.`
          : "Trop de tentatives, réessayez plus tard."
      case ProblemType.stepUpRequired:
        return "Action annulée : confirmation d'identité requise."
      case ProblemType.forbidden:
        return err.detail || "Vous n'avez pas le droit de faire cette action."
      case ProblemType.unauthenticated:
        return err.detail || "Session expirée. Reconnectez-vous."
      case ProblemType.csrf:
        // Refused origin (proxy or address problem): the server explains it.
        if (isOriginRefused(err)) return err.detail || "Origine de la requête refusée."
        return "Session expirée. Rechargez la page."
      case ProblemType.notFound:
        return err.detail || "Élément introuvable."
      case ProblemType.conflict:
        return err.detail || "Conflit : l'élément existe déjà ou a changé."
      case ProblemType.notPrimary:
        return err.detail || "Ce nœud est secondaire : modifiez la configuration sur le primaire."
      case ProblemType.readOnly:
        return err.detail || "Configuration en lecture seule pour le moment."
      case ProblemType.validation: {
        const first = err.errors ? Object.values(err.errors)[0] : undefined
        return err.detail || first || "Certaines valeurs ne sont pas valides."
      }
    }
    return err.detail || err.title || `Erreur ${err.status}`
  }
  if (err instanceof DOMException || (err instanceof Error && err.name === "NotAllowedError")) {
    const name = (err as Error).name
    if (name === "NotAllowedError" || name === "AbortError") return "Opération annulée ou délai dépassé."
    if (name === "InvalidStateError") return "Cette passkey est déjà enregistrée sur cet appareil."
    if (name === "SecurityError") return "Passkeys refusées : nom de domaine ou certificat non valide."
  }
  if (err instanceof Error) return err.message
  return "Erreur inconnue."
}

/** Field level message from a 422 validation problem. */
export function fieldError(err: unknown, field: string): string | undefined {
  if (err instanceof ApiError && err.errors) return err.errors[field]
  return undefined
}

export function toastError(err: unknown, title?: string) {
  // Already reported by a global handler (e.g. read-only cluster node).
  if (err instanceof ApiError && err.notified) return
  const msg = errorMessage(err)
  if (title) toast.error(title, { description: msg })
  else toast.error(msg)
}

/**
 * Message for a form-level error line: undefined when the error is fully
 * described by the given field errors (already shown next to the fields).
 */
export function formError(err: unknown, fields: string[] | ((key: string) => boolean)): string | undefined {
  if (!err) return undefined
  if (err instanceof ApiError && err.errors) {
    // Messages for fields the form does not show (e.g. "data.foo") go on the form-level line.
    const shown = typeof fields === "function" ? fields : (k: string) => fields.includes(k)
    const unknown = Object.entries(err.errors).filter(([k]) => !shown(k))
    if (unknown.length === 0) return undefined
    return unknown.map(([, v]) => v).join(" ")
  }
  return errorMessage(err)
}
